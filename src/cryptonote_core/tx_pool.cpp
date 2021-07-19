// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <unordered_set>
#include <vector>

#include "tx_pool.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "blockchain_db/locked_txn.h"
#include "blockchain_db/blockchain_db.h"
#include "common/boost_serialization_helper.h"
#include "common/lock.h"
#include "common/hex.h"
#include "epee/int-util.h"
#include "epee/misc_language.h"
#include "epee/warnings.h"
#include "common/perf_timer.h"
#include "crypto/hash.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "txpool"

DISABLE_VS_WARNINGS(4244 4345 4503) //'boost::foreach_detail_::or_' : decorated name length exceeded, name was truncated

using namespace crypto;

namespace cryptonote
{
  namespace
  {
    //TODO: constants such as these should at least be in the header,
    //      but probably somewhere more accessible to the rest of the
    //      codebase.  As it stands, it is at best nontrivial to test
    //      whether or not changing these parameters (or adding new)
    //      will work correctly.
    time_t const MIN_RELAY_TIME = (60 * 5); // only start re-relaying transactions after that many seconds
    time_t const MAX_RELAY_TIME = (60 * 60 * 4); // at most that many seconds between resends
    float const ACCEPT_THRESHOLD = 1.0f;

    // a kind of increasing backoff within min/max bounds
    uint64_t get_relay_delay(time_t now, time_t received)
    {
      time_t d = (now - received + MIN_RELAY_TIME) / MIN_RELAY_TIME * MIN_RELAY_TIME;
      if (d > MAX_RELAY_TIME)
        d = MAX_RELAY_TIME;
      return d;
    }

    uint64_t get_transaction_weight_limit(uint8_t version)
    {
      // from v10, bulletproofs, limit a tx to 50% of the minimum block weight
      if (version >= network_version_10_bulletproofs)
        return get_min_block_weight(version) / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
      else
        return get_min_block_weight(version) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    }
  }
  //---------------------------------------------------------------------------------
  // warning: bchs is passed here uninitialized, so don't do anything but store it
  tx_memory_pool::tx_memory_pool(Blockchain& bchs): m_blockchain(bchs), m_txpool_max_weight(DEFAULT_TXPOOL_MAX_WEIGHT), m_txpool_weight(0), m_cookie(0)
  {

  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_duplicated_non_standard_tx(transaction const &tx, uint8_t hard_fork_version) const
  {
    auto &service_node_list = m_blockchain.get_service_node_list();
    if (tx.type == txtype::state_change)
    {
      tx_extra_service_node_state_change state_change;
      if (!get_service_node_state_change_from_tx_extra(tx.extra, state_change, hard_fork_version))
      {
        MERROR("Could not get service node state change from tx: " << get_transaction_hash(tx) << ", possibly corrupt tx in your blockchain, rejecting malformed state change");
        return false;
      }

      crypto::public_key service_node_to_change;
      auto const quorum_type               = service_nodes::quorum_type::obligations;
      auto const quorum_group              = service_nodes::quorum_group::worker;

      // NOTE: We can fail to resolve a public key if we are popping blocks greater than the number of quorums we store.
      bool const can_resolve_quorum_pubkey = service_node_list.get_quorum_pubkey(quorum_type,
                                                                                 quorum_group,
                                                                                 state_change.block_height,
                                                                                 state_change.service_node_index,
                                                                                 service_node_to_change);

      std::vector<transaction> pool_txs;
      get_transactions(pool_txs);
      for (const transaction& pool_tx : pool_txs)
      {
        if (pool_tx.type != txtype::state_change)
          continue;

        tx_extra_service_node_state_change pool_tx_state_change;
        if (!get_service_node_state_change_from_tx_extra(pool_tx.extra, pool_tx_state_change, hard_fork_version))
        {
          LOG_PRINT_L1("Could not get service node state change from tx: " << get_transaction_hash(pool_tx) << ", possibly corrupt tx in the pool");
          continue;
        }

        if (hard_fork_version >= cryptonote::network_version_12_checkpointing)
        {
          crypto::public_key service_node_to_change_in_the_pool;
          bool same_service_node = false;
          if (can_resolve_quorum_pubkey && service_node_list.get_quorum_pubkey(quorum_type, quorum_group, pool_tx_state_change.block_height, pool_tx_state_change.service_node_index, service_node_to_change_in_the_pool))
          {
            same_service_node = (service_node_to_change == service_node_to_change_in_the_pool);
          }
          else
          {
            same_service_node = (state_change == pool_tx_state_change);
          }

          if (same_service_node && pool_tx_state_change.state == state_change.state)
            return true;
        }
        else
        {
          if (state_change == pool_tx_state_change)
            return true;
        }
      }
    }
    else if (tx.type == txtype::key_image_unlock)
    {
      tx_extra_tx_key_image_unlock unlock;
      if (!cryptonote::get_field_from_tx_extra(tx.extra, unlock))
      {
        MERROR("Could not get key image unlock from tx: " << get_transaction_hash(tx) << ", tx to add is possibly invalid, rejecting");
        return true;
      }

      std::vector<transaction> pool_txs;
      get_transactions(pool_txs);
      for (const transaction& pool_tx : pool_txs)
      {
        if (pool_tx.type != tx.type)
          continue;

        tx_extra_tx_key_image_unlock pool_unlock;
        if (!cryptonote::get_field_from_tx_extra(pool_tx.extra, pool_unlock))
        {
          LOG_PRINT_L1("Could not get key image unlock from tx: " << get_transaction_hash(tx) << ", possibly corrupt tx in the pool");
          return true;
        }

        if (unlock == pool_unlock)
        {
          LOG_PRINT_L1("New TX: " << get_transaction_hash(tx) << ", has TX: " << get_transaction_hash(pool_tx) << " from the pool that is requesting to unlock the same key image already.");
          return true;
        }
      }

    }
    else if (tx.type == txtype::oxen_name_system)
    {
      tx_extra_oxen_name_system data;
      if (!cryptonote::get_field_from_tx_extra(tx.extra, data))
      {
        MERROR("Could not get acquire name service from tx: " << get_transaction_hash(tx) << ", tx to add is possibly invalid, rejecting");
        return true;
      }

      std::vector<transaction> pool_txs;
      get_transactions(pool_txs);
      for (const transaction& pool_tx : pool_txs)
      {
        if (pool_tx.type != tx.type)
          continue;

        tx_extra_oxen_name_system pool_data;
        if (!cryptonote::get_field_from_tx_extra(pool_tx.extra, pool_data))
        {
          LOG_PRINT_L1("Could not get acquire name service from tx: " << get_transaction_hash(tx) << ", possibly corrupt tx in the pool");
          return true;
        }

        if (data.type == pool_data.type && data.name_hash == pool_data.name_hash)
        {
          LOG_PRINT_L1("New TX: " << get_transaction_hash(tx) << ", has TX: " << get_transaction_hash(pool_tx) << " from the pool that is requesting the same ONS entry already.");
          return true;
        }
      }
    }
    else
    {
      if (tx.type != txtype::standard && tx.type != txtype::stake)
      {
        // NOTE(oxen): This is a developer error. If we come across this in production, be conservative and just reject
        MERROR("Unrecognised transaction type: " << tx.type << " for tx: " << get_transaction_hash(tx));
        return true;
      }
    }

    return false;
  }

  // Blink notes: a blink quorum member adds an incoming blink tx into the mempool to make sure it
  // can be accepted, but sets it as do_not_relay initially.  If it gets added, the quorum member
  // sends a signature to other quorum members.  Once enough signatures are received it updates it
  // to set `do_not_relay` to false and starts relaying it (other quorum members do the same).

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, const crypto::hash &id, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, const tx_pool_options &opts, uint8_t hf_version,
      uint64_t *blink_rollback_height)
  {
    // this should already be called with that lock, but let's make it explicit for clarity
    std::unique_lock lock{m_transactions_lock};

    PERF_TIMER(add_tx);
    if (tx.version == txversion::v0)
    {
      // v0 never accepted
      LOG_PRINT_L1("transaction version 0 is invalid");
      tvc.m_verifivation_failed = true;
      return false;
    }

    // we do not accept transactions that timed out before, unless they're
    // kept_by_block
    if (!opts.kept_by_block && m_timed_out_transactions.find(id) != m_timed_out_transactions.end())
    {
      // not clear if we should set that, since verifivation (sic) did not fail before, since
      // the tx was accepted before timing out.
      tvc.m_verifivation_failed = true;
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    //TODO check if has_txin_gen then it should comply with the desired correct payout of get_sn_rewards

    uint64_t fee, burned;

    if (!get_tx_miner_fee(tx, fee, hf_version >= HF_VERSION_FEE_BURNING, &burned))
    {
      // This code is a bit convoluted: the above sets `fee`, and returns false for a pre-ringct tx
      // with a too-low fee, but for ringct (v2+) txes it just sets `fee` but doesn't check it and
      // always returns true: the actual v2 tx fee amount gets tested in the check_fee call below
      tvc.m_verifivation_failed = true;
      tvc.m_fee_too_low = true;
      return false;
    }


    if(hf_version < cryptonote::network_version_19)
    {
      if (!opts.kept_by_block && tx.is_transfer() && !m_blockchain.check_fee(tx_weight, tx.vout.size(), fee, burned, opts))
      {
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
      }
    }

    size_t tx_weight_limit = get_transaction_weight_limit(hf_version);
    if ((!opts.kept_by_block || hf_version >= HF_VERSION_PER_BYTE_FEE) && tx_weight > tx_weight_limit)
    {
      LOG_PRINT_L1("transaction is too heavy: " << tx_weight << " bytes, maximum weight: " << tx_weight_limit);
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    {
      std::vector<crypto::hash> conflict_txs;
      bool double_spend = have_tx_keyimges_as_spent(tx, &conflict_txs);

      if (double_spend)
      {
        if (opts.kept_by_block)
        {
          // The tx came from a block popped from the chain; we keep it around even if the key
          // images are spent so that we notice the double spend *unless* the tx is conflicting with
          // one or more blink txs, in which case we drop it because it can never be accepted.
          auto blink_lock = blink_shared_lock();
          double_spend = false;
          for (const auto &tx_hash : conflict_txs)
          {
            if (tx_hash != id && m_blinks.count(tx_hash))
            {
              // Warn on this because it almost certainly indicates something malicious
              MWARNING("Not re-adding popped/incoming tx " << id << " to the mempool: it conflicts with blink tx " << tx_hash);
              double_spend = true;
              break;
            }
          }
        }
        else if (opts.approved_blink)
        {
          MDEBUG("Incoming blink tx is approved, but has " << conflict_txs.size() << " conflicting local tx(es); dropping conflicts");
          if (remove_blink_conflicts(id, conflict_txs, blink_rollback_height))
            double_spend = false;
          else
            MERROR("Blink error: incoming blink tx cannot be accepted as it conflicts with checkpointed txs");
        }

        if (double_spend)
        {
          mark_double_spend(tx);
          LOG_PRINT_L1("Transaction with id= "<< id << " used already spent key images");
          tvc.m_verifivation_failed = true;
          tvc.m_double_spend = true;
          return false;
        }
      }
    }
    if (!opts.kept_by_block && have_duplicated_non_standard_tx(tx, hf_version))
    {
      mark_double_spend(tx);
      LOG_PRINT_L1("Transaction with id= "<< id << " already has a duplicate tx for height");
      tvc.m_verifivation_failed = true;
      tvc.m_double_spend = true;
      return false;
    }

    if (!m_blockchain.check_tx_outputs(tx, tvc))
    {
      LOG_PRINT_L1("Transaction with id= "<< id << " has at least one invalid output");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }

    // assume failure during verification steps until success is certain
    tvc.m_verifivation_failed = true;

    time_t receive_time = time(nullptr);

    crypto::hash max_used_block_id = null_hash;
    uint64_t max_used_block_height = 0;
    cryptonote::txpool_tx_meta_t meta;
    bool inputs_okay = check_tx_inputs([&tx]()->cryptonote::transaction&{ return tx; }, id, max_used_block_height, max_used_block_id, tvc, opts.kept_by_block,
        opts.approved_blink ? blink_rollback_height : nullptr);
    const bool non_standard_tx = !tx.is_transfer();
    if (!inputs_okay)
    {
      // if the transaction was valid before (kept_by_block), then it
      // may become valid again, so ignore the failed inputs check.
      if(opts.kept_by_block)
      {
        meta.weight = tx_weight;
        meta.fee = fee;
        meta.max_used_block_id = null_hash;
        meta.max_used_block_height = 0;
        meta.last_failed_height = 0;
        meta.last_failed_id = null_hash;
        meta.kept_by_block = opts.kept_by_block;
        meta.receive_time = receive_time;
        meta.last_relayed_time = time(NULL);
        meta.relayed = opts.relayed;
        meta.do_not_relay = opts.do_not_relay;
        meta.double_spend_seen = (have_tx_keyimges_as_spent(tx) || have_duplicated_non_standard_tx(tx, hf_version));
        meta.bf_padding = 0;
        memset(meta.padding, 0, sizeof(meta.padding));
        try
        {
          m_parsed_tx_cache.insert(std::make_pair(id, tx));
          std::unique_lock b_lock{m_blockchain};
          LockedTXN lock(m_blockchain);
          m_blockchain.add_txpool_tx(id, blob, meta);
          if (!insert_key_images(tx, id, opts.kept_by_block))
            return false;
          m_txs_by_fee_and_receive_time.emplace(std::tuple<bool, double, std::time_t>(non_standard_tx, fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
          lock.commit();
        }
        catch (const std::exception &e)
        {
          MERROR("Error adding transaction to txpool: " << e.what());
          return false;
        }
        tvc.m_verifivation_impossible = true;
        tvc.m_added_to_pool = true;
      }else
      {
        LOG_PRINT_L1("tx used wrong inputs, rejected");
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
      }
    }
    else
    {
      //update transactions container
      meta.weight = tx_weight;
      meta.kept_by_block = opts.kept_by_block;
      meta.fee = fee;
      meta.max_used_block_id = max_used_block_id;
      meta.max_used_block_height = max_used_block_height;
      meta.last_failed_height = 0;
      meta.last_failed_id = null_hash;
      meta.receive_time = receive_time;
      meta.last_relayed_time = time(NULL);
      meta.relayed = opts.relayed;
      meta.do_not_relay = opts.do_not_relay;
      meta.double_spend_seen = false;
      meta.bf_padding = 0;
      memset(meta.padding, 0, sizeof(meta.padding));

      try
      {
        if (opts.kept_by_block)
          m_parsed_tx_cache.insert(std::make_pair(id, tx));
        std::unique_lock b_lock{m_blockchain};
        LockedTXN lock(m_blockchain);
        m_blockchain.remove_txpool_tx(id);
        m_blockchain.add_txpool_tx(id, blob, meta);
        if (!insert_key_images(tx, id, opts.kept_by_block))
          return false;
        m_txs_by_fee_and_receive_time.emplace(std::tuple<bool, double, std::time_t>(non_standard_tx, fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
        lock.commit();
      }
      catch (const std::exception &e)
      {
        MERROR("internal error: error adding transaction to txpool: " << e.what());
        return false;
      }
      tvc.m_added_to_pool = true;

      if((meta.fee > 0 || non_standard_tx) && !opts.do_not_relay)
        tvc.m_should_be_relayed = true;
    }

    tvc.m_verifivation_failed = false;
    m_txpool_weight += tx_weight;

    ++m_cookie;

    MINFO("Transaction added to pool: txid " << id << " weight: " << tx_weight << " fee/byte: " << (fee / (double)(tx_weight ? tx_weight : 1)));

    if (!opts.kept_by_block && !opts.do_not_relay)
      for (auto& notify : m_tx_notify)
        notify(id, tx, blob, opts);

    prune(id);

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, tx_verification_context& tvc, const tx_pool_options &opts, uint8_t version)
  {
    crypto::hash h = null_hash;
    size_t blob_size = 0;
    cryptonote::blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    if (bl.size() == 0 || !get_transaction_hash(tx, h))
      return false;
    return add_tx(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, opts, version);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_new_blink(const std::shared_ptr<blink_tx> &blink_ptr, tx_verification_context &tvc, bool &blink_exists)
  {
    assert((bool) blink_ptr);
    std::unique_lock lock{m_transactions_lock};
    auto &blink = *blink_ptr;
    auto &tx = var::get<transaction>(blink.tx); // will throw if just a hash w/o a transaction
    auto txhash = get_transaction_hash(tx);

    {
      auto lock = blink_shared_lock();
      blink_exists = m_blinks.count(txhash);
      if (blink_exists)
        return false;
    }

    bool approved = blink.approved();
    auto hf_version = m_blockchain.get_network_version(blink.height);
    bool result = add_tx(tx, tvc, tx_pool_options::new_blink(approved, hf_version), hf_version);
    if (result && approved)
    {
      auto lock = blink_unique_lock();
      m_blinks[txhash] = blink_ptr;
    }
    else if (!result)
    {
      // Adding failed, but might have failed because another thread inserted it, so check again for
      // existence of the blink
      auto lock = blink_shared_lock();
      blink_exists = m_blinks.count(txhash);
    }
    return result;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_existing_blink(std::shared_ptr<blink_tx> blink_ptr)
  {
    assert(blink_ptr && blink_ptr->approved());
    auto &ptr = m_blinks[blink_ptr->get_txhash()];
    if (ptr)
      return false;

    ptr = blink_ptr;
    return true;
  }
  //---------------------------------------------------------------------------------
  std::shared_ptr<blink_tx> tx_memory_pool::get_blink(const crypto::hash &tx_hash) const
  {
    auto it = m_blinks.find(tx_hash);
    if (it != m_blinks.end())
        return it->second;
    return {};
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::has_blink(const crypto::hash &tx_hash) const
  {
    return m_blinks.find(tx_hash) != m_blinks.end();
  }

  void tx_memory_pool::keep_missing_blinks(std::vector<crypto::hash> &tx_hashes) const
  {
    auto lock = blink_shared_lock();
    tx_hashes.erase(
        std::remove_if(tx_hashes.begin(), tx_hashes.end(),
          [this](const crypto::hash &tx_hash) { return m_blinks.count(tx_hash) > 0; }),
        tx_hashes.end());
  }

  std::pair<std::vector<crypto::hash>, std::vector<uint64_t>> tx_memory_pool::get_blink_hashes_and_mined_heights() const
  {
    std::pair<std::vector<crypto::hash>, std::vector<uint64_t>> hnh;
    auto &hashes = hnh.first;
    auto &heights = hnh.second;
    {
      auto lock = blink_shared_lock();
      if (!m_blinks.empty())
      {
        hashes.reserve(m_blinks.size());
        for (auto &b : m_blinks)
          hashes.push_back(b.first);
      }
    }

    heights = m_blockchain.get_transactions_heights(hashes);

    // Filter out (and delete from the blink pool) any blinks that are in immutable blocks
    const uint64_t immutable_height = m_blockchain.get_immutable_height();
    size_t next_good = 0;
    for (size_t i = 0; i < hashes.size(); i++)
    {
      if (heights[i] > immutable_height || heights[i] == 0 /* unmined mempool blink */)
      {
        // Swap elements into the "good" part of the list so that when we're we'll have divided the
        // vector into [0, ..., next_good-1] elements containing the parts we want to return, and
        // [next_good, ...] containing the elements to remove from blink storage.
        if (i != next_good)
        {
          using std::swap;
          swap(heights[i], heights[next_good]);
          swap(hashes[i], hashes[next_good]);
        }
        next_good++;
      }
    }

    if (next_good < hashes.size())
    {
      auto lock = blink_unique_lock();
      for (size_t i = next_good; i < hashes.size(); i++)
        m_blinks.erase(hashes[i]);
    }
    hashes.resize(next_good);
    heights.resize(next_good);

    return hnh;
  }

  std::map<uint64_t, crypto::hash> tx_memory_pool::get_blink_checksums() const
  {
    std::map<uint64_t, crypto::hash> result;

    auto hnh = get_blink_hashes_and_mined_heights();
    auto &hashes = hnh.first;
    auto &heights = hnh.second;

    for (size_t i = 0; i < hashes.size(); i++)
    {
      auto it = result.lower_bound(heights[i]);
      if (it == result.end() || it->first != heights[i])
        result.emplace_hint(it, heights[i], hashes[i]);
      else
        it->second ^= hashes[i];
    }
    return result;
  }

  //---------------------------------------------------------------------------------
  std::vector<crypto::hash> tx_memory_pool::get_mined_blinks(const std::set<uint64_t> &want_heights) const
  {
    std::vector<crypto::hash> result;

    auto hnh = get_blink_hashes_and_mined_heights();
    auto &hashes = hnh.first;
    auto &heights = hnh.second;
    for (size_t i = 0; i < heights.size(); i++)
    {
      if (want_heights.count(heights[i]))
        result.push_back(hashes[i]);
    }
    return result;
  }

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::remove_blink_conflicts(const crypto::hash &id, const std::vector<crypto::hash> &conflict_txs, uint64_t *blink_rollback_height)
  {
    auto bl_lock = blink_shared_lock(std::defer_lock);
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    std::lock(bl_lock, bc_lock);

    // Since this is a signed blink tx, we want to see if we can eject any existing mempool
    // txes to make room.

    // First check to see if any of the conflicting txes is itself an approved blink as a
    // safety check (it shouldn't be possible if the network is functioning properly).
    for (const auto &tx_hash : conflict_txs)
    {
      if (m_blinks.count(tx_hash))
      {
        MERROR("Blink error: incoming blink tx " << id << " conflicts with another blink tx " << tx_hash);
        return false;
      }
    }

    uint64_t rollback_height_needed = blink_rollback_height ? *blink_rollback_height : 0;
    std::vector<crypto::hash> mempool_txs;

    // Next make sure none of the conflicting txes are mined in immutable blocks
    auto immutable_height = m_blockchain.get_immutable_height();
    auto heights = m_blockchain.get_transactions_heights(conflict_txs);
    for (size_t i = 0; i < heights.size(); ++i)
    {
      MDEBUG("Conflicting tx " << conflict_txs[i] << (heights[i] ? "mined at height " + std::to_string(heights[i]) : "in mempool"));
      if (!heights[i])
      {
        mempool_txs.push_back(conflict_txs[i]);
      }
      else if (heights[i] > immutable_height && blink_rollback_height)
      {
        if (rollback_height_needed == 0 || rollback_height_needed > heights[i])
          rollback_height_needed = heights[i];
        // else already set to something at least as early as this tx
      }
      else
        return false;
    }

    if (!mempool_txs.empty())
    {
      LockedTXN txnlock(m_blockchain);
      for (auto &tx : mempool_txs)
      {
        MWARNING("Removing conflicting tx " << tx << " from mempool for incoming blink tx " << id);
        if (!remove_tx(tx))
        {
          MERROR("Internal error: Unable to clear conflicting tx " << tx << " from mempool for incoming blink tx " << id);
          return false;
        }
      }
      txnlock.commit();
    }

    if (blink_rollback_height && rollback_height_needed < *blink_rollback_height)
    {
      MINFO("Incoming blink tx requires a rollback to the " << rollback_height_needed << " to un-mine conflicting transactions");
      *blink_rollback_height = rollback_height_needed;
    }

    return true;
  }

  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_txpool_weight() const
  {
    std::unique_lock lock{m_transactions_lock};
    return m_txpool_weight;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_txpool_max_weight(size_t bytes)
  {
    std::unique_lock lock{m_transactions_lock};
    m_txpool_max_weight = bytes;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::remove_tx(const crypto::hash &txid, const txpool_tx_meta_t *meta, const sorted_tx_container::iterator *stc_it)
  {
    const auto it = stc_it ? *stc_it : find_tx_in_sorted_container(txid);
    if (it == m_txs_by_fee_and_receive_time.end())
    {
      MERROR("Failed to find tx in txpool sorted list");
      return false;
    }

    cryptonote::blobdata tx_blob = m_blockchain.get_txpool_tx_blob(txid);
    cryptonote::transaction_prefix tx;
    if (!parse_and_validate_tx_prefix_from_blob(tx_blob, tx))
    {
      MERROR("Failed to parse tx from txpool");
      return false;
    }

    txpool_tx_meta_t lookup_meta;
    if (!meta)
    {
      if (m_blockchain.get_txpool_tx_meta(txid, lookup_meta))
        meta = &lookup_meta;
      else
      {
        MERROR("Failed to find tx in txpool");
        return false;
      }
    }

    // remove first, in case this throws, so key images aren't removed
    const uint64_t tx_fee = std::get<1>(it->first);
    MINFO("Removing tx " << txid << " from txpool: weight: " << meta->weight << ", fee/byte: " << tx_fee);
    m_blockchain.remove_txpool_tx(txid);
    m_txpool_weight -= meta->weight;
    remove_transaction_keyimages(tx, txid);
    m_txs_by_fee_and_receive_time.erase(it);

    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::prune(const crypto::hash &skip)
  {
    auto blink_lock = blink_shared_lock(std::defer_lock);
    std::unique_lock tx_lock{*this, std::defer_lock};
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    std::lock(blink_lock, tx_lock, bc_lock);
    LockedTXN lock(m_blockchain);
    bool changed = false;

    // Tries checking conditions for pruning and, if appropriate, removing the tx.
    // Returns false on failure, true for no prune wanted or a successful prune.
    auto try_pruning = [this, &skip, &changed](auto &it, bool forward) -> bool {
      try
      {
        const crypto::hash &txid = it->second;
        txpool_tx_meta_t meta;
        if (!m_blockchain.get_txpool_tx_meta(txid, meta))
        {
          MERROR("Failed to find tx in txpool");
          return false;
        }
        auto del_it = forward ? it++ : it--;

        // don't prune the kept_by_block ones, they're likely added because we're adding a block with those
        // don't prune blink txes
        // don't prune the one we just added
        if (meta.kept_by_block || this->has_blink(txid) || txid == skip)
          return true;

        if (this->remove_tx(txid, &meta, &del_it))
        {
          changed = true;
          return true;
        }
        return false;
      }
      catch (const std::exception &e)
      {
        MERROR("Error while pruning txpool: " << e.what());
        return false;
      }
    };

    const auto unexpired = std::time(nullptr) - MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME;
    for (auto it = m_txs_by_fee_and_receive_time.begin(); it != m_txs_by_fee_and_receive_time.end(); )
    {
      const bool is_standard_tx = !std::get<0>(it->first);
      const time_t receive_time = std::get<2>(it->first);

      if (is_standard_tx || receive_time >= unexpired)
        break;

      if (!try_pruning(it, true /*forward*/))
        return;
    }

    // this will never remove the first one, but we don't care
    auto it = m_txs_by_fee_and_receive_time.end();
    if (it != m_txs_by_fee_and_receive_time.begin())
      it = std::prev(it);
    while (m_txpool_weight > m_txpool_max_weight && it != m_txs_by_fee_and_receive_time.begin())
    {
      if (!try_pruning(it, false /*forward*/))
        return;
    }
    lock.commit();
    if (changed)
      ++m_cookie;
    if (m_txpool_weight > m_txpool_max_weight)
      MINFO("Pool weight after pruning is still larger than limit: " << m_txpool_weight << "/" << m_txpool_max_weight);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::insert_key_images(const transaction_prefix &tx, const crypto::hash &id, bool kept_by_block)
  {
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, txin, false);
      std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
      CHECK_AND_ASSERT_MES(kept_by_block || kei_image_set.size() == 0, false, "internal error: kept_by_block=" << kept_by_block
                                          << ",  kei_image_set.size()=" << kei_image_set.size() << "\ntxin.k_image=" << txin.k_image
                                          << "\ntx_id=" << id );
      auto ins_res = kei_image_set.insert(id);
      CHECK_AND_ASSERT_MES(ins_res.second, false, "internal error: try to insert duplicate iterator in key_image set");
    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  //FIXME: Can return early before removal of all of the key images.
  //       At the least, need to make sure that a false return here
  //       is treated properly.  Should probably not return early, however.
  bool tx_memory_pool::remove_transaction_keyimages(const transaction_prefix& tx, const crypto::hash &actual_hash)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    // ND: Speedup
    for(const txin_v& vi: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(vi, txin_to_key, txin, false);
      auto it = m_spent_key_images.find(txin.k_image);
      CHECK_AND_ASSERT_MES(it != m_spent_key_images.end(), false, "failed to find transaction input in key images. img=" << txin.k_image
                                    << "\ntransaction id = " << actual_hash);
      std::unordered_set<crypto::hash>& key_image_set =  it->second;
      CHECK_AND_ASSERT_MES(key_image_set.size(), false, "empty key_image set, img=" << txin.k_image
        << "\ntransaction id = " << actual_hash);

      auto it_in_set = key_image_set.find(actual_hash);
      CHECK_AND_ASSERT_MES(it_in_set != key_image_set.end(), false, "transaction id not found in key_image set, img=" << txin.k_image
        << "\ntransaction id = " << actual_hash);
      key_image_set.erase(it_in_set);
      if(!key_image_set.size())
      {
        //it is now empty hash container for this key_image
        m_spent_key_images.erase(it);
      }

    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::take_tx(const crypto::hash &id, transaction &tx, cryptonote::blobdata &txblob, size_t& tx_weight, uint64_t& fee, bool &relayed, bool &do_not_relay, bool &double_spend_seen)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    auto sorted_it = find_tx_in_sorted_container(id);

    try
    {
      LockedTXN lock(m_blockchain);
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(id, meta))
      {
        MERROR("Failed to find tx in txpool");
        return false;
      }
      txblob = m_blockchain.get_txpool_tx_blob(id);
      auto ci = m_parsed_tx_cache.find(id);
      if (ci != m_parsed_tx_cache.end())
      {
        tx = ci->second;
      }
      else if (!parse_and_validate_tx_from_blob(txblob, tx))
      {
        MERROR("Failed to parse tx from txpool");
        return false;
      }
      else
      {
        tx.set_hash(id);
      }
      tx_weight = meta.weight;
      fee = meta.fee;
      relayed = meta.relayed;
      do_not_relay = meta.do_not_relay;
      double_spend_seen = meta.double_spend_seen;

      // remove first, in case this throws, so key images aren't removed
      m_blockchain.remove_txpool_tx(id);
      m_txpool_weight -= tx_weight;
      remove_transaction_keyimages(tx, id);
      lock.commit();
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to remove tx from txpool: " << e.what());
      return false;
    }

    if (sorted_it != m_txs_by_fee_and_receive_time.end())
      m_txs_by_fee_and_receive_time.erase(sorted_it);
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::on_idle()
  {
    m_remove_stuck_tx_interval.do_call([this](){return remove_stuck_transactions();});
  }

  void tx_memory_pool::add_notify(std::function<void(const crypto::hash&, const transaction&, const std::string&, const tx_pool_options&)> notify)
  {
    std::unique_lock lock{m_transactions_lock};
    m_tx_notify.push_back(std::move(notify));
  }

  //---------------------------------------------------------------------------------
  sorted_tx_container::iterator tx_memory_pool::find_tx_in_sorted_container(const crypto::hash& id) const
  {
    return std::find_if( m_txs_by_fee_and_receive_time.begin(), m_txs_by_fee_and_receive_time.end()
                       , [&](const sorted_tx_container::value_type& a){
                         return a.second == id;
                       }
    );
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::remove_stuck_transactions()
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    std::list<std::pair<crypto::hash, uint64_t>> remove;
    m_blockchain.for_all_txpool_txes([this, &remove](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata*) {
      uint64_t tx_age = time(nullptr) - meta.receive_time;

      if((tx_age > CRYPTONOTE_MEMPOOL_TX_LIVETIME && !meta.kept_by_block) ||
         (tx_age > CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME && meta.kept_by_block) )
      {
        LOG_PRINT_L1("Tx " << txid << " removed from tx pool due to outdated, age: " << tx_age );
        auto sorted_it = find_tx_in_sorted_container(txid);
        if (sorted_it == m_txs_by_fee_and_receive_time.end())
        {
          LOG_PRINT_L1("Removing tx " << txid << " from tx pool, but it was not found in the sorted txs container!");
        }
        else
        {
          m_txs_by_fee_and_receive_time.erase(sorted_it);
        }
        m_timed_out_transactions.insert(txid);
        remove.push_back(std::make_pair(txid, meta.weight));
      }
      return true;
    }, false);

    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain);
      for (const std::pair<crypto::hash, uint64_t> &entry: remove)
      {
        const crypto::hash &txid = entry.first;
        try
        {
          cryptonote::blobdata bd = m_blockchain.get_txpool_tx_blob(txid);
          cryptonote::transaction_prefix tx;
          if (!parse_and_validate_tx_prefix_from_blob(bd, tx))
          {
            MERROR("Failed to parse tx from txpool");
            // continue
          }
          else
          {
            // remove first, so we only remove key images if the tx removal succeeds
            m_blockchain.remove_txpool_tx(txid);
            m_txpool_weight -= entry.second;
            remove_transaction_keyimages(tx, txid);
          }
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove stuck transaction: " << txid);
          // ignore error
        }
      }
      lock.commit();
      ++m_cookie;
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_relayable_transactions(std::vector<std::pair<crypto::hash, cryptonote::blobdata>> &txs) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const uint64_t now = time(NULL);
    txs.reserve(m_blockchain.get_txpool_tx_count());
    m_blockchain.for_all_txpool_txes([this, now, &txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *){
      if(!meta.do_not_relay && (!meta.relayed || now - meta.last_relayed_time > get_relay_delay(now, meta.receive_time)))
      {
        // if the tx is older than half the max lifetime, we don't re-relay it, to avoid a problem
        // mentioned by smooth where nodes would flush txes at slightly different times, causing
        // flushed txes to be re-added when received from a node which was just about to flush it
        uint64_t max_age = meta.kept_by_block ? CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME : CRYPTONOTE_MEMPOOL_TX_LIVETIME;
        if (now - meta.receive_time <= max_age / 2)
        {
          try
          {
            cryptonote::blobdata bd = m_blockchain.get_txpool_tx_blob(txid);
            if (meta.fee == 0)
            {
              cryptonote::transaction tx;
              if (!cryptonote::parse_and_validate_tx_from_blob(bd, tx))
              {
                LOG_PRINT_L1("TX in pool could not be parsed from blob, txid: " << txid);
                return true;
              }

              if (tx.type != txtype::state_change)
                return true;

              tx_verification_context tvc;
              uint64_t max_used_block_height = 0;
              crypto::hash max_used_block_id = null_hash;
              if (!m_blockchain.check_tx_inputs(tx, max_used_block_height, max_used_block_id, tvc, /*kept_by_block*/ false))
              {
                LOG_PRINT_L1("TX type: " << tx.type << " considered for relaying failed tx inputs check, txid: " << txid << ", reason: " << print_tx_verification_context(tvc, &tx));
                return true;
              }
            }

            txs.push_back(std::make_pair(txid, bd));
          }
          catch (const std::exception &e)
          {
            MERROR("Failed to get transaction blob from db");
            // ignore error
          }
        }
      }
      return true;
    }, false);
    return true;
  }
  //---------------------------------------------------------------------------------
  int tx_memory_pool::set_relayable(const std::vector<crypto::hash> &tx_hashes) {
    int updated = 0;
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
    LockedTXN lock(m_blockchain);
    for (auto &tx : tx_hashes)
    {
      try {
        txpool_tx_meta_t meta;
        if (m_blockchain.get_txpool_tx_meta(tx, meta) && meta.do_not_relay)
        {
          meta.do_not_relay = false;
          m_blockchain.update_txpool_tx(tx, meta);
          ++updated;
        }
      } catch (const std::exception &e) {
        MERROR("Failed to upate txpool transaction metadata: " << e.what());
      }
    }
    lock.commit();

    return updated;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_relayed(const std::vector<std::pair<crypto::hash, cryptonote::blobdata>> &txs)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const time_t now = time(NULL);
    LockedTXN lock(m_blockchain);
    for (auto &tx : txs)
    {
      try
      {
        txpool_tx_meta_t meta;
        if (m_blockchain.get_txpool_tx_meta(tx.first, meta))
        {
          meta.relayed = true;
          meta.last_relayed_time = now;
          m_blockchain.update_txpool_tx(tx.first, meta);
        }
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to update txpool transaction metadata: " << e.what());
        // continue
      }
    }
    lock.commit();
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_transactions_count(bool include_unrelayed_txes) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
    return m_blockchain.get_txpool_tx_count(include_unrelayed_txes);
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::get_transactions(std::vector<transaction>& txs, bool include_unrelayed_txes) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    txs.reserve(m_blockchain.get_txpool_tx_count(include_unrelayed_txes));
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      transaction tx;
      if (!parse_and_validate_tx_from_blob(*bd, tx))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx.set_hash(txid);
      txs.push_back(std::move(tx));
      return true;
    }, true, include_unrelayed_txes);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_hashes(std::vector<crypto::hash>& txs, bool include_unrelayed_txes, bool include_only_blinked) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    txs.reserve(m_blockchain.get_txpool_tx_count(include_unrelayed_txes));
    m_blockchain.for_all_txpool_txes([&txs, include_only_blinked, this](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      bool include_tx = true;
      if (include_only_blinked) include_tx = has_blink(txid);
      if (include_tx) txs.push_back(txid);
      return true;
    }, false, include_unrelayed_txes);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_backlog(std::vector<rpc::tx_backlog_entry>& backlog, bool include_unrelayed_txes) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const uint64_t now = time(NULL);
    backlog.reserve(m_blockchain.get_txpool_tx_count(include_unrelayed_txes));
    m_blockchain.for_all_txpool_txes([&backlog, now](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      backlog.push_back({meta.weight, meta.fee, meta.receive_time - now});
      return true;
    }, false, include_unrelayed_txes);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_stats(struct rpc::txpool_stats& stats, bool include_unrelayed_txes) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    const uint64_t now = time(NULL);
    std::map<uint64_t, rpc::txpool_histo> agebytes;
    stats.txs_total = m_blockchain.get_txpool_tx_count(include_unrelayed_txes);
    std::vector<uint32_t> weights;
    weights.reserve(stats.txs_total);
    m_blockchain.for_all_txpool_txes([&stats, &weights, now, &agebytes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      weights.push_back(meta.weight);
      stats.bytes_total += meta.weight;
      if (!stats.bytes_min || meta.weight < stats.bytes_min)
        stats.bytes_min = meta.weight;
      if (meta.weight > stats.bytes_max)
        stats.bytes_max = meta.weight;
      if (!meta.relayed)
        stats.num_not_relayed++;
      stats.fee_total += meta.fee;
      if (!stats.oldest || meta.receive_time < stats.oldest)
        stats.oldest = meta.receive_time;
      if (meta.receive_time < now - 600)
        stats.num_10m++;
      if (meta.last_failed_height)
        stats.num_failing++;
      uint64_t age = now - meta.receive_time + (now == meta.receive_time);
      agebytes[age].txs++;
      agebytes[age].bytes += meta.weight;
      if (meta.double_spend_seen)
        ++stats.num_double_spends;
      return true;
    }, false, include_unrelayed_txes);
    stats.bytes_med = epee::misc_utils::median(weights);
    if (stats.txs_total > 1)
    {
      /* looking for 98th percentile */
      size_t end = stats.txs_total * 0.02;
      uint64_t delta, factor;
      std::map<uint64_t, rpc::txpool_histo>::iterator it, i2;
      if (end)
      {
        /* If enough txs, spread the first 98% of results across
         * the first 9 bins, drop final 2% in last bin.
         */
        it = agebytes.end();
        size_t cumulative_num = 0;
        /* Since agebytes is not empty and end is nonzero, the
         * below loop can always run at least once.
         */
        do {
          --it;
          cumulative_num += it->second.txs;
        } while (it != agebytes.begin() && cumulative_num < end);
        stats.histo_98pc = it->first;
        factor = 9;
        delta = it->first;
        stats.histo.resize(10);
      } else
      {
        /* If not enough txs, don't reserve the last slot;
         * spread evenly across all 10 bins.
         */
        stats.histo_98pc = 0;
        it = agebytes.end();
        factor = stats.txs_total > 9 ? 10 : stats.txs_total;
        delta = now - stats.oldest;
        stats.histo.resize(factor);
      }
      if (!delta)
        delta = 1;
      for (i2 = agebytes.begin(); i2 != it; i2++)
      {
        size_t i = (i2->first * factor - 1) / delta;
        stats.histo[i].txs += i2->second.txs;
        stats.histo[i].bytes += i2->second.bytes;
      }
      for (; i2 != agebytes.end(); i2++)
      {
        stats.histo[factor].txs += i2->second.txs;
        stats.histo[factor].bytes += i2->second.bytes;
      }
    }
  }
  //------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_transactions_and_spent_keys_info(std::vector<rpc::tx_info>& tx_infos, std::vector<rpc::spent_key_image_info>& key_image_infos, std::function<void(const transaction&, rpc::tx_info&)> post_process, bool include_sensitive_data) const
  {
    std::unique_lock tx_lock{m_transactions_lock, std::defer_lock};
    std::unique_lock bc_lock{m_blockchain, std::defer_lock};
    auto blink_lock = blink_shared_lock(std::defer_lock);
    std::lock(tx_lock, bc_lock, blink_lock);

    tx_infos.reserve(m_blockchain.get_txpool_tx_count());
    key_image_infos.reserve(m_blockchain.get_txpool_tx_count());

    m_blockchain.for_all_txpool_txes([&tx_infos, this, include_sensitive_data, post_process=std::move(post_process)](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      transaction tx;
      if (!parse_and_validate_tx_from_blob(*bd, tx))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx_infos.emplace_back();
      auto& txi = tx_infos.back();
      txi.id_hash = tools::type_to_hex(txid);
      txi.tx_blob = *bd;
      tx.set_hash(txid);
      txi.tx_json = obj_to_json_str(tx);
      txi.blob_size = bd->size();
      txi.weight = meta.weight;
      txi.fee = meta.fee;
      txi.kept_by_block = meta.kept_by_block;
      txi.max_used_block_height = meta.max_used_block_height;
      txi.max_used_block_id_hash = tools::type_to_hex(meta.max_used_block_id);
      txi.last_failed_height = meta.last_failed_height;
      txi.last_failed_id_hash = tools::type_to_hex(meta.last_failed_id);
      // In restricted mode we do not include this data:
      txi.receive_time = include_sensitive_data ? meta.receive_time : 0;
      txi.relayed = meta.relayed;
      // In restricted mode we do not include this data:
      txi.last_relayed_time = include_sensitive_data ? meta.last_relayed_time : 0;
      txi.do_not_relay = meta.do_not_relay;
      txi.double_spend_seen = meta.double_spend_seen;
      txi.blink = has_blink(txid);
      if (post_process)
        post_process(tx, txi);
      return true;
    }, true, include_sensitive_data);

    txpool_tx_meta_t meta;
    for (const key_images_container::value_type& kee : m_spent_key_images) {
      const crypto::key_image& k_image = kee.first;
      const std::unordered_set<crypto::hash>& kei_image_set = kee.second;
      rpc::spent_key_image_info ki{};
      ki.id_hash = tools::type_to_hex(k_image);
      for (const crypto::hash& tx_id_hash : kei_image_set)
      {
        if (!include_sensitive_data)
        {
          try
          {
            if (!m_blockchain.get_txpool_tx_meta(tx_id_hash, meta))
            {
              MERROR("Failed to get tx meta from txpool");
              return false;
            }
            if (!meta.relayed)
              // Do not include that transaction if in restricted mode and it's not relayed
              continue;
          }
          catch (const std::exception &e)
          {
            MERROR("Failed to get tx meta from txpool: " << e.what());
            return false;
          }
        }
        ki.txs_hashes.push_back(tools::type_to_hex(tx_id_hash));
      }
      // Only return key images for which we have at least one tx that we can show for them
      if (!ki.txs_hashes.empty())
        key_image_infos.push_back(ki);
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::check_for_key_images(const std::vector<crypto::key_image>& key_images, std::vector<bool>& spent) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    spent.clear();

    for (const auto& image : key_images)
    {
      spent.push_back(m_spent_key_images.find(image) == m_spent_key_images.end() ? false : true);
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  int tx_memory_pool::find_transactions(const std::vector<crypto::hash> &tx_hashes, std::vector<cryptonote::blobdata> &txblobs) const
  {
    if (tx_hashes.empty())
      return 0;
    txblobs.reserve(txblobs.size() + tx_hashes.size());
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    int added = 0;
    for (auto &id : tx_hashes)
    {
      try
      {
        cryptonote::blobdata txblob;
        m_blockchain.get_txpool_tx_blob(id, txblob);
        txblobs.push_back(std::move(txblob));
        ++added;
      }
      catch (...) { /* ignore */ }
    }
    return added;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction(const crypto::hash& id, cryptonote::blobdata& txblob) const
  {
    std::vector<cryptonote::blobdata> found;
    find_transactions({{id}}, found);
    if (found.empty())
      return false;
    txblob = std::move(found[0]);
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_inc(block const &blk)
  {
    std::unique_lock lock{m_transactions_lock};
    m_input_cache.clear();
    m_parsed_tx_cache.clear();

    std::vector<transaction> pool_txs;
    get_transactions(pool_txs);
    if (pool_txs.empty()) return true;

    // NOTE: For transactions in the pool, on new block received, if a Service
    // Node changed state any older state changes that the node cannot
    // transition to now are invalid and cannot be used, so take them out from
    // the pool.

    // Otherwise multiple state changes can queue up until they are applicable
    // and be applied on the node.
    uint64_t const block_height = cryptonote::get_block_height(blk);
    auto &service_node_list = m_blockchain.get_service_node_list();
    for (transaction const &pool_tx : pool_txs)
    {
      tx_extra_service_node_state_change state_change;
      crypto::public_key service_node_pubkey;
      if (pool_tx.type == txtype::state_change &&
          get_service_node_state_change_from_tx_extra(pool_tx.extra, state_change, blk.major_version))
      {
        // TODO(oxen): PERF(oxen): On pop_blocks we return all the TXs to the
        // pool. The greater the pop_blocks, the more txs that are queued in the
        // pool, and for every subsequent block you sync, get_transactions has
        // to allocate these transactions and we have to search every
        // transaction in the pool every synced block- causing great slowdown.

        // It'd be nice to optimise this or rearchitect the way this pruning is
        // done to be smarter.

        if (state_change.block_height >= block_height) // NOTE: Can occur if we pop_blocks and old popped state changes are returned to the pool.
          continue;

        if (service_node_list.get_quorum_pubkey(service_nodes::quorum_type::obligations,
                                                service_nodes::quorum_group::worker,
                                                state_change.block_height,
                                                state_change.service_node_index,
                                                service_node_pubkey))
        {
          crypto::hash tx_hash;
          if (!get_transaction_hash(pool_tx, tx_hash))
          {
            MERROR("Failed to get transaction hash from txpool to check if we can prune a state change");
            continue;
          }

          txpool_tx_meta_t meta;
          if (!m_blockchain.get_txpool_tx_meta(tx_hash, meta))
          {
            MERROR("Failed to get tx meta from txpool to check if we can prune a state change");
            continue;
          }

          if (meta.kept_by_block) // Do not prune transaction if kept by block (belongs to alt block, so we need incase we switch to alt-chain)
            continue;

          std::vector<service_nodes::service_node_pubkey_info> service_node_array = service_node_list.get_service_node_list_state({service_node_pubkey});
          if (service_node_array.empty() ||
              !service_node_array[0].info->can_transition_to_state(blk.major_version, state_change.block_height, state_change.state))
          {
            transaction tx;
            cryptonote::blobdata blob;
            size_t tx_weight;
            uint64_t fee;
            bool relayed, do_not_relay, double_spend_seen;
            take_tx(tx_hash, tx, blob, tx_weight, fee, relayed, do_not_relay, double_spend_seen);
          }
        }
      }
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_dec()
  {
    std::unique_lock lock{m_transactions_lock};
    m_input_cache.clear();
    m_parsed_tx_cache.clear();
    return true;
  }
  //------------------------------------------------------------------
  std::vector<uint8_t> tx_memory_pool::have_txs(const std::vector<crypto::hash> &hashes) const
  {
    std::vector<uint8_t> result(hashes.size(), false);
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    auto &db = m_blockchain.get_db();
    for (size_t i = 0; i < hashes.size(); i++)
      result[i] = db.txpool_has_tx(hashes[i]);

    return result;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx(const crypto::hash &id) const
  {
    return have_txs({{id}})[0];
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimges_as_spent(const transaction& tx, std::vector<crypto::hash> *conflicting) const
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);


    bool ret = false;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, true);//should never fail
      auto it = m_spent_key_images.find(tokey_in.k_image);
      if (it != m_spent_key_images.end())
      {
        if (!conflicting)
          return true;
        ret = true;
        conflicting->insert(conflicting->end(), it->second.begin(), it->second.end());
      }
    }
    return ret;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimg_as_spent(const crypto::key_image& key_im) const
  {
    std::unique_lock lock{m_transactions_lock};
    return m_spent_key_images.end() != m_spent_key_images.find(key_im);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::check_tx_inputs(const std::function<cryptonote::transaction&()> &get_tx, const crypto::hash &txid, uint64_t &max_used_block_height,
      crypto::hash &max_used_block_id, tx_verification_context &tvc, bool kept_by_block, uint64_t* blink_rollback_height) const
  {
    if (!kept_by_block)
    {
      const std::unordered_map<crypto::hash, std::tuple<bool, tx_verification_context, uint64_t, crypto::hash>>::const_iterator i = m_input_cache.find(txid);
      if (i != m_input_cache.end())
      {
        max_used_block_height = std::get<2>(i->second);
        max_used_block_id = std::get<3>(i->second);
        tvc = std::get<1>(i->second);
        return std::get<0>(i->second);
      }
    }
    std::unordered_set<crypto::key_image> key_image_conflicts;
    bool ret = m_blockchain.check_tx_inputs(get_tx(), max_used_block_height, max_used_block_id, tvc, kept_by_block, blink_rollback_height ? &key_image_conflicts : nullptr);

    if (ret && !key_image_conflicts.empty())
    {
      // There are some key image conflicts, but since we have blink_rollback_height this is an
      // approved blink tx that we want to accept via rollback, if possible.

      auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);
      uint64_t immutable = m_blockchain.get_immutable_height();
      uint64_t height = m_blockchain.get_current_blockchain_height();
      bool can_fix_with_a_rollback = false;
      if (height - immutable > 100)
      {
        // Sanity check; if this happens checkpoints are failing and we can't guarantee blinks
        // anyway (because the blink quorums are not immutable).
        MERROR("Unable to scan for conflicts: blockchain checkpoints are too far back");
      }
      else
      {
        MDEBUG("Found " << key_image_conflicts.size() << " conflicting key images for blink tx " << txid << "; checking to see if we can roll back");
        // Check all the key images of all the blockchain transactions in blocks since the immutable
        // height, and remove any conflicts from the set of conflicts, updating the rollback height
        // as we go.  If we remove all then rolling back will work, and we can accept the blink,
        // otherwise we have to refuse it (because immutable blocks have to trump a blink tx).
        //
        // This sounds expensive, but in reality the blocks since the immutable checkpoint is
        // usually only around 8-12, we do this in reverse order (conflicts are most likely to be in
        // the last block or two), and there is little incentive to actively exploit this since this
        // code is here, and even if someone did want to they'd have to also be 51% attacking the
        // network to wipe out recently mined blinks -- but that can't work anyway.
        //
        std::vector<cryptonote::block> blocks;
        if (m_blockchain.get_blocks_only(immutable + 1, height, blocks))
        {
          std::vector<cryptonote::transaction> txs;
          std::vector<crypto::hash> missed_txs;
          uint64_t earliest = height;
          for (auto it = blocks.rbegin(); it != blocks.rend(); it++)
          {
            const auto& block = *it;
            auto block_height = cryptonote::get_block_height(block);
            txs.clear();
            missed_txs.clear();

            if (!m_blockchain.get_transactions(block.tx_hashes, txs, missed_txs))
            {
              MERROR("Unable to get transactions for block " << block.hash);
              can_fix_with_a_rollback = false;
              break;
            }
            for (const auto& tx : txs) {
              for (const auto& in : tx.vin) {
                if (auto* ttk = std::get_if<txin_to_key>(&in); ttk && key_image_conflicts.erase(ttk->k_image)) {
                  earliest = std::min(earliest, block_height);
                  if (key_image_conflicts.empty())
                    goto end;
                }
              }
            }
          }
end:
          if (key_image_conflicts.empty() && earliest < height && earliest > immutable)
          {
            MDEBUG("Blink admission requires rolling back to height " << earliest);
            can_fix_with_a_rollback = true;
            if (*blink_rollback_height == 0 || *blink_rollback_height > earliest)
              *blink_rollback_height = earliest;
          }
        }
        else
          MERROR("Failed to retrieve blocks for trying a blink rollback!");
      }
      if (!can_fix_with_a_rollback)
      {
        MWARNING("Blink admission of " << txid << " is not possible even with a rollback: found " << key_image_conflicts.size() << " key image conflicts in immutable blocks");
        ret = false;
        tvc.m_double_spend = true;
      }
    }

    if (!kept_by_block)
      m_input_cache.insert(std::make_pair(txid, std::make_tuple(ret, tvc, max_used_block_height, max_used_block_id)));
    return ret;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::is_transaction_ready_to_go(txpool_tx_meta_t& txd, const crypto::hash &txid, const cryptonote::blobdata &txblob, transaction &tx) const
  {
    struct transction_parser
    {
      transction_parser(const cryptonote::blobdata &txblob, const crypto::hash &txid, transaction &tx): txblob(txblob), txid(txid), tx(tx), parsed(false) {}
      cryptonote::transaction &operator()()
      {
        if (!parsed)
        {
          if (!parse_and_validate_tx_from_blob(txblob, tx))
            throw std::runtime_error("failed to parse transaction blob");
          tx.set_hash(txid);
          parsed = true;
        }
        return tx;
      }
      const cryptonote::blobdata &txblob;
      const crypto::hash &txid;
      transaction &tx;
      bool parsed;
    } lazy_tx(txblob, txid, tx);

    //not the best implementation at this time, sorry :(
    //check is ring_signature already checked ?
    if(txd.max_used_block_id == null_hash)
    {//not checked, lets try to check

      if(txd.last_failed_id != null_hash && m_blockchain.get_current_blockchain_height() > txd.last_failed_height && txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
        return false;//we already sure that this tx is broken for this height

      tx_verification_context tvc;
      if(!check_tx_inputs(lazy_tx, txid, txd.max_used_block_height, txd.max_used_block_id, tvc))
      {
        txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
        txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
        return false;
      }
    }else
    {
      if(txd.max_used_block_height >= m_blockchain.get_current_blockchain_height())
        return false;
      if(true)
      {
        //if we already failed on this height and id, skip actual ring signature check
        if(txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
          return false;
        //check ring signature again, it is possible (with very small chance) that this transaction become again valid
        tx_verification_context tvc;
        if(!check_tx_inputs(lazy_tx, txid, txd.max_used_block_height, txd.max_used_block_id, tvc))
        {
          txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
          txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
          return false;
        }
      }
    }
    //if we here, transaction seems valid, but, anyway, check for key_images collisions with blockchain, just to be sure
    if(m_blockchain.have_tx_keyimges_as_spent(lazy_tx()))
    {
      txd.double_spend_seen = true;
      return false;
    }

    //transaction is ok.
    return true;
  }
  //---------------------------------------------------------------------------------
  /**
   * @brief check if any of a transaction's spent key images are present in a given set
   *
   * @param kic the set of key images to check against
   * @param tx the transaction to check
   *
   * @return true if any key images present in the set, otherwise false
   */
  static bool have_key_images(const std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, false);
      if(k_images.count(itk.k_image))
        return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------

  /**
   * @brief append the key images from a transaction to the given set
   *
   * @param kic the set of key images to append to
   * @param tx the transaction
   *
   * @return false if any append fails, otherwise true
   */
  static bool append_key_images(std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, false);
      auto i_res = k_images.insert(itk.k_image);
      CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::mark_double_spend(const transaction &tx)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    bool changed = false;
    LockedTXN lock(m_blockchain);
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], txin_to_key, itk, void());
      const key_images_container::const_iterator it = m_spent_key_images.find(itk.k_image);
      if (it != m_spent_key_images.end())
      {
        for (const crypto::hash &txid: it->second)
        {
          txpool_tx_meta_t meta;
          if (!m_blockchain.get_txpool_tx_meta(txid, meta))
          {
            MERROR("Failed to find tx meta in txpool");
            // continue, not fatal
            continue;
          }
          if (!meta.double_spend_seen)
          {
            MDEBUG("Marking " << txid << " as double spending " << itk.k_image);
            meta.double_spend_seen = true;
            changed = true;
            try
            {
              m_blockchain.update_txpool_tx(txid, meta);
            }
            catch (const std::exception &e)
            {
              MERROR("Failed to update tx meta: " << e.what());
              // continue, not fatal
            }
          }
        }
      }
    }
    lock.commit();
    if (changed)
      ++m_cookie;
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::fill_block_template(block &bl, size_t median_weight, uint64_t already_generated_coins, size_t &total_weight, uint64_t &raw_fee, uint64_t &expected_reward, uint8_t version, uint64_t height)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    total_weight         = 0;
    raw_fee              = 0;
    uint64_t best_reward = 0;
    {
      // NOTE: Calculate base line empty block reward
      oxen_block_reward_context block_reward_context = {};
      block_reward_context.height                    = height;

      block_reward_parts reward_parts = {};
      if (!get_oxen_block_reward(median_weight, total_weight, already_generated_coins, version, reward_parts, block_reward_context))
      {
        MERROR("Failed to get block reward for empty block");
        return false;
      }

      best_reward = version >= cryptonote::network_version_16_pulse ? 0 /*Empty block, starts with 0 fee*/ : reward_parts.base_miner;
    }

    size_t const max_total_weight = 2 * median_weight - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    std::unordered_set<crypto::key_image> k_images;

    LOG_PRINT_L2("Filling block template, median weight " << median_weight << ", " << m_txs_by_fee_and_receive_time.size() << " txes in the pool");

    LockedTXN lock(m_blockchain);

    uint64_t next_reward = 0;
    uint64_t net_fee     = 0;

    for (auto sorted_it : m_txs_by_fee_and_receive_time)
    {
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(sorted_it.second, meta))
      {
        MERROR("  failed to find tx meta");
        continue;
      }
      LOG_PRINT_L2("Considering " << sorted_it.second << ", weight " << meta.weight << ", current block weight " << total_weight << "/" << max_total_weight << ", current reward " << print_money(best_reward));

      // Can not exceed maximum block weight
      if (max_total_weight < total_weight + meta.weight)
      {
        LOG_PRINT_L2("  would exceed maximum block weight");
        continue;
      }

      // NOTE: Calculate the next block reward for the block producer
      oxen_block_reward_context next_block_reward_context = {};
      next_block_reward_context.height                    = height;
      next_block_reward_context.fee                       = raw_fee + meta.fee;

      block_reward_parts next_reward_parts           = {};
      if(!get_oxen_block_reward(median_weight, total_weight + meta.weight, already_generated_coins, version, next_reward_parts, next_block_reward_context))
      {
        LOG_PRINT_L2("Block reward calculation bug");
        return false;
      }

      // NOTE: Use the net fee for comparison (after penalty is applied).
      // After HF16, penalty is applied on the miner fee. Before, penalty is
      // applied on the base reward.
      if (version >= cryptonote::network_version_16_pulse)
      {
        next_reward = next_reward_parts.miner_fee;
      }
      else
      {
        next_reward = next_reward_parts.base_miner + next_reward_parts.miner_fee;
        assert(next_reward_parts.miner_fee == raw_fee + meta.fee);
      }

      // If we're getting lower reward tx, don't include this TX
      if (next_reward < best_reward)
      {
        LOG_PRINT_L2("  would decrease reward to " << print_money(next_reward));
        continue;
      }

      cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(sorted_it.second);
      cryptonote::transaction tx;

      // Skip transactions that are not ready to be
      // included into the blockchain or that are
      // missing key images
      const cryptonote::txpool_tx_meta_t original_meta = meta;
      bool ready = false;
      try
      {
        ready = is_transaction_ready_to_go(meta, sorted_it.second, txblob, tx);
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to check transaction readiness: " << e.what());
        // continue, not fatal
      }
      if (memcmp(&original_meta, &meta, sizeof(meta)))
      {
        try
        {
          m_blockchain.update_txpool_tx(sorted_it.second, meta);
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to update tx meta: " << e.what());
          // continue, not fatal
        }
      }
      if (!ready)
      {
        LOG_PRINT_L2("  not ready to go");
        continue;
      }
      if (have_key_images(k_images, tx))
      {
        LOG_PRINT_L2("  key images already seen");
        continue;
      }

      bl.tx_hashes.push_back(sorted_it.second);
      total_weight += meta.weight;
      raw_fee      += meta.fee;
      net_fee       = next_reward_parts.miner_fee;
      best_reward   = next_reward;
      append_key_images(k_images, tx);
      LOG_PRINT_L2("  added, new block weight " << total_weight << "/" << max_total_weight << ", reward " << print_money(best_reward));
    }
    lock.commit();

    expected_reward = best_reward;
    LOG_PRINT_L2("Block template filled with " << bl.tx_hashes.size() << " txes, weight "
        << total_weight << "/" << max_total_weight << ", reward " << print_money(best_reward)
        << " (including " << print_money(net_fee) << " in fees)");
    return true;
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::validate(uint8_t version)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    size_t tx_weight_limit = get_transaction_weight_limit(version);
    std::unordered_set<crypto::hash> remove;

    m_txpool_weight = 0;
    m_blockchain.for_all_txpool_txes([this, &remove, tx_weight_limit](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata*) {
      m_txpool_weight += meta.weight;
      if (meta.weight > tx_weight_limit) {
        LOG_PRINT_L1("Transaction " << txid << " is too big (" << meta.weight << " bytes), removing it from pool");
        remove.insert(txid);
      }
      else if (m_blockchain.have_tx(txid)) {
        LOG_PRINT_L1("Transaction " << txid << " is in the blockchain, removing it from pool");
        remove.insert(txid);
      }
      return true;
    }, false);

    size_t n_removed = 0;
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain);
      for (const crypto::hash &txid: remove)
      {
        try
        {
          cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(txid);
          cryptonote::transaction tx;
          if (!parse_and_validate_tx_from_blob(txblob, tx))
          {
            MERROR("Failed to parse tx from txpool");
            continue;
          }
          // remove tx from db first
          m_blockchain.remove_txpool_tx(txid);
          m_txpool_weight -= get_transaction_weight(tx, txblob.size());
          remove_transaction_keyimages(tx, txid);
          auto sorted_it = find_tx_in_sorted_container(txid);
          if (sorted_it == m_txs_by_fee_and_receive_time.end())
          {
            LOG_PRINT_L1("Removing tx " << txid << " from tx pool, but it was not found in the sorted txs container!");
          }
          else
          {
            m_txs_by_fee_and_receive_time.erase(sorted_it);
          }
          ++n_removed;
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to remove invalid tx from pool");
          // continue
        }
      }
      lock.commit();
    }
    if (n_removed > 0)
      ++m_cookie;
    return n_removed;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::init(size_t max_txpool_weight)
  {
    auto locks = tools::unique_locks(m_transactions_lock, m_blockchain);

    m_txpool_max_weight = max_txpool_weight ? max_txpool_weight : DEFAULT_TXPOOL_MAX_WEIGHT;
    m_txs_by_fee_and_receive_time.clear();
    m_spent_key_images.clear();
    m_txpool_weight = 0;
    std::vector<crypto::hash> remove;

    // first add the not kept by block, then the kept by block,
    // to avoid rejection due to key image collision
    for (int pass = 0; pass < 2; ++pass)
    {
      const bool kept = pass == 1;
      bool r = m_blockchain.for_all_txpool_txes([this, &remove, kept](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd) {
        if (kept != (bool)meta.kept_by_block)
          return true;
        cryptonote::transaction_prefix tx;
        if (!parse_and_validate_tx_prefix_from_blob(*bd, tx))
        {
          MWARNING("Failed to parse tx from txpool, removing");
          remove.push_back(txid);
          return true;
        }
        if (!insert_key_images(tx, txid, meta.kept_by_block))
        {
          MFATAL("Failed to insert key images from txpool tx");
          return false;
        }

        const bool non_standard_tx = !tx.is_transfer();
        m_txs_by_fee_and_receive_time.emplace(std::tuple<bool, double, time_t>(non_standard_tx, meta.fee / (double)meta.weight, meta.receive_time), txid);
        m_txpool_weight += meta.weight;
        return true;
      }, true);
      if (!r)
        return false;
    }
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain);
      for (const auto &txid: remove)
      {
        try
        {
          m_blockchain.remove_txpool_tx(txid);
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove corrupt transaction: " << txid);
          // ignore error
        }
      }
      lock.commit();
    }

    m_cookie = 0;

    // Ignore deserialization error
    return true;
  }

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::deinit()
  {
    return true;
  }
}
