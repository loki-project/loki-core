// Copyright (c) 2014-2018, The Monero Project
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

#include <iterator>
#include <limits>
#include <vector>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <array>
#include <random>
#include <sstream>
#include <fstream>

#include "common/string_util.h"
#include "common/varint.h"
#include "epee/console_handler.h"
#include "common/rules.h"

#include "cryptonote_config.h"
#include "p2p/net_node.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_core/uptime_proof.h"
#include "oxen_economy.h"
#include "ringct/rctSigs.h"

#include "chaingen.h"
#include "device/device.hpp"
#include "crypto/crypto.h"

extern "C"
{
#include <sodium.h>
}

#include <sqlite3.h>
void oxen_register_callback(std::vector<test_event_entry> &events,
                            std::string const &callback_name,
                            oxen_callback callback)
{
  events.push_back(oxen_callback_entry{callback_name, callback});
}

std::vector<cryptonote::hard_fork>
oxen_generate_hard_fork_table(uint8_t hf_version, uint64_t pos_delay)
{
  assert(hf_version < cryptonote::network_version_count);
  // We always need block 0 == v7 for the genesis block:
  std::vector<cryptonote::hard_fork> result{{cryptonote::network_version_7, 0, 0}};
  uint64_t version_height = 1;
  // HF15 reduces and HF16+ eliminates miner block rewards, so we need to ensure we have enough
  // HF14 blocks to generate enough LOKI for tests:
  if (hf_version > cryptonote::network_version_14_blink) {
      result.push_back({cryptonote::network_version_14_blink, 0, version_height});
      version_height += pos_delay;
  }

  result.push_back({hf_version, 0, version_height});
  return result;
}

uint64_t oxen_chain_generator_db::get_block_height(crypto::hash const &hash) const
{
  oxen_blockchain_entry const &entry = this->block_table.at(hash);
  uint64_t result                    = cryptonote::get_block_height(entry.block);
  return result;
}

cryptonote::block oxen_chain_generator_db::get_block_from_height(uint64_t height) const
{
  assert(height < blocks.size());
  cryptonote::block const &result = this->blocks[height].block;
  assert(cryptonote::get_block_height(result) == height);
  return result;
}

cryptonote::block_header oxen_chain_generator_db::get_block_header_from_height(uint64_t height) const
{
  return get_block_from_height(height);
}

service_nodes::service_node_keys oxen_chain_generator::get_cached_keys(const crypto::public_key &pubkey) const {
  service_nodes::service_node_keys keys;
  keys.pub = pubkey;
  auto it = service_node_keys_.find(keys.pub);
  assert(it != service_node_keys_.end());
  if (it != service_node_keys_.end())
    keys.key = it->second;
  return keys;
}

bool oxen_chain_generator_db::get_tx(const crypto::hash &h, cryptonote::transaction &tx) const
{
  auto it = tx_table.find(h);
  if (it == tx_table.end()) return false;
  tx = it->second;
  return true;
}

std::vector<cryptonote::checkpoint_t>
oxen_chain_generator_db::get_checkpoints_range(uint64_t start, uint64_t end, size_t num_desired_checkpoints) const
{
  assert(start < blocks.size());
  assert(end < blocks.size());

  std::vector<cryptonote::checkpoint_t> result = {};
  int offset = 1;
  if (start >= end) offset = -1;
  for (int index = static_cast<int>(start);
       index != static_cast<int>(end);
       index += offset)
  {
    if (result.size() >= num_desired_checkpoints) break;
    if (blocks[index].checkpointed) result.push_back(blocks[index].checkpoint);
  }

  if (result.size() < num_desired_checkpoints && blocks[end].checkpointed)
      result.push_back(blocks[end].checkpoint);
  return result;
}

std::vector<cryptonote::block> oxen_chain_generator_db::get_blocks_range(const uint64_t &h1,
                                                                         const uint64_t &h2) const
{
  assert(h1 <= h2);
  std::vector<cryptonote::block> result;
  result.reserve(h2 - h1);
  for (uint64_t height = h1; height <= h2; height++)
  {
    result.push_back(blocks[height].block);
    assert(cryptonote::get_block_height(result.back()) == height);
  }
  return result;
}

oxen_chain_generator::oxen_chain_generator(std::vector<test_event_entry> &events, const std::vector<cryptonote::hard_fork>& hard_forks)
: events_(events)
, hard_forks_(hard_forks)
{
  bool init = ons_db_->init(nullptr, cryptonote::FAKECHAIN, ons::init_oxen_name_system("", false /*read_only*/));
  assert(init);

  sqlite_db_->load_database(":memory:");

  first_miner_.generate();
  oxen_blockchain_entry genesis = oxen_chain_generator::create_genesis_block(first_miner_, 1338224400);
  events_.push_back(genesis.block);
  db_.blocks.push_back(genesis);

  // NOTE: Load hard forks into the event vector which gets extracted out at
  // run-time. This is preferred over-overriding a get_test_options<> struct
  // since this forces the hard fork information to be specified inline at the
  // testing site, so modifying and updating tests is localised to one spot.
  event_replay_settings settings = {};
  settings.hard_forks            = hard_forks;
  events_.push_back(settings);
}

service_nodes::quorum_manager oxen_chain_generator::top_quorum() const
{
  service_nodes::quorum_manager result = top().service_node_state.quorums;
  return result;
}

service_nodes::quorum_manager oxen_chain_generator::quorum(uint64_t height) const
{
  assert(height > 0 && height < db_.blocks.size());
  service_nodes::quorum_manager result = db_.blocks[height].service_node_state.quorums;
  return result;
}

std::shared_ptr<const service_nodes::quorum> oxen_chain_generator::get_quorum(service_nodes::quorum_type type, uint64_t height) const
{
  // TODO(oxen): Bad copy pasta from get_quorum, if it ever changes at the source this will break :<
  if (type == service_nodes::quorum_type::checkpointing)
  {
    assert(height >= service_nodes::REORG_SAFETY_BUFFER_BLOCKS_POST_HF12);
    height -= service_nodes::REORG_SAFETY_BUFFER_BLOCKS_POST_HF12;
  }

  assert(height > 0 && height < db_.blocks.size());
  service_nodes::quorum_manager manager = db_.blocks[height].service_node_state.quorums;
  std::shared_ptr<const service_nodes::quorum> result = manager.get(type);
  return result;
}

oxen_blockchain_entry &oxen_chain_generator::add_block(oxen_blockchain_entry const &entry, bool can_be_added_to_blockchain, std::string const &fail_msg)
{
  crypto::hash block_hash = get_block_hash(entry.block);
  if (can_be_added_to_blockchain)
  {
    db_.blocks.push_back(entry);
    assert(db_.block_table.count(block_hash) == 0);
    db_.block_table[block_hash] = db_.blocks.back();
  }
  else
  {
    assert(db_.block_table.count(block_hash) == 0);
    db_.block_table[block_hash] = entry;
  }

  oxen_blockchain_entry &result = (can_be_added_to_blockchain) ? db_.blocks.back() : db_.block_table[block_hash];
  for (cryptonote::transaction &tx : result.txs)
  {
    crypto::hash tx_hash = get_transaction_hash(tx);
    assert(db_.tx_table.count(tx_hash) == 0);
    db_.tx_table[tx_hash] = tx;
  }

  if (can_be_added_to_blockchain && entry.block.major_version >= cryptonote::network_version_15_ons)
  {
    ons_db_->add_block(entry.block, entry.txs);
  }

  std::vector<cryptonote::batch_sn_payment> contributors;
  if ( entry.block.major_version >= cryptonote::network_version_19)
  {
    auto service_node_array = service_node_contributors_.find(entry.block.service_node_winner_key);
    if (service_node_array != service_node_contributors_.end())
    {
      for (auto & contributor : (*service_node_array).second)
      {
        contributors.emplace_back(contributor.first, contributor.second, cryptonote::FAKECHAIN);
      }
    }
  }
  sqlite_db_->add_block(cryptonote::FAKECHAIN, entry.block, contributors);

  // TODO(oxen): State history culling and alt states
  state_history_.emplace_hint(state_history_.end(), result.service_node_state);

  if (result.checkpointed)
  {
    oxen_block_with_checkpoint data = {};
    data.has_checkpoint             = true;
    data.block                      = result.block;
    data.checkpoint                 = result.checkpoint;
    events_.push_back(oxen_blockchain_addable<oxen_block_with_checkpoint>(data, can_be_added_to_blockchain, fail_msg));
  }
  else
  {
    events_.push_back(oxen_blockchain_addable<cryptonote::block>(result.block, can_be_added_to_blockchain, fail_msg));
  }

  cryptonote::block sopthing = entry.block;

  return result;
}

cryptonote::account_base oxen_chain_generator::add_account()
{
  cryptonote::account_base account;
  account.generate();
  events_.push_back(account);
  return account;
}

void oxen_chain_generator::add_blocks_until_version(uint8_t hf_version)
{
  assert(hard_forks_.size());
  assert(hf_version_ <= hard_forks_.back().version);
  assert(db_.blocks.size() >= 1); // NOTE: We must have genesis block
  for (;;)
  {
    oxen_blockchain_entry &entry = create_and_add_next_block();
    if (entry.block.major_version == hf_version) return;
  }
}

void oxen_chain_generator::add_n_blocks(int n)
{
  for (auto i = 0; i < n; ++i) {
    create_and_add_next_block();
  }
}

bool oxen_chain_generator::add_blocks_until_next_checkpointable_height()
{
  if (top().service_node_state.active_service_nodes_infos().size() < service_nodes::CHECKPOINT_QUORUM_SIZE)
    return false;

  // NOTE: Add blocks until we get to the first height that has a checkpointing
  // quorum AND there are service nodes in the quorum. Note we do this naively
  // as tests shouldn't have to care about implementation details.
  for (;;)
  {
    create_and_add_next_block();
    std::shared_ptr<const service_nodes::quorum> quorum = get_quorum(service_nodes::quorum_type::checkpointing, height());
    if (quorum && quorum->validators.size()) break;
  }

  return true;
}

void oxen_chain_generator::add_service_node_checkpoint(uint64_t block_height, size_t num_votes)
{
  oxen_blockchain_entry &entry = db_.blocks[block_height];
  entry.checkpointed           = true;
  entry.checkpoint             = create_service_node_checkpoint(block_height, num_votes);
  events_.push_back(entry.checkpoint);
}

void oxen_chain_generator::add_mined_money_unlock_blocks()
{
  add_n_blocks(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
}

void oxen_chain_generator::add_transfer_unlock_blocks()
{
  add_n_blocks(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE);
}

void oxen_chain_generator::add_tx(cryptonote::transaction const &tx, bool can_be_added_to_blockchain, std::string const &fail_msg, bool kept_by_block)
{
  events_.emplace_back(oxen_blockchain_addable<oxen_transaction>{{tx, kept_by_block}, can_be_added_to_blockchain, fail_msg});
}

cryptonote::transaction
oxen_chain_generator::create_and_add_oxen_name_system_tx(cryptonote::account_base const &src,
                                                         uint8_t hf_version,
                                                         ons::mapping_type type,
                                                         std::string const &name,
                                                         ons::mapping_value const &value,
                                                         ons::generic_owner const *owner,
                                                         ons::generic_owner const *backup_owner,
                                                         bool kept_by_block)
{
  cryptonote::transaction t = create_oxen_name_system_tx(src, hf_version, type, name, value, owner, backup_owner);
  add_tx(t, true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, kept_by_block);
  return t;
}

cryptonote::transaction
oxen_chain_generator::create_and_add_oxen_name_system_tx_update(cryptonote::account_base const &src,
                                                                uint8_t hf_version,
                                                                ons::mapping_type type,
                                                                std::string const &name,
                                                                ons::mapping_value const *value,
                                                                ons::generic_owner const *owner,
                                                                ons::generic_owner const *backup_owner,
                                                                ons::generic_signature *signature,
                                                                bool kept_by_block)
{
  cryptonote::transaction t = create_oxen_name_system_tx_update(src, hf_version, type, name, value, owner, backup_owner, signature);
  add_tx(t, true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, kept_by_block);
  return t;
}

cryptonote::transaction
oxen_chain_generator::create_and_add_oxen_name_system_tx_renew(cryptonote::account_base const &src,
                                                               uint8_t hf_version,
                                                               ons::mapping_type type,
                                                               std::string const &name,
                                                               bool kept_by_block)
{
  cryptonote::transaction t = create_oxen_name_system_tx_renew(src, hf_version, type, name);
  add_tx(t, true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, kept_by_block);
  return t;
}


cryptonote::transaction oxen_chain_generator::create_and_add_tx(const cryptonote::account_base &src,
                                                                const cryptonote::account_public_address &dest,
                                                                uint64_t amount,
                                                                uint64_t fee,
                                                                bool kept_by_block)
{
  cryptonote::transaction t = create_tx(src, dest, amount, fee);
  oxen_tx_builder(events_, t, db_.blocks.back().block, src, dest, amount, hf_version_).with_fee(fee).build();
  add_tx(t, true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, kept_by_block);
  return t;
}

cryptonote::transaction oxen_chain_generator::create_and_add_big_tx(
        const cryptonote::account_base &src,
        const cryptonote::account_public_address &dest,
        uint64_t junk_size,
        uint64_t amount,
        uint64_t fee,
        bool kept_by_block)
{
  cryptonote::transaction t = create_tx(src, dest, amount, fee);
  oxen_tx_builder(events_, t, db_.blocks.back().block, src, dest, amount, hf_version_).with_fee(fee).with_junk(junk_size).build();
  add_tx(t, true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, kept_by_block);
  return t;
}

cryptonote::transaction oxen_chain_generator::create_and_add_state_change_tx(service_nodes::new_state state, const crypto::public_key &pub_key, uint16_t reasons_all, uint16_t reasons_any, uint64_t height, const std::vector<uint64_t> &voters, uint64_t fee, bool kept_by_block)
{
  cryptonote::transaction result = create_state_change_tx(state, pub_key, reasons_all, reasons_any, height, voters, fee);
  add_tx(result, true /*can_be_added_to_blockchain*/, "" /*fail_msg*/, kept_by_block);
  return result;
}

cryptonote::transaction oxen_chain_generator::create_and_add_registration_tx(const cryptonote::account_base &src, const cryptonote::keypair &sn_keys, bool kept_by_block)
{
  cryptonote::transaction result = create_registration_tx(src, sn_keys);
  add_tx(result, true /*can_be_added_to_blockchain*/, "" /*fail_msg*/, kept_by_block);
  return result;
}

cryptonote::transaction oxen_chain_generator::create_and_add_staking_tx(const crypto::public_key &pub_key, const cryptonote::account_base &src, uint64_t amount, bool kept_by_block)
{
  cryptonote::transaction result = create_staking_tx(pub_key, src, amount);
  add_tx(result, true /*can_be_added_to_blockchain*/, "" /*fail_msg*/, kept_by_block);
  return result;
}

oxen_blockchain_entry &oxen_chain_generator::create_and_add_next_block(const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint, bool can_be_added_to_blockchain, std::string const &fail_msg)
{
  oxen_blockchain_entry entry   = create_next_block(txs, checkpoint);
  oxen_blockchain_entry &result = add_block(entry, can_be_added_to_blockchain, fail_msg);
  return result;
}

cryptonote::transaction oxen_chain_generator::create_tx(const cryptonote::account_base &src,
                                                        const cryptonote::account_public_address &dest,
                                                        uint64_t amount,
                                                        uint64_t fee) const
{
  cryptonote::transaction t;
  oxen_tx_builder(events_, t, db_.blocks.back().block, src, dest, amount, hf_version_).with_fee(fee).build();
  return t;
}

cryptonote::transaction
oxen_chain_generator::create_registration_tx(const cryptonote::account_base &src,
                                             const cryptonote::keypair &service_node_keys,
                                             uint64_t src_portions,
                                             uint64_t src_operator_cut,
                                             std::array<oxen_service_node_contribution, 3> const &contributions,
                                             int num_contributors) const
{
  cryptonote::transaction result = {};
  {
    std::vector<cryptonote::account_public_address> contributors;
    std::vector<uint64_t> portions;

    contributors.reserve(1 + num_contributors);
    portions.reserve    (1 + num_contributors);

    contributors.push_back(src.get_keys().m_account_address);
    portions.push_back(src_portions);
    for (int i = 0; i < num_contributors; i++)
    {
      oxen_service_node_contribution const &entry = contributions[i];
      contributors.push_back(entry.contributor);
      portions.push_back    (entry.portions);
    }

    uint64_t new_height    = get_block_height(top().block) + 1;
    uint8_t new_hf_version = get_hf_version_at(new_height);
    const auto staking_requirement = service_nodes::get_staking_requirement(cryptonote::FAKECHAIN, new_height);
    uint64_t amount                = service_nodes::portions_to_amount(portions[0], staking_requirement);

    uint64_t unlock_time = 0;
    if (new_hf_version < cryptonote::network_version_11_infinite_staking)
      unlock_time = new_height + service_nodes::staking_num_lock_blocks(cryptonote::FAKECHAIN);

    std::vector<uint8_t> extra;
    cryptonote::add_service_node_pubkey_to_tx_extra(extra, service_node_keys.pub);
    const uint64_t exp_timestamp = time(nullptr) + STAKING_AUTHORIZATION_EXPIRATION_WINDOW;

    crypto::hash hash;
    if (!cryptonote::get_registration_hash(contributors, src_operator_cut, portions, exp_timestamp, hash))
    {
      MERROR("Could not make registration hash from addresses and portions");
      return {};
    }

    crypto::signature signature;
    crypto::generate_signature(hash, service_node_keys.pub, service_node_keys.sec, signature);
    add_service_node_register_to_tx_extra(extra, contributors, src_operator_cut, portions, exp_timestamp, signature);
    add_service_node_contributor_to_tx_extra(extra, contributors.at(0));
    oxen_tx_builder(events_, result, top().block, src /*from*/, src.get_keys().m_account_address /*to*/, amount, new_hf_version)
        .with_tx_type(cryptonote::txtype::stake)
        .with_unlock_time(unlock_time)
        .with_extra(extra)
        .build();
  }

  service_node_keys_[service_node_keys.pub] = service_node_keys.sec; // NOTE: Save generated key for reuse later if we need to interact with the node again
  return result;
}

cryptonote::transaction oxen_chain_generator::create_staking_tx(const crypto::public_key &pub_key, const cryptonote::account_base &src, uint64_t amount) const
{
  cryptonote::transaction result = {};
  std::vector<uint8_t> extra;
  cryptonote::add_service_node_pubkey_to_tx_extra(extra, pub_key);
  cryptonote::add_service_node_contributor_to_tx_extra(extra, src.get_keys().m_account_address);

  uint64_t new_height    = get_block_height(top().block) + 1;
  uint8_t new_hf_version = get_hf_version_at(new_height);

  uint64_t unlock_time = 0;
  if (new_hf_version < cryptonote::network_version_11_infinite_staking)
    unlock_time = new_height + service_nodes::staking_num_lock_blocks(cryptonote::FAKECHAIN);

  oxen_tx_builder(events_, result, top().block, src /*from*/, src.get_keys().m_account_address /*to*/, amount, new_hf_version)
      .with_tx_type(cryptonote::txtype::stake)
      .with_unlock_time(unlock_time)
      .with_extra(extra)
      .build();
  return result;
}

cryptonote::transaction oxen_chain_generator::create_state_change_tx(service_nodes::new_state state, const crypto::public_key &pub_key, uint16_t reasons_all, uint16_t reasons_any, uint64_t height, const std::vector<uint64_t>& voters, uint64_t fee) const
{
  if (height == UINT64_MAX)
    height = this->height();

  auto hf_version = get_hf_version_at(height + 1);

  service_nodes::quorum_manager const &quorums                   = quorum(height);
  std::vector<crypto::public_key> const &validator_service_nodes = quorums.obligations->validators;
  std::vector<crypto::public_key> const &worker_service_nodes    = quorums.obligations->workers;

  size_t worker_index = std::numeric_limits<size_t>::max();
  for (size_t i = 0; i < worker_service_nodes.size(); i++)
  {
    crypto::public_key const &check_key = worker_service_nodes[i];
    if (pub_key == check_key) worker_index = i;
  }
  assert(worker_index < worker_service_nodes.size());

  using scver = cryptonote::tx_extra_service_node_state_change::version_t;
  cryptonote::tx_extra_service_node_state_change state_change_extra(
          hf_version >= cryptonote::network_version_18 ? scver::v4_reasons : scver::v0,
          state, height, worker_index, reasons_all, reasons_any, {});
  if (voters.size())
  {
    for (const auto voter_index : voters)
    {
      auto voter_keys = get_cached_keys(validator_service_nodes[voter_index]);
      service_nodes::quorum_vote_t vote = service_nodes::make_state_change_vote(state_change_extra.block_height, voter_index, state_change_extra.service_node_index, state, 0, voter_keys);
      state_change_extra.votes.push_back({vote.signature, (uint32_t)voter_index});
    }
  }
  else
  {
    for (size_t i = 0; i < service_nodes::STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE; i++)
    {
      auto voter_keys = get_cached_keys(validator_service_nodes[i]);

      service_nodes::quorum_vote_t vote = service_nodes::make_state_change_vote(state_change_extra.block_height, i, state_change_extra.service_node_index, state, 0, voter_keys);
      state_change_extra.votes.push_back({vote.signature, (uint32_t)i});
    }
  }

  cryptonote::transaction result;
  {
    std::vector<uint8_t> extra;
    const bool full_tx_made = cryptonote::add_service_node_state_change_to_tx_extra(result.extra, state_change_extra, hf_version);
    assert(full_tx_made);
    if (fee)
      oxen_tx_builder(events_, result, top().block, first_miner_, first_miner_.get_keys().m_account_address, 0 /*amount*/, hf_version)
        .with_tx_type(cryptonote::txtype::state_change)
        .with_fee(fee)
        .with_extra(extra)
        .build();
    else
    {
      result.type    = cryptonote::txtype::state_change;
      result.version = cryptonote::transaction::get_max_version_for_hf(hf_version);
    }
  }

  return result;
}

cryptonote::checkpoint_t oxen_chain_generator::create_service_node_checkpoint(uint64_t block_height, size_t num_votes) const
{
  service_nodes::quorum const &quorum = *get_quorum(service_nodes::quorum_type::checkpointing, block_height);
  assert(num_votes < quorum.validators.size());

  oxen_blockchain_entry const &entry = db_.blocks[block_height];
  crypto::hash const block_hash      = cryptonote::get_block_hash(entry.block);
  cryptonote::checkpoint_t result    = service_nodes::make_empty_service_node_checkpoint(block_hash, block_height);
  result.signatures.reserve(num_votes);
  for (size_t i = 0; i < num_votes; i++)
  {
    auto keys = get_cached_keys(quorum.validators[i]);
    service_nodes::quorum_vote_t vote = service_nodes::make_checkpointing_vote(entry.block.major_version, result.block_hash, block_height, i, keys);
    result.signatures.push_back(service_nodes::quorum_signature(vote.index_in_group, vote.signature));
  }

  return result;
}

cryptonote::transaction oxen_chain_generator::create_oxen_name_system_tx(cryptonote::account_base const &src,
                                                                         uint8_t hf_version,
                                                                         ons::mapping_type type,
                                                                         std::string const &name,
                                                                         ons::mapping_value const &value,
                                                                         ons::generic_owner const *owner,
                                                                         ons::generic_owner const *backup_owner,
                                                                         std::optional<uint64_t> burn_override) const
{
  ons::generic_owner generic_owner = {};
  if (owner)
  {
    generic_owner = *owner;
  }
  else
  {
    generic_owner = ons::make_monero_owner(src.get_keys().m_account_address, false /*subaddress*/);
  }

  cryptonote::block const &head = top().block;
  uint64_t new_height           = get_block_height(top().block) + 1;
  uint8_t new_hf_version        = get_hf_version_at(new_height);
  uint64_t burn = burn_override.value_or(ons::burn_needed(new_hf_version, type));

  auto lcname = tools::lowercase_ascii_string(name);
  crypto::hash name_hash       = ons::name_to_hash(lcname);
  std::string name_base64_hash = ons::name_to_base64_hash(lcname);
  crypto::hash prev_txid = crypto::null_hash;
  if (ons::mapping_record mapping = ons_db_->get_mapping(type, name_base64_hash, new_height))
    prev_txid = mapping.txid;

  ons::mapping_value encrypted_value = value;
  bool encrypted = encrypted_value.encrypt(lcname, &name_hash, hf_version <= cryptonote::network_version_15_ons);
  assert(encrypted);

  std::vector<uint8_t> extra;
  cryptonote::tx_extra_oxen_name_system data = cryptonote::tx_extra_oxen_name_system::make_buy(generic_owner, backup_owner, type, name_hash, encrypted_value.to_string(), prev_txid);
  cryptonote::add_oxen_name_system_to_tx_extra(extra, data);
  cryptonote::add_burned_amount_to_tx_extra(extra, burn);
  cryptonote::transaction result = {};
  oxen_tx_builder(events_, result, head, src /*from*/, src.get_keys().m_account_address, 0 /*amount*/, new_hf_version)
      .with_tx_type(cryptonote::txtype::oxen_name_system)
      .with_extra(extra)
      .with_fee(burn + TESTS_DEFAULT_FEE)
      .build();

  return result;
}

cryptonote::transaction oxen_chain_generator::create_oxen_name_system_tx_update(cryptonote::account_base const &src,
                                                                                uint8_t hf_version,
                                                                                ons::mapping_type type,
                                                                                std::string const &name,
                                                                                ons::mapping_value const *value,
                                                                                ons::generic_owner const *owner,
                                                                                ons::generic_owner const *backup_owner,
                                                                                ons::generic_signature *signature,
                                                                                bool use_asserts) const
{
  auto lcname = tools::lowercase_ascii_string(name);
  crypto::hash name_hash = ons::name_to_hash(lcname);
  crypto::hash prev_txid = {};
  {
    std::string name_base64_hash = ons::name_to_base64_hash(lcname);
    ons::mapping_record mapping  = ons_db_->get_mapping(type, name_base64_hash);
    if (use_asserts) assert(mapping);
    prev_txid = mapping.txid;
  }

  ons::mapping_value encrypted_value = {};
  if (value)
  {
    encrypted_value = *value;
    if (!encrypted_value.encrypted)
    {
      assert(!signature); // Can't specify a signature with an unencrypted value because encrypting generates a new nonce and would invalidate it
      bool encrypted = encrypted_value.encrypt(lcname, &name_hash, hf_version <= cryptonote::network_version_15_ons);
      if (use_asserts) assert(encrypted);
    }
  }

  ons::generic_signature signature_ = {};
  if (!signature)
  {
    signature = &signature_;
    auto data = ons::tx_extra_signature(encrypted_value.to_view(), owner, backup_owner, prev_txid);
    crypto::hash hash{};
    if (!data.empty())
        crypto_generichash(reinterpret_cast<unsigned char*>(hash.data), sizeof(hash), reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr, 0);
    generate_signature(hash, src.get_keys().m_account_address.m_spend_public_key, src.get_keys().m_spend_secret_key, signature->monero);
    signature->type = ons::generic_owner_sig_type::monero;
  }

  std::vector<uint8_t> extra;
  cryptonote::tx_extra_oxen_name_system data = cryptonote::tx_extra_oxen_name_system::make_update(*signature, type, name_hash, encrypted_value.to_view(), owner, backup_owner, prev_txid);
  cryptonote::add_oxen_name_system_to_tx_extra(extra, data);

  cryptonote::block const &head = top().block;
  uint64_t new_height           = get_block_height(top().block) + 1;
  uint8_t new_hf_version        = get_hf_version_at(new_height);

  cryptonote::transaction result = {};
  oxen_tx_builder(events_, result, head, src /*from*/, src.get_keys().m_account_address, 0 /*amount*/, new_hf_version)
      .with_tx_type(cryptonote::txtype::oxen_name_system)
      .with_extra(extra)
      .with_fee(TESTS_DEFAULT_FEE)
      .build();

  return result;
}

cryptonote::transaction
oxen_chain_generator::create_oxen_name_system_tx_update_w_extra(cryptonote::account_base const &src, uint8_t hf_version, cryptonote::tx_extra_oxen_name_system const &ons_extra) const
{
  std::vector<uint8_t> extra;
  cryptonote::add_oxen_name_system_to_tx_extra(extra, ons_extra);

  cryptonote::block const &head = top().block;
  uint64_t new_height           = get_block_height(top().block) + 1;
  uint8_t new_hf_version        = get_hf_version_at(new_height);

  cryptonote::transaction result = {};
  oxen_tx_builder(events_, result, head, src /*from*/, src.get_keys().m_account_address, 0 /*amount*/, new_hf_version)
      .with_tx_type(cryptonote::txtype::oxen_name_system)
      .with_extra(extra)
      .with_fee(TESTS_DEFAULT_FEE)
      .build();
  return result;
}

cryptonote::transaction oxen_chain_generator::create_oxen_name_system_tx_renew(cryptonote::account_base const &src,
                                                                               uint8_t hf_version,
                                                                               ons::mapping_type type,
                                                                               std::string const &name,
                                                                               std::optional<uint64_t> burn_override) const
{
  auto lcname = tools::lowercase_ascii_string(name);
  crypto::hash name_hash = ons::name_to_hash(lcname);
  crypto::hash prev_txid = {};
  {
    std::string name_base64_hash = ons::name_to_base64_hash(lcname);
    ons::mapping_record mapping  = ons_db_->get_mapping(type, name_base64_hash);
    prev_txid = mapping.txid;
  }

  uint8_t new_hf_version = get_hf_version_at(get_block_height(top().block) + 1);
  uint64_t burn = burn_override.value_or(ons::burn_needed(new_hf_version, type));

  std::vector<uint8_t> extra;
  cryptonote::tx_extra_oxen_name_system data = cryptonote::tx_extra_oxen_name_system::make_renew(type, name_hash, prev_txid);
  cryptonote::add_oxen_name_system_to_tx_extra(extra, data);
  cryptonote::add_burned_amount_to_tx_extra(extra, burn);

  cryptonote::block const &head = top().block;

  cryptonote::transaction result = {};
  oxen_tx_builder(events_, result, head, src /*from*/, src.get_keys().m_account_address, 0 /*amount*/, new_hf_version)
      .with_tx_type(cryptonote::txtype::oxen_name_system)
      .with_extra(extra)
      .with_fee(burn + TESTS_DEFAULT_FEE)
      .build();

  return result;
}

static void fill_nonce_with_test_generator(test_generator *generator, cryptonote::block& blk, const cryptonote::difficulty_type& diffic, uint64_t height)
{
  cryptonote::randomx_longhash_context randomx_context = {};
  if (generator->m_hf_version >= cryptonote::network_version_12_checkpointing)
  {
    randomx_context.seed_height = crypto::rx_seedheight(height);
    cryptonote::block prev      = blk;
    do
    {
      prev = generator->m_blocks_info[prev.prev_id].block;
    }
    while (cryptonote::get_block_height(prev) != randomx_context.seed_height);

    randomx_context.seed_block_hash           = cryptonote::get_block_hash(prev);
    randomx_context.current_blockchain_height = height;
  }

  blk.nonce = 0;
  auto get_block_hash = [&randomx_context](const cryptonote::block &b, uint64_t height, unsigned int threads, crypto::hash &hash) {
    hash = cryptonote::get_block_longhash(cryptonote::FAKECHAIN, randomx_context, b, height, threads);
    return true;
  };

  while (!cryptonote::miner::find_nonce_for_given_block(get_block_hash, blk, diffic, height))
    blk.timestamp++;
}

void fill_nonce_with_oxen_generator(oxen_chain_generator const *generator, cryptonote::block& blk, const cryptonote::difficulty_type& diffic, uint64_t height)
{
  cryptonote::randomx_longhash_context randomx_context = {};
  if (generator->blocks().size() && generator->hardfork() >= cryptonote::network_version_12_checkpointing)
  {
    randomx_context.seed_height = crypto::rx_seedheight(height);
    randomx_context.seed_block_hash = cryptonote::get_block_hash(generator->blocks()[randomx_context.seed_height].block);
    randomx_context.current_blockchain_height = height;
  }

  blk.nonce = 0;
  auto get_block_hash = [&randomx_context](const cryptonote::block &blk, uint64_t height, unsigned int threads, crypto::hash &hash) {
    hash = cryptonote::get_block_longhash(cryptonote::FAKECHAIN, randomx_context, blk, height, threads);
    return true;
  };

  while (!cryptonote::miner::find_nonce_for_given_block(get_block_hash, blk, TEST_DEFAULT_DIFFICULTY, height))
    blk.timestamp++;
}

oxen_blockchain_entry oxen_chain_generator::create_genesis_block(const cryptonote::account_base &miner, uint64_t timestamp)
{
  uint64_t height              = 0;
  oxen_blockchain_entry result = {};
  cryptonote::block &blk       = result.block;
  blk.major_version            = hf_version_;
  blk.minor_version            = hf_version_;
  blk.timestamp                = timestamp;
  blk.prev_id                  = crypto::null_hash;

  // TODO(doyle): Does this evaluate to 0? If so we can simplify this a lot more
  size_t target_block_weight = get_transaction_weight(blk.miner_tx);
  std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds;
  uint64_t block_rewards = 0;

  while (true)
  {
    bool constructed = false;
    std::tie(constructed, block_rewards) = construct_miner_tx(height,
                                          0 /*median_weight*/,
                                          0 /*already_generated_coins*/,
                                          target_block_weight,
                                          0 /*total_fee*/,
                                          blk.miner_tx,
                                          cryptonote::oxen_miner_tx_context::miner_block(cryptonote::FAKECHAIN, miner.get_keys().m_account_address),
                                          sn_rwds,
                                          cryptonote::blobdata(),
                                          hf_version_);
    assert(constructed);

    size_t actual_block_weight = get_transaction_weight(blk.miner_tx);
    if (target_block_weight < actual_block_weight)
    {
      target_block_weight = actual_block_weight;
    }
    else if (actual_block_weight < target_block_weight)
    {
      size_t delta = target_block_weight - actual_block_weight;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
      actual_block_weight = get_transaction_weight(blk.miner_tx);
      if (actual_block_weight == target_block_weight)
      {
        break;
      }
      else
      {
        assert(target_block_weight < actual_block_weight);
        delta = actual_block_weight - target_block_weight;
        blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
        actual_block_weight = get_transaction_weight(blk.miner_tx);
        if (actual_block_weight == target_block_weight)
        {
          break;
        }
        else
        {
          assert(actual_block_weight < target_block_weight);
          blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
          target_block_weight = get_transaction_weight(blk.miner_tx);
        }
      }
    }
    else
    {
      break;
    }
  }

  fill_nonce_with_oxen_generator(this, blk, TEST_DEFAULT_DIFFICULTY, height);
  result.block_weight = get_transaction_weight(blk.miner_tx);
  uint64_t block_reward, block_reward_unpenalized;
  cryptonote::get_base_block_reward(0 /*median_weight*/, result.block_weight, 0 /*already_generated_coins*/, block_reward, block_reward_unpenalized, hf_version_, height);
  result.already_generated_coins = block_reward;
  return result;
}

bool oxen_chain_generator::block_begin(oxen_blockchain_entry &entry, oxen_create_block_params &params, const std::vector<cryptonote::transaction> &tx_list) const
{
  assert(params.hf_version >= params.prev.block.major_version);
  uint64_t height          = get_block_height(params.prev.block) + 1;
  entry                    = {};
  cryptonote::block &blk   = entry.block;
  blk.major_version        = params.hf_version;
  blk.minor_version        = params.hf_version;
  blk.height               = height;
  blk.timestamp            = params.timestamp;
  blk.prev_id              = get_block_hash(params.prev.block);

  uint64_t total_fee  = params.total_fee;
  bool calc_total_fee = total_fee == 0;
  size_t txs_weight   = 0;
  blk.tx_hashes.reserve(tx_list.size());
  for(const cryptonote::transaction &tx : tx_list)
  {
    blk.tx_hashes.push_back(get_transaction_hash(tx));
    uint64_t fee = 0;
    bool r       = get_tx_miner_fee(tx, fee, blk.major_version >= HF_VERSION_FEE_BURNING);
    CHECK_AND_ASSERT_MES(r, false, "wrong transaction passed to construct_block");
    txs_weight  += get_transaction_weight(tx);
    if (calc_total_fee) total_fee += fee;
  }

  // NOTE: Calculate governance
  cryptonote::oxen_miner_tx_context miner_tx_context;
  service_nodes::quorum pulse_quorum;
  std::vector<service_nodes::pubkey_and_sninfo> active_snode_list =
      params.prev.service_node_state.active_service_nodes_infos();

  bool pulse_block_is_possible = blk.major_version >= cryptonote::network_version_16_pulse && active_snode_list.size() >= service_nodes::pulse_min_service_nodes(cryptonote::FAKECHAIN);
  bool make_pulse_block        = (params.type == oxen_create_block_type::automatic && pulse_block_is_possible) || params.type == oxen_create_block_type::pulse;

  if (make_pulse_block)
  {
    // NOTE: Set up Pulse Header
    blk.pulse.validator_bitset = service_nodes::pulse_validator_bit_mask(); // NOTE: Everyone participates
    blk.pulse.round = params.pulse_round;
    for (size_t i = 0; i < sizeof(blk.pulse.random_value.data); i++)
      blk.pulse.random_value.data[i] = static_cast<char>(tools::uniform_distribution_portable(tools::rng, 256));

    // NOTE: Get Pulse Quorum necessary for this block
    std::vector<crypto::hash> entropy = service_nodes::get_pulse_entropy_for_next_block(db_, params.prev.block, blk.pulse.round);
    pulse_quorum = service_nodes::generate_pulse_quorum(cryptonote::FAKECHAIN, params.block_leader.key, blk.major_version, active_snode_list, entropy, blk.pulse.round);
    assert(pulse_quorum.validators.size() == service_nodes::PULSE_QUORUM_NUM_VALIDATORS);
    assert(pulse_quorum.workers.size() == 1);

    service_nodes::payout block_producer = {};
    if (pulse_quorum.workers[0] == params.block_leader.key)
    {
      block_producer = params.block_leader;
    }
    else
    {
      crypto::public_key block_producer_key = pulse_quorum.workers[0];
      auto it = params.prev.service_node_state.service_nodes_infos.find(block_producer_key);
      assert(it != params.prev.service_node_state.service_nodes_infos.end());
      block_producer = service_nodes::service_node_info_to_payout(block_producer_key, *(it->second));
    }

    miner_tx_context = cryptonote::oxen_miner_tx_context::pulse_block(cryptonote::FAKECHAIN, block_producer, params.block_leader);
    blk.service_node_winner_key = miner_tx_context.pulse_block_producer.key;
  }
  else
  {
    miner_tx_context = cryptonote::oxen_miner_tx_context::miner_block(cryptonote::FAKECHAIN, params.miner_acc.get_keys().m_account_address, params.block_leader);
    blk.service_node_winner_key = miner_tx_context.block_leader.key;
  }

  if (blk.major_version >= cryptonote::network_version_10_bulletproofs &&
      cryptonote::height_has_governance_output(cryptonote::FAKECHAIN, blk.major_version, height))
  {
    constexpr uint64_t num_blocks       = cryptonote::get_config(cryptonote::FAKECHAIN).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    uint64_t start_height               = height - num_blocks;

    if (blk.major_version == cryptonote::network_version_15_ons)
      miner_tx_context.batched_governance = FOUNDATION_REWARD_HF15 * num_blocks;
    else if (blk.major_version == cryptonote::network_version_16_pulse)
      miner_tx_context.batched_governance = (FOUNDATION_REWARD_HF15 + CHAINFLIP_LIQUIDITY_HF16) * num_blocks;
    else if (blk.major_version >= cryptonote::network_version_17)
      miner_tx_context.batched_governance = FOUNDATION_REWARD_HF17 * num_blocks;
    else
    {
      for (int i = (int)get_block_height(params.prev.block), count = 0;
           i >= 0 && count <= (int)num_blocks;
           i--, count++)
      {
        oxen_blockchain_entry const &historical_entry = db_.blocks[i];
        if (historical_entry.block.major_version < cryptonote::network_version_10_bulletproofs) break;
        miner_tx_context.batched_governance += cryptonote::derive_governance_from_block_reward(cryptonote::FAKECHAIN, historical_entry.block, blk.major_version);
      }
    }
  }

  size_t target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds;
  if (hf_version_ >= cryptonote::network_version_19)
  {
    sn_rwds = sqlite_db_->get_sn_payments(cryptonote::FAKECHAIN, height); //Rewards to pay out
  }
  uint64_t block_rewards = 0;
  bool r;
  while (true)
  {
    std::tie(r, block_rewards) = construct_miner_tx(height,
                                    epee::misc_utils::median(params.block_weights),
                                    params.prev.already_generated_coins,
                                    target_block_weight,
                                    total_fee,
                                    blk.miner_tx,
                                    miner_tx_context,
                                    sn_rwds,
                                    cryptonote::blobdata(),
                                    blk.major_version
                                    );
    if (!r)
      return false;

    entry.block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    if (target_block_weight < entry.block_weight)
    {
      target_block_weight = entry.block_weight;
    }
    else if (entry.block_weight < target_block_weight)
    {
      size_t delta = target_block_weight - entry.block_weight;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
      entry.block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
      if (entry.block_weight == target_block_weight)
      {
        break;
      }
      else
      {
        CHECK_AND_ASSERT_MES(target_block_weight < entry.block_weight, false, "Unexpected block size");
        delta = entry.block_weight - target_block_weight;
        blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
        entry.block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        if (entry.block_weight == target_block_weight)
        {
          break;
        }
        else
        {
          CHECK_AND_ASSERT_MES(entry.block_weight < target_block_weight, false, "Unexpected block size");
          blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
          target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        }
      }
    }
    else
    {
      break;
    }
  }

  blk.reward = block_rewards;
  entry.txs = tx_list;
  uint64_t block_reward, block_reward_unpenalized;
  cryptonote::get_base_block_reward(epee::misc_utils::median(params.block_weights), entry.block_weight, params.prev.already_generated_coins, block_reward, block_reward_unpenalized, params.hf_version, height);
  entry.already_generated_coins = block_reward + params.prev.already_generated_coins;

  // NOTE: This relies on the block hash, so must be done after
  if (make_pulse_block)
  {
    crypto::hash block_hash = cryptonote::get_block_hash(blk);
    assert(blk.signatures.empty());

    // NOTE: Fill Pulse Signature Data
    for (size_t i = 0; i < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES; i++)
    {
      service_nodes::service_node_keys validator_keys = get_cached_keys(pulse_quorum.validators[i]);
      assert(validator_keys.pub == pulse_quorum.validators[i]);

      service_nodes::quorum_signature signature = {};
      signature.voter_index                     = i;
      crypto::generate_signature(block_hash, validator_keys.pub, validator_keys.key, signature.signature);
      blk.signatures.push_back(signature);
    }
  }

  return true;
}

void oxen_chain_generator::block_end(oxen_blockchain_entry &entry, oxen_create_block_params const &params) const
{
  entry.service_node_state = params.prev.service_node_state;
  entry.service_node_state.update_from_block(db_, cryptonote::FAKECHAIN, state_history_, {} /*state_archive*/, {} /*alt_states*/, entry.block, entry.txs, nullptr);
}

bool oxen_chain_generator::process_registration_tx(cryptonote::transaction& tx, uint64_t block_height, uint8_t hf_version)
{
  service_nodes::contributor_args_t contributor_args = {};
  crypto::public_key service_node_key;
  uint64_t expiration_timestamp{0};
  crypto::signature signature;

  if (!service_nodes::reg_tx_extract_fields(tx, contributor_args, expiration_timestamp, service_node_key, signature))
    return false;

  uint64_t staking_requirement = service_nodes::get_staking_requirement(cryptonote::FAKECHAIN, block_height);
  std::vector<std::pair<cryptonote::account_public_address, uint64_t>> contributors;
  for (size_t i = 0; i < contributor_args.addresses.size(); i++)
  {
    uint64_t hi, lo, resulthi, resultlo;
    lo = mul128(staking_requirement, contributor_args.portions[i], &hi);
    div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);

    contributors.emplace_back(contributor_args.addresses[i], resultlo);
  }

  service_node_contributors_[service_node_key] = contributors;

  return true;
}

bool oxen_chain_generator::create_block(oxen_blockchain_entry &entry,
                                        oxen_create_block_params &params,
                                        const std::vector<cryptonote::transaction> &tx_list) const
{
  if (!block_begin(entry, params, tx_list))
    return false;

  if (entry.block.signatures.empty())
    fill_nonce_with_oxen_generator(this, entry.block, TEST_DEFAULT_DIFFICULTY, cryptonote::get_block_height(entry.block));

  block_end(entry, params);
  return true;
}

oxen_create_block_params oxen_chain_generator::next_block_params() const
{
  oxen_blockchain_entry const &prev = top();
  uint64_t next_height              = height() + 1;

  oxen_create_block_params result = {};
  result.prev                     = prev;
  result.miner_acc                = first_miner_;
  result.timestamp                = prev.block.timestamp + tools::to_seconds(TARGET_BLOCK_TIME);
  result.block_weights            = last_n_block_weights(height(), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  result.hf_version               = get_hf_version_at(next_height);
  result.block_leader             = prev.service_node_state.get_block_leader();
  result.total_fee                = 0; // Request chain generator to calculate the fee
  return result;
}

oxen_blockchain_entry oxen_chain_generator::create_next_block(const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint)
{
  oxen_blockchain_entry result          = {};
  oxen_create_block_params block_params = next_block_params();
  create_block(result, block_params, txs);
  if (checkpoint)
  {
    result.checkpoint   = *checkpoint;
    result.checkpointed = true;
  }

  hf_version_ = result.block.major_version;
  return result;
}

uint8_t oxen_chain_generator::get_hf_version_at(uint64_t height) const {

  uint8_t cur_hf_ver = 0;
  for (auto i = 0u; i < hard_forks_.size(); ++i)
  {
    if (height < hard_forks_[i].height) break;
    cur_hf_ver = hard_forks_[i].version;
  }

  assert(cur_hf_ver != 0);
  return cur_hf_ver;
}

std::vector<uint64_t> oxen_chain_generator::last_n_block_weights(uint64_t height, uint64_t num) const
{
  std::vector<uint64_t> result;
  if (num > height) num = height;
  result.reserve(num);
  assert(height < db_.blocks.size());

  for (size_t i = 0; i < num; i++)
  {
    uint64_t index = height - num + i;
    result.push_back(db_.blocks[index].block_weight);
    if ((height - i) == 0) break;
  }
  return result;
}

/// --------------------------------------------------------------
void test_generator::get_block_chain(std::vector<block_info>& blockchain, const crypto::hash& head, size_t n) const
{
  crypto::hash curr = head;
  while (crypto::null_hash != curr && blockchain.size() < n)
  {
    auto it = m_blocks_info.find(curr);
    if (m_blocks_info.end() == it)
    {
      throw std::runtime_error("block hash wasn't found");
    }

    blockchain.push_back(it->second);
    curr = it->second.prev_id;
  }

  std::reverse(blockchain.begin(), blockchain.end());
}

// TODO(oxen): Copypasta
void test_generator::get_block_chain(std::vector<cryptonote::block> &blockchain,
                                     const crypto::hash &head,
                                     size_t n) const
{
  crypto::hash curr = head;
  while (crypto::null_hash != curr && blockchain.size() < n)
  {
    auto it = m_blocks_info.find(curr);
    if (m_blocks_info.end() == it)
    {
      throw std::runtime_error("block hash wasn't found");
    }

    blockchain.push_back(it->second.block);
    curr = it->second.prev_id;
  }

  std::reverse(blockchain.begin(), blockchain.end());
}

void test_generator::get_last_n_block_weights(std::vector<uint64_t>& block_weights, const crypto::hash& head, size_t n) const
{
  std::vector<block_info> blockchain;
  get_block_chain(blockchain, head, n);
  for (auto& bi : blockchain)
  {
    block_weights.push_back(bi.block_weight);
  }
}

uint64_t test_generator::get_already_generated_coins(const crypto::hash& blk_id) const
{
  auto it = m_blocks_info.find(blk_id);
  if (it == m_blocks_info.end())
    throw std::runtime_error("block hash wasn't found");

  return it->second.already_generated_coins;
}

uint64_t test_generator::get_already_generated_coins(const cryptonote::block& blk) const
{
  crypto::hash blk_hash;
  get_block_hash(blk, blk_hash);
  return get_already_generated_coins(blk_hash);
}

void test_generator::add_block(const cryptonote::block& blk, size_t txs_weight, std::vector<uint64_t>& block_weights, uint64_t already_generated_coins)
{
  const size_t block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  uint64_t block_reward, block_reward_unpenalized;
  cryptonote::get_base_block_reward(epee::misc_utils::median(block_weights), block_weight, already_generated_coins, block_reward, block_reward_unpenalized, m_hf_version, 0);
  m_blocks_info.insert({get_block_hash(blk), block_info(blk.prev_id, already_generated_coins + block_reward, block_weight, blk)});
}

static void manual_calc_batched_governance(const test_generator &generator,
                                           const crypto::hash &head,
                                           cryptonote::oxen_miner_tx_context &miner_tx_context,
                                           int hard_fork_version,
                                           uint64_t height)
{
  miner_tx_context.batched_governance = 0;
  if (hard_fork_version >= cryptonote::network_version_10_bulletproofs &&
      cryptonote::height_has_governance_output(cryptonote::FAKECHAIN, hard_fork_version, height))
  {
    uint64_t num_blocks                 = cryptonote::get_config(cryptonote::FAKECHAIN).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    uint64_t start_height               = height - num_blocks;

    if (hard_fork_version >= cryptonote::network_version_15_ons)
    {
      miner_tx_context.batched_governance = num_blocks * cryptonote::governance_reward_formula(0, hard_fork_version);
      return;
    }

    if (height < num_blocks)
    {
      start_height = 0;
      num_blocks   = height;
    }

    std::vector<cryptonote::block> blockchain;
    blockchain.reserve(num_blocks);
    generator.get_block_chain(blockchain, head, num_blocks);

    for (const cryptonote::block &entry : blockchain)
    {
      uint64_t block_height = cryptonote::get_block_height(entry);
      if (block_height < start_height)
        continue;

      if (entry.major_version >= cryptonote::network_version_10_bulletproofs)
        miner_tx_context.batched_governance += cryptonote::derive_governance_from_block_reward(cryptonote::FAKECHAIN, entry, hard_fork_version);
    }
  }
}

bool test_generator::construct_block(cryptonote::block &blk,
                                     uint64_t height,
                                     const crypto::hash &prev_id,
                                     const cryptonote::account_base &miner_acc,
                                     uint64_t timestamp,
                                     uint64_t already_generated_coins,
                                     std::vector<uint64_t> &block_weights,
                                     const std::list<cryptonote::transaction> &tx_list,
                                     const service_nodes::payout &block_leader)
{
  /// a temporary workaround
  blk.major_version = m_hf_version;
  blk.minor_version = m_hf_version;

  blk.timestamp = timestamp;
  blk.prev_id = prev_id;

  blk.tx_hashes.reserve(tx_list.size());
  for (const cryptonote::transaction &tx : tx_list)
  {
    crypto::hash tx_hash;
    cryptonote::get_transaction_hash(tx, tx_hash);
    blk.tx_hashes.push_back(tx_hash);
  }

  uint64_t total_fee = 0;
  size_t txs_weight = 0;
  for (auto& tx : tx_list)
  {
    uint64_t fee = 0;
    bool r = get_tx_miner_fee(tx, fee, blk.major_version >= HF_VERSION_FEE_BURNING);
    CHECK_AND_ASSERT_MES(r, false, "wrong transaction passed to construct_block");
    total_fee += fee;
    txs_weight += get_transaction_weight(tx);
  }

  auto miner_tx_context = cryptonote::oxen_miner_tx_context::miner_block(cryptonote::FAKECHAIN, miner_acc.get_keys().m_account_address, block_leader);
  blk.miner_tx = {};
  size_t target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
  manual_calc_batched_governance(*this, prev_id, miner_tx_context, m_hf_version, height);

  uint64_t block_rewards = 0;
  bool r;
  std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds;
  while (true)
  {
    std::tie(r, block_rewards) = construct_miner_tx(height,
                                  epee::misc_utils::median(block_weights),
                                  already_generated_coins,
                                  target_block_weight,
                                  total_fee,
                                  blk.miner_tx,
                                  miner_tx_context,
                                  sn_rwds,
                                  cryptonote::blobdata(),
                                  m_hf_version);
    if (!r)
      return false;

    size_t actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    if (target_block_weight < actual_block_weight)
    {
      target_block_weight = actual_block_weight;
    }
    else if (actual_block_weight < target_block_weight)
    {
      size_t delta = target_block_weight - actual_block_weight;
      blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
      actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
      if (actual_block_weight == target_block_weight)
      {
        break;
      }
      else
      {
        CHECK_AND_ASSERT_MES(target_block_weight < actual_block_weight, false, "Unexpected block size");
        delta = actual_block_weight - target_block_weight;
        blk.miner_tx.extra.resize(blk.miner_tx.extra.size() - delta);
        actual_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        if (actual_block_weight == target_block_weight)
        {
          break;
        }
        else
        {
          CHECK_AND_ASSERT_MES(actual_block_weight < target_block_weight, false, "Unexpected block size");
          blk.miner_tx.extra.resize(blk.miner_tx.extra.size() + delta, 0);
          target_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
        }
      }
    }
    else
    {
      break;
    }
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);
  fill_nonce_with_test_generator(this, blk, TEST_DEFAULT_DIFFICULTY, height);
  add_block(blk, txs_weight, block_weights, already_generated_coins);

  return true;
}

bool test_generator::construct_block(cryptonote::block &blk,
                                     const cryptonote::account_base &miner_acc,
                                     uint64_t timestamp)
{
  std::vector<uint64_t> block_weights;
  std::list<cryptonote::transaction> tx_list;
  return construct_block(blk, 0, crypto::null_hash, miner_acc, timestamp, 0, block_weights, tx_list);
}

bool test_generator::construct_block(cryptonote::block &blk,
                                     const cryptonote::block &blk_prev,
                                     const cryptonote::account_base &miner_acc,
                                     const std::list<cryptonote::transaction> &tx_list /* = {}*/,
                                     const service_nodes::payout &block_leader)
{
  uint64_t height = var::get<cryptonote::txin_gen>(blk_prev.miner_tx.vin.front()).height + 1;
  crypto::hash prev_id = get_block_hash(blk_prev);
  // Keep difficulty unchanged
  uint64_t timestamp = blk_prev.timestamp + tools::to_seconds(TARGET_BLOCK_TIME);
  uint64_t already_generated_coins = get_already_generated_coins(prev_id);
  std::vector<uint64_t> block_weights;
  get_last_n_block_weights(block_weights, prev_id, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

  return construct_block(blk, height, prev_id, miner_acc, timestamp, already_generated_coins, block_weights, tx_list, block_leader);
}

bool test_generator::construct_block_manually(
    cryptonote::block &blk,
    const cryptonote::block &prev_block,
    const cryptonote::account_base &miner_acc,
    int actual_params /* = bf_none*/,
    uint8_t major_ver /* = 0*/,
    uint8_t minor_ver /* = 0*/,
    uint64_t timestamp /* = 0*/,
    const crypto::hash &prev_id /* = crypto::hash()*/,
    const cryptonote::difficulty_type &diffic /* = 1*/,
    const cryptonote::transaction &miner_tx /* = transaction()*/,
    const std::vector<crypto::hash> &tx_hashes /* = std::vector<crypto::hash>()*/,
    size_t txs_weight /* = 0*/,
    size_t miner_fee /*= 0*/)
{
  blk.major_version = actual_params & bf_major_ver ? major_ver : static_cast<uint8_t>(cryptonote::network_version_7);
  blk.minor_version = actual_params & bf_minor_ver ? minor_ver : static_cast<uint8_t>(cryptonote::network_version_7);
  blk.timestamp     = actual_params & bf_timestamp ? timestamp : prev_block.timestamp + tools::to_seconds(TARGET_BLOCK_TIME); // Keep difficulty unchanged
  blk.prev_id       = actual_params & bf_prev_id   ? prev_id   : get_block_hash(prev_block);
  blk.tx_hashes     = actual_params & bf_tx_hashes ? tx_hashes : std::vector<crypto::hash>();

  size_t height = get_block_height(prev_block) + 1;
  blk.height = height;
  uint64_t already_generated_coins = get_already_generated_coins(prev_block);
  std::vector<uint64_t> block_weights;
  get_last_n_block_weights(block_weights, get_block_hash(prev_block), CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  if (actual_params & bf_miner_tx)
  {
    blk.miner_tx = miner_tx;
  }
  else
  {
    // TODO: This will work, until size of constructed block is less then CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE
    cryptonote::oxen_miner_tx_context miner_tx_context = {};
    miner_tx_context.nettype                           = cryptonote::FAKECHAIN;
    manual_calc_batched_governance(*this, prev_id, miner_tx_context, m_hf_version, height);

    std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds;
    size_t current_block_weight = txs_weight + get_transaction_weight(blk.miner_tx);
    uint64_t block_rewards = 0;
    bool r;
    std::tie(r, block_rewards) = construct_miner_tx(height, epee::misc_utils::median(block_weights), already_generated_coins, current_block_weight, miner_fee, blk.miner_tx, cryptonote::oxen_miner_tx_context::miner_block(cryptonote::FAKECHAIN, miner_acc.get_keys().m_account_address), sn_rwds, cryptonote::blobdata(), m_hf_version);
    if (!r)
      return false;
  }

  //blk.tree_root_hash = get_tx_tree_hash(blk);

  cryptonote::difficulty_type a_diffic = actual_params & bf_diffic ? diffic : TEST_DEFAULT_DIFFICULTY;
  fill_nonce_with_test_generator(this, blk, a_diffic, height);

  add_block(blk, txs_weight, block_weights, already_generated_coins);

  return true;
}

bool test_generator::construct_block_manually_tx(cryptonote::block& blk, const cryptonote::block& prev_block,
                                                 const cryptonote::account_base& miner_acc,
                                                 const std::vector<crypto::hash>& tx_hashes, size_t txs_weight)
{
  return construct_block_manually(blk, prev_block, miner_acc, bf_tx_hashes, 0, 0, 0, crypto::hash(), 0, cryptonote::transaction(), tx_hashes, txs_weight, 0);
}

cryptonote::transaction make_registration_tx(std::vector<test_event_entry>& events,
                                             const cryptonote::account_base& account,
                                             const cryptonote::keypair& service_node_keys,
                                             uint64_t operator_cut,
                                             const std::vector<cryptonote::account_public_address>& contributors,
                                             const std::vector<uint64_t>& portions,
                                             const cryptonote::block& head,
                                             uint8_t hf_version)
{
  const auto new_height          = cryptonote::get_block_height(head) + 1;
  const auto staking_requirement = service_nodes::get_staking_requirement(cryptonote::FAKECHAIN, new_height);
  uint64_t amount                = service_nodes::portions_to_amount(portions[0], staking_requirement);

  cryptonote::transaction tx;
  uint64_t unlock_time = 0;
  if (hf_version < cryptonote::network_version_11_infinite_staking)
    unlock_time = new_height + service_nodes::staking_num_lock_blocks(cryptonote::FAKECHAIN);

  std::vector<uint8_t> extra;
  cryptonote::add_service_node_pubkey_to_tx_extra(extra, service_node_keys.pub);
  const uint64_t exp_timestamp = time(nullptr) + STAKING_AUTHORIZATION_EXPIRATION_WINDOW;

  crypto::hash hash;
  if (!cryptonote::get_registration_hash(contributors, operator_cut, portions, exp_timestamp, hash))
  {
    MERROR("Could not make registration hash from addresses and portions");
    return {};
  }

  crypto::signature signature;
  crypto::generate_signature(hash, service_node_keys.pub, service_node_keys.sec, signature);
  add_service_node_register_to_tx_extra(extra, contributors, operator_cut, portions, exp_timestamp, signature);
  add_service_node_contributor_to_tx_extra(extra, contributors.at(0));

  cryptonote::txtype tx_type = cryptonote::txtype::standard;
  if (hf_version >= cryptonote::network_version_15_ons) tx_type = cryptonote::txtype::stake; // NOTE: txtype stake was not introduced until HF14
  oxen_tx_builder(events, tx, head, account, account.get_keys().m_account_address, amount, hf_version).with_tx_type(tx_type).with_extra(extra).with_unlock_time(unlock_time).build();
  events.push_back(tx);
  return tx;
}

namespace
{
  uint64_t get_inputs_amount(const std::vector<cryptonote::tx_source_entry> &s)
  {
    uint64_t r = 0;
    for (const cryptonote::tx_source_entry &e : s)
    {
      r += e.amount;
    }

    return r;
  }
}

uint64_t get_amount(const cryptonote::account_base& account, const cryptonote::transaction& tx, rct::key& mask, int i)
{
  crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
  crypto::key_derivation derivation;
  if (!crypto::generate_key_derivation(tx_pub_key, account.get_keys().m_view_secret_key, derivation))
    return 0;

  if (!std::holds_alternative<cryptonote::txout_to_key>(tx.vout[i].target))
    return 0;

  hw::device& hwdev = hw::get_device("default");

  uint64_t money_transferred = 0;

  crypto::secret_key scalar1;
  hwdev.derivation_to_scalar(derivation, i, scalar1);
  try
  {
    if (rct::is_rct_simple(tx.rct_signatures.type))
      money_transferred = rct::decodeRctSimple(tx.rct_signatures, rct::sk2rct(scalar1), i, mask, hwdev);
    else if (tx.rct_signatures.type == rct::RCTType::Full)
      money_transferred = rct::decodeRct(tx.rct_signatures, rct::sk2rct(scalar1), i, hwdev);
    else if (tx.rct_signatures.type == rct::RCTType::Null)
      money_transferred = tx.vout[i].amount;
    else {
      LOG_PRINT_L0(__func__ << ": Unsupported rct type: " << (int)tx.rct_signatures.type);
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    LOG_PRINT_L0("Failed to decode input " << i << ": " << e.what());
    return 0;
  }

  return money_transferred;
}

uint64_t get_amount(const cryptonote::account_base& account, const cryptonote::transaction& tx, int i)
{
  rct::key mask_unused;
  return get_amount(account, tx, mask_unused, i);
}

bool init_output_indices(std::vector<output_index>& outs, std::vector<size_t>& outs_mine, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, const cryptonote::account_base& from) {

    for (const cryptonote::block& blk : blockchain) {
        std::vector<const cryptonote::transaction*> vtx;
        vtx.push_back(&blk.miner_tx);

        for(const crypto::hash &h : blk.tx_hashes) {
            const auto cit = mtx.find(h);
            if (mtx.end() == cit)
                throw std::runtime_error("block contains an unknown tx hash");

            vtx.push_back(cit->second);
        }

        for (size_t i = 0; i < vtx.size(); i++) {
            const cryptonote::transaction &tx = *vtx[i];

            for (size_t j = 0; j < tx.vout.size(); ++j) {
                const cryptonote::tx_out &out = tx.vout[j];

                if (std::holds_alternative<cryptonote::txout_to_key>(out.target)) {

                    const auto height = var::get<cryptonote::txin_gen>(blk.miner_tx.vin.front()).height;

                    output_index oi(out.target, out.amount, height, i, j, &blk, vtx[i]);
                    oi.unlock_time            = (tx.version < cryptonote::txversion::v3_per_output_unlock_times) ? tx.unlock_time : tx.output_unlock_times[j];
                    oi.idx                    = outs.size();
                    oi.mask                   = rct::zeroCommit(out.amount);
                    oi.is_coin_base           = (i == 0);
                    oi.deterministic_key_pair = false;
                    oi.set_rct(tx.version >= cryptonote::txversion::v2_ringct);

                    const auto gov_key          = cryptonote::get_deterministic_keypair_from_height(height);
                    bool account_received_money = is_out_to_acc(from.get_keys(), var::get<cryptonote::txout_to_key>(out.target), gov_key.pub, {}, j);
                    if (account_received_money)
                      oi.deterministic_key_pair = true;

                    if (!account_received_money)
                      account_received_money = is_out_to_acc(from.get_keys(), var::get<cryptonote::txout_to_key>(out.target), cryptonote::get_tx_pub_key_from_extra(tx), cryptonote::get_additional_tx_pub_keys_from_extra(tx), j);

                    if (account_received_money)
                    {
                        outs_mine.push_back(oi.idx);
                        if (oi.amount == 0)
                        {
                          assert(oi.is_coin_base == false);
                          oi.amount = get_amount(from, tx, j);
                          oi.mask   = tx.rct_signatures.outPk[j].mask;
                        }
                    }
                    outs.push_back(oi);
                }
            }
        }
    }

    return true;
}

bool init_spent_output_indices(std::vector<output_index>& outs,
                               const std::vector<size_t>& outs_mine,
                               const std::vector<cryptonote::block>& blockchain,
                               const map_hash2tx_t& mtx,
                               const cryptonote::account_base& from)
{

    if (mtx.empty())
    {
      // NOTE: There are no transactions, so outputs haven't been spent yet (i.e. a blockchain with strictly just rewards)
      return true;
    }

    for (size_t out_idx : outs_mine) {
        output_index& oi = outs[out_idx];

        // construct key image for this output
        crypto::key_image img;
        cryptonote::keypair in_ephemeral;
        crypto::public_key out_key = var::get<cryptonote::txout_to_key>(oi.out).key;
        std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
        subaddresses[from.get_keys().m_account_address.m_spend_public_key] = {0,0};

        const auto tx_pk = oi.deterministic_key_pair ? cryptonote::get_deterministic_keypair_from_height(oi.blk_height).pub
                                                     : get_tx_pub_key_from_extra(*oi.p_tx);

        generate_key_image_helper(from.get_keys(),
                                  subaddresses,
                                  out_key,
                                  tx_pk,
                                  get_additional_tx_pub_keys_from_extra(*oi.p_tx),
                                  oi.out_no,
                                  in_ephemeral,
                                  img,
                                  hw::get_device(("default")));

        // lookup for this key image in the events vector
        for (auto& tx_pair: mtx)
        {
            const cryptonote::transaction& tx = *tx_pair.second;
            for (const cryptonote::txin_v &in : tx.vin)
            {
              if (std::holds_alternative<cryptonote::txin_to_key>(in))
              {
                const auto &itk = var::get<cryptonote::txin_to_key>(in);
                if (itk.k_image == img)
                {
                  oi.spent = true;
                }
              }
            }
        }
    }

    return true;
}

static bool fill_output_entries(const std::vector<output_index>& out_indices, size_t sender_out, size_t nmix, size_t& real_entry_idx, std::vector<cryptonote::tx_source_entry::output_entry>& output_entries)
{
  if (out_indices.size() <= nmix)
    return false;

  bool sender_out_found = false;
  size_t rest = nmix;
  for (size_t i = 0; i < out_indices.size() && (0 < rest || !sender_out_found); ++i)
  {
    const output_index& oi = out_indices[i];
    if (oi.spent)
      continue;

    bool append = false;
    if (i == sender_out)
    {
      append = true;
      sender_out_found = true;
      real_entry_idx = output_entries.size();
    }
    else if (0 < rest)
    {
      --rest;
      append = true;
    }

    if (append)
    {
      rct::key comm = oi.commitment();
      const cryptonote::txout_to_key& otk = var::get<cryptonote::txout_to_key>(oi.out);
      output_entries.push_back(cryptonote::tx_source_entry::output_entry(oi.idx, rct::ctkey({rct::pk2rct(otk.key), comm})));
    }
  }

  return 0 == rest && sender_out_found;
}

bool fill_tx_sources(std::vector<cryptonote::tx_source_entry>& sources, const std::vector<test_event_entry>& events,
                     const cryptonote::block& blk_head, const cryptonote::account_base& from, uint64_t amount, size_t nmix)
{
    /// Don't fill up sources if the amount is zero
    if (amount == 0) return true;

    std::vector<output_index> outs;
    std::vector<size_t> outs_mine;

    std::vector<cryptonote::block> blockchain;
    map_hash2tx_t mtx;
    if (!find_block_chain(events, blockchain, mtx, cryptonote::get_block_hash(blk_head)))
        return false;

    if (!init_output_indices(outs, outs_mine, blockchain, mtx, from))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, mtx, from))
        return false;

    uint64_t sources_amount = 0;
    bool sources_found = false;
    for (const size_t sender_out : outs_mine) {

        const output_index& oi = outs[sender_out];
        if (oi.spent) continue;
        if (!cryptonote::rules::is_output_unlocked(oi.unlock_time, cryptonote::get_block_height(blk_head))) continue;

        cryptonote::tx_source_entry ts;
        const auto& tx = *oi.p_tx;
        ts.amount = oi.amount;
        ts.real_output_in_tx_index = oi.out_no;
        ts.real_out_tx_key = get_tx_pub_key_from_extra(tx); // incoming tx public key
        ts.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx);
        ts.mask = rct::identity();
        ts.rct = true;

        rct::key comm = rct::zeroCommit(ts.amount);
        for(auto & ot : ts.outputs)
          ot.second.mask = comm;

        /// Filling in the mask
        {
            crypto::key_derivation derivation;
            bool r = crypto::generate_key_derivation(ts.real_out_tx_key, from.get_keys().m_view_secret_key, derivation);
            CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
            crypto::secret_key amount_key;
            crypto::derivation_to_scalar(derivation, oi.out_no, amount_key);

            if (rct::is_rct_simple(tx.rct_signatures.type))
            {
                rct::decodeRctSimple(tx.rct_signatures, rct::sk2rct(amount_key), oi.out_no, ts.mask, hw::get_device("default"));
            }
            else if (tx.rct_signatures.type == rct::RCTType::Full)
            {
                rct::decodeRct(tx.rct_signatures, rct::sk2rct(amount_key), oi.out_no, ts.mask, hw::get_device("default"));
            }
        }

        if (!fill_output_entries(outs, sender_out, nmix, ts.real_output, ts.outputs)) continue;

        sources.push_back(ts);

        sources_amount += ts.amount;

        sources_found = amount <= sources_amount;
        if (sources_found) return true;
    }

    return false;
}

bool fill_tx_destination(cryptonote::tx_destination_entry &de, const cryptonote::account_public_address &to, uint64_t amount) {
    de.addr = to;
    de.amount = amount;
    return true;
}

void fill_tx_sources_and_multi_destinations(const std::vector<test_event_entry>& events,
                                            const cryptonote::block& blk_head,
                                            const cryptonote::account_base& from,
                                            const cryptonote::account_public_address& to,
                                            uint64_t const *amount,
                                            int num_amounts,
                                            uint64_t fee,
                                            size_t nmix,
                                            std::vector<cryptonote::tx_source_entry>& sources,
                                            std::vector<cryptonote::tx_destination_entry>& destinations,
                                            bool always_add_change_ouput,
                                            uint64_t *change_amount)
{

  sources.clear();
  destinations.clear();

  uint64_t total_amount = fee;
  for (int i = 0; i < num_amounts; ++i)
    total_amount += amount[i];

  if (!fill_tx_sources(sources, events, blk_head, from, total_amount, nmix))
  {
    throw std::runtime_error("couldn't fill transaction sources");
  }

  for (int i = 0; i < num_amounts; ++i)
  {
    cryptonote::tx_destination_entry de;
    if (!fill_tx_destination(de, to, amount[i]))
      throw std::runtime_error("couldn't fill transaction destination");
    destinations.push_back(de);
  }

  cryptonote::tx_destination_entry de_change;
  uint64_t cash_back = get_inputs_amount(sources) - (total_amount);
  if (0 < cash_back || always_add_change_ouput)
  {
    if (!fill_tx_destination(de_change, from.get_keys().m_account_address, cash_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }

  if (change_amount) *change_amount = (cash_back > 0) ? cash_back : 0;
}

map_txid_output_t::iterator block_tracker::find_out(const crypto::hash &txid, size_t out)
{
  return find_out(std::make_pair(txid, out));
}

map_txid_output_t::iterator block_tracker::find_out(const output_hasher &id)
{
  return m_map_outs.find(id);
}

void block_tracker::process(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx)
{
  std::vector<const cryptonote::block*> blks;
  blks.reserve(blockchain.size());

  for (const cryptonote::block &blk : blockchain)
  {
    auto hsh = cryptonote::get_block_hash(blk);
    auto it = m_blocks.find(hsh);
    if (it == m_blocks.end()){
      m_blocks[hsh] = blk;
    }

    blks.push_back(&m_blocks[hsh]);
  }

  process(blks, mtx);
}

void block_tracker::process(const std::vector<const cryptonote::block*>& blockchain, const map_hash2tx_t& mtx)
{
  for (const cryptonote::block *blk : blockchain)
  {
    std::vector<const cryptonote::transaction *> vtx;
    vtx.push_back(&(blk->miner_tx));

    for(const crypto::hash &h : blk->tx_hashes) {
      const map_hash2tx_t::const_iterator cit = mtx.find(h);
      CHECK_AND_ASSERT_THROW_MES(mtx.end() != cit, "block contains an unknown tx hash");
      vtx.push_back(cit->second);
    }

    for (size_t i = 0; i < vtx.size(); i++) {
      process(blk, vtx[i], i);
    }
  }
}

void block_tracker::process(const cryptonote::block *blk, const cryptonote::transaction *tx, size_t i)
{
  for (size_t j = 0; j < tx->vout.size(); ++j) {
    const cryptonote::tx_out &out = tx->vout[j];

    if (!std::holds_alternative<cryptonote::txout_to_key>(out.target)) { // out_to_key
      continue;
    }

    const uint64_t rct_amount = tx->version == cryptonote::txversion::v2_ringct ? 0 : out.amount;
    const output_hasher hid = std::make_pair(tx->hash, j);
    auto it = find_out(hid);
    if (it != m_map_outs.end()){
      continue;
    }

    output_index oi(out.target, out.amount, var::get<cryptonote::txin_gen>(blk->miner_tx.vin.front()).height, i, j, blk, tx);
    oi.set_rct(tx->version == cryptonote::txversion::v2_ringct); oi.idx = m_outs[rct_amount].size();
    oi.unlock_time = tx->unlock_time;
    oi.is_coin_base = tx->vin.size() == 1 && std::holds_alternative<cryptonote::txin_gen>(tx->vin.back());

    m_outs[rct_amount].push_back(oi);
    m_map_outs.insert({hid, oi});
  }
}

void block_tracker::global_indices(const cryptonote::transaction *tx, std::vector<uint64_t> &indices)
{
  indices.clear();

  for(size_t j=0; j < tx->vout.size(); ++j){
    auto it = find_out(tx->hash, j);
    if (it != m_map_outs.end()){
      indices.push_back(it->second.idx);
    }
  }
}

void block_tracker::get_fake_outs(size_t num_outs, uint64_t amount, uint64_t global_index, uint64_t cur_height, std::vector<get_outs_entry> &outs){
  auto & vct = m_outs[amount];
  const size_t n_outs = vct.size();
  CHECK_AND_ASSERT_THROW_MES(n_outs > 0, "n_outs is 0");

  std::set<size_t> used;
  std::vector<size_t> choices;
  choices.resize(n_outs);
  for(size_t i=0; i < n_outs; ++i) choices[i] = i;
  shuffle(choices.begin(), choices.end(), std::default_random_engine(crypto::rand<unsigned>()));

  size_t n_iters = 0;
  ssize_t idx = -1;
  outs.reserve(num_outs);
  while(outs.size() < num_outs){
    n_iters += 1;
    idx = (idx + 1) % n_outs;
    size_t oi_idx = choices[(size_t)idx];
    CHECK_AND_ASSERT_THROW_MES((n_iters / n_outs) <= outs.size(), "Fake out pick selection problem");

    auto & oi = vct[oi_idx];
    if (oi.idx == global_index)
      continue;
    if (!std::holds_alternative<cryptonote::txout_to_key>(oi.out))
      continue;
    if (oi.unlock_time > cur_height)
      continue;
    if (used.find(oi_idx) != used.end())
      continue;

    rct::key comm = oi.commitment();
    auto out = var::get<cryptonote::txout_to_key>(oi.out);
    auto item = std::make_tuple(oi.idx, out.key, comm);
    outs.push_back(item);
    used.insert(oi_idx);
  }
}

std::string block_tracker::dump_data()
{
  std::ostringstream ss;
  for (auto &m_out : m_outs)
  {
    auto & vct = m_out.second;
    ss << m_out.first << " => |vector| = " << vct.size() << '\n';

    for (const auto & oi : vct)
    {
      auto out = var::get<cryptonote::txout_to_key>(oi.out);

      ss << "    idx: " << oi.idx
      << ", rct: " << oi.rct
      << ", xmr: " << oi.amount
      << ", key: " << dump_keys(out.key.data)
      << ", msk: " << dump_keys(oi.comm.bytes)
      << ", txid: " << dump_keys(oi.p_tx->hash.data)
      << '\n';
    }
  }

  return ss.str();
}

void block_tracker::dump_data(const std::string & fname)
{
  std::ofstream myfile;
  myfile.open (fname);
  myfile << dump_data();
  myfile.close();
}

std::string dump_data(const cryptonote::transaction &tx)
{
  std::ostringstream ss;
  ss << "msg: " << dump_keys(tx.rct_signatures.message.bytes)
     << ", vin: ";

  for(auto & in : tx.vin){
    if (std::holds_alternative<cryptonote::txin_to_key>(in)){
      auto tk = var::get<cryptonote::txin_to_key>(in);
      std::vector<uint64_t> full_off;
      int64_t last = -1;

      ss << " i: " << tk.amount << " [";
      for(auto ix : tk.key_offsets){
        ss << ix << ", ";
        if (last == -1){
          last = ix;
          full_off.push_back(ix);
        } else {
          last += ix;
          full_off.push_back((uint64_t)last);
        }
      }

      ss << "], full: [";
      for(auto ix : full_off){
        ss << ix << ", ";
      }
      ss << "]; ";

    } else if (std::holds_alternative<cryptonote::txin_gen>(in)){
      ss << " h: " << var::get<cryptonote::txin_gen>(in).height << ", ";
    } else {
      ss << " ?, ";
    }
  }

  ss << ", mixring: \n";
  for (const auto & row : tx.rct_signatures.mixRing){
    for(auto cur : row){
      ss << "    (" << dump_keys(cur.dest.bytes) << ", " << dump_keys(cur.mask.bytes) << ")\n ";
    }
    ss << "; ";
  }

  return ss.str();
}

cryptonote::account_public_address get_address(const var_addr_t& inp)
{
  if (std::holds_alternative<cryptonote::account_public_address>(inp)){
    return var::get<cryptonote::account_public_address>(inp);
  } else if (std::holds_alternative<cryptonote::account_keys>(inp)){
    return var::get<cryptonote::account_keys>(inp).m_account_address;
  } else if (std::holds_alternative<cryptonote::account_base>(inp)){
    return var::get<cryptonote::account_base>(inp).get_keys().m_account_address;
  } else if (std::holds_alternative<cryptonote::tx_destination_entry>(inp)){
    return var::get<cryptonote::tx_destination_entry>(inp).addr;
  } else {
    throw std::runtime_error("Unexpected type");
  }
}

uint64_t sum_amount(const std::vector<cryptonote::tx_destination_entry>& destinations)
{
  uint64_t amount = 0;
  for(auto & cur : destinations){
    amount += cur.amount;
  }

  return amount;
}

uint64_t sum_amount(const std::vector<cryptonote::tx_source_entry>& sources)
{
  uint64_t amount = 0;
  for(auto & cur : sources){
    amount += cur.amount;
  }

  return amount;
}

void fill_tx_destinations(const var_addr_t& from, const std::vector<cryptonote::tx_destination_entry>& dests,
                          uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations,
                          bool always_change)

{
  destinations.clear();
  uint64_t amount = sum_amount(dests);
  std::copy(dests.begin(), dests.end(), std::back_inserter(destinations));

  cryptonote::tx_destination_entry de_change;
  uint64_t cash_back = get_inputs_amount(sources) - (amount + fee);

  if (cash_back > 0 || always_change) {
    if (!fill_tx_destination(de_change, get_address(from), cash_back <= 0 ? 0 : cash_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations,
                          std::vector<cryptonote::tx_destination_entry>& destinations_pure,
                          bool always_change)
{
  destinations.clear();

  cryptonote::tx_destination_entry de;
  if (!fill_tx_destination(de, to, amount))
    throw std::runtime_error("couldn't fill transaction destination");
  destinations.push_back(de);
  destinations_pure.push_back(de);

  cryptonote::tx_destination_entry de_change;
  uint64_t cash_back = get_inputs_amount(sources) - (amount + fee);

  if (cash_back > 0 || always_change) {
    if (!fill_tx_destination(de_change, get_address(from), cash_back <= 0 ? 0 : cash_back))
      throw std::runtime_error("couldn't fill transaction cache back destination");
    destinations.push_back(de_change);
  }
}

void fill_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const cryptonote::block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_public_address& to,
                                      uint64_t amount, uint64_t fee, size_t nmix, std::vector<cryptonote::tx_source_entry>& sources,
                                      std::vector<cryptonote::tx_destination_entry>& destinations, uint64_t *change_amount)
{
  uint64_t *amounts = &amount;
  int num_amounts   = 1;
  fill_tx_sources_and_multi_destinations(events, blk_head, from, to, amounts, num_amounts, fee, nmix, sources, destinations, true /*always_add_change_output*/, change_amount);
}

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations, bool always_change)
{
  std::vector<cryptonote::tx_destination_entry> destinations_pure;
  fill_tx_destinations(from, to, amount, fee, sources, destinations, destinations_pure, always_change);
}

cryptonote::tx_destination_entry build_dst(const var_addr_t& to, bool is_subaddr, uint64_t amount)
{
  cryptonote::tx_destination_entry de;
  de.amount = amount;
  de.addr = get_address(to);
  de.is_subaddress = is_subaddr;
  return de;
}

std::vector<cryptonote::tx_destination_entry> build_dsts(const var_addr_t& to1, bool sub1, uint64_t am1)
{
  std::vector<cryptonote::tx_destination_entry> res;
  res.push_back(build_dst(to1, sub1, am1));
  return res;
}

std::vector<cryptonote::tx_destination_entry> build_dsts(std::initializer_list<dest_wrapper_t> inps)
{
  std::vector<cryptonote::tx_destination_entry> res;
  res.reserve(inps.size());
  for(auto & c : inps){
    res.push_back(build_dst(c.addr, c.is_subaddr, c.amount));
  }
  return res;
}

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const cryptonote::block& blk_head,
                         const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         uint64_t fee, size_t nmix, rct::RangeProofType range_proof_type, int bp_version)
{
  std::vector<cryptonote::tx_source_entry> sources;
  std::vector<cryptonote::tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(events, blk_head, from, get_address(to), amount, fee, nmix, sources, destinations);

  cryptonote::tx_destination_entry change_addr;
  return construct_tx_rct(from.get_keys(), sources, destinations, change_addr, std::vector<uint8_t>(), tx, 0, range_proof_type, bp_version);
}

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const cryptonote::block& blk_head,
                         const cryptonote::account_base& from, std::vector<cryptonote::tx_destination_entry> destinations,
                         uint64_t fee, size_t nmix, rct::RangeProofType range_proof_type, int bp_version)
{
  std::vector<cryptonote::tx_source_entry> sources;
  std::vector<cryptonote::tx_destination_entry> destinations_all;
  uint64_t amount = sum_amount(destinations);

  if (!fill_tx_sources(sources, events, blk_head, from, amount + fee, nmix))
  {
    throw std::runtime_error("couldn't fill transaction sources");
  }

  fill_tx_destinations(from, destinations, fee, sources, destinations_all, true);

  cryptonote::tx_destination_entry change_addr;
  return construct_tx_rct(from.get_keys(), sources, destinations_all, change_addr, std::vector<uint8_t>(), tx, 0, range_proof_type, bp_version);
}

bool construct_tx_to_key(cryptonote::transaction& tx,
                         const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, rct::RangeProofType range_proof_type, int bp_version)
{
  cryptonote::tx_destination_entry change_addr;
  std::vector<cryptonote::tx_destination_entry> destinations;
  fill_tx_destinations(from, get_address(to), amount, fee, sources, destinations);
  return construct_tx_rct(from.get_keys(), sources, destinations, change_addr, std::vector<uint8_t>(), tx, 0, range_proof_type, bp_version);
}

bool construct_tx_to_key(cryptonote::transaction& tx,
                         const cryptonote::account_base& from,
                         const std::vector<cryptonote::tx_destination_entry>& destinations,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, rct::RangeProofType range_proof_type, int bp_version)
{
  cryptonote::tx_destination_entry change_addr;
  std::vector<cryptonote::tx_destination_entry> all_destinations;
  fill_tx_destinations(from, destinations, fee, sources, all_destinations, true);
  return construct_tx_rct(from.get_keys(), sources, all_destinations, change_addr, std::vector<uint8_t>(), tx, 0, range_proof_type, bp_version);
}

bool construct_tx_rct(const cryptonote::account_keys& sender_account_keys, std::vector<cryptonote::tx_source_entry>& sources, const std::vector<cryptonote::tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, std::vector<uint8_t> extra, cryptonote::transaction& tx, uint64_t unlock_time, rct::RangeProofType range_proof_type, int bp_version)
{
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0, 0};
  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  std::vector<cryptonote::tx_destination_entry> destinations_copy = destinations;
  rct::RCTConfig rct_config = {range_proof_type, bp_version};
  return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct_config, nullptr);
}

cryptonote::transaction construct_tx_with_fee(std::vector<test_event_entry> &events,
                                              const cryptonote::block &blk_head,
                                              const cryptonote::account_base &acc_from,
                                              const cryptonote::account_base &acc_to,
                                              uint64_t amount,
                                              uint64_t fee)
{
  cryptonote::transaction tx;
  oxen_tx_builder(events, tx, blk_head, acc_from, acc_to.get_keys().m_account_address, amount, cryptonote::network_version_7).with_fee(fee).build();
  events.push_back(tx);
  return tx;
}

uint64_t get_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {
    uint64_t res = 0;
    std::vector<output_index> outs;
    std::vector<size_t> outs_mine;

    map_hash2tx_t confirmed_txs;
    get_confirmed_txs(blockchain, mtx, confirmed_txs);

    if (!init_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    for (const size_t out_idx : outs_mine) {
            if (outs[out_idx].spent) continue;
            res += outs[out_idx].amount;
    }

    return res;
}

uint64_t get_unlocked_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx) {

    if (blockchain.empty()) return 0;

    uint64_t res = 0;
    std::vector<output_index> outs;
    std::vector<size_t> outs_mine;

    map_hash2tx_t confirmed_txs;
    get_confirmed_txs(blockchain, mtx, confirmed_txs);

    if (!init_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    if (!init_spent_output_indices(outs, outs_mine, blockchain, confirmed_txs, addr))
        return false;

    for (const size_t out_idx : outs_mine) {
        const auto unlocked = cryptonote::rules::is_output_unlocked(outs[out_idx].unlock_time, get_block_height(blockchain.back()));
        if (outs[out_idx].spent || !unlocked) continue;
        res += outs[out_idx].amount;
    }

    return res;
}

bool extract_hard_forks(const std::vector<test_event_entry>& events, std::vector<cryptonote::hard_fork>& hard_forks)
{
  for(auto & ev : events)
  {
    if (std::holds_alternative<event_replay_settings>(ev))
    {
      const auto & rep_settings = var::get<event_replay_settings>(ev);
      if (rep_settings.hard_forks)
      {
        const auto & hf = *rep_settings.hard_forks;
        std::copy(hf.begin(), hf.end(), std::back_inserter(hard_forks));
      }
    }
  }

  return !hard_forks.empty();
}

void get_confirmed_txs(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, map_hash2tx_t& confirmed_txs)
{
  std::unordered_set<crypto::hash> confirmed_hashes;
  for (const auto& blk : blockchain)
  {
    for (const auto& tx_hash : blk.tx_hashes)
    {
      confirmed_hashes.insert(tx_hash);
    }
  }

  for (const auto& tx_pair : mtx)
  {
    if (0 != confirmed_hashes.count(tx_pair.first))
    {
      confirmed_txs.insert(tx_pair);
    }
  }
}

bool trim_block_chain(std::vector<cryptonote::block>& blockchain, const crypto::hash& tail){
  size_t cut = 0;
  bool found = true;

  for(size_t i = 0; i < blockchain.size(); ++i){
    crypto::hash chash = get_block_hash(blockchain[i]);
    if (chash == tail){
      cut = i;
      found = true;
      break;
    }
  }

  if (found && cut > 0){
    blockchain.erase(blockchain.begin(), blockchain.begin() + cut);
  }

  return found;
}

bool trim_block_chain(std::vector<const cryptonote::block*>& blockchain, const crypto::hash& tail){
  size_t cut = 0;
  bool found = true;

  for(size_t i = 0; i < blockchain.size(); ++i){
    crypto::hash chash = get_block_hash(*blockchain[i]);
    if (chash == tail){
      cut = i;
      found = true;
      break;
    }
  }

  if (found && cut > 0){
    blockchain.erase(blockchain.begin(), blockchain.begin() + cut);
  }

  return found;
}

uint64_t num_blocks(const std::vector<test_event_entry>& events)
{
  uint64_t res = 0;
  for (const test_event_entry& ev : events)
  {
    if (std::holds_alternative<cryptonote::block>(ev))
    {
      res += 1;
    }
  }

  return res;
}

cryptonote::block get_head_block(const std::vector<test_event_entry>& events)
{
  for(auto it = events.rbegin(); it != events.rend(); ++it)
  {
    auto &ev = *it;
    if (std::holds_alternative<cryptonote::block>(ev))
    {
      return var::get<cryptonote::block>(ev);
    }
  }

  throw std::runtime_error("No block event");
}

bool find_block_chain(const std::vector<test_event_entry> &events, std::vector<cryptonote::block> &blockchain, map_hash2tx_t &mtx, const crypto::hash &head)
{
  std::unordered_map<crypto::hash, const cryptonote::block *> block_index;
  for (const test_event_entry &ev : events)
  {
    if (std::holds_alternative<cryptonote::block>(ev))
    {
      const auto *blk                   = &var::get<cryptonote::block>(ev);
      block_index[get_block_hash(*blk)] = blk;
    }
    else if (std::holds_alternative<oxen_blockchain_addable<oxen_block_with_checkpoint>>(ev))
    {
      const auto *blk                        = &var::get<oxen_blockchain_addable<oxen_block_with_checkpoint>>(ev);
      block_index[get_block_hash(blk->data.block)] = &blk->data.block;
    }
    else if (std::holds_alternative<oxen_blockchain_addable<cryptonote::block>>(ev))
    {
      const auto *blk = &var::get<oxen_blockchain_addable<cryptonote::block>>(ev);
      block_index[get_block_hash(blk->data)] = &blk->data;
    }
    else if (std::holds_alternative<cryptonote::transaction>(ev))
    {
      const auto &tx                = var::get<cryptonote::transaction>(ev);
      mtx[get_transaction_hash(tx)] = &tx;
    }
    else if (std::holds_alternative<oxen_blockchain_addable<oxen_transaction>>(ev))
    {
      const auto &entry                        = var::get<oxen_blockchain_addable<oxen_transaction>>(ev);
      mtx[get_transaction_hash(entry.data.tx)] = &entry.data.tx;
    }
  }

  bool b_success  = false;
  crypto::hash id = head;
  for (auto it = block_index.find(id); block_index.end() != it; it = block_index.find(id))
  {
    blockchain.push_back(*it->second);
    id = it->second->prev_id;
    if (crypto::null_hash == id)
    {
      b_success = true;
      break;
    }
  }
  reverse(blockchain.begin(), blockchain.end());

  return b_success;
}

bool find_block_chain(const std::vector<test_event_entry> &events, std::vector<const cryptonote::block *> &blockchain, map_hash2tx_t &mtx, const crypto::hash &head)
{
  std::unordered_map<crypto::hash, const cryptonote::block *> block_index;
  for (const test_event_entry &ev : events)
  {
    if (std::holds_alternative<cryptonote::block>(ev) ||
        std::holds_alternative<oxen_blockchain_addable<oxen_block_with_checkpoint>>(ev) ||
        std::holds_alternative<oxen_blockchain_addable<cryptonote::block>>(ev))
    {
      if (std::holds_alternative<cryptonote::block>(ev))
      {
        const auto *blk                   = &var::get<cryptonote::block>(ev);
        block_index[get_block_hash(*blk)] = blk;
      }
      else if (std::holds_alternative<oxen_blockchain_addable<oxen_block_with_checkpoint>>(ev))
      {
        const auto *blk = &var::get<oxen_blockchain_addable<oxen_block_with_checkpoint>>(ev);
        block_index[get_block_hash(blk->data.block)] = &blk->data.block;
      }
      else if (std::holds_alternative<oxen_blockchain_addable<cryptonote::block>>(ev))
      {
        const auto *blk = &var::get<oxen_blockchain_addable<cryptonote::block>>(ev);
        block_index[get_block_hash(blk->data)] = &blk->data;
      }
    }
    else if (std::holds_alternative<cryptonote::transaction>(ev) ||
             std::holds_alternative<oxen_blockchain_addable<oxen_transaction>>(ev))
    {
      if (std::holds_alternative<cryptonote::transaction>(ev))
      {
        const auto &tx                = var::get<cryptonote::transaction>(ev);
        mtx[get_transaction_hash(tx)] = &tx;
      }
      else if (std::holds_alternative<oxen_blockchain_addable<oxen_transaction>>(ev))
      {
        const auto &entry                        = var::get<oxen_blockchain_addable<oxen_transaction>>(ev);
        mtx[get_transaction_hash(entry.data.tx)] = &entry.data.tx;
      }
    }
  }

  bool b_success  = false;
  crypto::hash id = head;
  for (auto it = block_index.find(id); block_index.end() != it; it = block_index.find(id))
  {
    blockchain.push_back(it->second);
    id = it->second->prev_id;
    if (crypto::null_hash == id)
    {
      b_success = true;
      break;
    }
  }
  reverse(blockchain.begin(), blockchain.end());
  return b_success;
}


void test_chain_unit_base::register_callback(const std::string& cb_name, verify_callback cb)
{
  m_callbacks[cb_name] = cb;
}
bool test_chain_unit_base::verify(const std::string& cb_name, cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  auto cb_it = m_callbacks.find(cb_name);
  if(cb_it == m_callbacks.end())
  {
    LOG_ERROR("Failed to find callback " << cb_name);
    return false;
  }
  return cb_it->second(c, ev_index, events);
}

bool test_chain_unit_base::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/)
{
  return !bvc.m_verifivation_failed;
}

bool test_chain_unit_base::check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool /*tx_added*/, size_t /*event_index*/, const cryptonote::transaction& /*tx*/)
{
  return !tvc.m_verifivation_failed;
}

bool test_chain_unit_base::check_tx_verification_context_array(const std::vector<cryptonote::tx_verification_context>& tvcs, size_t /*tx_added*/, size_t /*event_index*/, const std::vector<cryptonote::transaction>& /*txs*/)
{
  for (const cryptonote::tx_verification_context &tvc: tvcs)
    if (tvc.m_verifivation_failed)
      return false;
  return true;
}
