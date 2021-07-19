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

#include "cryptonote_config.h"
#include "ringct/rctTypes.h"
#include <functional>
#include <algorithm>
#include <chrono>

#include <boost/endian/conversion.hpp>

extern "C" {
#include <sodium.h>
}

#include "ringct/rctSigs.h"
#include "epee/net/local_ip.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_core/uptime_proof.h"
#include "epee/int-util.h"
#include "common/scoped_message_writer.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/random.h"
#include "common/lock.h"
#include "common/hex.h"
#include "epee/misc_os_dependent.h"
#include "blockchain.h"
#include "service_node_quorum_cop.h"

#include "pulse.h"
#include "service_node_list.h"
#include "uptime_proof.h"
#include "service_node_rules.h"
#include "service_node_swarm.h"
#include "version.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "service_nodes"

namespace service_nodes
{
  size_t constexpr STORE_LONG_TERM_STATE_INTERVAL = 10000;

  constexpr auto X25519_MAP_PRUNING_INTERVAL = 5min;
  constexpr auto X25519_MAP_PRUNING_LAG = 24h;
  static_assert(X25519_MAP_PRUNING_LAG > config::UPTIME_PROOF_VALIDITY, "x25519 map pruning lag is too short!");

  static uint64_t short_term_state_cull_height(uint8_t hf_version, uint64_t block_height)
  {
    size_t constexpr DEFAULT_SHORT_TERM_STATE_HISTORY = 6 * STATE_CHANGE_TX_LIFETIME_IN_BLOCKS;
    static_assert(DEFAULT_SHORT_TERM_STATE_HISTORY >= BLOCKS_EXPECTED_IN_HOURS(12), // Arbitrary, but raises a compilation failure if it gets shortened.
        "not enough short term state storage for blink quorum retrieval!");
    uint64_t result =
        (block_height < DEFAULT_SHORT_TERM_STATE_HISTORY) ? 0 : block_height - DEFAULT_SHORT_TERM_STATE_HISTORY;
    return result;
  }

  service_node_list::service_node_list(cryptonote::Blockchain &blockchain)
  : m_blockchain(blockchain) // Warning: don't touch `blockchain`, it gets initialized *after* us
  , m_service_node_keys(nullptr)
  , m_state{this}
  {
  }

  void service_node_list::init()
  {
    std::lock_guard lock(m_sn_mutex);
    if (m_blockchain.get_network_version() < cryptonote::network_version_9_service_nodes)
    {
      reset(true);
      return;
    }

    uint64_t current_height = m_blockchain.get_current_blockchain_height();
    bool loaded = load(current_height);
    if (loaded && m_transient.old_quorum_states.size() < std::min(m_store_quorum_history, uint64_t{10})) {
      LOG_PRINT_L0("Full history storage requested, but " << m_transient.old_quorum_states.size() << " old quorum states found");
      loaded = false; // Either we don't have stored history or the history is very short, so recalculation is necessary or cheap.
    }

    if (!loaded || m_state.height > current_height)
      reset(true);
  }

  template <typename UnaryPredicate>
  static std::vector<service_nodes::pubkey_and_sninfo> sort_and_filter(const service_nodes_infos_t &sns_infos, UnaryPredicate p, bool reserve = true) {
    std::vector<pubkey_and_sninfo> result;
    if (reserve) result.reserve(sns_infos.size());
    for (const auto& key_info : sns_infos)
      if (p(*key_info.second))
        result.push_back(key_info);

    std::sort(result.begin(), result.end(),
      [](const pubkey_and_sninfo &a, const pubkey_and_sninfo &b) {
        return memcmp(reinterpret_cast<const void*>(&a), reinterpret_cast<const void*>(&b), sizeof(a)) < 0;
      });
    return result;
  }

  std::vector<pubkey_and_sninfo> service_node_list::state_t::active_service_nodes_infos() const {
    return sort_and_filter(service_nodes_infos, [](const service_node_info &info) { return info.is_active(); }, /*reserve=*/ true);
  }

  std::vector<pubkey_and_sninfo> service_node_list::state_t::decommissioned_service_nodes_infos() const {
    return sort_and_filter(service_nodes_infos, [](const service_node_info &info) { return info.is_decommissioned() && info.is_fully_funded(); }, /*reserve=*/ false);
  }

  std::shared_ptr<const quorum> service_node_list::get_quorum(quorum_type type, uint64_t height, bool include_old, std::vector<std::shared_ptr<const quorum>> *alt_quorums) const
  {
    height = offset_testing_quorum_height(type, height);
    std::lock_guard lock(m_sn_mutex);
    quorum_manager const *quorums = nullptr;
    if (height == m_state.height)
      quorums = &m_state.quorums;
    else // NOTE: Search m_transient.state_history && m_transient.state_archive
    {
      auto it = m_transient.state_history.find(height);
      if (it != m_transient.state_history.end())
        quorums = &it->quorums;

      if (!quorums)
      {
        auto it = m_transient.state_archive.find(height);
        if (it != m_transient.state_archive.end()) quorums = &it->quorums;
      }
    }

    if (!quorums && include_old) // NOTE: Search m_transient.old_quorum_states
    {
      auto it =
          std::lower_bound(m_transient.old_quorum_states.begin(),
                           m_transient.old_quorum_states.end(),
                           height,
                           [](quorums_by_height const &entry, uint64_t height) { return entry.height < height; });

      if (it != m_transient.old_quorum_states.end() && it->height == height)
        quorums = &it->quorums;
    }

    if (alt_quorums)
    {
      for (const auto& [hash, alt_state] : m_transient.alt_state)
      {
        if (alt_state.height == height)
        {
          std::shared_ptr<const quorum> alt_result = alt_state.quorums.get(type);
          if (alt_result) alt_quorums->push_back(alt_result);
        }
      }
    }

    if (!quorums)
      return nullptr;

    std::shared_ptr<const quorum> result = quorums->get(type);
    return result;
  }

  static bool get_pubkey_from_quorum(quorum const &quorum, quorum_group group, size_t quorum_index, crypto::public_key &key)
  {
    std::vector<crypto::public_key> const *array = nullptr;
    if      (group == quorum_group::validator) array = &quorum.validators;
    else if (group == quorum_group::worker)    array = &quorum.workers;
    else
    {
      MERROR("Invalid quorum group specified");
      return false;
    }

    if (quorum_index >= array->size())
    {
      MERROR("Quorum indexing out of bounds: " << quorum_index << ", quorum_size: " << array->size());
      return false;
    }

    key = (*array)[quorum_index];
    return true;
  }

  bool service_node_list::get_quorum_pubkey(quorum_type type, quorum_group group, uint64_t height, size_t quorum_index, crypto::public_key &key) const
  {
    std::shared_ptr<const quorum> quorum = get_quorum(type, height);
    if (!quorum)
    {
      LOG_PRINT_L1("Quorum for height: " << height << ", was not stored by the daemon");
      return false;
    }

    bool result = get_pubkey_from_quorum(*quorum, group, quorum_index, key);
    return result;
  }

  size_t service_node_list::get_service_node_count() const
  {
    std::lock_guard lock(m_sn_mutex);
    return m_state.service_nodes_infos.size();
  }

  std::vector<service_node_pubkey_info> service_node_list::get_service_node_list_state(const std::vector<crypto::public_key> &service_node_pubkeys) const
  {
    std::lock_guard lock(m_sn_mutex);
    std::vector<service_node_pubkey_info> result;

    if (service_node_pubkeys.empty())
    {
      result.reserve(m_state.service_nodes_infos.size());

      for (const auto &info : m_state.service_nodes_infos)
        result.emplace_back(info);
    }
    else
    {
      result.reserve(service_node_pubkeys.size());
      for (const auto &it : service_node_pubkeys)
      {
        auto find_it = m_state.service_nodes_infos.find(it);
        if (find_it != m_state.service_nodes_infos.end())
          result.emplace_back(*find_it);
      }
    }

    return result;
  }

  void service_node_list::set_my_service_node_keys(const service_node_keys *keys)
  {
    std::lock_guard lock(m_sn_mutex);
    m_service_node_keys = keys;
  }

  void service_node_list::set_quorum_history_storage(uint64_t hist_size) {
    if (hist_size == 1)
      hist_size = std::numeric_limits<uint64_t>::max();
    m_store_quorum_history = hist_size;
  }

  bool service_node_list::is_service_node(const crypto::public_key& pubkey, bool require_active) const
  {
    std::lock_guard lock(m_sn_mutex);
    auto it = m_state.service_nodes_infos.find(pubkey);
    return it != m_state.service_nodes_infos.end() && (!require_active || it->second->is_active());
  }

  bool service_node_list::is_key_image_locked(crypto::key_image const &check_image, uint64_t *unlock_height, service_node_info::contribution_t *the_locked_contribution) const
  {
    for (const auto& pubkey_info : m_state.service_nodes_infos)
    {
      const service_node_info &info = *pubkey_info.second;
      for (const service_node_info::contributor_t &contributor : info.contributors)
      {
        for (const service_node_info::contribution_t &contribution : contributor.locked_contributions)
        {
          if (check_image == contribution.key_image)
          {
            if (the_locked_contribution) *the_locked_contribution = contribution;
            if (unlock_height) *unlock_height = info.requested_unlock_height;
            return true;
          }
        }
      }
    }
    return false;
  }

  bool reg_tx_extract_fields(const cryptonote::transaction& tx, contributor_args_t &contributor_args, uint64_t& expiration_timestamp, crypto::public_key& service_node_key, crypto::signature& signature)
  {
    cryptonote::tx_extra_service_node_register registration;
    if (!get_field_from_tx_extra(tx.extra, registration))
      return false;
    if (!cryptonote::get_service_node_pubkey_from_tx_extra(tx.extra, service_node_key))
      return false;

    contributor_args.addresses.clear();
    contributor_args.addresses.reserve(registration.m_public_spend_keys.size());
    for (size_t i = 0; i < registration.m_public_spend_keys.size(); i++) {
      contributor_args.addresses.emplace_back();
      contributor_args.addresses.back().m_spend_public_key = registration.m_public_spend_keys[i];
      contributor_args.addresses.back().m_view_public_key  = registration.m_public_view_keys[i];
    }

    contributor_args.portions_for_operator = registration.m_portions_for_operator;
    contributor_args.portions              = registration.m_portions;
    contributor_args.success               = true;

    expiration_timestamp = registration.m_expiration_timestamp;
    signature            = registration.m_service_node_signature;
    return true;
  }

  uint64_t offset_testing_quorum_height(quorum_type type, uint64_t height)
  {
    uint64_t result = height;
    if (type == quorum_type::checkpointing)
    {
        if (result < REORG_SAFETY_BUFFER_BLOCKS_POST_HF12)
            return 0;
        result -= REORG_SAFETY_BUFFER_BLOCKS_POST_HF12;
    }
    return result;
  }

  void validate_contributor_args(uint8_t hf_version, contributor_args_t const &contributor_args)
  {
    if (contributor_args.portions.empty())
      throw invalid_contributions{"No portions given"};
    if (contributor_args.portions.size() != contributor_args.addresses.size())
      throw invalid_contributions{"Number of portions (" + std::to_string(contributor_args.portions.size()) + ") doesn't match the number of addresses (" + std::to_string(contributor_args.portions.size()) + ")"};
    if (contributor_args.portions.size() > MAX_NUMBER_OF_CONTRIBUTORS)
      throw invalid_contributions{"Too many contributors"};
    if (contributor_args.portions_for_operator > STAKING_PORTIONS)
      throw invalid_contributions{"Operator portions are too high"};

    if (!check_service_node_portions(hf_version, contributor_args.portions))
    {
        std::stringstream stream;
        for (size_t i = 0; i < contributor_args.portions.size(); i++)
        {
            if (i) stream << ", ";
            stream << contributor_args.portions[i];
        }
        throw invalid_contributions{"Invalid portions: {" + stream.str() + "}"};
    }
  }

  void validate_contributor_args_signature(contributor_args_t const &contributor_args, uint64_t const expiration_timestamp, crypto::public_key const &service_node_key, crypto::signature const &signature)
  {
    crypto::hash hash = {};
    if (!get_registration_hash(contributor_args.addresses, contributor_args.portions_for_operator, contributor_args.portions, expiration_timestamp, hash))
      throw invalid_contributions{"Failed to generate registration hash"};

    if (!crypto::check_key(service_node_key))
      throw invalid_contributions{"Service Node Key was not a valid crypto key" + tools::type_to_hex(service_node_key)};

    if (!crypto::check_signature(hash, service_node_key, signature))
      throw invalid_contributions{"Failed to validate service node with key:" + tools::type_to_hex(service_node_key) + " and hash: " + tools::type_to_hex(hash)};
  }

  struct parsed_tx_contribution
  {
    cryptonote::account_public_address address;
    uint64_t transferred;
    crypto::secret_key tx_key;
    std::vector<service_node_info::contribution_t> locked_contributions;
  };

  static uint64_t get_staking_output_contribution(const cryptonote::transaction& tx, int i, crypto::key_derivation const &derivation, hw::device& hwdev)
  {
    if (!std::holds_alternative<cryptonote::txout_to_key>(tx.vout[i].target))
    {
      return 0;
    }

    rct::key mask;
    uint64_t money_transferred = 0;

    crypto::secret_key scalar1;
    hwdev.derivation_to_scalar(derivation, i, scalar1);
    try
    {
      switch (tx.rct_signatures.type)
      {
          case rct::RCTType::Simple:
          case rct::RCTType::Bulletproof:
          case rct::RCTType::Bulletproof2:
          case rct::RCTType::CLSAG:
              money_transferred = rct::decodeRctSimple(tx.rct_signatures, rct::sk2rct(scalar1), i, mask, hwdev);
              break;
          case rct::RCTType::Full:
              money_transferred = rct::decodeRct(tx.rct_signatures, rct::sk2rct(scalar1), i, mask, hwdev);
              break;
          default:
              LOG_PRINT_L0(__func__ << ": Unsupported rct type: " << (int)tx.rct_signatures.type);
              return 0;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decode input " << i);
      return 0;
    }

    return money_transferred;
  }

  bool tx_get_staking_components(cryptonote::transaction_prefix const &tx, staking_components *contribution, crypto::hash const &txid)
  {
    staking_components contribution_unused_ = {};
    if (!contribution) contribution = &contribution_unused_;
    if (!cryptonote::get_service_node_pubkey_from_tx_extra(tx.extra, contribution->service_node_pubkey))
      return false; // Is not a contribution TX don't need to check it.

    if (!cryptonote::get_service_node_contributor_from_tx_extra(tx.extra, contribution->address))
      return false;

    if (!cryptonote::get_tx_secret_key_from_tx_extra(tx.extra, contribution->tx_key))
    {
      LOG_PRINT_L1("TX: There was a service node contributor but no secret key in the tx extra for tx: " << txid);
      return false;
    }

    return true;
  }

  bool tx_get_staking_components(cryptonote::transaction const &tx, staking_components *contribution)
  {
      bool result = tx_get_staking_components(tx, contribution, cryptonote::get_transaction_hash(tx));
      return result;
  }

  bool tx_get_staking_components_and_amounts(cryptonote::network_type nettype,
                                             uint8_t hf_version,
                                             cryptonote::transaction const &tx,
                                             uint64_t block_height,
                                             staking_components *contribution)
  {
    staking_components contribution_unused_ = {};
    if (!contribution) contribution = &contribution_unused_;

    if (!tx_get_staking_components(tx, contribution))
      return false;

    // A cryptonote transaction is constructed as follows
    // P = Hs(aR)G + B

    // P := Stealth Address
    // a := Receiver's secret view key
    // B := Receiver's public spend key
    // R := TX Public Key
    // G := Elliptic Curve

    // In Loki we pack into the tx extra information to reveal information about the TX
    // A := Public View Key (we pack contributor into tx extra, 'parsed_contribution.address')
    // r := TX Secret Key   (we pack secret key into tx extra,  'parsed_contribution.tx_key`)

    // Calulate 'Derivation := Hs(Ar)G'
    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(contribution->address.m_view_public_key, contribution->tx_key, derivation))
    {
      LOG_PRINT_L1("TX: Failed to generate key derivation on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    hw::device &hwdev         = hw::get_device("default");
    contribution->transferred = 0;
    bool stake_decoded        = true;
    if (hf_version >= cryptonote::network_version_11_infinite_staking)
    {
      // In Infinite Staking, we lock the key image that would be generated if
      // you tried to send your stake and prevent it from being transacted on
      // the network whilst you are a Service Node. To do this, we calculate
      // the future key image that would be generated when they user tries to
      // spend the staked funds. A key image is derived from the ephemeral, one
      // time transaction private key, 'x' in the Cryptonote Whitepaper.

      // This is only possible to generate if they are the staking to themselves
      // as you need the recipients private keys to generate the key image that
      // would be generated, when they want to spend it in the future.

      cryptonote::tx_extra_tx_key_image_proofs key_image_proofs;
      if (!get_field_from_tx_extra(tx.extra, key_image_proofs))
      {
        LOG_PRINT_L1("TX: Didn't have key image proofs in the tx_extra, rejected on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
        stake_decoded = false;
      }

      for (size_t output_index = 0; stake_decoded && output_index < tx.vout.size(); ++output_index)
      {
        uint64_t transferred = get_staking_output_contribution(tx, output_index, derivation, hwdev);
        if (transferred == 0)
          continue;

        // So prove that the destination stealth address can be decoded using the
        // staker's packed address, which means that the recipient of the
        // contribution is themselves (and hence they have the necessary secrets
        // to generate the future key image).

        // i.e Verify the packed information is valid by computing the stealth
        // address P' (which should equal P if matching) using

        // 'Derivation := Hs(Ar)G' (we calculated earlier) instead of 'Hs(aR)G'
        // P' = Hs(Ar)G + B
        //    = Hs(aR)G + B
        //    = Derivation + B
        //    = P

        crypto::public_key ephemeral_pub_key;
        {
          // P' := Derivation + B
          if (!hwdev.derive_public_key(derivation, output_index, contribution->address.m_spend_public_key, ephemeral_pub_key))
          {
            LOG_PRINT_L1("TX: Could not derive TX ephemeral key on height: " << block_height << " for tx: " << get_transaction_hash(tx) << " for output: " << output_index);
            continue;
          }

          // Stealth address public key should match the public key referenced in the TX only if valid information is given.
          const auto& out_to_key = var::get<cryptonote::txout_to_key>(tx.vout[output_index].target);
          if (out_to_key.key != ephemeral_pub_key)
          {
            LOG_PRINT_L1("TX: Derived TX ephemeral key did not match tx stored key on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx) << " for output: " << output_index);
            continue;
          }
        }

        // To prevent the staker locking any arbitrary key image, the provided
        // key image is included and verified in a ring signature which
        // guarantees that 'the staker proves that he knows such 'x' (one time
        // ephemeral secret key) and that (the future key image) P = xG'.
        // Consequently the key image is not falsified and actually the future
        // key image.

        // The signer can try falsify the key image, but the equation used to
        // construct the key image is re-derived by the verifier, false key
        // images will not match the re-derived key image.
        for (auto proof = key_image_proofs.proofs.begin(); proof != key_image_proofs.proofs.end(); proof++)
        {
          if (!crypto::check_key_image_signature(proof->key_image, ephemeral_pub_key, proof->signature))
            continue;

          contribution->locked_contributions.emplace_back(service_node_info::contribution_t::version_t::v0, ephemeral_pub_key, proof->key_image, transferred);
          contribution->transferred += transferred;
          key_image_proofs.proofs.erase(proof);
          break;
        }
      }
    }

    if (hf_version < cryptonote::network_version_11_infinite_staking)
    {
      // Pre Infinite Staking, we only need to prove the amount sent is
      // sufficient to become a contributor to the Service Node and that there
      // is sufficient lock time on the staking output.
      for (size_t i = 0; i < tx.vout.size(); i++)
      {
        bool has_correct_unlock_time = false;
        {
          uint64_t unlock_time = tx.unlock_time;
          if (tx.version >= cryptonote::txversion::v3_per_output_unlock_times)
            unlock_time = tx.output_unlock_times[i];

          uint64_t min_height = block_height + staking_num_lock_blocks(nettype);
          has_correct_unlock_time = unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER && unlock_time >= min_height;
        }

        if (has_correct_unlock_time)
        {
          contribution->transferred += get_staking_output_contribution(tx, i, derivation, hwdev);
          stake_decoded = true;
        }
      }
    }

    return stake_decoded;
  }

  /// Makes a copy of the given service_node_info and replaces the shared_ptr with a pointer to the copy.
  /// Returns the non-const service_node_info (which is now held by the passed-in shared_ptr lvalue ref).
  static service_node_info &duplicate_info(std::shared_ptr<const service_node_info> &info_ptr) {
    auto new_ptr = std::make_shared<service_node_info>(*info_ptr);
    info_ptr = new_ptr;
    return *new_ptr;
  }

  bool service_node_list::state_t::process_state_change_tx(state_set const &state_history,
                                                           state_set const &state_archive,
                                                           std::unordered_map<crypto::hash, state_t> const &alt_states,
                                                           cryptonote::network_type nettype,
                                                           const cryptonote::block &block,
                                                           const cryptonote::transaction &tx,
                                                           const service_node_keys *my_keys)
  {
    if (tx.type != cryptonote::txtype::state_change)
      return false;

    uint8_t const hf_version = block.major_version;
    cryptonote::tx_extra_service_node_state_change state_change;
    if (!cryptonote::get_service_node_state_change_from_tx_extra(tx.extra, state_change, hf_version))
    {
      MERROR("Transaction: " << cryptonote::get_transaction_hash(tx) << ", did not have valid state change data in tx extra rejecting malformed tx");
      return false;
    }

    auto it = state_history.find(state_change.block_height);
    if (it == state_history.end())
    {
      it = state_archive.find(state_change.block_height);
      if (it == state_archive.end())
      {
        MERROR("Transaction: " << cryptonote::get_transaction_hash(tx) << " in block "
                               << cryptonote::get_block_height(block) << " " << cryptonote::get_block_hash(block)
                               << " references quorum height " << state_change.block_height
                               << " but that height is not stored!");
        return false;
      }
    }

    quorum_manager const *quorums = &it->quorums;
    cryptonote::tx_verification_context tvc = {};
    if (!verify_tx_state_change(
            state_change, cryptonote::get_block_height(block), tvc, *quorums->obligations, hf_version))
    {
      quorums = nullptr;
      for (const auto& [hash, alt_state] : alt_states)
      {
        if (alt_state.height != state_change.block_height) continue;

        quorums = &alt_state.quorums;
        if (!verify_tx_state_change(state_change, cryptonote::get_block_height(block), tvc, *quorums->obligations, hf_version))
        {
          quorums = nullptr;
          continue;
        }
      }
    }

    if (!quorums)
    {
      MERROR("Could not get a quorum that could completely validate the votes from state change in tx: " << get_transaction_hash(tx) << ", skipping transaction");
      return false;
    }

    crypto::public_key key;
    if (!get_pubkey_from_quorum(*quorums->obligations, quorum_group::worker, state_change.service_node_index, key))
    {
      MERROR("Retrieving the public key from state change in tx: " << cryptonote::get_transaction_hash(tx) << " failed");
      return false;
    }

    auto iter = service_nodes_infos.find(key);
    if (iter == service_nodes_infos.end()) {
      LOG_PRINT_L2("Received state change tx for non-registered service node " << key << " (perhaps a delayed tx?)");
      return false;
    }

    uint64_t block_height = cryptonote::get_block_height(block);
    auto &info = duplicate_info(iter->second);
    bool is_me = my_keys && my_keys->pub == key;

    switch (state_change.state) {
      case new_state::deregister:
        if (is_me)
          MGINFO_RED("Deregistration for service node (yours): " << key);
        else
          LOG_PRINT_L1("Deregistration for service node: " << key);

        if (hf_version >= cryptonote::network_version_11_infinite_staking)
        {
          for (const auto &contributor : info.contributors)
          {
            for (const auto &contribution : contributor.locked_contributions)
            {
              key_image_blacklist.emplace_back(); // NOTE: Use default value for version in key_image_blacklist_entry
              key_image_blacklist_entry &entry = key_image_blacklist.back();
              entry.key_image                  = contribution.key_image;
              entry.unlock_height              = block_height + staking_num_lock_blocks(nettype);
              entry.amount                     = contribution.amount;
            }
          }
        }

        service_nodes_infos.erase(iter);
        return true;

      case new_state::decommission:
        if (hf_version < cryptonote::network_version_12_checkpointing) {
          MERROR("Invalid decommission transaction seen before network v12");
          return false;
        }

        if (info.is_decommissioned()) {
          LOG_PRINT_L2("Received decommission tx for already-decommissioned service node " << key << "; ignoring");
          return false;
        }

        if (is_me)
          MGINFO_RED("Temporary decommission for service node (yours): " << key);
        else
          LOG_PRINT_L1("Temporary decommission for service node: " << key);

        info.active_since_height = -info.active_since_height;
        info.last_decommission_height = block_height;
        info.last_decommission_reason_consensus_all = state_change.reason_consensus_all;
        info.last_decommission_reason_consensus_any = state_change.reason_consensus_any;
        info.decommission_count++;

        if (hf_version >= cryptonote::network_version_13_enforce_checkpoints) {
          // Assigning invalid swarm id effectively kicks the node off
          // its current swarm; it will be assigned a new swarm id when it
          // gets recommissioned. Prior to HF13 this step was incorrectly
          // skipped.
          info.swarm_id = UNASSIGNED_SWARM_ID;
        }

        if (sn_list && !sn_list->m_rescanning)
        {
          auto &proof = sn_list->proofs[key];
          proof.timestamp = proof.effective_timestamp = 0;
          proof.store(key, sn_list->m_blockchain);
        }
        return true;

      case new_state::recommission: {
        if (hf_version < cryptonote::network_version_12_checkpointing) {
          MERROR("Invalid recommission transaction seen before network v12");
          return false;
        }

        if (!info.is_decommissioned()) {
          LOG_PRINT_L2("Received recommission tx for already-active service node " << key << "; ignoring");
          return false;
        }

        if (is_me)
          MGINFO_GREEN("Recommission for service node (yours): " << key);
        else
          LOG_PRINT_L1("Recommission for service node: " << key);

        // To figure out how much credit the node gets at recommissioned we need to know how much it
        // had when it got decommissioned, and how long it's been decommisioned.
        int64_t credit_at_decomm = quorum_cop::calculate_decommission_credit(info, info.last_decommission_height);
        int64_t decomm_blocks = block_height - info.last_decommission_height;

        info.active_since_height = block_height;
        info.recommission_credit = RECOMMISSION_CREDIT(credit_at_decomm, decomm_blocks);
        // Move the SN at the back of the list as if it had just registered (or just won)
        info.last_reward_block_height = block_height;
        info.last_reward_transaction_index = std::numeric_limits<uint32_t>::max();

        // NOTE: Only the quorum deciding on this node agrees that the service
        // node has a recent uptime atleast for it to be recommissioned not
        // necessarily the entire network. Ensure the entire network agrees
        // simultaneously they are online if we are recommissioning by resetting
        // the failure conditions.  We set only the effective but not *actual*
        // timestamp so that we delay obligations checks but don't prevent the
        // next actual proof from being sent/relayed.
        if (sn_list)
        {
          auto &proof = sn_list->proofs[key];
          proof.effective_timestamp = block.timestamp;
          proof.checkpoint_participation.reset();
          proof.pulse_participation.reset();
          proof.timestamp_participation.reset();
          proof.timesync_status.reset();
        }
        return true;
      }
      case new_state::ip_change_penalty:
        if (hf_version < cryptonote::network_version_12_checkpointing) {
          MERROR("Invalid ip_change_penalty transaction seen before network v12");
          return false;
        }

        if (info.is_decommissioned()) {
          LOG_PRINT_L2("Received reset position tx for service node " << key << " but it is already decommissioned; ignoring");
          return false;
        }

        if (is_me)
          MGINFO_RED("Reward position reset for service node (yours): " << key);
        else
          LOG_PRINT_L1("Reward position reset for service node: " << key);


        // Move the SN at the back of the list as if it had just registered (or just won)
        info.last_reward_block_height = block_height;
        info.last_reward_transaction_index = std::numeric_limits<uint32_t>::max();
        info.last_ip_change_height = block_height;
        return true;

      default:
        // dev bug!
        MERROR("BUG: Service node state change tx has unknown state " << static_cast<uint16_t>(state_change.state));
        return false;
    }
  }

  bool service_node_list::state_t::process_key_image_unlock_tx(cryptonote::network_type nettype, uint64_t block_height, const cryptonote::transaction &tx)
  {
    crypto::public_key snode_key;
    if (!cryptonote::get_service_node_pubkey_from_tx_extra(tx.extra, snode_key))
      return false;

    auto it = service_nodes_infos.find(snode_key);
    if (it == service_nodes_infos.end())
      return false;

    const service_node_info &node_info = *it->second;
    if (node_info.requested_unlock_height != KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
    {
      LOG_PRINT_L1("Unlock TX: Node already requested an unlock at height: "
                   << node_info.requested_unlock_height << " rejected on height: " << block_height
                   << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    cryptonote::tx_extra_tx_key_image_unlock unlock;
    if (!cryptonote::get_field_from_tx_extra(tx.extra, unlock))
    {
      LOG_PRINT_L1("Unlock TX: Didn't have key image unlock in the tx_extra, rejected on height: "
                   << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    uint64_t unlock_height = get_locked_key_image_unlock_height(nettype, node_info.registration_height, block_height);
    for (const auto &contributor : node_info.contributors)
    {
      auto cit = std::find_if(contributor.locked_contributions.begin(),
                              contributor.locked_contributions.end(),
                              [&unlock](const service_node_info::contribution_t &contribution) {
                                return unlock.key_image == contribution.key_image;
                              });
      if (cit != contributor.locked_contributions.end())
      {
        // NOTE(oxen): This should be checked in blockchain check_tx_inputs already
        if (crypto::check_signature(service_nodes::generate_request_stake_unlock_hash(unlock.nonce),
                    cit->key_image_pub_key, unlock.signature))
        {
          duplicate_info(it->second).requested_unlock_height = unlock_height;
          return true;
        }
        else
        {
          LOG_PRINT_L1("Unlock TX: Couldn't verify key image unlock in the tx_extra, rejected on height: "
                       << block_height << " for tx: " << get_transaction_hash(tx));
          return false;
        }
      }
    }

    return false;
  }

  bool is_registration_tx(cryptonote::network_type nettype, uint8_t hf_version, const cryptonote::transaction& tx, uint64_t block_timestamp, uint64_t block_height, uint32_t index, crypto::public_key& key, service_node_info& info)
  {
    contributor_args_t contributor_args = {};
    crypto::public_key service_node_key;
    uint64_t expiration_timestamp{0};
    crypto::signature signature;

    if (!reg_tx_extract_fields(tx, contributor_args, expiration_timestamp, service_node_key, signature))
      return false;

    try
    {
      validate_contributor_args(hf_version, contributor_args);
      validate_contributor_args_signature(contributor_args, expiration_timestamp, service_node_key, signature);
    }
    catch (const invalid_contributions &e)
    {
      LOG_PRINT_L1("Register TX: " << cryptonote::get_transaction_hash(tx) << ", Height: " << block_height << ". " << e.what());
      return false;
    }

    if (expiration_timestamp < block_timestamp)
    {
      LOG_PRINT_L1("Register TX: Has expired. The block timestamp: " << block_timestamp <<
                   " is greater than the expiration timestamp: " << expiration_timestamp <<
                   " on height: " << block_height <<
                   " for tx:" << cryptonote::get_transaction_hash(tx));
      return false;
    }

    // check the initial contribution exists

    uint64_t staking_requirement = get_staking_requirement(nettype, block_height);
    cryptonote::account_public_address address;

    staking_components stake = {};
    if (!tx_get_staking_components_and_amounts(nettype, hf_version, tx, block_height, &stake))
    {
      LOG_PRINT_L1("Register TX: Had service node registration fields, but could not decode contribution on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    if (hf_version >= cryptonote::network_version_16_pulse)
    {
      // In HF16 we start enforcing three things that were always done but weren't actually enforced:
      // 1. the staked amount in the tx must be a single output.
      if (stake.locked_contributions.size() != 1)
      {
        LOG_PRINT_L1("Register TX invalid: multi-output registration transactions are not permitted as of HF16");
        return false;
      }

      // 2. the staked amount must be from the operator.  (Previously there was a weird edge case where you
      // could manually construct a registration tx that stakes for someone *other* than the operator).
      if (stake.address != contributor_args.addresses[0])
      {
        LOG_PRINT_L1("Register TX invalid: registration stake is not from the operator");
        return false;
      }

      // 3. The operator must be staking at least his reserved amount in the registration details.
      // (We check this later, after we calculate reserved atomic currency amounts).  In the pre-HF16
      // code below it only had to satisfy >= 25% even if the reserved operator stake was higher.
    }
    else // Pre-HF16
    {
      const uint64_t min_transfer = get_min_node_contribution(hf_version, staking_requirement, 0, 0);
      if (stake.transferred < min_transfer)
      {
        LOG_PRINT_L1("Register TX: Contribution transferred: " << stake.transferred << " didn't meet the minimum transfer requirement: " << min_transfer << " on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
        return false;
      }

      size_t total_num_of_addr = contributor_args.addresses.size();
      if (std::find(contributor_args.addresses.begin(), contributor_args.addresses.end(), stake.address) == contributor_args.addresses.end())
        total_num_of_addr++;

      // Don't need this check for HF16+ because the number of reserved spots is already checked in
      // the registration details, and we disallow a non-operator registration.
      if (total_num_of_addr > MAX_NUMBER_OF_CONTRIBUTORS)
      {
        LOG_PRINT_L1("Register TX: Number of participants: " << total_num_of_addr <<
                     " exceeded the max number of contributors: " << MAX_NUMBER_OF_CONTRIBUTORS <<
                     " on height: " << block_height <<
                     " for tx: " << cryptonote::get_transaction_hash(tx));
        return false;
      }
    }

    // don't actually process this contribution now, do it when we fall through later.

    key = service_node_key;

    info.staking_requirement           = staking_requirement;
    info.operator_address              = contributor_args.addresses[0];
    info.portions_for_operator         = contributor_args.portions_for_operator;
    info.registration_height           = block_height;
    info.registration_hf_version       = hf_version;
    info.last_reward_block_height      = block_height;
    info.last_reward_transaction_index = index;
    info.swarm_id                      = UNASSIGNED_SWARM_ID;
    info.last_ip_change_height         = block_height;

    for (size_t i = 0; i < contributor_args.addresses.size(); i++)
    {
      // Check for duplicates
      auto iter = std::find(contributor_args.addresses.begin(), contributor_args.addresses.begin() + i, contributor_args.addresses[i]);
      if (iter != contributor_args.addresses.begin() + i)
      {
        LOG_PRINT_L1("Register TX: There was a duplicate participant for service node on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
        return false;
      }

      uint64_t hi, lo, resulthi, resultlo;
      lo = mul128(info.staking_requirement, contributor_args.portions[i], &hi);
      div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);

      info.contributors.emplace_back();
      auto &contributor = info.contributors.back();
      contributor.reserved                         = resultlo;
      contributor.address                          = contributor_args.addresses[i];
      info.total_reserved += resultlo;
    }

    // In HF16 we require that the amount staked in the registration tx be at least the amount
    // reserved for the operator.  Before HF16 it only had to be >= 25%, even if the operator
    // reserved amount was higher (though wallets would never actually do this).
    if (hf_version >= cryptonote::network_version_16_pulse && stake.transferred < info.contributors[0].reserved)
    {
      LOG_PRINT_L1("Register TX rejected: TX does not have sufficient operator stake");
      return false;
    }

    return true;
  }

  bool service_node_list::state_t::process_registration_tx(cryptonote::network_type nettype, const cryptonote::block &block, const cryptonote::transaction& tx, uint32_t index, const service_node_keys *my_keys)
  {
    uint8_t const hf_version       = block.major_version;
    uint64_t const block_timestamp = block.timestamp;
    uint64_t const block_height    = cryptonote::get_block_height(block);

    crypto::public_key key;
    auto info_ptr = std::make_shared<service_node_info>();
    service_node_info &info = *info_ptr;
    if (!is_registration_tx(nettype, hf_version, tx, block_timestamp, block_height, index, key, info))
      return false;

    if (hf_version >= cryptonote::network_version_11_infinite_staking)
    {
      // NOTE(oxen): Grace period is not used anymore with infinite staking. So, if someone somehow reregisters, we just ignore it
      const auto iter = service_nodes_infos.find(key);
      if (iter != service_nodes_infos.end())
        return false;

      // Explicitly reset any stored proof to 0, and store it just in case this is a
      // re-registration: we want to wipe out any data from the previous registration.
      if (sn_list && !sn_list->m_rescanning)
      {
        auto &proof = sn_list->proofs[key];
        proof = {};
        proof.store(key, sn_list->m_blockchain);
      }

      if (my_keys && my_keys->pub == key) MGINFO_GREEN("Service node registered (yours): " << key << " on height: " << block_height);
      else                                LOG_PRINT_L1("New service node registered: "     << key << " on height: " << block_height);
    }
    else
    {
      // NOTE: A node doesn't expire until registration_height + lock blocks excess now which acts as the grace period
      // So it is possible to find the node still in our list.
      bool registered_during_grace_period = false;
      const auto iter = service_nodes_infos.find(key);
      if (iter != service_nodes_infos.end())
      {
        if (hf_version >= cryptonote::network_version_10_bulletproofs)
        {
          service_node_info const &old_info = *iter->second;
          uint64_t expiry_height = old_info.registration_height + staking_num_lock_blocks(nettype);
          if (block_height < expiry_height)
            return false;

          // NOTE: Node preserves its position in list if it reregisters during grace period.
          registered_during_grace_period = true;
          info.last_reward_block_height = old_info.last_reward_block_height;
          info.last_reward_transaction_index = old_info.last_reward_transaction_index;
        }
        else
        {
          return false;
        }
      }

      if (my_keys && my_keys->pub == key)
      {
        if (registered_during_grace_period)
        {
          MGINFO_GREEN("Service node re-registered (yours): " << key << " at block height: " << block_height);
        }
        else
        {
          MGINFO_GREEN("Service node registered (yours): " << key << " at block height: " << block_height);
        }
      }
      else
      {
        LOG_PRINT_L1("New service node registered: " << key << " at block height: " << block_height);
      }
    }

    service_nodes_infos[key] = std::move(info_ptr);
    return true;
  }

  bool service_node_list::state_t::process_contribution_tx(cryptonote::network_type nettype, const cryptonote::block &block, const cryptonote::transaction& tx, uint32_t index)
  {
    uint64_t const block_height = cryptonote::get_block_height(block);
    uint8_t const hf_version    = block.major_version;

    staking_components stake = {};
    if (!tx_get_staking_components_and_amounts(nettype, hf_version, tx, block_height, &stake))
    {
      if (stake.service_node_pubkey)
        LOG_PRINT_L1("TX: Could not decode contribution for service node: " << stake.service_node_pubkey << " on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    auto iter = service_nodes_infos.find(stake.service_node_pubkey);
    if (iter == service_nodes_infos.end())
    {
      LOG_PRINT_L1("TX: Contribution received for service node: "
                   << stake.service_node_pubkey << ", but could not be found in the service node list on height: "
                   << block_height << " for tx: " << cryptonote::get_transaction_hash(tx)
                   << "\n"
                      "This could mean that the service node was deregistered before the contribution was processed.");
      return false;
    }

    const service_node_info& curinfo = *iter->second;
    if (curinfo.is_fully_funded())
    {
      LOG_PRINT_L1("TX: Service node: " << stake.service_node_pubkey
                                        << " is already fully funded, but contribution received on height: "
                                        << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    if (!cryptonote::get_tx_secret_key_from_tx_extra(tx.extra, stake.tx_key))
    {
      LOG_PRINT_L1("TX: Failed to get tx secret key from contribution received on height: "  << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    auto &contributors = curinfo.contributors;
    const size_t existing_contributions = curinfo.total_num_locked_contributions();
    size_t other_reservations = 0; // Number of spots that must be left open, *not* counting this contributor (if they have a reserved spot)
    bool new_contributor = true;
    size_t contributor_position = 0;
    uint64_t contr_unfilled_reserved = 0;
    for (size_t i = 0; i < contributors.size(); i++)
    {
      const auto& c = contributors[i];
      if (c.address == stake.address)
      {
        contributor_position = i;
        new_contributor = false;
        if (c.amount < c.reserved)
          contr_unfilled_reserved = c.reserved - c.amount;
      }
      else if (c.amount < c.reserved)
        other_reservations++;
    }

    if (hf_version >= cryptonote::network_version_16_pulse && stake.locked_contributions.size() != 1)
    {
      // Nothing has ever created stake txes with multiple stake outputs, but we start enforcing
      // that in HF16.
      LOG_PRINT_L1("Ignoring staking tx: multi-output stakes are not permitted as of HF16");
      return false;
    }

    // Check node contributor counts
    {
      bool too_many_contributions = false;
      if (hf_version >= cryptonote::network_version_16_pulse)
        // Before HF16 we didn't properly take into account unfilled reservation spots
        too_many_contributions = existing_contributions + other_reservations + 1 > MAX_NUMBER_OF_CONTRIBUTORS;
      else if (hf_version >= cryptonote::network_version_11_infinite_staking)
        // As of HF11 we allow up to 4 stakes total (except for the loophole closed above)
        too_many_contributions = existing_contributions + stake.locked_contributions.size() > MAX_NUMBER_OF_CONTRIBUTORS;
      else
        // Before HF11 we allowed up to 4 contributors, but each can contribute multiple times
        too_many_contributions = new_contributor && contributors.size() >= MAX_NUMBER_OF_CONTRIBUTORS;

      if (too_many_contributions)
      {
        LOG_PRINT_L1("TX: Already hit the max number of contributions: "
                     << MAX_NUMBER_OF_CONTRIBUTORS
                     << " for contributor: " << cryptonote::get_account_address_as_str(nettype, false, stake.address)
                     << " on height: " << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
        return false;
      }
    }

    // Check that the contribution is large enough
    uint64_t min_contribution;
    if (!new_contributor && hf_version < cryptonote::network_version_11_infinite_staking)
    { // Follow-up contributions from an existing contributor could be any size before HF11
      min_contribution = 1;
    }
    else if (hf_version < cryptonote::network_version_16_pulse)
    {
      // The implementation before HF16 was a bit broken w.r.t. properly handling reserved amounts
      min_contribution = get_min_node_contribution(hf_version, curinfo.staking_requirement, curinfo.total_reserved, existing_contributions);
    }
    else // HF16+:
    {
      if (contr_unfilled_reserved > 0)
        // We've got a reserved spot: require that it be filled in one go.  (Reservation contribution rules are already enforced in the registration).
        min_contribution = contr_unfilled_reserved;
      else
        min_contribution = get_min_node_contribution(hf_version, curinfo.staking_requirement, curinfo.total_reserved, existing_contributions + other_reservations);
    }

    if (stake.transferred < min_contribution)
    {
      LOG_PRINT_L1("TX: Amount " << stake.transferred << " did not meet min " << min_contribution
                                 << " for service node: " << stake.service_node_pubkey << " on height: "
                                 << block_height << " for tx: " << cryptonote::get_transaction_hash(tx));
      return false;
    }

    // Check that the contribution isn't too large.  Subtract contr_unfilled_reserved because we want to
    // calculate this using only the total reserved amounts of *other* contributors but not our own.
    if (auto max = get_max_node_contribution(hf_version, curinfo.staking_requirement, curinfo.total_reserved - contr_unfilled_reserved);
        stake.transferred > max)
    {
      MINFO("TX: Amount " << stake.transferred << " is too large (max " << max << ").  This is probably a result of competing stakes.");
      return false;
    }

    //
    // Successfully Validated
    //

    auto &info = duplicate_info(iter->second);
    if (new_contributor)
    {
      contributor_position = info.contributors.size();
      info.contributors.emplace_back().address = stake.address;
    }
    service_node_info::contributor_t& contributor = info.contributors[contributor_position];

    // In this action, we cannot
    // increase total_reserved so much that it is >= staking_requirement
    uint64_t can_increase_reserved_by = info.staking_requirement - info.total_reserved;
    uint64_t max_amount               = contributor.reserved + can_increase_reserved_by;
    stake.transferred = std::min(max_amount - contributor.amount, stake.transferred);

    contributor.amount     += stake.transferred;
    info.total_contributed += stake.transferred;

    if (contributor.amount > contributor.reserved)
    {
      info.total_reserved += contributor.amount - contributor.reserved;
      contributor.reserved = contributor.amount;
    }

    info.last_reward_block_height = block_height;
    info.last_reward_transaction_index = index;

    if (hf_version >= cryptonote::network_version_11_infinite_staking)
      for (const auto &contribution : stake.locked_contributions)
        contributor.locked_contributions.push_back(contribution);

    LOG_PRINT_L1("Contribution of " << stake.transferred << " received for service node " << stake.service_node_pubkey);
    if (info.is_fully_funded()) {
      info.active_since_height = block_height;
      return true;
    }
    return false;
  }

  static std::string dump_pulse_block_data(cryptonote::block const &block, service_nodes::quorum const *quorum)
  {
    std::stringstream stream;
    std::bitset<8 * sizeof(block.pulse.validator_bitset)> const validator_bitset = block.pulse.validator_bitset;
    stream << "Block(" << cryptonote::get_block_height(block) << "): " << cryptonote::get_block_hash(block) << "\n";
    stream << "Leader: ";
    if (quorum) stream << (quorum->workers.empty() ? "(invalid leader)" : oxenmq::to_hex(tools::view_guts(quorum->workers[0]))) << "\n";
    else        stream << "(invalid quorum)\n";
    stream << "Round: " << +block.pulse.round << "\n";
    stream << "Validator Bitset: " << validator_bitset << "\n";

    stream << "Signatures: ";
    if (block.signatures.empty()) stream << "(none)";

    for (service_nodes::quorum_signature const &entry : block.signatures)
    {
      stream << "\n";
      stream << "  [" << +entry.voter_index << "] validator: ";
      if (quorum)
      {
        stream << ((entry.voter_index >= quorum->validators.size()) ? "(invalid quorum index)" : oxenmq::to_hex(tools::view_guts(quorum->validators[entry.voter_index])));
        stream << ", signature: " << oxenmq::to_hex(tools::view_guts(entry.signature));
      }
      else stream << "(invalid quorum)";
    }

    return stream.str();
  }

  static bool verify_block_components(cryptonote::network_type nettype,
                                      cryptonote::block const &block,
                                      bool miner_block,
                                      bool alt_block,
                                      bool log_errors,
                                      pulse::timings &timings,
                                      std::shared_ptr<const quorum> pulse_quorum,
                                      std::vector<std::shared_ptr<const quorum>> &alt_pulse_quorums)
  {
    std::string_view block_type = alt_block ? "alt block "sv : "block "sv;
    uint64_t height             = cryptonote::get_block_height(block);
    crypto::hash hash           = cryptonote::get_block_hash(block);

    if (miner_block)
    {

      if (cryptonote::block_has_pulse_components(block))
      {
        if (log_errors) MGINFO("Pulse " << block_type << "received but only miner blocks are permitted\n" << dump_pulse_block_data(block, pulse_quorum.get()));
        return false;
      }

      if (block.pulse.round != 0)
      {
        if (log_errors) MGINFO("Miner " << block_type << "given but unexpectedly set round " << block.pulse.round <<  " on height " << height);
        return false;
      }

      if (block.pulse.validator_bitset != 0)
      {
        std::bitset<8 * sizeof(block.pulse.validator_bitset)> const bitset = block.pulse.validator_bitset;
        if (log_errors) MGINFO("Miner " << block_type << "block given but unexpectedly set validator bitset " << bitset <<  " on height " << height);
        return false;
      }

      if (block.signatures.size())
      {
        if (log_errors) MGINFO("Miner " << block_type << "block given but unexpectedly has " << block.signatures.size() <<  " signatures on height " << height);
        return false;
      }

      return true;
    }
    else
    {
      if (!cryptonote::block_has_pulse_components(block))
      {
        if (log_errors) MGINFO("Miner " << block_type << "received but only pulse blocks are permitted\n" << dump_pulse_block_data(block, pulse_quorum.get()));
        return false;
      }

      // TODO(doyle): Core tests need to generate coherent timestamps with
      // Pulse. So we relax the rules here for now.
      if (nettype != cryptonote::FAKECHAIN)
      {
        auto round_begin_timestamp = timings.r0_timestamp + (block.pulse.round * PULSE_ROUND_TIME);
        auto round_end_timestamp   = round_begin_timestamp + PULSE_ROUND_TIME;

        uint64_t begin_time = tools::to_seconds(round_begin_timestamp.time_since_epoch());
        uint64_t end_time   = tools::to_seconds(round_end_timestamp.time_since_epoch());
        if (!(block.timestamp >= begin_time && block.timestamp <= end_time))
        {
          std::string time  = tools::get_human_readable_timestamp(block.timestamp);
          std::string begin = tools::get_human_readable_timestamp(begin_time);
          std::string end   = tools::get_human_readable_timestamp(end_time);
          if (log_errors) MGINFO("Pulse " << block_type << "with round " << +block.pulse.round << " specifies timestamp " << time << " is not within an acceptable range of time [" << begin << ", " << end << "]");
          return false;
        }
      }

      if (block.nonce != 0)
      {
        if (log_errors) MGINFO("Pulse " << block_type << "specified a nonce when quorum block generation is available, nonce: " << block.nonce);
        return false;
      }

      bool quorum_verified = false;
      if (alt_block)
      {
        // NOTE: Check main pulse quorum. It might not necessarily exist because
        // the alt-block's chain could be in any arbitrary state.
        bool failed_quorum_verify = true;
        if (pulse_quorum)
        {
          LOG_PRINT_L1("Verifying alt-block " << height << ":" << hash << " against main chain quorum");
          failed_quorum_verify = service_nodes::verify_quorum_signatures(*pulse_quorum,
                                                                         quorum_type::pulse,
                                                                         block.major_version,
                                                                         height,
                                                                         hash,
                                                                         block.signatures,
                                                                         &block) == false;
        }

        // NOTE: Check alt pulse quorums
        if (failed_quorum_verify)
        {
          LOG_PRINT_L1("Verifying alt-block " << height << ":" << hash << " against alt chain quorum(s)");
          for (auto const &alt_quorum : alt_pulse_quorums)
          {
            if (service_nodes::verify_quorum_signatures(*alt_quorum,
                                                        quorum_type::pulse,
                                                        block.major_version,
                                                        height,
                                                        hash,
                                                        block.signatures,
                                                        &block))
            {
              failed_quorum_verify = false;
              break;
            }
          }
        }

        quorum_verified = !failed_quorum_verify;
      }
      else
      {
        // NOTE: We only accept insufficient node for Pulse if we're on an alt
        // block (that chain would be in any arbitrary state, we could be
        // completely isolated from the correct network for example).
        bool insufficient_nodes_for_pulse = pulse_quorum == nullptr;
        if (insufficient_nodes_for_pulse)
        {
          if (log_errors) MGINFO("Pulse " << block_type << "specified but no quorum available " << dump_pulse_block_data(block, pulse_quorum.get()));
          return false;
        }

        quorum_verified = service_nodes::verify_quorum_signatures(*pulse_quorum,
                                                                  quorum_type::pulse,
                                                                  block.major_version,
                                                                  cryptonote::get_block_height(block),
                                                                  cryptonote::get_block_hash(block),
                                                                  block.signatures,
                                                                  &block);
      }

      if (quorum_verified)
      {
        // NOTE: These invariants are already checked in verify_quorum_signatures
        if (alt_block)
          LOG_PRINT_L1("Alt-block " << height << ":" << hash << " verified successfully");
        assert(block.pulse.validator_bitset != 0);
        assert(block.pulse.validator_bitset < (1 << PULSE_QUORUM_NUM_VALIDATORS));
        assert(block.signatures.size() == service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
      }
      else
      {
        if (log_errors)
          MGINFO("Pulse " << block_type << "failed quorum verification\n" << dump_pulse_block_data(block, pulse_quorum.get()));
      }

      return quorum_verified;
    }
  }

  static bool find_block_in_db(cryptonote::BlockchainDB const &db, crypto::hash const &hash, cryptonote::block &block)
  {
    try
    {
      block = db.get_block(hash);
    }
    catch(std::exception const &e)
    {
      // ignore not found block, try alt db
      LOG_PRINT_L1("Block " << hash << " not found in main DB, searching alt DB");
      cryptonote::alt_block_data_t alt_data;
      cryptonote::blobdata blob;
      if (!db.get_alt_block(hash, &alt_data, &blob, nullptr))
      {
        MERROR("Failed to find block " << hash);
        return false;
      }

      if (!cryptonote::parse_and_validate_block_from_blob(blob, block, nullptr))
      {
        MERROR("Failed to parse alt block blob at " << alt_data.height << ":" << hash);
        return false;
      }
    }

    return true;
  }


  bool service_node_list::verify_block(const cryptonote::block &block, bool alt_block, cryptonote::checkpoint_t const *checkpoint)
  {
    if (block.major_version < cryptonote::network_version_9_service_nodes)
      return true;

    std::string_view block_type = alt_block ? "alt block "sv : "block "sv;

    //
    // NOTE: Verify the checkpoint given on this height that locks in a block in the past.
    //
    if (block.major_version >= cryptonote::network_version_13_enforce_checkpoints && checkpoint)
    {
      std::vector<std::shared_ptr<const service_nodes::quorum>> alt_quorums;
      std::shared_ptr<const quorum> quorum = get_quorum(quorum_type::checkpointing, checkpoint->height, false, alt_block ? &alt_quorums : nullptr);

      if (!quorum)
      {
        MGINFO("Failed to get testing quorum checkpoint for " << block_type << cryptonote::get_block_hash(block));
        return false;
      }

      bool failed_checkpoint_verify = !service_nodes::verify_checkpoint(block.major_version, *checkpoint, *quorum);
      if (alt_block && failed_checkpoint_verify)
      {
        for (std::shared_ptr<const service_nodes::quorum> alt_quorum : alt_quorums)
        {
          if (service_nodes::verify_checkpoint(block.major_version, *checkpoint, *alt_quorum))
          {
            failed_checkpoint_verify = false;
            break;
          }
        }
      }

      if (failed_checkpoint_verify)
      {
        MGINFO("Service node checkpoint failed verification for " << block_type << cryptonote::get_block_hash(block));
        return false;
      }
    }

    //
    // NOTE: Get Pulse Block Timing Information
    //
    pulse::timings timings = {};
    uint64_t height        = cryptonote::get_block_height(block);
    if (block.major_version >= cryptonote::network_version_16_pulse)
    {
      uint64_t prev_timestamp = 0;
      if (alt_block)
      {
        cryptonote::block prev_block;
        if (!find_block_in_db(m_blockchain.get_db(), block.prev_id, prev_block))
        {
          MGINFO("Alt block " << cryptonote::get_block_hash(block) << " references previous block " << block.prev_id << " not available in DB.");
          return false;
        }

        prev_timestamp = prev_block.timestamp;
      }
      else
      {
        uint64_t prev_height = height - 1;
        prev_timestamp       = m_blockchain.get_db().get_block_timestamp(prev_height);
      }

      if (!pulse::get_round_timings(m_blockchain, height, prev_timestamp, timings))
      {
        MGINFO("Failed to query the block data for Pulse timings to validate incoming " << block_type << "at height " << height);
        return false;
      }
    }

    //
    // NOTE: Load Pulse Quorums
    //
    std::shared_ptr<const quorum>              pulse_quorum;
    std::vector<std::shared_ptr<const quorum>> alt_pulse_quorums;
    bool pulse_hf = block.major_version >= cryptonote::network_version_16_pulse;

    if (pulse_hf)
    {
      pulse_quorum = get_quorum(quorum_type::pulse,
                                height,
                                false /*include historical quorums*/,
                                alt_block ? &alt_pulse_quorums : nullptr);
    }

    if (m_blockchain.nettype() != cryptonote::FAKECHAIN)
    {
      // TODO(doyle): Core tests don't generate proper timestamps for detecting
      // timeout yet. So we don't do a timeout check and assume all blocks
      // incoming from Pulse are valid if they have the correct signatures
      // (despite timestamp being potentially wrong).
      if (pulse::time_point(std::chrono::seconds(block.timestamp)) >= timings.miner_fallback_timestamp)
        pulse_quorum = nullptr;
    }

    //
    // NOTE: Verify Block
    //
    bool result = false;
    if (alt_block)
    {
      // NOTE: Verify as a pulse block first if possible, then as a miner block.
      // This alt block could belong to a chain that is in an arbitrary state.
      if (pulse_hf)
        result = verify_block_components(m_blockchain.nettype(), block, false /*miner_block*/, true /*alt_block*/, false /*log_errors*/, timings, pulse_quorum, alt_pulse_quorums);

      if (!result)
        result = verify_block_components(m_blockchain.nettype(), block, true /*miner_block*/, true /*alt_block*/, false /*log_errors*/, timings, pulse_quorum, alt_pulse_quorums);
    }
    else
    {
      // NOTE: No pulse quorums are generated when the network has insufficient nodes to generate quorums
      //       Or, block specifies time after all the rounds have timed out
      bool miner_block = !pulse_hf || !pulse_quorum;

      result = verify_block_components(m_blockchain.nettype(),
                                       block,
                                       miner_block,
                                       false /*alt_block*/,
                                       true /*log_errors*/,
                                       timings,
                                       pulse_quorum,
                                       alt_pulse_quorums);
    }

    return result;
  }

  bool service_node_list::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint)
  {
    if (block.major_version < cryptonote::network_version_9_service_nodes)
      return true;

    std::lock_guard lock(m_sn_mutex);
    process_block(block, txs);
    bool result = verify_block(block, false /*alt_block*/, checkpoint);
    if (result && cryptonote::block_has_pulse_components(block))
    {
      // NOTE: Only record participation if its a block we recently received.
      // Otherwise processing blocks in retrospect/re-loading on restart seeds
      // in old-data.
      uint64_t const block_height = cryptonote::get_block_height(block);
      bool newest_block           = m_blockchain.get_current_blockchain_height() == (block_height + 1);

      auto now                    = pulse::clock::now().time_since_epoch();
      auto earliest_time          = std::chrono::seconds(block.timestamp) - TARGET_BLOCK_TIME;
      auto latest_time            = std::chrono::seconds(block.timestamp) + TARGET_BLOCK_TIME;

      if (newest_block && (now >= earliest_time && now <= latest_time))
      {
        std::shared_ptr<const quorum> quorum = get_quorum(quorum_type::pulse, block_height, false, nullptr);
        if (!quorum || quorum->validators.empty())
        {
          MFATAL("Unexpected Pulse error " << (quorum ? " quorum was not generated" : " quorum was empty"));
          return false;
        }

        for (size_t validator_index = 0; validator_index < service_nodes::PULSE_QUORUM_NUM_VALIDATORS; validator_index++)
        {
          uint16_t bit      = 1 << validator_index;
          bool participated = block.pulse.validator_bitset & bit;
          record_pulse_participation(quorum->validators[validator_index], block_height, block.pulse.round, participated);
        }
      }
    }
    return result;
  }

  static std::mt19937_64 quorum_rng(uint8_t hf_version, crypto::hash const &hash, quorum_type type)
  {
    std::mt19937_64 result;
    if (hf_version >= cryptonote::network_version_16_pulse)
    {
      std::array<uint32_t, (sizeof(hash) / sizeof(uint32_t)) + 1> src = {static_cast<uint32_t>(type)};
      std::memcpy(&src[1], &hash, sizeof(hash));
      for (uint32_t &val : src) boost::endian::little_to_native_inplace(val);
      std::seed_seq sequence(src.begin(), src.end());
      result.seed(sequence);
    }
    else
    {
      uint64_t seed = 0;
      std::memcpy(&seed, hash.data, sizeof(seed));
      boost::endian::little_to_native_inplace(seed);
      seed += static_cast<uint64_t>(type);
      result.seed(seed);
    }

    return result;
  }

  static std::vector<size_t> generate_shuffled_service_node_index_list(
      uint8_t hf_version,
      size_t list_size,
      crypto::hash const &block_hash,
      quorum_type type,
      size_t sublist_size  = 0,
      size_t sublist_up_to = 0)
  {
    std::vector<size_t> result(list_size);
    std::iota(result.begin(), result.end(), 0);
    std::mt19937_64 rng = quorum_rng(hf_version, block_hash, type);

    //       Shuffle 2
    //       |=================================|
    //       |                                 |
    // Shuffle 1                               |
    // |==============|                        |
    // |     |        |                        |
    // |sublist_size  |                        |
    // |     |    sublist_up_to                |
    // 0     N        Y                        Z
    // [.......................................]

    // If we have a list [0,Z) but we need a shuffled sublist of the first N values that only
    // includes values from [0,Y) then we do this using two shuffles: first of the [0,Y) sublist,
    // then of the [N,Z) sublist (which is already partially shuffled, but that doesn't matter).  We
    // reuse the same seed for both partial shuffles, but again, that isn't an issue.
    if ((0 < sublist_size && sublist_size < list_size) && (0 < sublist_up_to && sublist_up_to < list_size)) {
      assert(sublist_size <= sublist_up_to); // Can't select N random items from M items when M < N
      auto rng_copy = rng;
      tools::shuffle_portable(result.begin(), result.begin() + sublist_up_to, rng);
      tools::shuffle_portable(result.begin() + sublist_size, result.end(), rng_copy);
    }
    else {
      tools::shuffle_portable(result.begin(), result.end(), rng);
    }
    return result;
  }

  template <typename It>
  static std::vector<crypto::hash> make_pulse_entropy_from_blocks(It begin, It end, uint8_t pulse_round)
  {
    std::vector<crypto::hash> result;
    result.reserve(std::distance(begin, end));

    for (auto it = begin; it != end; it++)
    {
      cryptonote::block const &block = *it;
      crypto::hash hash              = {};
      if (block.major_version >= cryptonote::network_version_16_pulse &&
          cryptonote::block_has_pulse_components(block))
      {
        std::array<uint8_t, 1 + sizeof(block.pulse.random_value)> src = {pulse_round};
        std::copy(std::begin(block.pulse.random_value.data), std::end(block.pulse.random_value.data), src.begin() + 1);
        crypto::cn_fast_hash(src.data(), src.size(), hash.data);
      }
      else
      {
        crypto::hash block_hash = cryptonote::get_block_hash(block);
        std::array<uint8_t, 1 + sizeof(hash)> src = {pulse_round};
        std::copy(std::begin(block_hash.data), std::end(block_hash.data), src.begin() + 1);
        crypto::cn_fast_hash(src.data(), src.size(), hash.data);
      }

      assert(hash != crypto::null_hash);
      result.push_back(hash);
    }

    return result;
  }

  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db,
                                                             cryptonote::block const &top_block,
                                                             uint8_t pulse_round)
  {
    uint64_t const top_height = cryptonote::get_block_height(top_block);
    if (top_height < PULSE_QUORUM_ENTROPY_LAG)
    {
      MERROR("Insufficient blocks to get quorum entropy for Pulse, height is " << top_height << ", we need " << PULSE_QUORUM_ENTROPY_LAG << " blocks.");
      return {};
    }

    uint64_t const start_height = top_height - PULSE_QUORUM_ENTROPY_LAG;
    uint64_t const end_height   = start_height + PULSE_QUORUM_SIZE;

    std::vector<cryptonote::block> blocks;
    blocks.reserve(PULSE_QUORUM_SIZE);

    // NOTE: Go backwards from the block and retrieve the blocks for entropy.
    // We search by block so that this function handles alternatives blocks as
    // well as mainchain blocks.
    crypto::hash prev_hash = top_block.prev_id;
    uint64_t prev_height   = top_height;
    while (prev_height > start_height)
    {
      cryptonote::block block;
      if (!find_block_in_db(db, prev_hash, block))
      {
        MERROR("Failed to get quorum entropy for Pulse, block at " << prev_height << prev_hash);
        return {};
      }

      prev_hash = block.prev_id;
      if (prev_height >= start_height && prev_height <= end_height)
        blocks.push_back(block);

      prev_height--;
    }

    return make_pulse_entropy_from_blocks(blocks.rbegin(), blocks.rend(), pulse_round);
  }

  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db,
                                                             crypto::hash const &top_hash,
                                                             uint8_t pulse_round)
  {
    cryptonote::block top_block;
    if (!find_block_in_db(db, top_hash, top_block))
    {
      MERROR("Failed to get quorum entropy for Pulse, next block parent " << top_hash);
      return {};
    }

    return get_pulse_entropy_for_next_block(db, top_block, pulse_round);
  }

  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db,
                                                             uint8_t pulse_round)
  {
    return get_pulse_entropy_for_next_block(db, db.get_top_block(), pulse_round);
  }

  service_nodes::quorum generate_pulse_quorum(cryptonote::network_type nettype,
                                              crypto::public_key const &block_leader,
                                              uint8_t hf_version,
                                              std::vector<pubkey_and_sninfo> const &active_snode_list,
                                              std::vector<crypto::hash> const &pulse_entropy,
                                              uint8_t pulse_round)
  {
    service_nodes::quorum result = {};
    if (active_snode_list.size() < pulse_min_service_nodes(nettype))
    {
      LOG_PRINT_L2("Insufficient active Service Nodes for Pulse: " << active_snode_list.size());
      return result;
    }

    if (pulse_entropy.size() != PULSE_QUORUM_SIZE)
    {
      LOG_PRINT_L2("Blockchain has insufficient blocks to generate Pulse data");
      return result;
    }

    std::vector<pubkey_and_sninfo const *> pulse_candidates;
    pulse_candidates.reserve(active_snode_list.size());
    for (auto &node : active_snode_list)
    {
      if (node.first != block_leader || pulse_round > 0)
        pulse_candidates.push_back(&node);
    }

    // NOTE: Sort ascending in height i.e. sort preferring the longest time since the validator was in a Pulse quorum.
    std::sort(
        pulse_candidates.begin(), pulse_candidates.end(), [](pubkey_and_sninfo const *a, pubkey_and_sninfo const *b) {
          if (a->second->pulse_sorter == b->second->pulse_sorter)
            return memcmp(reinterpret_cast<const void *>(&a->first), reinterpret_cast<const void *>(&b->first), sizeof(a->first)) < 0;
          return a->second->pulse_sorter < b->second->pulse_sorter;
        });

    crypto::public_key block_producer;
    if (pulse_round == 0)
    {
      block_producer = block_leader;
    }
    else
    {
      std::mt19937_64 rng   = quorum_rng(hf_version, pulse_entropy[0], quorum_type::pulse);
      size_t producer_index = tools::uniform_distribution_portable(rng, pulse_candidates.size());
      block_producer        = pulse_candidates[producer_index]->first;
      pulse_candidates.erase(pulse_candidates.begin() + producer_index);
    }

    // NOTE: Order the candidates so the first half nodes in the list is the validators for this round.
    // - Divide the list in half, select validators from the first half of the list.
    // - Swap the chosen validator into the moving first half of the list.
    auto running_it              = pulse_candidates.begin();
    size_t const partition_index = (pulse_candidates.size() - 1) / 2;
    if (partition_index == 0)
    {
      running_it += service_nodes::PULSE_QUORUM_NUM_VALIDATORS;
    }
    else
    {
      for (size_t i = 0; i < service_nodes::PULSE_QUORUM_NUM_VALIDATORS; i++)
      {
        crypto::hash const &entropy = pulse_entropy[i + 1];
        std::mt19937_64 rng         = quorum_rng(hf_version, entropy, quorum_type::pulse);
        size_t validators_available = std::distance(running_it, pulse_candidates.end());
        size_t swap_index = tools::uniform_distribution_portable(rng, std::min(partition_index, validators_available));
        std::swap(*running_it, *(running_it + swap_index));
        running_it++;
      }
    }

    result.workers.push_back(block_producer);
    result.validators.reserve(PULSE_QUORUM_NUM_VALIDATORS);
    for (auto it = pulse_candidates.begin(); it != running_it; it++)
    {
      crypto::public_key const &node_key = (*it)->first;
      result.validators.push_back(node_key);
    }
    return result;
  }

  static void generate_other_quorums(service_node_list::state_t &state, std::vector<pubkey_and_sninfo> const &active_snode_list, cryptonote::network_type nettype, uint8_t hf_version)
  {
    assert(state.block_hash != crypto::null_hash);

    // The two quorums here have different selection criteria: the entire checkpoint quorum and the
    // state change *validators* want only active service nodes, but the state change *workers*
    // (i.e. the nodes to be tested) also include decommissioned service nodes.  (Prior to v12 there
    // are no decommissioned nodes, so this distinction is irrelevant for network concensus).
    std::vector<pubkey_and_sninfo> decomm_snode_list;
    if (hf_version >= cryptonote::network_version_12_checkpointing)
      decomm_snode_list = state.decommissioned_service_nodes_infos();

    quorum_type const max_quorum_type = max_quorum_type_for_hf(hf_version);
    for (int type_int = 0; type_int <= (int)max_quorum_type; type_int++)
    {
      auto type   = static_cast<quorum_type>(type_int);
      auto quorum = std::make_shared<service_nodes::quorum>();
      std::vector<size_t> pub_keys_indexes;

      size_t num_validators = 0;
      size_t num_workers    = 0;
      switch(type)
      {
        case quorum_type::obligations:
        {
          size_t total_nodes         = active_snode_list.size() + decomm_snode_list.size();
          num_validators             = std::min(active_snode_list.size(), STATE_CHANGE_QUORUM_SIZE);
          pub_keys_indexes           = generate_shuffled_service_node_index_list(hf_version, total_nodes, state.block_hash, type, num_validators, active_snode_list.size());
          state.quorums.obligations  = quorum;
          size_t num_remaining_nodes = total_nodes - num_validators;
          num_workers                = std::min(num_remaining_nodes, std::max(STATE_CHANGE_MIN_NODES_TO_TEST, num_remaining_nodes/STATE_CHANGE_NTH_OF_THE_NETWORK_TO_TEST));
        }
        break;

        case quorum_type::checkpointing:
        {
          // Checkpoint quorums only exist every CHECKPOINT_INTERVAL blocks, but the height that gets
          // used to generate the quorum (i.e. the `height` variable here) is actually `H -
          // REORG_SAFETY_BUFFER_BLOCKS_POST_HF12`, where H is divisible by CHECKPOINT_INTERVAL, but
          // REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 is not (it equals 11).  Hence the addition here to
          // "undo" the lag before checking to see if we're on an interval multiple:
          if ((state.height + REORG_SAFETY_BUFFER_BLOCKS_POST_HF12) % CHECKPOINT_INTERVAL != 0)
            continue; // Not on an interval multiple: no checkpointing quorum is defined.

          size_t total_nodes = active_snode_list.size();

          // TODO(oxen): Soft fork, remove when testnet gets reset
          if (nettype == cryptonote::TESTNET && state.height < 85357)
            total_nodes = active_snode_list.size() + decomm_snode_list.size();

          if (total_nodes >= CHECKPOINT_QUORUM_SIZE)
          {
            pub_keys_indexes = generate_shuffled_service_node_index_list(hf_version, total_nodes, state.block_hash, type);
            num_validators   = std::min(pub_keys_indexes.size(), CHECKPOINT_QUORUM_SIZE);
          }
          state.quorums.checkpointing = quorum;
        }
        break;

        case quorum_type::blink:
        {
          if (state.height % BLINK_QUORUM_INTERVAL != 0)
            continue;

          // Further filter the active SN list for the blink quorum to only include SNs that are not
          // scheduled to finish unlocking between the quorum height and a few blocks after the
          // associated blink height.
          pub_keys_indexes.reserve(active_snode_list.size());
          uint64_t const active_until = state.height + BLINK_EXPIRY_BUFFER;
          for (size_t index = 0; index < active_snode_list.size(); index++)
          {
            pubkey_and_sninfo const &entry = active_snode_list[index];
            uint64_t requested_unlock_height = entry.second->requested_unlock_height;
            if (requested_unlock_height == KEY_IMAGE_AWAITING_UNLOCK_HEIGHT || requested_unlock_height > active_until)
              pub_keys_indexes.push_back(index);
          }

          if (pub_keys_indexes.size() >= BLINK_MIN_VOTES)
          {
            std::mt19937_64 rng = quorum_rng(hf_version, state.block_hash, type);
            tools::shuffle_portable(pub_keys_indexes.begin(), pub_keys_indexes.end(), rng);
            num_validators = std::min<size_t>(pub_keys_indexes.size(), BLINK_SUBQUORUM_SIZE);
          }
          // Otherwise leave empty to signal that there aren't enough SNs to form a usable quorum (to
          // distinguish it from an invalid height, which gets left as a nullptr)
          state.quorums.blink = quorum;

        }
        break;

        // NOTE: NOP. Pulse quorums are generated pre-Service Node List changes for the block
        case quorum_type::pulse: continue;
        default: MERROR("Unhandled quorum type enum with value: " << type_int); continue;
      }

      quorum->validators.reserve(num_validators);
      quorum->workers.reserve(num_workers);

      size_t i = 0;
      for (; i < num_validators; i++)
      {
        quorum->validators.push_back(active_snode_list[pub_keys_indexes[i]].first);
      }

      for (; i < num_validators + num_workers; i++)
      {
        size_t j = pub_keys_indexes[i];
        if (j < active_snode_list.size())
          quorum->workers.push_back(active_snode_list[j].first);
        else
          quorum->workers.push_back(decomm_snode_list[j - active_snode_list.size()].first);
      }
    }
  }

  void service_node_list::state_t::update_from_block(cryptonote::BlockchainDB const &db,
                                                     cryptonote::network_type nettype,
                                                     state_set const &state_history,
                                                     state_set const &state_archive,
                                                     std::unordered_map<crypto::hash, state_t> const &alt_states,
                                                     const cryptonote::block &block,
                                                     const std::vector<cryptonote::transaction> &txs,
                                                     const service_node_keys *my_keys)
  {
    ++height;
    bool need_swarm_update = false;
    uint64_t block_height  = cryptonote::get_block_height(block);
    assert(height == block_height);
    quorums                  = {};
    block_hash               = cryptonote::get_block_hash(block);
    uint8_t const hf_version = block.major_version;

    //
    // Generate Pulse Quorum before any SN changes are applied to the list because,
    // the Leader and Validators for this block generated Pulse Data before any
    // TX's included in the block were applied
    //   i.e. before any deregistrations, registrations, decommissions, recommissions.
    //
    crypto::public_key winner_pubkey = cryptonote::get_service_node_winner_from_tx_extra(block.miner_tx.extra);
    if (hf_version >= cryptonote::network_version_16_pulse)
    {
      std::vector<crypto::hash> entropy = get_pulse_entropy_for_next_block(db, block.prev_id, block.pulse.round);
      quorum pulse_quorum = generate_pulse_quorum(nettype, winner_pubkey, hf_version, active_service_nodes_infos(), entropy, block.pulse.round);
      if (verify_pulse_quorum_sizes(pulse_quorum))
      {
        // NOTE: Send candidate to the back of the list
        for (size_t quorum_index = 0 ; quorum_index < pulse_quorum.validators.size(); quorum_index++)
        {
          crypto::public_key const &key                          = pulse_quorum.validators[quorum_index];
          auto &info_ptr                                         = service_nodes_infos[key];
          service_node_info &new_info                            = duplicate_info(info_ptr);
          new_info.pulse_sorter.last_height_validating_in_quorum = height;
          new_info.pulse_sorter.quorum_index                     = quorum_index;
        }

        quorums.pulse = std::make_shared<service_nodes::quorum>(std::move(pulse_quorum));
      }
    }

    //
    // Remove expired blacklisted key images
    //
    if (hf_version >= cryptonote::network_version_11_infinite_staking)
    {
      for (auto entry = key_image_blacklist.begin(); entry != key_image_blacklist.end();)
      {
        if (block_height >= entry->unlock_height)
          entry = key_image_blacklist.erase(entry);
        else
          entry++;
      }
    }

    //
    // Expire Nodes
    //
    for (const crypto::public_key& pubkey : get_expired_nodes(db, nettype, block.major_version, block_height))
    {
      auto i = service_nodes_infos.find(pubkey);
      if (i != service_nodes_infos.end())
      {
        if (my_keys && my_keys->pub == pubkey) MGINFO_GREEN("Service node expired (yours): " << pubkey << " at block height: " << block_height);
        else                                   LOG_PRINT_L1("Service node expired: " << pubkey << " at block height: " << block_height);

        need_swarm_update += i->second->is_active();
        service_nodes_infos.erase(i);
      }
    }

    //
    // Advance the list to the next candidate for a reward
    //
    {
      auto it = service_nodes_infos.find(winner_pubkey);
      if (it != service_nodes_infos.end())
      {
        // set the winner as though it was re-registering at transaction index=UINT32_MAX for this block
        auto &info = duplicate_info(it->second);
        info.last_reward_block_height = block_height;
        info.last_reward_transaction_index = UINT32_MAX;
      }
    }

    //
    // Process TXs in the Block
    //
    cryptonote::txtype max_tx_type     = cryptonote::transaction::get_max_type_for_hf(hf_version);
    cryptonote::txtype staking_tx_type = (max_tx_type < cryptonote::txtype::stake) ? cryptonote::txtype::standard : cryptonote::txtype::stake;
    for (uint32_t index = 0; index < txs.size(); ++index)
    {
      const cryptonote::transaction& tx = txs[index];
      if (tx.type == staking_tx_type)
      {
        process_registration_tx(nettype, block, tx, index, my_keys);
        need_swarm_update += process_contribution_tx(nettype, block, tx, index);
      }
      else if (tx.type == cryptonote::txtype::state_change)
      {
        need_swarm_update += process_state_change_tx(state_history, state_archive, alt_states, nettype, block, tx, my_keys);
      }
      else if (tx.type == cryptonote::txtype::key_image_unlock)
      {
        process_key_image_unlock_tx(nettype, block_height, tx);
      }
    }

    // Filtered pubkey-sorted vector of service nodes that are active (fully funded and *not* decommissioned).
    std::vector<pubkey_and_sninfo> active_snode_list = sort_and_filter(service_nodes_infos, [](const service_node_info &info) { return info.is_active(); });

    if (need_swarm_update)
    {
      crypto::hash const block_hash = cryptonote::get_block_hash(block);
      uint64_t seed = 0;
      std::memcpy(&seed, block_hash.data, sizeof(seed));

      /// Gather existing swarms from infos
      swarm_snode_map_t existing_swarms;
      for (const auto &key_info : active_snode_list)
        existing_swarms[key_info.second->swarm_id].push_back(key_info.first);

      calc_swarm_changes(existing_swarms, seed);

      /// Apply changes
      for (const auto& [swarm_id, snodes] : existing_swarms) {
        for (const auto& snode : snodes) {
          auto& sn_info_ptr = service_nodes_infos.at(snode);
          if (sn_info_ptr->swarm_id == swarm_id) continue; /// nothing changed for this snode
          duplicate_info(sn_info_ptr).swarm_id = swarm_id;
        }
      }
    }

    generate_other_quorums(*this, active_snode_list, nettype, hf_version);
  }

  void service_node_list::process_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    uint64_t block_height = cryptonote::get_block_height(block);
    uint8_t hf_version    = block.major_version;

    if (hf_version < cryptonote::network_version_9_service_nodes)
      return;

    // Cull old history
    uint64_t cull_height = short_term_state_cull_height(hf_version, block_height);
    {
      auto end_it = m_transient.state_history.upper_bound(cull_height);
      for (auto it = m_transient.state_history.begin(); it != end_it; it++)
      {
        if (m_store_quorum_history)
          m_transient.old_quorum_states.emplace_back(it->height, it->quorums);

        uint64_t next_long_term_state         = ((it->height / STORE_LONG_TERM_STATE_INTERVAL) + 1) * STORE_LONG_TERM_STATE_INTERVAL;
        uint64_t dist_to_next_long_term_state = next_long_term_state - it->height;
        bool need_quorum_for_future_states    = (dist_to_next_long_term_state <= VOTE_LIFETIME + VOTE_OR_TX_VERIFY_HEIGHT_BUFFER);
        if ((it->height % STORE_LONG_TERM_STATE_INTERVAL) == 0 || need_quorum_for_future_states)
        {
          m_transient.state_added_to_archive = true;
          if (need_quorum_for_future_states) // Preserve just quorum
          {
            state_t &state            = const_cast<state_t &>(*it); // safe: set order only depends on state_t.height
            state.service_nodes_infos = {};
            state.key_image_blacklist = {};
            state.only_loaded_quorums = true;
          }
          m_transient.state_archive.emplace_hint(m_transient.state_archive.end(), std::move(*it));
        }

      }
      m_transient.state_history.erase(m_transient.state_history.begin(), end_it);

      if (m_transient.old_quorum_states.size() > m_store_quorum_history)
        m_transient.old_quorum_states.erase(m_transient.old_quorum_states.begin(), m_transient.old_quorum_states.begin() + (m_transient.old_quorum_states.size() -  m_store_quorum_history));
    }

    // Cull alt state history
    for (auto it = m_transient.alt_state.begin(); it != m_transient.alt_state.end(); )
    {
      state_t const &alt_state = it->second;
      if (alt_state.height < cull_height) it = m_transient.alt_state.erase(it);
      else it++;
    }

    cryptonote::network_type nettype = m_blockchain.nettype();
    m_transient.state_history.insert(m_transient.state_history.end(), m_state);
    m_state.update_from_block(m_blockchain.get_db(), nettype, m_transient.state_history, m_transient.state_archive, {}, block, txs, m_service_node_keys);
  }

  void service_node_list::blockchain_detached(uint64_t height, bool /*by_pop_blocks*/)
  {
    std::lock_guard lock(m_sn_mutex);

    uint64_t revert_to_height = height - 1;
    bool reinitialise         = false;
    bool using_archive        = false;
    {
      auto it = m_transient.state_history.find(revert_to_height); // Try finding detached height directly
      reinitialise = (it == m_transient.state_history.end() || it->only_loaded_quorums);
      if (!reinitialise)
        m_transient.state_history.erase(std::next(it), m_transient.state_history.end());
    }

    // TODO(oxen): We should loop through the prev 10k heights for robustness, but avoid for v4.0.5. Already enough changes going in
    if (reinitialise) // Try finding the next closest old state at 10k intervals
    {
      uint64_t prev_interval = revert_to_height - (revert_to_height % STORE_LONG_TERM_STATE_INTERVAL);
      auto it                = m_transient.state_archive.find(prev_interval);
      reinitialise           = (it == m_transient.state_archive.end() || it->only_loaded_quorums);
      if (!reinitialise)
      {
        m_transient.state_history.clear();
        m_transient.state_archive.erase(std::next(it), m_transient.state_archive.end());
        using_archive = true;
      }
    }

    if (reinitialise)
    {
      m_transient.state_history.clear();
      m_transient.state_archive.clear();
      init();
      return;
    }

    auto &history = (using_archive) ? m_transient.state_archive : m_transient.state_history;
    auto it = std::prev(history.end());
    m_state = std::move(*it);
    history.erase(it);
  }

  std::vector<crypto::public_key> service_node_list::state_t::get_expired_nodes(cryptonote::BlockchainDB const &db,
                                                                               cryptonote::network_type nettype,
                                                                               uint8_t hf_version,
                                                                               uint64_t block_height) const
  {
    std::vector<crypto::public_key> expired_nodes;
    uint64_t const lock_blocks = staking_num_lock_blocks(nettype);

    // TODO(oxen): This should really use the registration height instead of getting the block and expiring nodes.
    // But there's something subtly off when using registration height causing syncing problems.
    if (hf_version == cryptonote::network_version_9_service_nodes)
    {
      if (block_height <= lock_blocks)
        return expired_nodes;

      const uint64_t expired_nodes_block_height = block_height - lock_blocks;
      cryptonote::block block                   = {};
      try
      {
        block = db.get_block_from_height(expired_nodes_block_height);
      }
      catch (std::exception const &e)
      {
        LOG_ERROR("Failed to get historical block to find expired nodes in v9: " << e.what());
        return expired_nodes;
      }

      if (block.major_version < cryptonote::network_version_9_service_nodes)
        return expired_nodes;

      for (crypto::hash const &hash : block.tx_hashes)
      {
        cryptonote::transaction tx;
        if (!db.get_tx(hash, tx))
        {
          LOG_ERROR("Failed to get historical tx to find expired service nodes in v9");
          continue;
        }

        uint32_t index = 0;
        crypto::public_key key;
        service_node_info info = {};
        if (is_registration_tx(nettype, cryptonote::network_version_9_service_nodes, tx, block.timestamp, expired_nodes_block_height, index, key, info))
          expired_nodes.push_back(key);
        index++;
      }

    }
    else
    {
      for (auto it = service_nodes_infos.begin(); it != service_nodes_infos.end(); it++)
      {
        crypto::public_key const &snode_key = it->first;
        const service_node_info &info       = *it->second;
        if (info.registration_hf_version >= cryptonote::network_version_11_infinite_staking)
        {
          if (info.requested_unlock_height != KEY_IMAGE_AWAITING_UNLOCK_HEIGHT && block_height > info.requested_unlock_height)
            expired_nodes.push_back(snode_key);
        }
        else // Version 10 Bulletproofs
        {
          /// Note: this code exhibits a subtle unintended behaviour: a snode that
          /// registered in hardfork 9 and was scheduled for deregistration in hardfork 10
          /// will have its life is slightly prolonged by the "grace period", although it might
          /// look like we use the registration height to determine the expiry height.
          uint64_t node_expiry_height = info.registration_height + lock_blocks + STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS;
          if (block_height > node_expiry_height)
            expired_nodes.push_back(snode_key);
        }
      }
    }

    return expired_nodes;
  }

  service_nodes::payout service_node_list::state_t::get_block_leader() const
  {
    crypto::public_key key = crypto::null_pkey;
    service_node_info const *info = nullptr;
    {
      auto oldest_waiting = std::make_tuple(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint32_t>::max(), crypto::null_pkey);
      for (const auto &info_it : service_nodes_infos)
      {
        const auto &sninfo = *info_it.second;
        if (sninfo.is_active())
        {
          auto waiting_since = std::make_tuple(sninfo.last_reward_block_height, sninfo.last_reward_transaction_index, info_it.first);
          if (waiting_since < oldest_waiting)
          {
            oldest_waiting = waiting_since;
            info           = &sninfo;
          }
        }
      }
      key = std::get<2>(oldest_waiting);
    }

    if (key == crypto::null_pkey)
      return service_nodes::null_payout;
    return service_node_info_to_payout(key, *info);
  }

  template <typename T>
  static constexpr bool within_one(T a, T b) {
      return (a > b ? a - b : b - a) <= T{1};
  }

  // NOTE: Verify queued service node coinbase or pulse block producer rewards
  static bool verify_coinbase_tx_output(cryptonote::transaction const &miner_tx,
                                        uint64_t height,
                                        size_t output_index,
                                        cryptonote::account_public_address const &receiver,
                                        uint64_t reward)
  {
    if (output_index >= miner_tx.vout.size())
    {
      MGINFO_RED("Output Index: " << output_index << ", indexes out of bounds in vout array with size: " << miner_tx.vout.size());
      return false;
    }

    cryptonote::tx_out const &output = miner_tx.vout[output_index];

    // Because FP math is involved in reward calculations (and compounded by CPUs, compilers,
    // expression contraction, and RandomX fiddling with the rounding modes) we can end up with a
    // 1 ULP difference in the reward calculations.
    // TODO(oxen): eliminate all FP math from reward calculations
    if (!within_one(output.amount, reward))
    {
      MGINFO_RED("Service node reward amount incorrect. Should be " << cryptonote::print_money(reward) << ", is: " << cryptonote::print_money(output.amount));
      return false;
    }

    if (!std::holds_alternative<cryptonote::txout_to_key>(output.target))
    {
      MGINFO_RED("Service node output target type should be txout_to_key");
      return false;
    }

    // NOTE: Loki uses the governance key in the one-time ephemeral key
    // derivation for both Pulse Block Producer/Queued Service Node Winner rewards
    crypto::key_derivation derivation{};
    crypto::public_key out_eph_public_key{};
    cryptonote::keypair gov_key = cryptonote::get_deterministic_keypair_from_height(height);

    bool r = crypto::generate_key_derivation(receiver.m_view_public_key, gov_key.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to generate_key_derivation(" << receiver.m_view_public_key << ", " << gov_key.sec << ")");
    r = crypto::derive_public_key(derivation, output_index, receiver.m_spend_public_key, out_eph_public_key);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< receiver.m_spend_public_key << ")");

    if (var::get<cryptonote::txout_to_key>(output.target).key != out_eph_public_key)
    {
      MGINFO_RED("Invalid service node reward at output: " << output_index << ", output key, specifies wrong key");
      return false;
    }

    return true;
  }

  bool service_node_list::validate_miner_tx(cryptonote::block const &block, cryptonote::block_reward_parts const &reward_parts) const
  {
    uint8_t const hf_version = block.major_version;
    if (hf_version < cryptonote::network_version_9_service_nodes)
      return true;

    std::lock_guard lock(m_sn_mutex);
    uint64_t const height                   = cryptonote::get_block_height(block);
    cryptonote::transaction const &miner_tx = block.miner_tx;

    // NOTE: Basic queued service node list winner checks
    // NOTE(oxen): Service node reward distribution is calculated from the
    // original amount, i.e. 50% of the original base reward goes to service
    // nodes not 50% of the reward after removing the governance component (the
    // adjusted base reward post hardfork 10).
    payout const block_leader = m_state.get_block_leader();
    {
      auto const check_block_leader_pubkey = cryptonote::get_service_node_winner_from_tx_extra(miner_tx.extra);
      if (block_leader.key != check_block_leader_pubkey)
      {
        MGINFO_RED("Service node reward winner is incorrect! Expected " << block_leader.key << ", block has " << check_block_leader_pubkey);
        return false;
      }
    }

    enum struct verify_mode
    {
      miner,
      pulse_block_leader_is_producer,
      pulse_different_block_producer,
      batched_no_outputs,
      batched_bulk_outputs,
    };

    verify_mode mode                      = verify_mode::miner;
    crypto::public_key block_producer_key = {};

    //
    // NOTE: Determine if block leader/producer are different or the same.
    //
    if (cryptonote::block_has_pulse_components(block))
    {
      std::vector<crypto::hash> entropy = get_pulse_entropy_for_next_block(m_blockchain.get_db(), block.prev_id, block.pulse.round);
      quorum pulse_quorum = generate_pulse_quorum(m_blockchain.nettype(), block_leader.key, hf_version, m_state.active_service_nodes_infos(), entropy, block.pulse.round);
      if (!verify_pulse_quorum_sizes(pulse_quorum))
      {
        MGINFO_RED("Pulse block received but Pulse has insufficient nodes for quorum, block hash " << cryptonote::get_block_hash(block) << ", height " << height);
        return false;
      }

      block_producer_key = pulse_quorum.workers[0];
      mode               = (block_producer_key == block_leader.key) ? verify_mode::pulse_block_leader_is_producer
                                                                    : verify_mode::pulse_different_block_producer;

      if (block.pulse.round == 0 && (mode == verify_mode::pulse_different_block_producer))
      {
        MGINFO_RED("The block producer in pulse round 0 should be the same node as the block leader: " << block_leader.key << ", actual producer: " << block_producer_key);
        return false;
      }
    }

    // NOTE: Verify miner tx vout composition
    //
    // Miner Block
    // 1       | Miner
    // Up To 4 | Queued Service Node
    // Up To 1 | Governance
    //
    // Pulse Block
    // Up to 4 | Block Producer (0-3 for Pooled Service Node)
    // Up To 4 | Queued Service Node
    // Up To 1 | Governance
    //
    // NOTE: See cryptonote_tx_utils.cpp construct_miner_tx(...) for payment details.
    //

    std::shared_ptr<const service_node_info> block_producer = nullptr;
    size_t expected_vouts_size                        = 0;

    //TODO sean - 
    // - Check that a batch should be paid out, compare with the output of get_sn_payments
    // - Check that the new amount in the block is right
    // - Check that the winner in the block is actually the winner
    // - Check that the height in the block matches the height in coinbase if exists and it is in order
    // - Check that the Service node winner is actually an address
    // - Check that the amount of contributors is correct in the block when calling add_block(contributors)
    // - Hard code a limit to the block amount?
    if (block.major_version >= cryptonote::network_version_19)
      return true;

    //mode = verify_mode::batched_no_outputs;
    //MGINFO("Batched miner reward");
    // make a verify_mode for this.
    if (mode == verify_mode::pulse_block_leader_is_producer || mode == verify_mode::pulse_different_block_producer)
    {
      auto info_it = m_state.service_nodes_infos.find(block_producer_key);
      if (info_it == m_state.service_nodes_infos.end())
      {
        MGINFO_RED("The pulse block producer for round: " << +block.pulse.round << " is not currently a Service Node: " << block_producer_key);
        return false;
      }

      block_producer = info_it->second;
      if (mode == verify_mode::pulse_different_block_producer && reward_parts.miner_fee > 0)
      {
        expected_vouts_size += block_producer->contributors.size();
      }
    }
    else
    {
      if ((reward_parts.base_miner + reward_parts.miner_fee) > 0) // (HF >= 16) this can be zero, no miner coinbase.
      {
        expected_vouts_size += 1; /*miner*/
      }
    }

    if (mode != verify_mode::batched_no_outputs)
    {
      expected_vouts_size += block_leader.payouts.size();
    }
    expected_vouts_size += static_cast<size_t>(cryptonote::height_has_governance_output(m_blockchain.nettype(), hf_version, height));
    if (miner_tx.vout.size() != expected_vouts_size)
    {
      char const *type = mode == verify_mode::miner
                             ? "miner"
                             : mode == verify_mode::pulse_block_leader_is_producer ? "pulse" : "pulse alt round";
      MGINFO_RED("Expected " << type << " block, the miner TX specifies a different amount of outputs vs the expected: " << expected_vouts_size << ", miner tx outputs: " << miner_tx.vout.size());
      return false;
    }

    if (hf_version >= cryptonote::network_version_16_pulse)
    {
      if (reward_parts.base_miner != 0)
      {
        MGINFO_RED("Miner reward is incorrect expected 0 reward, block specified " << cryptonote::print_money(reward_parts.base_miner));
        return false;
      }
    }

    // NOTE: Verify Coinbase Amounts
    switch(mode)
    {
      case verify_mode::miner:
      {
        size_t vout_index = 0 + (reward_parts.base_miner + reward_parts.miner_fee > 0);

        // We don't verify the miner reward amount because it is already implied by the overall
        // sum of outputs check and because when there are truncation errors on other outputs the
        // miner reward ends up with the difference (and so actual miner output amount can be a few
        // atoms larger than base_miner+miner_fee).

        std::vector<uint64_t> split_rewards = cryptonote::distribute_reward_by_portions(block_leader.payouts,
                                                                                        reward_parts.service_node_total,
                                                                                        hf_version >= cryptonote::network_version_16_pulse /*distribute_remainder*/);

        for (size_t i = 0; i < block_leader.payouts.size(); i++)
        {
          payout_entry const &payout = block_leader.payouts[i];
          if (split_rewards[i])
          {
            if (!verify_coinbase_tx_output(miner_tx, height, vout_index, payout.address, split_rewards[i]))
              return false;
            vout_index++;
          }
        }
      }
      break;

      case verify_mode::pulse_block_leader_is_producer:
      {
        uint64_t total_reward = reward_parts.service_node_total + reward_parts.miner_fee;
        std::vector<uint64_t> split_rewards = cryptonote::distribute_reward_by_portions(block_leader.payouts, total_reward, true /*distribute_remainder*/);
        assert(total_reward > 0);

        size_t vout_index = 0;
        for (size_t i = 0; i < block_leader.payouts.size(); i++)
        {
          payout_entry const &payout = block_leader.payouts[i];
          if (split_rewards[i])
          {
            if (!verify_coinbase_tx_output(miner_tx, height, vout_index, payout.address, split_rewards[i]))
              return false;
            vout_index++;
          }
        }
      }
      break;

      case verify_mode::pulse_different_block_producer:
      {
        size_t vout_index = 0;
        {
          payout block_producer_payouts       = service_node_info_to_payout(block_producer_key, *block_producer);
          std::vector<uint64_t> split_rewards = cryptonote::distribute_reward_by_portions(block_producer_payouts.payouts, reward_parts.miner_fee, true /*distribute_remainder*/);
          for (size_t i = 0; i < block_producer_payouts.payouts.size(); i++)
          {
            payout_entry const &payout = block_producer_payouts.payouts[i];
            if (split_rewards[i])
            {
              if (!verify_coinbase_tx_output(miner_tx, height, vout_index, payout.address, split_rewards[i]))
                return false;
              vout_index++;
            }
          }
        }

        std::vector<uint64_t> split_rewards = cryptonote::distribute_reward_by_portions(block_leader.payouts, reward_parts.service_node_total, true /*distribute_remainder*/);
        for (size_t i = 0; i < block_leader.payouts.size(); i++)
        {
          payout_entry const &payout = block_leader.payouts[i];
          if (split_rewards[i])
          {
            if (!verify_coinbase_tx_output(miner_tx, height, vout_index, payout.address, split_rewards[i]))
              return false;
            vout_index++;
          }
        }
      }
      break;

      case verify_mode::batched_no_outputs:
      {
        //TODO sean do some checks here
      }
      break;

      case verify_mode::batched_bulk_outputs:
      {
        //TODO sean do some checks here
      }
      break;
    }

    return true;
  }

  bool service_node_list::alt_block_added(cryptonote::block const &block, std::vector<cryptonote::transaction> const &txs, cryptonote::checkpoint_t const *checkpoint)
  {
    // NOTE: The premise is to search the main list and the alternative list for
    // the parent of the block we just received, generate the new Service Node
    // state with this alt-block and verify that the block passes all
    // the necessary checks.

    // On success, this function returns true, signifying the block is valid to
    // store into the alt-chain until it gathers enough blocks to cause
    // a reorganization (more checkpoints/PoW than the main chain).

    if (block.major_version < cryptonote::network_version_9_service_nodes)
      return true;

    uint64_t block_height         = cryptonote::get_block_height(block);
    state_t const *starting_state = nullptr;
    crypto::hash const block_hash = get_block_hash(block);

    auto it = m_transient.alt_state.find(block_hash);
    if (it != m_transient.alt_state.end()) return true; // NOTE: Already processed alt-state for this block

    // NOTE: Check if alt block forks off some historical state on the canonical chain
    if (!starting_state)
    {
      auto it = m_transient.state_history.find(block_height - 1);
      if (it != m_transient.state_history.end())
        if (block.prev_id == it->block_hash) starting_state = &(*it);
    }

    // NOTE: Check if alt block forks off some historical alt state on an alt chain
    if (!starting_state)
    {
      auto it = m_transient.alt_state.find(block.prev_id);
      if (it != m_transient.alt_state.end()) starting_state = &it->second;
    }

    if (!starting_state)
    {
      LOG_PRINT_L1("Received alt block but couldn't find parent state in historical state");
      return false;
    }

    if (starting_state->block_hash != block.prev_id)
    {
      LOG_PRINT_L1("Unexpected state_t's hash: " << starting_state->block_hash
                                                 << ", does not match the block prev hash: " << block.prev_id);
      return false;
    }

    // NOTE: Generate the next Service Node list state from this Alt block.
    state_t alt_state = *starting_state;
    alt_state.update_from_block(m_blockchain.get_db(), m_blockchain.nettype(), m_transient.state_history, m_transient.state_archive, m_transient.alt_state, block, txs, m_service_node_keys);
    auto alt_it = m_transient.alt_state.find(block_hash);
    if (alt_it != m_transient.alt_state.end())
      alt_it->second = std::move(alt_state);
    else
      m_transient.alt_state.emplace(block_hash, std::move(alt_state));

    return verify_block(block, true /*alt_block*/, checkpoint);
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  static service_node_list::quorum_for_serialization serialize_quorum_state(uint8_t hf_version, uint64_t height, quorum_manager const &quorums)
  {
    service_node_list::quorum_for_serialization result = {};
    result.height                                      = height;
    if (quorums.obligations)   result.quorums[static_cast<uint8_t>(quorum_type::obligations)] = *quorums.obligations;
    if (quorums.checkpointing) result.quorums[static_cast<uint8_t>(quorum_type::checkpointing)] = *quorums.checkpointing;
    return result;
  }

  static service_node_list::state_serialized serialize_service_node_state_object(uint8_t hf_version, service_node_list::state_t const &state, bool only_serialize_quorums = false)
  {
    service_node_list::state_serialized result = {};
    result.version                             = service_node_list::state_serialized::get_version(hf_version);
    result.height                              = state.height;
    result.quorums                             = serialize_quorum_state(hf_version, state.height, state.quorums);
    result.only_stored_quorums                 = state.only_loaded_quorums || only_serialize_quorums;

    if (only_serialize_quorums)
     return result;

    result.infos.reserve(state.service_nodes_infos.size());
    for (const auto &kv_pair : state.service_nodes_infos)
      result.infos.emplace_back(kv_pair);

    result.key_image_blacklist = state.key_image_blacklist;
    result.block_hash          = state.block_hash;
    return result;
  }

  bool service_node_list::store()
  {
    if (!m_blockchain.has_db())
        return false; // Haven't been initialized yet

    uint8_t hf_version = m_blockchain.get_network_version();
    if (hf_version < cryptonote::network_version_9_service_nodes)
      return true;

    data_for_serialization *data[] = {&m_transient.cache_long_term_data, &m_transient.cache_short_term_data};
    auto const serialize_version   = data_for_serialization::get_version(hf_version);
    std::lock_guard lock(m_sn_mutex);

    for (data_for_serialization *serialize_entry : data)
    {
      if (serialize_entry->version != serialize_version) m_transient.state_added_to_archive = true;
      serialize_entry->version = serialize_version;
      serialize_entry->clear();
    }

    m_transient.cache_short_term_data.quorum_states.reserve(m_transient.old_quorum_states.size());
    for (const quorums_by_height &entry : m_transient.old_quorum_states)
      m_transient.cache_short_term_data.quorum_states.push_back(serialize_quorum_state(hf_version, entry.height, entry.quorums));


    if (m_transient.state_added_to_archive)
    {
      for (auto const &it : m_transient.state_archive)
        m_transient.cache_long_term_data.states.push_back(serialize_service_node_state_object(hf_version, it));
    }

    // NOTE: A state_t may reference quorums up to (VOTE_LIFETIME
    // + VOTE_OR_TX_VERIFY_HEIGHT_BUFFER) blocks back. So in the
    // (MAX_SHORT_TERM_STATE_HISTORY | 2nd oldest checkpoint) window of states we store, the
    // first (VOTE_LIFETIME + VOTE_OR_TX_VERIFY_HEIGHT_BUFFER) states we only
    // store their quorums, such that the following states have quorum
    // information preceeding it.

    uint64_t const max_short_term_height = short_term_state_cull_height(hf_version, (m_state.height - 1)) + VOTE_LIFETIME + VOTE_OR_TX_VERIFY_HEIGHT_BUFFER;
    for (auto it = m_transient.state_history.begin();
         it != m_transient.state_history.end() && it->height <= max_short_term_height;
         it++)
    {
      // TODO(oxen): There are 2 places where we convert a state_t to be a serialized state_t without quorums. We should only do this in one location for clarity.
      m_transient.cache_short_term_data.states.push_back(serialize_service_node_state_object(hf_version, *it, it->height < max_short_term_height /*only_serialize_quorums*/));
    }

    m_transient.cache_data_blob.clear();
    if (m_transient.state_added_to_archive)
    {
      serialization::binary_string_archiver ba;
      try {
        serialization::serialize(ba, m_transient.cache_long_term_data);
      } catch (const std::exception& e) {
        LOG_ERROR("Failed to store service node info: failed to serialize long term data: " << e.what());
        return false;
      }
      m_transient.cache_data_blob.append(ba.str());
      {
        auto &db = m_blockchain.get_db();
        cryptonote::db_wtxn_guard txn_guard{db};
        db.set_service_node_data(m_transient.cache_data_blob, true /*long_term*/);
      }
    }

    m_transient.cache_data_blob.clear();
    {
      serialization::binary_string_archiver ba;
      try {
        serialization::serialize(ba, m_transient.cache_short_term_data);
      } catch (const std::exception& e) {
        LOG_ERROR("Failed to store service node info: failed to serialize short term data: " << e.what());
        return false;
      }
      m_transient.cache_data_blob.append(ba.str());
      {
        auto &db = m_blockchain.get_db();
        cryptonote::db_wtxn_guard txn_guard{db};
        db.set_service_node_data(m_transient.cache_data_blob, false /*long_term*/);
      }
    }

    m_transient.state_added_to_archive = false;
    return true;
  }

  //TODO: remove after HF18, snode revision 1
  crypto::hash service_node_list::hash_uptime_proof(const cryptonote::NOTIFY_UPTIME_PROOF::request &proof) const
  {
    size_t buf_size;
    crypto::hash result;

    auto buf = tools::memcpy_le(proof.pubkey.data, proof.timestamp, proof.public_ip, proof.storage_https_port, proof.pubkey_ed25519.data, proof.qnet_port, proof.storage_omq_port);
    buf_size = buf.size();
    crypto::cn_fast_hash(buf.data(), buf_size, result);
    return result;
  }

  cryptonote::NOTIFY_UPTIME_PROOF::request service_node_list::generate_uptime_proof(
      uint32_t public_ip, uint16_t storage_https_port, uint16_t storage_omq_port, uint16_t quorumnet_port) const
  {
    assert(m_service_node_keys);
    const auto& keys = *m_service_node_keys;
    cryptonote::NOTIFY_UPTIME_PROOF::request result = {};
    result.snode_version                            = OXEN_VERSION;
    result.timestamp                                = time(nullptr);
    result.pubkey                                   = keys.pub;
    result.public_ip                                = public_ip;
    result.storage_https_port                       = storage_https_port;
    result.storage_omq_port                         = storage_omq_port;
    result.qnet_port                                = quorumnet_port;
    result.pubkey_ed25519                           = keys.pub_ed25519;

    crypto::hash hash = hash_uptime_proof(result);
    crypto::generate_signature(hash, keys.pub, keys.key, result.sig);
    crypto_sign_detached(result.sig_ed25519.data, NULL, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), keys.key_ed25519.data);
    return result;
  }

  uptime_proof::Proof service_node_list::generate_uptime_proof(uint32_t public_ip, uint16_t storage_https_port, uint16_t storage_omq_port, std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, std::array<uint16_t, 3> lokinet_version) const
  {
    const auto& keys = *m_service_node_keys;
    return uptime_proof::Proof(public_ip, storage_https_port, storage_omq_port, ss_version, quorumnet_port, lokinet_version, keys);
  }

#ifdef __cpp_lib_erase_if // # (C++20)
  using std::erase_if;
#else
  template <typename Container, typename Predicate>
  static void erase_if(Container &c, Predicate pred) {
    for (auto it = c.begin(), last = c.end(); it != last; ) {
      if (pred(*it))
        it = c.erase(it);
      else
        ++it;
    }
  }
#endif

  template <typename T>
  static bool update_val(T &val, const T &to) {
    if (val != to) {
      val = to;
      return true;
    }
    return false;
  }

  proof_info::proof_info()
    : proof(std::make_unique<uptime_proof::Proof>()) {};

  void proof_info::store(const crypto::public_key &pubkey, cryptonote::Blockchain &blockchain)
  {
    if (!proof) proof = std::unique_ptr<uptime_proof::Proof>(new uptime_proof::Proof());
    std::unique_lock lock{blockchain};
    auto &db = blockchain.get_db();
    db.set_service_node_proof(pubkey, *this);
  }

  bool proof_info::update(uint64_t ts, std::unique_ptr<uptime_proof::Proof> new_proof, const crypto::x25519_public_key &pk_x2)
  {
    bool update_db = false;
    if (!proof || *proof != *new_proof) {
      update_db = true;
      proof = std::move(new_proof);
    }
    update_db |= update_val(timestamp, ts);
    effective_timestamp = timestamp;
    pubkey_x25519 = pk_x2;

    // Track an IP change (so that the obligations quorum can penalize for IP changes)
    // We only keep the two most recent because all we really care about is whether it had more than one
    //
    // If we already know about the IP, update its timestamp:
    auto now = std::time(nullptr);
    if (public_ips[0].first && public_ips[0].first == proof->public_ip)
      public_ips[0].second = now;
    else if (public_ips[1].first && public_ips[1].first == proof->public_ip)
      public_ips[1].second = now;
    // Otherwise replace whichever IP has the older timestamp
    else if (public_ips[0].second > public_ips[1].second)
      public_ips[1] = {proof->public_ip, now};
    else
      public_ips[0] = {proof->public_ip, now};

    return update_db;
  };


  //TODO remove after HF18, snode revision 1
  bool proof_info::update(uint64_t ts,
                          uint32_t ip,
                          uint16_t s_https_port,
                          uint16_t s_omq_port,
                          uint16_t q_port,
                          std::array<uint16_t, 3> ver,
                          const crypto::ed25519_public_key& pk_ed,
                          const crypto::x25519_public_key& pk_x2)
  {
    bool update_db = false;
    if (!proof) proof = std::unique_ptr<uptime_proof::Proof>(new uptime_proof::Proof());
    update_db |= update_val(timestamp, ts);
    update_db |= update_val(proof->public_ip, ip);
    update_db |= update_val(proof->storage_https_port, s_https_port);
    update_db |= update_val(proof->storage_omq_port, s_omq_port);
    update_db |= update_val(proof->qnet_port, q_port);
    update_db |= update_val(proof->version, ver);
    update_db |= update_val(proof->pubkey_ed25519, pk_ed);
    effective_timestamp = timestamp;
    pubkey_x25519 = pk_x2;

    // Track an IP change (so that the obligations quorum can penalize for IP changes)
    // We only keep the two most recent because all we really care about is whether it had more than one
    //
    // If we already know about the IP, update its timestamp:
    auto now = std::time(nullptr);
    if (public_ips[0].first && public_ips[0].first == proof->public_ip)
      public_ips[0].second = now;
    else if (public_ips[1].first && public_ips[1].first == proof->public_ip)
      public_ips[1].second = now;
    // Otherwise replace whichever IP has the older timestamp
    else if (public_ips[0].second > public_ips[1].second)
      public_ips[1] = {proof->public_ip, now};
    else
      public_ips[0] = {proof->public_ip, now};

    return update_db;
  };

  void proof_info::update_pubkey(const crypto::ed25519_public_key &pk) {
    if (pk == proof->pubkey_ed25519)
      return;
    if (pk && 0 == crypto_sign_ed25519_pk_to_curve25519(pubkey_x25519.data, pk.data)) {
      proof->pubkey_ed25519 = pk;
    } else {
      MWARNING("Failed to derive x25519 pubkey from ed25519 pubkey " << proof->pubkey_ed25519);
      pubkey_x25519 = crypto::x25519_public_key::null();
      proof->pubkey_ed25519 = crypto::ed25519_public_key::null();
    }
  }

#define REJECT_PROOF(log) do { LOG_PRINT_L2("Rejecting uptime proof from " << proof.pubkey << ": " log); return false; } while (0)

  //TODO remove after HF18, snode revision 1
  bool service_node_list::handle_uptime_proof(cryptonote::NOTIFY_UPTIME_PROOF::request const &proof, bool &my_uptime_proof_confirmation, crypto::x25519_public_key &x25519_pkey)
  {
    auto vers = get_network_version_revision(m_blockchain.nettype(), m_blockchain.get_current_blockchain_height());
    if (vers >= std::pair<uint8_t, uint8_t>{cryptonote::network_version_18, 1})
      REJECT_PROOF("Old format (non-bt) proofs are not acceptable from v18+1 onwards");

    auto& netconf = get_config(m_blockchain.nettype());
    auto now = std::chrono::system_clock::now();

    // Validate proof version, timestamp range,
    auto time_deviation = now - std::chrono::system_clock::from_time_t(proof.timestamp);
    if (time_deviation > netconf.UPTIME_PROOF_TOLERANCE || time_deviation < -netconf.UPTIME_PROOF_TOLERANCE)
      REJECT_PROOF("timestamp is too far from now");

    for (auto const &min : MIN_UPTIME_PROOF_VERSIONS)
      if (vers >= min.hardfork_revision && proof.snode_version < min.oxend)
        REJECT_PROOF("v" << tools::join(".", min.oxend) << "+ oxend version is required for v" << +vers.first << "." << +vers.second << "+ network proofs");

    if (!debug_allow_local_ips && !epee::net_utils::is_ip_public(proof.public_ip))
      REJECT_PROOF("public_ip is not actually public");

    //
    // Validate proof signature
    //
    crypto::hash hash = hash_uptime_proof(proof);


    if (!crypto::check_signature(hash, proof.pubkey, proof.sig))
      REJECT_PROOF("signature validation failed");

    crypto::x25519_public_key derived_x25519_pubkey = crypto::x25519_public_key::null();
    if (!proof.pubkey_ed25519)
      REJECT_PROOF("required ed25519 auxiliary pubkey " << proof.pubkey_ed25519 << " not included in proof");

    if (0 != crypto_sign_verify_detached(proof.sig_ed25519.data, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), proof.pubkey_ed25519.data))
      REJECT_PROOF("ed25519 signature validation failed");

    if (0 != crypto_sign_ed25519_pk_to_curve25519(derived_x25519_pubkey.data, proof.pubkey_ed25519.data)
        || !derived_x25519_pubkey)
      REJECT_PROOF("invalid ed25519 pubkey included in proof (x25519 derivation failed)");

    if (proof.qnet_port == 0)
      REJECT_PROOF("invalid quorumnet port in uptime proof");

    auto locks = tools::unique_locks(m_blockchain, m_sn_mutex, m_x25519_map_mutex);
    auto it = m_state.service_nodes_infos.find(proof.pubkey);
    if (it == m_state.service_nodes_infos.end())
      REJECT_PROOF("no such service node is currently registered");

    auto &iproof = proofs[proof.pubkey];


    if (now <= std::chrono::system_clock::from_time_t(iproof.timestamp) + std::chrono::seconds{netconf.UPTIME_PROOF_FREQUENCY} / 2)
      REJECT_PROOF("already received one uptime proof for this node recently");

    if (m_service_node_keys && proof.pubkey == m_service_node_keys->pub)
    {
      my_uptime_proof_confirmation = true;
      MGINFO("Received uptime-proof confirmation back from network for Service Node (yours): " << proof.pubkey);
    }
    else
    {
      my_uptime_proof_confirmation = false;
      LOG_PRINT_L2("Accepted uptime proof from " << proof.pubkey);

      if (m_service_node_keys && proof.pubkey_ed25519 == m_service_node_keys->pub_ed25519)
        MGINFO_RED("Uptime proof from SN " << proof.pubkey << " is not us, but is using our ed/x25519 keys; "
            "this is likely to lead to deregistration of one or both service nodes.");
    }

    auto old_x25519 = iproof.pubkey_x25519;
    if (iproof.update(std::chrono::system_clock::to_time_t(now), proof.public_ip, proof.storage_https_port, proof.storage_omq_port, proof.qnet_port, proof.snode_version, proof.pubkey_ed25519, derived_x25519_pubkey))
      iproof.store(proof.pubkey, m_blockchain);

    if (now - x25519_map_last_pruned >= X25519_MAP_PRUNING_INTERVAL)
    {
      time_t cutoff = std::chrono::system_clock::to_time_t(now - X25519_MAP_PRUNING_LAG);
      erase_if(x25519_to_pub, [&cutoff](auto &x) { return x.second.second < cutoff; });
      x25519_map_last_pruned = now;
    }

    if (old_x25519 && old_x25519 != derived_x25519_pubkey)
      x25519_to_pub.erase(old_x25519);

    if (derived_x25519_pubkey)
      x25519_to_pub[derived_x25519_pubkey] = {proof.pubkey, std::chrono::system_clock::to_time_t(now)};

    if (derived_x25519_pubkey && (old_x25519 != derived_x25519_pubkey))
      x25519_pkey = derived_x25519_pubkey;

    return true;
  }

#undef REJECT_PROOF
#define REJECT_PROOF(log) do { LOG_PRINT_L2("Rejecting uptime proof from " << proof->pubkey << ": " log); return false; } while (0)

  bool service_node_list::handle_btencoded_uptime_proof(std::unique_ptr<uptime_proof::Proof> proof, bool &my_uptime_proof_confirmation, crypto::x25519_public_key &x25519_pkey)
  {
    auto vers = get_network_version_revision(m_blockchain.nettype(), m_blockchain.get_current_blockchain_height());
    auto& netconf = get_config(m_blockchain.nettype());
    auto now = std::chrono::system_clock::now();

    // Validate proof version, timestamp range,
    auto time_deviation = now - std::chrono::system_clock::from_time_t(proof->timestamp);
    if (time_deviation > netconf.UPTIME_PROOF_TOLERANCE || time_deviation < -netconf.UPTIME_PROOF_TOLERANCE)
      REJECT_PROOF("timestamp is too far from now");

    for (auto const &min : MIN_UPTIME_PROOF_VERSIONS) {
      if (vers >= min.hardfork_revision && m_blockchain.nettype() != cryptonote::DEVNET) {
        if (proof->version < min.oxend)
          REJECT_PROOF("v" << tools::join(".", min.oxend) << "+ oxend version is required for v" << +vers.first << "." << +vers.second << "+ network proofs");
        if (proof->lokinet_version < min.lokinet)
          REJECT_PROOF("v" << tools::join(".", min.lokinet) << "+ lokinet version is required for v" << +vers.first << "." << +vers.second << "+ network proofs");
        if (proof->storage_server_version < min.storage_server)
          REJECT_PROOF("v" << tools::join(".", min.storage_server) << "+ storage server version is required for v" << +vers.first << "." << +vers.second << "+ network proofs");
      }
    }

    if (!debug_allow_local_ips && !epee::net_utils::is_ip_public(proof->public_ip))
      REJECT_PROOF("public_ip is not actually public");

    //
    // Validate proof signature
    //
    crypto::hash hash = proof->hash_uptime_proof();

    if (!crypto::check_signature(hash, proof->pubkey, proof->sig))
      REJECT_PROOF("signature validation failed");

    crypto::x25519_public_key derived_x25519_pubkey = crypto::x25519_public_key::null();
    if (!proof->pubkey_ed25519)
      REJECT_PROOF("required ed25519 auxiliary pubkey " << proof->pubkey_ed25519 << " not included in proof");

    if (0 != crypto_sign_verify_detached(proof->sig_ed25519.data, reinterpret_cast<unsigned char *>(hash.data), sizeof(hash.data), proof->pubkey_ed25519.data))
      REJECT_PROOF("ed25519 signature validation failed");

    if (0 != crypto_sign_ed25519_pk_to_curve25519(derived_x25519_pubkey.data, proof->pubkey_ed25519.data)
        || !derived_x25519_pubkey)
      REJECT_PROOF("invalid ed25519 pubkey included in proof (x25519 derivation failed)");

    if (proof->qnet_port == 0)
      REJECT_PROOF("invalid quorumnet port in uptime proof");

    auto locks = tools::unique_locks(m_blockchain, m_sn_mutex, m_x25519_map_mutex);
    auto it = m_state.service_nodes_infos.find(proof->pubkey);
    if (it == m_state.service_nodes_infos.end())
      REJECT_PROOF("no such service node is currently registered");

    auto &iproof = proofs[proof->pubkey];

    if (now <= std::chrono::system_clock::from_time_t(iproof.timestamp) + std::chrono::seconds{netconf.UPTIME_PROOF_FREQUENCY} / 2)
      REJECT_PROOF("already received one uptime proof for this node recently");

    if (m_service_node_keys && proof->pubkey == m_service_node_keys->pub)
    {
      my_uptime_proof_confirmation = true;
      MGINFO("Received uptime-proof confirmation back from network for Service Node (yours): " << proof->pubkey);
    }
    else
    {
      my_uptime_proof_confirmation = false;
      LOG_PRINT_L2("Accepted uptime proof from " << proof->pubkey);

      if (m_service_node_keys && proof->pubkey_ed25519 == m_service_node_keys->pub_ed25519)
        MGINFO_RED("Uptime proof from SN " << proof->pubkey << " is not us, but is using our ed/x25519 keys; "
            "this is likely to lead to deregistration of one or both service nodes.");
    }

    auto old_x25519 = iproof.pubkey_x25519;
    if (iproof.update(std::chrono::system_clock::to_time_t(now), std::move(proof), derived_x25519_pubkey))
    {
      iproof.store(iproof.proof->pubkey, m_blockchain);
    }

    if (now - x25519_map_last_pruned >= X25519_MAP_PRUNING_INTERVAL)
    {
      time_t cutoff = std::chrono::system_clock::to_time_t(now - X25519_MAP_PRUNING_LAG);
      erase_if(x25519_to_pub, [&cutoff](const decltype(x25519_to_pub)::value_type &x) { return x.second.second < cutoff; });
      x25519_map_last_pruned = now;
    }

    if (old_x25519 && old_x25519 != derived_x25519_pubkey)
      x25519_to_pub.erase(old_x25519);

    if (derived_x25519_pubkey)
      x25519_to_pub[derived_x25519_pubkey] = {iproof.proof->pubkey, std::chrono::system_clock::to_time_t(now)};

    if (derived_x25519_pubkey && (old_x25519 != derived_x25519_pubkey))
      x25519_pkey = derived_x25519_pubkey;

    return true;
  }

  void service_node_list::cleanup_proofs()
  {
    MDEBUG("Cleaning up expired SN proofs");
    auto locks = tools::unique_locks(m_sn_mutex, m_blockchain);
    uint64_t now = std::time(nullptr);
    auto& db = m_blockchain.get_db();
    cryptonote::db_wtxn_guard guard{db};
    for (auto it = proofs.begin(); it != proofs.end(); )
    {
      auto& pubkey = it->first;
      auto& proof = it->second;
      // 6h here because there's no harm in leaving proofs around a bit longer (they aren't big, and
      // we only store one per SN), and it's possible that we could reorg a few blocks and resurrect
      // a service node but don't want to prematurely expire the proof.
      if (!m_state.service_nodes_infos.count(pubkey) && proof.timestamp + 6*60*60 < now)
      {
        db.remove_service_node_proof(pubkey);
        it = proofs.erase(it);
      }
      else
        ++it;
    }
  }

  crypto::public_key service_node_list::get_pubkey_from_x25519(const crypto::x25519_public_key &x25519) const {
    std::shared_lock lock{m_x25519_map_mutex};
    auto it = x25519_to_pub.find(x25519);
    if (it != x25519_to_pub.end())
      return it->second.first;
    return crypto::null_pkey;
  }

  crypto::public_key service_node_list::get_random_pubkey() {
    std::lock_guard lock{m_sn_mutex};
    auto it  = tools::select_randomly(m_state.service_nodes_infos.begin(), m_state.service_nodes_infos.end());
    if(it != m_state.service_nodes_infos.end()) {
      return it->first;
    } else {
      return m_state.service_nodes_infos.begin()->first;
    }
  }

  void service_node_list::initialize_x25519_map() {
    auto locks = tools::unique_locks(m_sn_mutex, m_x25519_map_mutex);

    auto now = std::time(nullptr);
    for (const auto &pk_info : m_state.service_nodes_infos)
    {
      auto it = proofs.find(pk_info.first);
      if (it == proofs.end())
       continue;
      if (const auto &x2_pk = it->second.pubkey_x25519)
        x25519_to_pub.emplace(x2_pk, std::make_pair(pk_info.first, now));
    }
  }

  std::string service_node_list::remote_lookup(std::string_view xpk) {
    if (xpk.size() != sizeof(crypto::x25519_public_key))
      return "";
    crypto::x25519_public_key x25519_pub;
    std::memcpy(x25519_pub.data, xpk.data(), xpk.size());

    auto pubkey = get_pubkey_from_x25519(x25519_pub);
    if (!pubkey) {
      MDEBUG("no connection available: could not find primary pubkey from x25519 pubkey " << x25519_pub);
      return "";
    }

    bool found = false;
    uint32_t ip = 0;
    uint16_t port = 0;
    for_each_service_node_info_and_proof(&pubkey, &pubkey + 1, [&](auto&, auto&, auto& proof) {
        found = true;
        ip = proof.proof->public_ip;
        port = proof.proof->qnet_port;
    });

    if (!found) {
      MDEBUG("no connection available: primary pubkey " << pubkey << " is not registered");
      return "";
    }
    if (!(ip && port)) {
      MDEBUG("no connection available: service node " << pubkey << " has no associated ip and/or port");
      return "";
    }

    return "tcp://" + epee::string_tools::get_ip_string_from_int32(ip) + ":" + std::to_string(port);
  }

  void service_node_list::record_checkpoint_participation(crypto::public_key const &pubkey, uint64_t height, bool participated)
  {
    std::lock_guard lock(m_sn_mutex);
    if (!m_state.service_nodes_infos.count(pubkey))
      return;

    participation_entry entry  = {};
    entry.height               = height;
    entry.voted                = participated;

    auto &info = proofs[pubkey];
    info.checkpoint_participation.add(entry);
  }

  void service_node_list::record_pulse_participation(crypto::public_key const &pubkey, uint64_t height, uint8_t round, bool participated)
  {
    std::lock_guard lock(m_sn_mutex);
    if (!m_state.service_nodes_infos.count(pubkey))
      return;

    participation_entry entry  = {};
    entry.is_pulse             = true;
    entry.height               = height;
    entry.voted                = participated;
    entry.pulse.round          = round;

    auto &info = proofs[pubkey];
    info.pulse_participation.add(entry);
  }

  void service_node_list::record_timestamp_participation(crypto::public_key const &pubkey, bool participated)
  {
    std::lock_guard lock(m_sn_mutex);
    if (!m_state.service_nodes_infos.count(pubkey))
      return;

    timestamp_participation_entry entry  = {};
    entry.participated                = participated;

    auto &info = proofs[pubkey];
    info.timestamp_participation.add(entry);
  }

  void service_node_list::record_timesync_status(crypto::public_key const &pubkey, bool synced)
  {
    std::lock_guard lock(m_sn_mutex);
    if (!m_state.service_nodes_infos.count(pubkey))
      return;

    timesync_entry entry  = {};
    entry.in_sync                = synced;

    auto &info = proofs[pubkey];
    info.timesync_status.add(entry);
  }

  std::optional<bool> proof_info::reachable_stats::reachable(const std::chrono::steady_clock::time_point& now) const {
    if (last_reachable >= last_unreachable)
      return true;
    if (last_unreachable > now - config::REACHABLE_MAX_FAILURE_VALIDITY)
      return false;
    // Last result was a failure, but it was a while ago, so we don't know for sure that it isn't
    // reachable now:
    return std::nullopt;
  }

  bool proof_info::reachable_stats::unreachable_for(std::chrono::seconds threshold, const std::chrono::steady_clock::time_point& now) const {
    if (auto maybe_reachable = reachable(now); !maybe_reachable /*stale*/ || *maybe_reachable /*good*/)
      return false;
    if (first_unreachable > now - threshold)
      return false; // Unreachable, but for less than the grace time
    return true;
  }

  bool service_node_list::set_peer_reachable(bool storage_server, const crypto::public_key& pubkey, bool reachable) {

    // (See .h for overview description)

    std::lock_guard lock(m_sn_mutex);

    const auto type = storage_server ? "storage server"sv : "lokinet"sv;

    if (!m_state.service_nodes_infos.count(pubkey)) {
      MDEBUG("Dropping " << type << " reachable report: " << pubkey << " is not a registered SN pubkey");
      return false;
    }

    MDEBUG("Received " << type << (reachable ? " reachable" : " UNREACHABLE") << " report for SN " << pubkey);

    const auto now = std::chrono::steady_clock::now();

    auto& reach = storage_server ? proofs[pubkey].ss_reachable : proofs[pubkey].lokinet_reachable;
    if (reachable) {
      reach.last_reachable = now;
      reach.first_unreachable = NEVER;
    } else {
      reach.last_unreachable = now;
      if (reach.first_unreachable == NEVER)
        reach.first_unreachable = now;
    }

    return true;

  }
  bool service_node_list::set_storage_server_peer_reachable(crypto::public_key const &pubkey, bool reachable)
  {
      return set_peer_reachable(true, pubkey, reachable);
  }

  bool service_node_list::set_lokinet_peer_reachable(crypto::public_key const &pubkey, bool reachable)
  {
      return set_peer_reachable(false, pubkey, reachable);
  }

  static quorum_manager quorum_for_serialization_to_quorum_manager(service_node_list::quorum_for_serialization const &source)
  {
    quorum_manager result = {};
    result.obligations = std::make_shared<quorum>(source.quorums[static_cast<uint8_t>(quorum_type::obligations)]);

    // Don't load any checkpoints that shouldn't exist (see the comment in generate_quorums as to why the `+BUFFER` term is here).
    if ((source.height + REORG_SAFETY_BUFFER_BLOCKS_POST_HF12) % CHECKPOINT_INTERVAL == 0)
      result.checkpointing = std::make_shared<quorum>(source.quorums[static_cast<uint8_t>(quorum_type::checkpointing)]);

    return result;
  }

  service_node_list::state_t::state_t(service_node_list* snl, state_serialized &&state)
  : height{state.height}
  , key_image_blacklist{std::move(state.key_image_blacklist)}
  , only_loaded_quorums{state.only_stored_quorums}
  , block_hash{state.block_hash}
  , sn_list{snl}
  {
    if (!sn_list)
      throw std::logic_error("Cannot deserialize a state_t without a service_node_list");
    if (state.version == state_serialized::version_t::version_0)
      block_hash = sn_list->m_blockchain.get_block_id_by_height(height);

    for (auto &pubkey_info : state.infos)
    {
      using version_t = service_node_info::version_t;
      auto &info = const_cast<service_node_info &>(*pubkey_info.info);
      if (info.version < version_t::v1_add_registration_hf_version)
      {
        info.version = version_t::v1_add_registration_hf_version;
        info.registration_hf_version = sn_list->m_blockchain.get_network_version(pubkey_info.info->registration_height);
      }
      if (info.version < version_t::v4_noproofs)
      {
        // Nothing to do here (the missing data will be generated in the new proofs db via uptime proofs).
        info.version = version_t::v4_noproofs;
      }
      if (info.version < version_t::v5_pulse_recomm_credit)
      {
        // If it's an old record then assume it's from before oxen 8, in which case there were only
        // two valid values here: initial for a node that has never been recommissioned, or 0 for a recommission.

        auto was = info.recommission_credit;
        if (info.decommission_count <= info.is_decommissioned()) // Has never been decommissioned (or is currently in the first decommission), so add initial starting credit
          info.recommission_credit = DECOMMISSION_INITIAL_CREDIT;
        else
          info.recommission_credit = 0;

        info.pulse_sorter.last_height_validating_in_quorum = info.last_reward_block_height;
        info.version = version_t::v5_pulse_recomm_credit;
      }
      if (info.version < version_t::v6_reassign_sort_keys)
      {
        info.pulse_sorter = {};
        info.version      = version_t::v6_reassign_sort_keys;
      }
      if (info.version < version_t::v7_decommission_reason)
      {
        // Nothing to do here (leave consensus reasons as 0s)
        info.version = version_t::v7_decommission_reason;
      }
      // Make sure we handled any future state version upgrades:
      assert(info.version == tools::enum_top<decltype(info.version)>);
      service_nodes_infos.emplace(std::move(pubkey_info.pubkey), std::move(pubkey_info.info));
    }
    quorums = quorum_for_serialization_to_quorum_manager(state.quorums);
  }

  bool service_node_list::load(const uint64_t current_height)
  {
    LOG_PRINT_L1("service_node_list::load()");
    reset(false);
    if (!m_blockchain.has_db())
    {
      return false;
    }

    // NOTE: Deserialize long term state history
    uint64_t bytes_loaded = 0;
    auto &db = m_blockchain.get_db();
    cryptonote::db_rtxn_guard txn_guard{db};
    std::string blob;
    if (db.get_service_node_data(blob, true /*long_term*/))
    {
      bytes_loaded += blob.size();
      data_for_serialization data_in = {};
      bool success = false;
      try {
        serialization::parse_binary(blob, data_in);
        success = true;
      } catch (...) {}

      if (success && data_in.states.size())
      {
        // NOTE: Previously the quorum for the next state is derived from the
        // state that's been updated from the next block. This is fixed in
        // version_1.

        // So, copy the quorum from (state.height-1) to (state.height), all
        // states need to have their (height-1) which means we're missing the
        // 10k-th interval and need to generate it based on the last state.

        if (data_in.states[0].version == state_serialized::version_t::version_0)
        {
          size_t const last_index = data_in.states.size() - 1;
          if ((data_in.states.back().height % STORE_LONG_TERM_STATE_INTERVAL) != 0)
          {
            LOG_PRINT_L0("Last serialised quorum height: " << data_in.states.back().height
                                                           << " in archive is unexpectedly not a multiple of: "
                                                           << STORE_LONG_TERM_STATE_INTERVAL << ", regenerating state");
            return false;
          }

          for (size_t i = data_in.states.size() - 1; i >= 1; i--)
          {
            state_serialized &serialized_entry      = data_in.states[i];
            state_serialized &prev_serialized_entry = data_in.states[i - 1];

            if ((prev_serialized_entry.height % STORE_LONG_TERM_STATE_INTERVAL) == 0)
            {
              // NOTE: drop this entry, we have insufficient data to derive
              // sadly, do this as a one off and if we ever need this data we
              // need to do a full rescan.
              continue;
            }

            state_t entry{this, std::move(serialized_entry)};
            entry.height--;
            entry.quorums = quorum_for_serialization_to_quorum_manager(prev_serialized_entry.quorums);

            if ((serialized_entry.height % STORE_LONG_TERM_STATE_INTERVAL) == 0)
            {
              state_t long_term_state                  = entry;
              cryptonote::block const &block           = db.get_block_from_height(long_term_state.height + 1);
              std::vector<cryptonote::transaction> txs = db.get_tx_list(block.tx_hashes);
              long_term_state.update_from_block(db, m_blockchain.nettype(), {} /*state_history*/, {} /*state_archive*/, {} /*alt_states*/, block, txs, nullptr /*my_keys*/);

              entry.service_nodes_infos                = {};
              entry.key_image_blacklist                = {};
              entry.only_loaded_quorums                = true;
              m_transient.state_archive.emplace_hint(m_transient.state_archive.begin(), std::move(long_term_state));
            }
            m_transient.state_archive.emplace_hint(m_transient.state_archive.begin(), std::move(entry));
          }
        }
        else
        {
          for (state_serialized &entry : data_in.states)
            m_transient.state_archive.emplace_hint(m_transient.state_archive.end(), this, std::move(entry));
        }
      }
    }

    // NOTE: Deserialize short term state history
    if (!db.get_service_node_data(blob, false))
      return false;

    bytes_loaded += blob.size();
    data_for_serialization data_in = {};
    try {
      serialization::parse_binary(blob, data_in);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse service node data from blob: " << e.what());
      return false;
    }

    if (data_in.states.empty())
      return false;

    {
      const uint64_t hist_state_from_height = current_height - m_store_quorum_history;
      uint64_t last_loaded_height = 0;
      for (auto &states : data_in.quorum_states)
      {
        if (states.height < hist_state_from_height)
          continue;

        quorums_by_height entry = {};
        entry.height            = states.height;
        entry.quorums           = quorum_for_serialization_to_quorum_manager(states);

        if (states.height <= last_loaded_height)
        {
          LOG_PRINT_L0("Serialised quorums is not stored in ascending order by height in DB, failed to load from DB");
          return false;
        }
        last_loaded_height = states.height;
        m_transient.old_quorum_states.push_back(entry);
      }
    }

    {
      assert(data_in.states.size() > 0);
      size_t const last_index = data_in.states.size() - 1;
      if (data_in.states[last_index].only_stored_quorums)
      {
        LOG_PRINT_L0("Unexpected last serialized state only has quorums loaded");
        return false;
      }

      if (data_in.states[0].version == state_serialized::version_t::version_0)
      {
        for (size_t i = last_index; i >= 1; i--)
        {
          state_serialized &serialized_entry      = data_in.states[i];
          state_serialized &prev_serialized_entry = data_in.states[i - 1];
          state_t entry{this, std::move(serialized_entry)};
          entry.quorums = quorum_for_serialization_to_quorum_manager(prev_serialized_entry.quorums);
          entry.height--;
          if (i == last_index) m_state = std::move(entry);
          else                 m_transient.state_archive.emplace_hint(m_transient.state_archive.end(), std::move(entry));
        }
      }
      else
      {
        size_t const last_index  = data_in.states.size() - 1;
        for (size_t i = 0; i < last_index; i++)
        {
          state_serialized &entry = data_in.states[i];
          if (entry.block_hash == crypto::null_hash) entry.block_hash = m_blockchain.get_block_id_by_height(entry.height);
          m_transient.state_history.emplace_hint(m_transient.state_history.end(), this, std::move(entry));
        }

        m_state = {this, std::move(data_in.states[last_index])};
      }
    }

    // NOTE: Load uptime proof data
    proofs = db.get_all_service_node_proofs();
    if (m_service_node_keys)
    {
      // Reset our own proof timestamp to zero so that we aggressively try to resend proofs on
      // startup (in case we are restarting because the last proof that we think went out didn't
      // actually make it to the network).
      auto &mine = proofs[m_service_node_keys->pub];
      mine.timestamp = mine.effective_timestamp = 0;
    }

    initialize_x25519_map();

    MGINFO("Service node data loaded successfully, height: " << m_state.height);
    MGINFO(m_state.service_nodes_infos.size()
           << " nodes and " << m_transient.state_history.size() << " recent states loaded, " << m_transient.state_archive.size()
           << " historical states loaded, (" << tools::get_human_readable_bytes(bytes_loaded) << ")");

    LOG_PRINT_L1("service_node_list::load() returning success");
    return true;
  }

  void service_node_list::reset(bool delete_db_entry)
  {
    m_transient = {};
    m_state     = state_t{this};

    if (m_blockchain.has_db() && delete_db_entry)
    {
      cryptonote::db_wtxn_guard txn_guard{m_blockchain.get_db()};
      m_blockchain.get_db().clear_service_node_data();
    }

    m_state.height = hard_fork_begins(m_blockchain.nettype(), cryptonote::network_version_9_service_nodes).value_or(1) - 1;
  }

  size_t service_node_info::total_num_locked_contributions() const
  {
    size_t result = 0;
    for (service_node_info::contributor_t const &contributor : this->contributors)
      result += contributor.locked_contributions.size();
    return result;
  }

  contributor_args_t convert_registration_args(cryptonote::network_type nettype,
                                               const std::vector<std::string> &args,
                                               uint64_t staking_requirement,
                                               uint8_t hf_version)
  {
    contributor_args_t result = {};
    if (args.size() % 2 == 0 || args.size() < 3)
    {
      result.err_msg = tr("Usage: <operator cut> <address> <fraction> [<address> <fraction> [...]]]");
      return result;
    }

    if ((args.size()-1)/ 2 > MAX_NUMBER_OF_CONTRIBUTORS)
    {
      result.err_msg = tr("Exceeds the maximum number of contributors, which is ") + std::to_string(MAX_NUMBER_OF_CONTRIBUTORS);
      return result;
    }

    try
    {
      result.portions_for_operator = boost::lexical_cast<uint64_t>(args[0]);
      if (result.portions_for_operator > STAKING_PORTIONS)
      {
        result.err_msg = tr("Invalid portion amount: ") + args[0] + tr(". Must be between 0 and ") + std::to_string(STAKING_PORTIONS);
        return result;
      }
    }
    catch (const std::exception &e)
    {
      result.err_msg = tr("Invalid portion amount: ") + args[0] + tr(". Must be between 0 and ") + std::to_string(STAKING_PORTIONS);
      return result;
    }

    struct addr_to_portion_t
    {
      cryptonote::address_parse_info info;
      uint64_t portions;
    };

    std::vector<addr_to_portion_t> addr_to_portions;
    size_t const OPERATOR_ARG_INDEX     = 1;
    for (size_t i = OPERATOR_ARG_INDEX, num_contributions = 0;
         i < args.size();
         i += 2, ++num_contributions)
    {
      cryptonote::address_parse_info info;
      if (!cryptonote::get_account_address_from_str(info, nettype, args[i]))
      {
        result.err_msg = tr("Failed to parse address: ") + args[i];
        return result;
      }

      if (info.has_payment_id)
      {
        result.err_msg = tr("Can't use a payment id for staking tx");
        return result;
      }

      if (info.is_subaddress)
      {
        result.err_msg = tr("Can't use a subaddress for staking tx");
        return result;
      }

      try
      {
        uint64_t num_portions = boost::lexical_cast<uint64_t>(args[i+1]);
        addr_to_portions.push_back({info, num_portions});
      }
      catch (const std::exception &e)
      {
        result.err_msg = tr("Invalid amount for contributor: ") + args[i] + tr(", with portion amount that could not be converted to a number: ") + args[i+1];
        return result;
      }
    }

    //
    // FIXME(doyle): FIXME(oxen) !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // This is temporary code to redistribute the insufficient portion dust
    // amounts between contributors. It should be removed in HF12.
    //
    std::array<uint64_t, MAX_NUMBER_OF_CONTRIBUTORS> excess_portions;
    std::array<uint64_t, MAX_NUMBER_OF_CONTRIBUTORS> min_contributions;
    {
      // NOTE: Calculate excess portions from each contributor
      uint64_t oxen_reserved = 0;
      for (size_t index = 0; index < addr_to_portions.size(); ++index)
      {
        addr_to_portion_t const &addr_to_portion = addr_to_portions[index];
        uint64_t min_contribution_portions       = service_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, oxen_reserved, index);
        uint64_t oxen_amount                     = service_nodes::portions_to_amount(staking_requirement, addr_to_portion.portions);
        oxen_reserved                           += oxen_amount;

        uint64_t excess = 0;
        if (addr_to_portion.portions > min_contribution_portions)
          excess = addr_to_portion.portions - min_contribution_portions;

        min_contributions[index] = min_contribution_portions;
        excess_portions[index]   = excess;
      }
    }

    uint64_t portions_left  = STAKING_PORTIONS;
    uint64_t total_reserved = 0;
    for (size_t i = 0; i < addr_to_portions.size(); ++i)
    {
      addr_to_portion_t &addr_to_portion = addr_to_portions[i];
      uint64_t min_portions = get_min_node_contribution_in_portions(hf_version, staking_requirement, total_reserved, i);

      uint64_t portions_to_steal = 0;
      if (addr_to_portion.portions < min_portions)
      {
          // NOTE: Steal dust portions from other contributor if we fall below
          // the minimum by a dust amount.
          uint64_t needed             = min_portions - addr_to_portion.portions;
          const uint64_t FUDGE_FACTOR = 10;
          const uint64_t DUST_UNIT    = (STAKING_PORTIONS / staking_requirement);
          const uint64_t DUST         = DUST_UNIT * FUDGE_FACTOR;
          if (needed > DUST)
            continue;

          for (size_t sub_index = 0; sub_index < addr_to_portions.size(); sub_index++)
          {
            if (i == sub_index) continue;
            uint64_t &contributor_excess = excess_portions[sub_index];
            if (contributor_excess > 0)
            {
              portions_to_steal = std::min(needed, contributor_excess);
              addr_to_portion.portions += portions_to_steal;
              contributor_excess -= portions_to_steal;
              needed -= portions_to_steal;
              result.portions[sub_index] -= portions_to_steal;

              if (needed == 0)
                break;
            }
          }

          // NOTE: Operator is sending in the minimum amount and it falls below
          // the minimum by dust, just increase the portions so it passes
          if (needed > 0 && addr_to_portions.size() < MAX_NUMBER_OF_CONTRIBUTORS)
            addr_to_portion.portions += needed;
      }

      if (addr_to_portion.portions < min_portions || (addr_to_portion.portions - portions_to_steal) > portions_left)
      {
        result.err_msg = tr("Invalid amount for contributor: ") + args[i] + tr(", with portion amount: ") + args[i+1] + tr(". The contributors must each have at least 25%, except for the last contributor which may have the remaining amount");
        return result;
      }

      if (min_portions == UINT64_MAX)
      {
        result.err_msg = tr("Too many contributors specified, you can only split a node with up to: ") + std::to_string(MAX_NUMBER_OF_CONTRIBUTORS) + tr(" people.");
        return result;
      }

      portions_left -= addr_to_portion.portions;
      portions_left += portions_to_steal;
      result.addresses.push_back(addr_to_portion.info.address);
      result.portions.push_back(addr_to_portion.portions);
      uint64_t oxen_amount = service_nodes::portions_to_amount(addr_to_portion.portions, staking_requirement);
      total_reserved      += oxen_amount;
    }

    result.success = true;
    return result;
  }

  bool make_registration_cmd(cryptonote::network_type nettype,
      uint8_t hf_version,
      uint64_t staking_requirement,
      const std::vector<std::string>& args,
      const service_node_keys &keys,
      std::string &cmd,
      bool make_friendly)
  {

    contributor_args_t contributor_args = convert_registration_args(nettype, args, staking_requirement, hf_version);
    if (!contributor_args.success)
    {
      MERROR(tr("Could not convert registration args, reason: ") << contributor_args.err_msg);
      return false;
    }

    uint64_t exp_timestamp = time(nullptr) + STAKING_AUTHORIZATION_EXPIRATION_WINDOW;

    crypto::hash hash;
    bool hashed = cryptonote::get_registration_hash(contributor_args.addresses, contributor_args.portions_for_operator, contributor_args.portions, exp_timestamp, hash);
    if (!hashed)
    {
      MERROR(tr("Could not make registration hash from addresses and portions"));
      return false;
    }

    crypto::signature signature;
    crypto::generate_signature(hash, keys.pub, keys.key, signature);

    std::stringstream stream;
    if (make_friendly)
    {
      stream << tr("Run this command in the wallet that will fund this registration:\n\n");
    }

    stream << "register_service_node";
    for (size_t i = 0; i < args.size(); ++i)
    {
      stream << " " << args[i];
    }

    stream << " " << exp_timestamp << " " << tools::type_to_hex(keys.pub) << " " << tools::type_to_hex(signature);

    if (make_friendly)
    {
      stream << "\n\n";
      time_t tt = exp_timestamp;

      struct tm tm;
      epee::misc_utils::get_gmt_time(tt, tm);

      char buffer[128];
      strftime(buffer, sizeof(buffer), "%Y-%m-%d %I:%M:%S %p UTC", &tm);
      stream << tr("This registration expires at ") << buffer << tr(".\n");
      stream << tr("This should be in about 2 weeks, if it isn't, check this computer's clock.\n");
      stream << tr("Please submit your registration into the blockchain before this time or it will be invalid.");
    }

    cmd = stream.str();
    return true;
  }

  bool service_node_info::can_be_voted_on(uint64_t height) const
  {
    // If the SN expired and was reregistered since the height we'll be voting on it prematurely
    if (!is_fully_funded()) {
      MDEBUG("SN vote at height " << height << " invalid: not fully funded");
      return false;
    } else if (height <= registration_height) {
      MDEBUG("SN vote at height " << height << " invalid: height <= reg height (" << registration_height << ")");
      return false;
    } else if (is_decommissioned() && height <= last_decommission_height) {
      MDEBUG("SN vote at height " << height << " invalid: height <= last decomm height (" << last_decommission_height << ")");
      return false;
    } else if (is_active()) {
      assert(active_since_height >= 0); // should be satisfied whenever is_active() is true
      if (height <= static_cast<uint64_t>(active_since_height)) {
        MDEBUG("SN vote at height " << height << " invalid: height <= active-since height (" << active_since_height << ")");
        return false;
      }
    }

    MTRACE("SN vote at height " << height << " is valid.");
    return true;
  }

  bool service_node_info::can_transition_to_state(uint8_t hf_version, uint64_t height, new_state proposed_state) const
  {
    if (hf_version >= cryptonote::network_version_13_enforce_checkpoints) {
      if (!can_be_voted_on(height)) {
        MDEBUG("SN state transition invalid: " << height << " is not a valid vote height");
        return false;
      }

      if (proposed_state == new_state::deregister) {
        if (height <= registration_height) {
          MDEBUG("SN deregister invalid: vote height (" << height << ") <= registration_height (" << registration_height << ")");
          return false;
        }
      } else if (proposed_state == new_state::ip_change_penalty) {
        if (height <= last_ip_change_height) {
          MDEBUG("SN ip change penality invalid: vote height (" << height << ") <= last_ip_change_height (" << last_ip_change_height << ")");
          return false;
        }
      }
    } else { // pre-HF13
      if (proposed_state == new_state::deregister) {
        if (height < registration_height) {
          MDEBUG("SN deregister invalid: vote height (" << height << ") < registration_height (" << registration_height << ")");
          return false;
        }
      }
    }

    if (is_decommissioned()) {
      if (proposed_state == new_state::decommission) {
        MDEBUG("SN decommission invalid: already decommissioned");
        return false;
      } else if (proposed_state == new_state::ip_change_penalty) {
        MDEBUG("SN ip change penalty invalid: currently decommissioned");
        return false;
      }
      return true; // recomm or dereg
    } else if (proposed_state == new_state::recommission) {
      MDEBUG("SN recommission invalid: not recommissioned");
      return false;
    }
    MTRACE("SN state change is valid");
    return true;
  }

  payout service_node_info_to_payout(crypto::public_key const &key, service_node_info const &info)
  {
    service_nodes::payout result = {};
    result.key                   = key;

    // Add contributors and their portions to winners.
    result.payouts.reserve(info.contributors.size());
    const uint64_t remaining_portions = STAKING_PORTIONS - info.portions_for_operator;
    for (const auto& contributor : info.contributors)
    {
      uint64_t hi, lo, resulthi, resultlo;
      lo = mul128(contributor.amount, remaining_portions, &hi);
      div128_64(hi, lo, info.staking_requirement, &resulthi, &resultlo);

      if (contributor.address == info.operator_address)
        resultlo += info.portions_for_operator;
      result.payouts.push_back({contributor.address, resultlo});
    }

    return result;
  }
}

