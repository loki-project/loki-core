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

#include "service_node_quorum_cop.h"
#include "service_node_deregister.h"
#include "service_node_list.h"
#include "cryptonote_config.h"
#include "cryptonote_core.h"
#include "version.h"
#include "common/loki.h"

#include "common/loki_integration_test_hooks.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "quorum_cop"

namespace service_nodes
{
  quorum_cop::quorum_cop(cryptonote::core& core)
    : m_core(core), m_uptime_proof_height(0)
  {
    init();
  }

  void quorum_cop::init()
  {
    m_uptime_proof_height = 0;
    m_uptime_proof_seen.clear();
  }

  void quorum_cop::blockchain_detached(uint64_t height)
  {
    if (m_uptime_proof_height >= height)
    {
      LOG_ERROR("The blockchain was detached to height: " << height << ", but quorum cop has already processed votes up to " << m_uptime_proof_height);
      LOG_ERROR("This implies a reorg occured that was over " << REORG_SAFETY_BUFFER_IN_BLOCKS << ". This should never happen! Please report this to the devs.");
      m_uptime_proof_height = height;
    }
  }

  void quorum_cop::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    process_uptime_quorum(block);
    process_checkpoint_quorum(block);
  }

  void quorum_cop::process_uptime_quorum(cryptonote::block const &block)
  {
    uint64_t const height = cryptonote::get_block_height(block);
    if (m_core.get_hard_fork_version(height) < 9)
      return;

    crypto::public_key my_pubkey;
    crypto::secret_key my_seckey;
    if (!m_core.get_service_node_keys(my_pubkey, my_seckey))
      return;

    time_t const now          = time(nullptr);
#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
    time_t const min_lifetime = 0;
#else
    time_t const min_lifetime = 60 * 60 * 2;
#endif
    bool alive_for_min_time   = (now - m_core.get_start_time()) >= min_lifetime;
    if (!alive_for_min_time)
    {
      return;
    }

    uint64_t const latest_height = std::max(m_core.get_current_blockchain_height(), m_core.get_target_blockchain_height());
    if (latest_height < service_nodes::deregister_vote::VOTE_LIFETIME_BY_HEIGHT)
      return;

    uint64_t const execute_justice_from_height = latest_height - service_nodes::deregister_vote::VOTE_LIFETIME_BY_HEIGHT;
    if (height < execute_justice_from_height)
      return;

    if (m_uptime_proof_height < execute_justice_from_height)
      m_uptime_proof_height = execute_justice_from_height;

    for (;m_uptime_proof_height < (height - REORG_SAFETY_BUFFER_IN_BLOCKS); m_uptime_proof_height++)
    {
      if (m_core.get_hard_fork_version(m_uptime_proof_height) < 9)
        continue;

      const std::shared_ptr<const quorum_uptime_proof> state = m_core.get_uptime_quorum(m_last_height);
      if (!state)
      {
        // TODO(loki): Fatal error
        LOG_ERROR("Quorum state for height: " << m_uptime_proof_height << " was not cached in daemon!");
        continue;
      }

      auto it = std::find(state->quorum_nodes.begin(), state->quorum_nodes.end(), my_pubkey);
      if (it == state->quorum_nodes.end())
        continue;

      //
      // NOTE: I am in the quorum
      //
      size_t my_index_in_quorum = it - state->quorum_nodes.begin();
      for (size_t node_index = 0; node_index < state->nodes_to_test.size(); ++node_index)
      {
        const crypto::public_key &node_key = state->nodes_to_test[node_index];

        CRITICAL_REGION_LOCAL(m_lock);
        bool vote_off_node = (m_uptime_proof_seen.find(node_key) == m_uptime_proof_seen.end());

        if (!vote_off_node)
          continue;

        service_nodes::deregister_vote vote = {};
        vote.block_height        = m_uptime_proof_height;
        vote.service_node_index  = node_index;
        vote.voters_quorum_index = my_index_in_quorum;
        vote.signature           = service_nodes::deregister_vote::sign_vote(vote.block_height, vote.service_node_index, my_pubkey, my_seckey);

        cryptonote::vote_verification_context vvc = {};
        if (!m_core.add_deregister_vote(vote, vvc))
        {
          LOG_ERROR("Failed to add deregister vote reason: " << print_vote_verification_context(vvc, &vote));
        }
      }
    }
  }

  void quorum_cop::process_checkpoint_quorum(cryptonote::block const &block)
  {
    uint64_t const height = cryptonote::get_block_height(block);
    if (m_core.get_hard_fork_version(height) < cryptonote::network_version_12_checkpointing)
      return;

    crypto::public_key my_pubkey;
    crypto::secret_key my_seckey;
    if (!m_core.get_service_node_keys(my_pubkey, my_seckey))
      return;

    if (height % CHECKPOINT_INTERVAL != 0)
      return;

    const std::shared_ptr<const quorum_state> state = m_core.get_quorum_state(height);
    if (!state)
    {
      // TODO(loki): Fatal error
      LOG_ERROR("Quorum state for height: " << height << " was not cached in daemon!");
      return;
    }

    auto it = std::find(state->quorum_nodes.begin(), state->quorum_nodes.end(), my_pubkey);
    if (it == state->quorum_nodes.end())
      return;

    //
    // NOTE: I am in the quorum, handle checkpointing
    //
    size_t my_index_in_quorum           = it - state->quorum_nodes.begin();
    service_nodes::checkpoint_vote vote = {};
    if (!cryptonote::get_block_hash(block, vote.block_hash))
    {
      // TODO(loki): Fatal error
      LOG_ERROR("Could not get block hash for block on height: " << height);
      return;
    }

    vote.block_height        = height;
    vote.voters_quorum_index = my_index_in_quorum;
    crypto::generate_signature(vote.block_hash, my_pubkey, my_seckey, vote.signature);

    cryptonote::vote_verification_context vvc = {};
    if (!m_core.add_checkpoint_vote(vote, vvc))
    {
      // TODO(doyle): CHECKPOINTING(doyle):
      LOG_ERROR("Failed to add checkpoint vote reason: " << print_vote_verification_context(vvc, nullptr));
    }
  }


  static crypto::hash make_hash(crypto::public_key const &pubkey, uint64_t timestamp)
  {
    char buf[44] = "SUP"; // Meaningless magic bytes
    crypto::hash result;
    memcpy(buf + 4, reinterpret_cast<const void *>(&pubkey), sizeof(pubkey));
    memcpy(buf + 4 + sizeof(pubkey), reinterpret_cast<const void *>(&timestamp), sizeof(timestamp));
    crypto::cn_fast_hash(buf, sizeof(buf), result);

    return result;
  }

  bool quorum_cop::handle_uptime_proof(const cryptonote::NOTIFY_UPTIME_PROOF::request &proof)
  {
    uint64_t now = time(nullptr);

    uint64_t timestamp               = proof.timestamp;
    const crypto::public_key& pubkey = proof.pubkey;
    const crypto::signature& sig     = proof.sig;

    if ((timestamp < now - UPTIME_PROOF_BUFFER_IN_SECONDS) || (timestamp > now + UPTIME_PROOF_BUFFER_IN_SECONDS))
      return false;

    if (!m_core.is_service_node(pubkey))
      return false;

    uint64_t height = m_core.get_current_blockchain_height();
    int version     = m_core.get_hard_fork_version(height);

    // NOTE: Only care about major version for now
    if (version >= cryptonote::network_version_11_infinite_staking && proof.snode_version_major < 3)
      return false;
    else if (version >= cryptonote::network_version_10_bulletproofs && proof.snode_version_major < 2)
      return false;

    CRITICAL_REGION_LOCAL(m_lock);
    if (m_uptime_proof_seen[pubkey].timestamp >= now - (UPTIME_PROOF_FREQUENCY_IN_SECONDS / 2))
      return false; // already received one uptime proof for this node recently.

    crypto::hash hash = make_hash(pubkey, timestamp);
    if (!crypto::check_signature(hash, pubkey, sig))
      return false;

    m_uptime_proof_seen[pubkey] = {now, proof.snode_version_major, proof.snode_version_minor, proof.snode_version_patch};
    return true;
  }

  void quorum_cop::generate_uptime_proof_request(cryptonote::NOTIFY_UPTIME_PROOF::request& req) const
  {
    req.snode_version_major = static_cast<uint16_t>(LOKI_VERSION_MAJOR);
    req.snode_version_minor = static_cast<uint16_t>(LOKI_VERSION_MINOR);
    req.snode_version_patch = static_cast<uint16_t>(LOKI_VERSION_PATCH);

    crypto::public_key pubkey;
    crypto::secret_key seckey;
    m_core.get_service_node_keys(pubkey, seckey);

    req.timestamp           = time(nullptr);
    req.pubkey              = pubkey;

    crypto::hash hash = make_hash(req.pubkey, req.timestamp);
    crypto::generate_signature(hash, pubkey, seckey, req.sig);
  }

  bool quorum_cop::prune_uptime_proof()
  {
    uint64_t now = time(nullptr);
    const uint64_t prune_from_timestamp = now - UPTIME_PROOF_MAX_TIME_IN_SECONDS;
    CRITICAL_REGION_LOCAL(m_lock);

    std::vector<crypto::public_key> to_remove;
    for (const auto &proof : m_uptime_proof_seen)
    {
      if (proof.second.timestamp < prune_from_timestamp)
        to_remove.push_back(proof.first);
    }
    for (const auto &pk : to_remove)
      m_uptime_proof_seen.erase(pk);

    return true;
  }

  proof_info quorum_cop::get_uptime_proof(const crypto::public_key &pubkey) const
  {

    CRITICAL_REGION_LOCAL(m_lock);
    const auto it = m_uptime_proof_seen.find(pubkey);
    if (it == m_uptime_proof_seen.end())
      return {};

    return it->second;
  }
}
