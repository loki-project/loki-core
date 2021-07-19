// Copyright (c) 2014-2019, The Monero Project
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

#include <unordered_set>
#include <random>
#include "epee/string_tools.h"
#include "common/apply_permutation.h"
#include "common/hex.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "epee/int-util.h"

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  static void classify_addresses(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    bool change_found = false;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && *change_addr == dst_entr && !change_found)
      {
        change_found = true;
        continue;
      }
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }

  keypair get_deterministic_keypair_from_height(uint64_t height)
  {
    keypair k;

    ec_scalar& sec = k.sec;

    for (int i=0; i < 8; i++)
    {
      uint64_t height_byte = height & ((uint64_t)0xFF << (i*8));
      uint8_t byte = height_byte >> i*8;
      sec.data[i] = byte;
    }
    for (int i=8; i < 32; i++)
    {
      sec.data[i] = 0x00;
    }

    generate_keys(k.pub, k.sec, k.sec, true);

    return k;
  }

  bool get_deterministic_output_key(const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key)
  {
    crypto::key_derivation derivation{};
    bool r = crypto::generate_key_derivation(address.m_view_public_key, tx_key.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << address.m_view_public_key << ", " << tx_key.sec << ")");

    r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, output_key);
    CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key(" << derivation << ", " << output_index << ", "<< address.m_spend_public_key << ")");

    return true;
  }

  bool validate_governance_reward_key(uint64_t height, std::string_view governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, const cryptonote::network_type nettype)
  {
    keypair gov_key = get_deterministic_keypair_from_height(height);

    cryptonote::address_parse_info governance_wallet_address;
    cryptonote::get_account_address_from_str(governance_wallet_address, nettype, governance_wallet_address_str);
    crypto::public_key correct_key;



    if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, output_index, correct_key))
    {
      MERROR("Failed to generate deterministic output key for governance wallet output validation");
      return false;
    }

    return correct_key == output_key;
  }

  uint64_t governance_reward_formula(uint64_t base_reward, uint8_t hf_version)
  {
    return hf_version >= network_version_17         ? FOUNDATION_REWARD_HF17 :
           hf_version >= network_version_16_pulse   ? FOUNDATION_REWARD_HF15 + CHAINFLIP_LIQUIDITY_HF16 :
           hf_version >= network_version_15_ons     ? FOUNDATION_REWARD_HF15 :
           base_reward / 20;
  }

  bool block_has_governance_output(network_type nettype, cryptonote::block const &block)
  {
    bool result = height_has_governance_output(nettype, block.major_version, get_block_height(block));
    return result;
  }

  bool height_has_governance_output(network_type nettype, uint8_t hard_fork_version, uint64_t height)
  {
    if (height == 0)
      return false;

    if (hard_fork_version <= network_version_9_service_nodes)
      return true;

    if (height % cryptonote::get_config(nettype).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS != 0)
    {
      return false;
    }

    return true;
  }

  uint64_t derive_governance_from_block_reward(network_type nettype, const cryptonote::block &block, uint8_t hf_version)
  {
    if (hf_version >= 15)
      return governance_reward_formula(0, hf_version);

    uint64_t result       = 0;
    uint64_t snode_reward = 0;
    size_t vout_end     = block.miner_tx.vout.size();

    if (block_has_governance_output(nettype, block))
      --vout_end; // skip the governance output, the governance may be the batched amount. we want the original base reward

    for (size_t vout_index = 1; vout_index < vout_end; ++vout_index)
    {
      tx_out const &output = block.miner_tx.vout[vout_index];
      snode_reward += output.amount;
    }

    uint64_t base_reward  = snode_reward * 2; // pre-HF15, SN reward = half of base reward
    uint64_t governance   = governance_reward_formula(base_reward, hf_version);
    uint64_t block_reward = base_reward - governance;

    uint64_t actual_reward = 0; // sanity check
    for (tx_out const &output : block.miner_tx.vout) actual_reward += output.amount;

    CHECK_AND_ASSERT_MES(block_reward <= actual_reward, false,
        "Rederiving the base block reward from the service node reward "
        "exceeded the actual amount paid in the block, derived block reward: "
        << block_reward << ", actual reward: " << actual_reward);

    result = governance;
    return result;
  }

  uint64_t service_node_reward_formula(uint64_t base_reward, uint8_t hard_fork_version)
  {
    return
      hard_fork_version >= network_version_15_ons          ? SN_REWARD_HF15 :
      hard_fork_version >= network_version_9_service_nodes ? base_reward / 2 : // 50% of base reward up until HF15's fixed payout
      0;
  }

  uint64_t get_portion_of_reward(uint64_t portions, uint64_t total_service_node_reward)
  {
    uint64_t hi, lo, rewardhi, rewardlo;
    lo = mul128(total_service_node_reward, portions, &hi);
    div128_64(hi, lo, STAKING_PORTIONS, &rewardhi, &rewardlo);
    return rewardlo;
  }

  std::vector<uint64_t> distribute_reward_by_portions(const std::vector<service_nodes::payout_entry>& payout, uint64_t total_reward, bool distribute_remainder)
  {
    uint64_t paid_reward = 0;
    std::vector<uint64_t> result;

    result.reserve(payout.size());
    for (auto const &entry : payout)
    {
      uint64_t reward = get_portion_of_reward(entry.portions, total_reward);
      paid_reward += reward;
      result.push_back(reward);
    }

    if (distribute_remainder && payout.size())
    {
      uint64_t remainder = total_reward - paid_reward;
      result.front() += remainder;
    }

    return result;
  }

  static uint64_t calculate_sum_of_portions(const std::vector<service_nodes::payout_entry>& payout, uint64_t total_service_node_reward)
  {
    uint64_t reward = 0;
    for (auto const &entry : payout)
      reward += get_portion_of_reward(entry.portions, total_service_node_reward);
    return reward;
  }

  std::pair<bool, uint64_t> construct_miner_tx(
      size_t height,
      size_t median_weight,
      uint64_t already_generated_coins,
      size_t current_block_weight,
      uint64_t fee,
      transaction& tx,
      const oxen_miner_tx_context &miner_tx_context,
      const std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds,
      const blobdata& extra_nonce,
      uint8_t hard_fork_version)
  {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();
    tx.output_unlock_times.clear();
    tx.type    = txtype::standard;
    tx.version = transaction::get_max_version_for_hf(hard_fork_version);

    keypair const txkey{hw::get_device("default")};
    keypair const gov_key = get_deterministic_keypair_from_height(height); // NOTE: Always need since we use same key for service node

    uint64_t block_rewards = 0;

    // NOTE: TX Extra
    add_tx_extra<tx_extra_pub_key>(tx, txkey.pub);
    if(!extra_nonce.empty())
    {
      if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        return std::make_pair(false, block_rewards);
    }

    // TODO(doyle): We don't need to do this. It's a deterministic key.
    if (already_generated_coins != 0)
      add_tx_extra<tx_extra_pub_key>(tx, gov_key.pub);


    add_service_node_winner_to_tx_extra(tx.extra, miner_tx_context.block_leader.key);


    oxen_block_reward_context block_reward_context = {};
    block_reward_context.fee                       = fee;
    block_reward_context.height                    = height;
    block_reward_context.block_leader_payouts      = miner_tx_context.block_leader.payouts;
    block_reward_context.batched_governance        = miner_tx_context.batched_governance;

    block_reward_parts reward_parts{};
    if(!get_oxen_block_reward(median_weight, current_block_weight, already_generated_coins, hard_fork_version, reward_parts, block_reward_context))
    {
      LOG_PRINT_L0("Failed to calculate block reward");
      return std::make_pair(false, block_rewards);
    }

    // TODO(doyle): Batching awards
    //
    // NOTE: Summarise rewards to payout (up to 9 payout entries/outputs)
    //
    // Miner Block
    // - 1       | Miner
    // - Up To 4 | Block Leader (Queued node at the top of the Service Node List)
    // - Up To 1 | Governance
    //
    // Pulse Block
    // - Up to 4 | Block Producer (0-3 for Pooled Service Node)
    // - Up To 4 | Block Leader   (Queued node at the top of the Service Node List)
    // - Up To 1 | Governance     (When a block is at the Governance payout interval)
    //
    // NOTE: Pulse Block Payment Details
    //
    // By default, when Pulse round is 0, the Block Producer is the Block
    // Leader. Coinbase and transaction fees are given to the Block Leader.
    // This is the common case, and in that instance we avoid generating
    // duplicate outputs and payment occurs in 1 output.
    //
    // On alternative rounds, transaction fees are given to the alternative
    // block producer (which is now different from the Block Leader). The
    // original block producer still receives the coinbase reward. A Pulse
    // round's failure is determined by the non-participation of the members of
    // the quorum, so failing a round's onus is not always on the original block
    // producer (it could be the validators colluding) hence why they still
    // receive the coinbase.
    //
    // Allocating the transaction fee to alternative block producers on
    // alternative rounds dis-incentivizes members in the quorum from
    // intentionally not participating in the quorum to try and attain a spot as
    // the subsequent alternative leader and snag a reward. The reward they
    // receive instead is just the transaction fee.
    //
    // Purposely not participating to exploit alternative round transaction fees
    // is further dis-incentivized as it is recorded on their behaviour metrics
    // (multiple non-participation marks over the monitoring period will induce
    // a decommission) by members of the quorum.

    std::vector<reward_payout>   rewards = {};
    std::vector<batch_sn_payment>   batched_rewards = {};
    const network_type nettype = miner_tx_context.nettype;

    if (hard_fork_version >= cryptonote::network_version_9_service_nodes)
      CHECK_AND_ASSERT_MES(miner_tx_context.block_leader.payouts.size(), std::make_pair(false, block_rewards), "Constructing a block leader reward for block but no payout entries specified");

    // NOTE: Add Block Producer Reward
    service_nodes::payout const &leader = miner_tx_context.block_leader;
    if (miner_tx_context.pulse)
    {
      // PULSE BLOCKS 
      
      CHECK_AND_ASSERT_MES(miner_tx_context.pulse_block_producer.payouts.size(), std::make_pair(false, block_rewards), "Constructing a reward for block produced by pulse but no payout entries specified");
      CHECK_AND_ASSERT_MES(miner_tx_context.pulse_block_producer.key, std::make_pair(false, block_rewards), "Null Key given for Pulse Block Producer");
      CHECK_AND_ASSERT_MES(hard_fork_version >= cryptonote::network_version_16_pulse, std::make_pair(false, block_rewards), "Pulse Block Producer is not valid until HF16, current HF" << hard_fork_version);

      uint64_t leader_reward = reward_parts.service_node_total;
      if (miner_tx_context.block_leader.key == miner_tx_context.pulse_block_producer.key)
      {
        leader_reward += reward_parts.miner_fee;
      }
      else if (reward_parts.miner_fee)
      {
        // Alternative Block Producer (receives just miner fee, if there is one)
        service_nodes::payout const &producer = miner_tx_context.pulse_block_producer;
        std::vector<uint64_t> split_rewards   = distribute_reward_by_portions(producer.payouts, reward_parts.miner_fee, true /*distribute_remainder*/);

        for (size_t i = 0; i < producer.payouts.size(); i++)
          if (hard_fork_version < cryptonote::network_version_19)
          {
            rewards.push_back({reward_type::snode, producer.payouts[i].address, split_rewards[i]});
          } else {
            batched_rewards.emplace_back(producer.payouts[i].address, split_rewards[i], nettype);
          }
      }

      std::vector<uint64_t> split_rewards = distribute_reward_by_portions(leader.payouts, leader_reward, true /*distribute_remainder*/);
      for (size_t i = 0; i < leader.payouts.size(); i++)
      {
        if (hard_fork_version < cryptonote::network_version_19) {
          rewards.push_back({reward_type::snode, leader.payouts[i].address, split_rewards[i]});
        } else {
          batched_rewards.emplace_back(leader.payouts[i].address, split_rewards[i], nettype);
        }

      }
    }
    else
    {
      // MINED BLOCKS 
      
      CHECK_AND_ASSERT_MES(miner_tx_context.pulse_block_producer.payouts.empty(), std::make_pair(false, block_rewards), "Constructing a reward for block produced by miner but payout entries specified");

      if (uint64_t miner_amount = reward_parts.base_miner + reward_parts.miner_fee; miner_amount)
      {
        if (hard_fork_version < cryptonote::network_version_19) {
          rewards.push_back({reward_type::miner, miner_tx_context.miner_block_producer, miner_amount});
        } else {
          batched_rewards.emplace_back(miner_tx_context.miner_block_producer, miner_amount, nettype);
        }
      }

      if (hard_fork_version >= cryptonote::network_version_9_service_nodes) {
        std::vector<uint64_t> split_rewards =
            distribute_reward_by_portions(leader.payouts,
                                          reward_parts.service_node_total,
                                          hard_fork_version >= cryptonote::network_version_16_pulse /*distribute_remainder*/);
        for (size_t i = 0; i < leader.payouts.size(); i++)
        {
          if (hard_fork_version < cryptonote::network_version_19) {
            rewards.push_back({reward_type::snode, leader.payouts[i].address, split_rewards[i]});
          } else {
            batched_rewards.emplace_back(leader.payouts[i].address, split_rewards[i], nettype);
          }
        }
      }
    }

    // Add SN rewards to the block
    if (sn_rwds)
      for (const auto &reward : *sn_rwds)
      {
        rewards.emplace_back(reward_type::snode, reward.address_info.address, reward.amount);
      }



    // NOTE: Add Governance Payout
    if (already_generated_coins != 0)
    {
      if (reward_parts.governance_paid == 0)
      {
        CHECK_AND_ASSERT_MES(hard_fork_version >= network_version_10_bulletproofs, std::make_pair(false, block_rewards), "Governance reward can NOT be 0 before hardfork 10, hard_fork_version: " << hard_fork_version);
      }
      else
      {
        cryptonote::address_parse_info governance_wallet_address;
        cryptonote::get_account_address_from_str(governance_wallet_address, nettype, cryptonote::get_config(nettype).governance_wallet_address(hard_fork_version));
        rewards.push_back({reward_type::governance, governance_wallet_address.address, reward_parts.governance_paid});

      }
    }

    if (hard_fork_version < cryptonote::network_version_19)
    {
      CHECK_AND_ASSERT_MES(rewards.size() <= 9, std::make_pair(false, block_rewards), "More rewards specified than supported, number of rewards: " << rewards.size()  << ", capacity: " << rewards.size());
      CHECK_AND_ASSERT_MES(rewards.size() > 0, std::make_pair(false, block_rewards), "Zero rewards are to be payed out, there should be at least 1");
    }

    // NOTE: Make TX Outputs
    uint64_t summary_amounts = 0;
    for (auto it = rewards.begin(); it != rewards.end(); ++it) {
      auto const &[type, address, amount] = *it;
      assert(amount > 0);

      crypto::public_key out_eph_public_key{};

      // TODO(doyle): I don't think txkey is necessary, just use the governance key?
      keypair const &derivation_pair = (type == reward_type::miner) ? txkey : gov_key;
      crypto::key_derivation derivation{};
      

      if (!get_deterministic_output_key(address, derivation_pair, it - rewards.begin(), out_eph_public_key))
      {
        MERROR("Failed to generate output one-time public key");
        return std::make_pair(false, block_rewards);
      }

      txout_to_key tk = {};
      tk.key          = out_eph_public_key;

      tx_out out = {};
      out.target = tk;
      out.amount = amount;
      tx.vout.push_back(out);
      tx.output_unlock_times.push_back(height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
      summary_amounts += amount;
    }

    uint64_t expected_amount = 0;
    if (hard_fork_version <= cryptonote::network_version_15_ons)
    {
      // NOTE: Use the amount actually paid out when we split the service node
      // reward (across up to 4 recipients) which may actually pay out less than
      // the total reward allocated for Service Nodes (due to remainder from
      // division). This occurred prior to HF15, after that we redistribute dust
      // properly.
      expected_amount = reward_parts.base_miner + reward_parts.miner_fee + reward_parts.governance_paid;
      for (auto reward : rewards)
      {
        [[maybe_unused]] auto const &[type, address, amount] = reward;
        if (type == reward_type::snode) expected_amount += amount;
      }
    }
    else
    {
      //TODO sean make this work
      expected_amount = reward_parts.governance_paid;
      if (hard_fork_version < cryptonote::network_version_19)
        expected_amount = expected_amount + reward_parts.base_miner + reward_parts.miner_fee + reward_parts.service_node_total;
      else
        expected_amount = summary_amounts;
    }

    CHECK_AND_ASSERT_MES(summary_amounts == expected_amount, std::make_pair(false, block_rewards), "Failed to construct miner tx, summary_amounts = " << summary_amounts << " not equal total block_reward = " << expected_amount);
    CHECK_AND_ASSERT_MES(tx.vout.size() == rewards.size(), std::make_pair(false, block_rewards), "TX output mis-match with rewards expected: " << rewards.size() << ", tx outputs: " << tx.vout.size());

    block_rewards = std::accumulate(batched_rewards.begin(), batched_rewards.end(), uint64_t(0), [](uint64_t const x, cryptonote::batch_sn_payment const y) { return x + y.amount; });

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(txin_gen{height});
    tx.invalidate_hashes();

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return std::make_pair(true, block_rewards);
  }

  bool get_oxen_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, int hard_fork_version, block_reward_parts &result, const oxen_block_reward_context &oxen_context)
  {
    result = {};
    uint64_t base_reward, base_reward_unpenalized;
    if (!get_base_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward, base_reward_unpenalized, hard_fork_version, oxen_context.height))
    {
      MERROR("Failed to calculate base block reward");
      return false;
    }

    if (base_reward == 0)
    {
      MERROR("Unexpected base reward of 0");
      return false;
    }

    if (already_generated_coins == 0)
    {
      result.original_base_reward = result.base_miner = base_reward;
      return true;
    }

    // We base governance fees and SN rewards based on the block reward formula.  (Prior to HF13,
    // however, they were accidentally based on the block reward formula *after* subtracting a
    // potential penalty if the block producer includes txes beyond the median size limit).
    result.original_base_reward = hard_fork_version >= network_version_13_enforce_checkpoints ? base_reward_unpenalized : base_reward;

    // There is a goverance fee due every block.  Beginning in hardfork 10 this is still subtracted
    // from the block reward as if it was paid, but the actual payments get batched into rare, large
    // accumulated payments.  (Before hardfork 10 they are included in every block, unbatched).
    result.governance_due  = governance_reward_formula(result.original_base_reward, hard_fork_version);
    result.governance_paid = hard_fork_version >= network_version_10_bulletproofs
        ? oxen_context.batched_governance
        : result.governance_due;

    uint64_t const service_node_reward = service_node_reward_formula(result.original_base_reward, hard_fork_version);
    if (hard_fork_version < cryptonote::network_version_16_pulse)
    {
      result.service_node_total = calculate_sum_of_portions(oxen_context.block_leader_payouts, service_node_reward);

      // The base_miner amount is everything left in the base reward after subtracting off the service
      // node and governance fee amounts (the due amount in the latter case). (Any penalty for
      // exceeding the block limit is already removed from base_reward).
      uint64_t non_miner_amounts = result.governance_due + result.service_node_total;
      result.base_miner = base_reward > non_miner_amounts ? base_reward - non_miner_amounts : 0;
      result.miner_fee = oxen_context.fee;
    }
    else
    {
      result.service_node_total = service_node_reward;

      if (oxen_context.testnet_override)
      {
        result.miner_fee = oxen_context.fee;
      }
      else
      {
        uint64_t const penalty = base_reward_unpenalized - base_reward;
        result.miner_fee = penalty >= oxen_context.fee ? 0 : oxen_context.fee - penalty;
      }

      // In HF16, the block producer changes between the Miner and Service Node
      // depending on the state of the Service Node network. The producer is no
      // longer allocated a block reward (unless they are a Service Node) but
      // always receive the transaction fees. Any penalty for exceeding the
      // block limit must now be paid from the common reward received by all
      // Block Producer's (i.e. their transaction fees for constructing the
      // block).
      uint64_t allocated = result.governance_due + result.service_node_total;
      uint64_t remainder = base_reward_unpenalized - allocated;
      if (allocated > base_reward_unpenalized || remainder != 0)
      {
        if (allocated > base_reward_unpenalized)
          MERROR("We allocated more reward " << cryptonote::print_money(allocated) << " than what was available " << cryptonote::print_money(base_reward_unpenalized));
        else
          MERROR("We allocated reward but there was still " << cryptonote::print_money(remainder) << " oxen left to distribute.");
        return false;
      }
    }

    return true;
  }


  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    bool found_change = false;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && *change_addr == i && !found_change)
      {
        found_change = true;
        continue;
      }
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->addr.m_view_public_key;
    return addr.m_view_public_key;
  }
  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout, bool shuffle_outs, oxen_construct_tx_params const &tx_params)
  {
    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();
    if (msout)
    {
      msout->c.clear();
    }

    tx.version = transaction::get_max_version_for_hf(tx_params.hf_version);
    CHECK_AND_ASSERT_MES(tx.version >= txversion::v4_tx_types, false, "Cannot construct pre-v4 transactions");
    CHECK_AND_ASSERT_MES(rct_config.range_proof_type == rct::RangeProofType::PaddedBulletproof &&
            (rct_config.bp_version == 0 || rct_config.bp_version >= 3),
            false, "Cannot construct pre-CLSAG transactions");

    tx.type = tx_params.tx_type;

    if (tx_params.burn_percent)
    {
      LOG_ERROR("cannot construct tx: internal error: burn percent must be converted to fixed burn amount in the wallet");
      return false;
    }

    tx.extra = extra;
    crypto::public_key txkey_pub;

    if (tx.type == txtype::stake) {
      crypto::secret_key tx_sk{tx_key};
      bool added = hwdev.update_staking_tx_secret_key(tx_sk);
      CHECK_AND_NO_ASSERT_MES(added, false, "Failed to add tx secret key to stake transaction");

      cryptonote::add_tx_secret_key_to_tx_extra(tx.extra, tx_sk);
    }

    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      bool add_dummy_payment_id = true;

      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash payment_id = null_hash;
        crypto::hash8 payment_id8 = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id8);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          remove_field_from_tx_extra<tx_extra_nonce>(tx.extra);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id8);
          add_dummy_payment_id = false;
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          add_dummy_payment_id = false;
        }
      }

      // we don't add one if we've got more than the usual 1 destination plus change
      if (destinations.size() > 2)
        add_dummy_payment_id = false;

      if (add_dummy_payment_id)
      {
        // if we have neither long nor short payment id, add a dummy short one,
        // this should end up being the vast majority of txes as time goes on
        std::string extra_nonce;
        crypto::hash8 payment_id8 = null_hash8;
        crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
        if (view_key_pub == null_pkey)
        {
          LOG_ERROR("Failed to get key to encrypt dummy payment id with");
        }
        else
        {
          hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key);
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add dummy encrypted payment id to tx extra");
            // continue anyway
          }
        }
      }
    }
    else
    {
      MWARNING("Failed to parse tx extra");
      tx_extra_fields.clear();
    }

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!msout && !(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "!\nderived_key:"
          << tools::type_to_hex(in_ephemeral.pub) << "\nreal output_public_key:"
          << tools::type_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_to_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.key_offsets.push_back(out_entry.first);

      input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
      tx.vin.push_back(input_to_key);
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_to_key &tk0 = var::get<txin_to_key>(tx.vin[i0]);
      const txin_to_key &tk1 = var::get<txin_to_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra<tx_extra_pub_key>(tx.extra);
    add_tx_extra<tx_extra_pub_key>(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys)
      CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;

    tx_extra_tx_key_image_proofs key_image_proofs;
    bool found_change_already = false;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      crypto::public_key out_eph_public_key;

      bool this_dst_is_change_addr = false;
      hwdev.generate_output_ephemeral_keys(static_cast<uint16_t>(tx.version), this_dst_is_change_addr, sender_account_keys, txkey_pub, tx_key,
                                           dst_entr, change_addr, output_index,
                                           need_additional_txkeys, additional_tx_keys,
                                           additional_tx_public_keys, amount_keys, out_eph_public_key);

      // Per-output unlock times:
      {
        if (change_addr && *change_addr == dst_entr && this_dst_is_change_addr && !found_change_already)
        {
          found_change_already = true;
          tx.output_unlock_times.push_back(0); // 0 unlock time for change
        }
        else
        {
          tx.output_unlock_times.push_back(unlock_time); // for now, all non-change have same unlock time
        }
      }

      if (tx.type == txtype::stake)
      {
        CHECK_AND_ASSERT_MES(dst_entr.addr == sender_account_keys.m_account_address, false, "A staking contribution must return back to the original sendee otherwise the pre-calculated key image is incorrect");
        CHECK_AND_ASSERT_MES(dst_entr.is_subaddress == false, false, "Staking back to a subaddress is not allowed"); // TODO(oxen): Maybe one day, revisit this
        CHECK_AND_ASSERT_MES(need_additional_txkeys == false, false, "Staking TX's can not required additional TX Keys"); // TODO(oxen): Maybe one day, revisit this

        if (!(change_addr && *change_addr == dst_entr))
        {
          auto& proof = key_image_proofs.proofs.emplace_back();
          keypair ephemeral_keys{};
          if(!generate_key_image_helper(sender_account_keys, subaddresses, out_eph_public_key, txkey_pub, additional_tx_public_keys, output_index, ephemeral_keys, proof.key_image, hwdev))
          {
            LOG_ERROR("Key image generation failed for staking TX!");
            return false;
          }

          hwdev.generate_key_image_signature(proof.key_image, out_eph_public_key, ephemeral_keys.sec, proof.signature);
        }
      }

      tx_out out;
      out.amount = dst_entr.amount;
      txout_to_key tk;
      tk.key = out_eph_public_key;
      out.target = tk;
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    if (tx.type == txtype::stake)
    {
      CHECK_AND_ASSERT_MES(key_image_proofs.proofs.size() >= 1, false, "No key image proofs were generated for staking tx");
      add_tx_key_image_proofs_to_tx_extra(tx.extra, key_image_proofs);

      if (tx_params.hf_version <= cryptonote::network_version_13_enforce_checkpoints)
        tx.type = txtype::standard;
    }

    remove_field_from_tx_extra<tx_extra_additional_pub_keys>(tx.extra);

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys)
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    uint64_t amount_in = 0, amount_out = 0;
    rct::ctkeyV inSk;
    inSk.reserve(sources.size());
    // mixRing indexing is done the other way round for simple
    rct::ctkeyM mixRing(sources.size());
    rct::keyV dest_keys;
    std::vector<uint64_t> inamounts, outamounts;
    std::vector<unsigned int> index;
    std::vector<rct::multisig_kLRki> kLRki;
    for (size_t i = 0; i < sources.size(); ++i)
    {
      rct::ctkey ctkey;
      amount_in += sources[i].amount;
      inamounts.push_back(sources[i].amount);
      index.push_back(sources[i].real_output);
      // inSk: (secret key, mask)
      ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
      ctkey.mask = sources[i].mask;
      inSk.push_back(ctkey);
      memwipe(&ctkey, sizeof(rct::ctkey));
      // inPk: (public key, commitment)
      // will be done when filling in mixRing
      if (msout)
      {
        kLRki.push_back(sources[i].multisig_kLRki);
      }
    }
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      dest_keys.push_back(rct::pk2rct(var::get<txout_to_key>(tx.vout[i].target).key));
      outamounts.push_back(tx.vout[i].amount);
      amount_out += tx.vout[i].amount;
    }

    for (size_t i = 0; i < sources.size(); ++i)
    {
      mixRing[i].resize(sources[i].outputs.size());
      for (size_t n = 0; n < sources[i].outputs.size(); ++n)
      {
        mixRing[i][n] = sources[i].outputs[n].second;
      }
    }

    if (tx_params.burn_fixed)
    {
      if (amount_in < amount_out + tx_params.burn_fixed)
      {
        LOG_ERROR("invalid burn amount: tx does not have enough unspent funds available; amount_in: " << std::to_string(amount_in) << "; amount_out + tx_params.burn_fixed: " << std::to_string(amount_out) << " + " << std::to_string(tx_params.burn_fixed));
        return false;
      }
      remove_field_from_tx_extra<tx_extra_burn>(tx.extra); // doesn't have to be present (but the wallet puts a dummy here as a safety to avoid growing the tx)
      if (!add_burned_amount_to_tx_extra(tx.extra, tx_params.burn_fixed))
      {
        LOG_ERROR("failed to add burn amount to tx extra");
        return false;
      }
    }

    // zero out all amounts to mask rct outputs, real amounts are now encrypted
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
      if (sources[i].rct)
        var::get<txin_to_key>(tx.vin[i]).amount = 0;
    }
    for (size_t i = 0; i < tx.vout.size(); ++i)
      tx.vout[i].amount = 0;

    crypto::hash tx_prefix_hash;
    get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
    rct::ctkeyV outSk;
    tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, dest_keys, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, msout ? &kLRki : NULL, msout, index, outSk, rct_config, hwdev);
    memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

    CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

    MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << "\n" << obj_to_json_str(tx) << "\n");

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout, oxen_construct_tx_params const &tx_params)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key, transaction::get_max_version_for_hf(tx_params.hf_version), tx_params.tx_type);
    try {
      // figure out if we need to make additional tx pubkeys
      size_t num_stdaddresses = 0;
      size_t num_subaddresses = 0;
      account_public_address single_dest_subaddress;
      classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
      bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
      if (need_additional_txkeys)
      {
        additional_tx_keys.clear();
        for (const auto &d: destinations)
          additional_tx_keys.push_back(keypair{sender_account_keys.get_device()}.sec);
      }

      bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct_config, msout, true /*shuffle_outs*/, tx_params);
      hwdev.close_tx();
      return r;
    } catch(...) {
      hwdev.close_tx();
      throw;
    }
  }
  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry> &sources, const std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const oxen_construct_tx_params &tx_params)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
     std::vector<tx_destination_entry> destinations_copy = destinations;

     // Always construct CLSAG transactions.  They weren't actually acceptable before HF 16, but
     // they are now for our fake networks (which we need to do because we no longer have pre-CLSAG
     // tx generation code).
     rct::RCTConfig rct_config{rct::RangeProofType::PaddedBulletproof, 3};

     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct_config, NULL, tx_params);
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(block& bl, network_type nettype)
  {
      const auto& conf = get_config(nettype);
    //genesis block
    bl = {};

    CHECK_AND_ASSERT_MES(oxenmq::is_hex(conf.GENESIS_TX), false, "failed to parse coinbase tx from hard coded blob");
    std::string tx_bl = oxenmq::from_hex(conf.GENESIS_TX);
    bool r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = 7;
    bl.minor_version = 7;
    bl.timestamp = 0;
    bl.nonce = conf.GENESIS_NONCE;
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, unsigned int threads, crypto::hash &hash){
      hash = cryptonote::get_block_longhash(UNDEFINED, cryptonote::randomx_longhash_context(NULL, b, height), b, height, threads);
      return true;
    }, bl, 1, 0);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_altblock_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height)
  {
    crypto::hash result = {};
    if (nettype == FAKECHAIN || b.major_version < network_version_12_checkpointing)
    {
      result = get_block_longhash(nettype, randomx_context, b, height, 0);
    }
    else
    {
      blobdata bd = get_block_hashing_blob(b);
      rx_slow_hash(randomx_context.current_blockchain_height, randomx_context.seed_height, randomx_context.seed_block_hash.data, bd.data(), bd.size(), result.data, 0, 1);
    }

    return result;
  }

  randomx_longhash_context::randomx_longhash_context(const Blockchain *pbc,
                                                     const block &b /*block to longhash*/,
                                                     const uint64_t height)
  {
    *this = {};
    if (b.major_version >= network_version_12_checkpointing)
    {
      if (pbc) // null only happens when generating genesis block, 0 init randomx is ok
      {
        seed_height               = rx_seedheight(height);
        seed_block_hash           = pbc->get_pending_block_id_by_height(seed_height);
        current_blockchain_height = pbc->get_current_blockchain_height();
      }
    }
  }

  crypto::hash get_block_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height, int miners)
  {
    crypto::hash result      = {};
    const blobdata bd        = get_block_hashing_blob(b);
    const uint8_t hf_version = b.major_version;

#if defined(OXEN_INTEGRATION_TESTS)
    miners = 0;
#endif

    crypto::cn_slow_hash_type cn_type = cn_slow_hash_type::heavy_v1;
    if (nettype == FAKECHAIN)
    {
      cn_type = cn_slow_hash_type::turtle_lite_v2;
    }
    else
    {
      if (hf_version >= network_version_12_checkpointing)
      {
        rx_slow_hash(randomx_context.current_blockchain_height,
                     randomx_context.seed_height,
                     randomx_context.seed_block_hash.data,
                     bd.data(),
                     bd.size(),
                     result.data,
                     miners,
                     0);
        return result;
      }

      if (hf_version >= network_version_11_infinite_staking)
        cn_type = cn_slow_hash_type::turtle_lite_v2;
      else if (hf_version >= network_version_7)
        cn_type = crypto::cn_slow_hash_type::heavy_v2;
    }

    crypto::cn_slow_hash(bd.data(), bd.size(), result, cn_type);
    return result;
  }

  crypto::hash get_block_longhash_w_blockchain(cryptonote::network_type nettype, const Blockchain *pbc, const block& b, uint64_t height, int miners)
  {
    crypto::hash result = get_block_longhash(nettype,randomx_longhash_context(pbc, b, height), b, height, miners);
    return result;
  }

  void get_block_longhash_reorg(const uint64_t split_height)
  {
    rx_reorg(split_height);
  }
}
