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

#pragma once
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "blockchain_db/sqlite/types.h"
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include "ringct/rctOps.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_basic/verification_context.h"

namespace cryptonote
{
  //---------------------------------------------------------------
  keypair  get_deterministic_keypair_from_height(uint64_t height);
  bool     get_deterministic_output_key         (const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key);
  bool     validate_governance_reward_key       (uint64_t height, std::string_view governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, const cryptonote::network_type nettype);

  uint64_t governance_reward_formula            (uint64_t base_reward, uint8_t hf_version);
  bool     block_has_governance_output          (network_type nettype, cryptonote::block const &block);
  bool     height_has_governance_output         (network_type nettype, uint8_t hard_fork_version, uint64_t height);
  uint64_t derive_governance_from_block_reward  (network_type nettype, const cryptonote::block &block, uint8_t hf_version);

  std::vector<uint64_t> distribute_reward_by_portions(const std::vector<service_nodes::payout_entry>& payout, uint64_t total_reward, bool distribute_remainder);
  uint64_t get_portion_of_reward                     (uint64_t portions, uint64_t total_service_node_reward);
  uint64_t service_node_reward_formula               (uint64_t base_reward, uint8_t hard_fork_version);

   /**
    * Returned type of parse_incoming_txs() that provides details about which transactions failed
    * and why.  This is passed on to handle_parsed_txs() (potentially after modification such as
    * setting `approved_blink`) to handle_parsed_txs() to actually insert the transactions.
    */
   struct tx_verification_batch_info {
     cryptonote::tx_verification_context tvc{}; // Verification information
     bool parsed = false; // Will be true if we were able to at least parse the transaction
     bool result = false; // Indicates that the transaction was parsed and passed some basic checks
     bool already_have = false; // Indicates that the tx was found to already exist (in mempool or blockchain)
     bool approved_blink = false; // Can be set between the parse and handle calls to make this a blink tx (that replaces conflicting non-blink txes)
     const blobdata *blob = nullptr; // Will be set to a pointer to the incoming blobdata (i.e. string). caller must keep it alive!
     crypto::hash tx_hash; // The transaction hash (only set if `parsed`)
     transaction tx; // The parsed transaction (only set if `parsed`)
   };

  struct oxen_miner_tx_context
  {
    static oxen_miner_tx_context miner_block(network_type nettype,
                                             cryptonote::account_public_address const &block_producer,
                                             service_nodes::payout const &block_leader = service_nodes::null_payout)
    {
        oxen_miner_tx_context result = {};
        result.nettype               = nettype;
        result.miner_block_producer  = block_producer;
        result.block_leader          = block_leader;
        return result;
    }

    static oxen_miner_tx_context pulse_block(network_type nettype,
                                             service_nodes::payout const &block_producer,
                                             service_nodes::payout const &block_leader = service_nodes::null_payout)
    {
      oxen_miner_tx_context result = {};
      result.pulse                 = true;
      result.nettype               = nettype;
      result.pulse_block_producer  = block_producer;
      result.block_leader          = block_leader;
      return result;
    }

    network_type           nettype = MAINNET;

    bool                   pulse;                // If true, pulse_.* varables are set, otherwise miner_block_producer is set, determining who should get the coinbase reward.
    service_nodes::payout  pulse_block_producer; // Can be different from the leader in Pulse if the original leader fails to complete the round, the block producer changes.

    account_public_address miner_block_producer;
    service_nodes::payout  block_leader;         // Winner from the Service Node queuing in the Service Node List.
    uint64_t               batched_governance;   // NOTE: 0 until hardfork v10, then use blockchain::calc_batched_governance_reward
  };

  enum struct reward_type
  {
    miner,
    snode,
    governance
  };

  struct reward_payout
  {
    reward_type            type;
    account_public_address address;
    uint64_t               amount;
    bool operator==(service_nodes::payout_entry const &other) const { return address == other.address; }

    reward_payout() = default;
    reward_payout(reward_type t, account_public_address addr, uint64_t amt): type{t}, address{std::move(addr)}, amount{amt} {}
  };

  std::pair<bool, uint64_t> construct_miner_tx(
      size_t height,
      size_t median_weight,
      uint64_t already_generated_coins,
      size_t current_block_weight,
      uint64_t fee,
      transaction& tx,
      const oxen_miner_tx_context &miner_context,
      const std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds,
      const blobdata& extra_nonce = blobdata(),
      uint8_t hard_fork_version = 1);

  struct block_reward_parts
  {
    uint64_t service_node_total;

    uint64_t governance_due;
    uint64_t governance_paid;

    uint64_t base_miner;
    uint64_t miner_fee;

    /// The base block reward from which non-miner amounts (i.e. SN rewards and governance fees) are
    /// calculated.  Before HF 13 this was (mistakenly) reduced by the block size penalty for
    /// exceeding the median block size; starting in HF 13 the miner pays the full penalty.
    uint64_t original_base_reward;
  };

  struct oxen_block_reward_context
  {
    using portions = uint64_t;
    bool                     testnet_override;
    uint64_t                 height;
    uint64_t                 fee;
    uint64_t                 batched_governance;   // Optional: 0 hardfork v10, then must be calculated using blockchain::calc_batched_governance_reward
    std::vector<service_nodes::payout_entry> block_leader_payouts = {service_nodes::null_payout_entry};
  };

  // NOTE(oxen): I would combine this into get_base_block_reward, but
  // cryptonote_basic as a library is to be able to trivially link with
  // cryptonote_core since it would have a circular dependency on Blockchain

  // NOTE: Block reward function that should be called after hard fork v10
  bool get_oxen_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, int hard_fork_version, block_reward_parts &result, const oxen_block_reward_context &oxen_context);


  struct tx_source_entry
  {
    using output_entry = std::pair<uint64_t, rct::ctkey>;

    std::vector<output_entry> outputs;  //index + key + optional ringct commitment
    size_t real_output;                 //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    std::vector<crypto::public_key> real_out_additional_tx_keys; //incoming real tx additional public keys
    size_t real_output_in_tx_index;     //index in transaction outputs vector
    uint64_t amount;                    //money
    bool rct;                           //true if the output is rct
    rct::key mask;                      //ringct amount mask
    rct::multisig_kLRki multisig_kLRki; //multisig info

    void push_output(uint64_t idx, const crypto::public_key &k, uint64_t amount) { outputs.push_back(std::make_pair(idx, rct::ctkey({rct::pk2rct(k), rct::zeroCommit(amount)}))); }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_additional_tx_keys)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(rct)
      FIELD(mask)
      FIELD(multisig_kLRki)

      if (real_output >= outputs.size())
        throw std::invalid_argument{"invalid real_output size"};
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    std::string original;
    uint64_t amount;                    //money
    account_public_address addr;        //destination address
    bool is_subaddress;
    bool is_integrated;

    tx_destination_entry() : amount(0), addr{}, is_subaddress(false), is_integrated(false) { }
    tx_destination_entry(uint64_t a, const account_public_address &ad, bool is_subaddress) : amount(a), addr(ad), is_subaddress(is_subaddress), is_integrated(false) { }
    tx_destination_entry(const std::string &o, uint64_t a, const account_public_address &ad, bool is_subaddress) : original(o), amount(a), addr(ad), is_subaddress(is_subaddress), is_integrated(false) { }

    bool operator==(const tx_destination_entry& other) const
    {
      return amount == other.amount && addr == other.addr;
    }

    std::string address(network_type nettype, const crypto::hash &payment_id) const
    {
      if (!original.empty())
      {
        return original;
      }

      if (is_integrated)
      {
        return get_account_integrated_address_as_str(nettype, addr, reinterpret_cast<const crypto::hash8 &>(payment_id));
      }

      return get_account_address_as_str(nettype, is_subaddress, addr);
    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(original)
      VARINT_FIELD(amount)
      FIELD(addr)
      FIELD(is_subaddress)
      FIELD(is_integrated)
    END_SERIALIZE()
  };

  struct oxen_construct_tx_params
  {
    uint8_t hf_version = cryptonote::network_version_7;
    txtype tx_type     = txtype::standard;

    // Can be set to non-zero values to have the tx be constructed specifying required burn amounts
    // Note that the percentage is relative to the minimal base tx fee, *not* the actual tx fee.
    //
    // For example if the base tx fee is 0.5, the priority sets the fee to 500%, the fixed burn
    // amount is 0.1, and the percentage burn is 300% then the tx overall fee will be 0.1+2.5=2.6,
    // and the burn amount will be 0.1+3(0.5)=1.6 (and thus the miner tx coinbase amount will be
    // 1.0).  (See also wallet2's get_fee_percent which needs to return a value large enough to
    // allow these amounts to be burned).
    uint64_t burn_fixed   = 0; // atomic units
    uint64_t burn_percent = 0; // 123 = 1.23x base fee.
  };

  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr);
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry> &sources, const std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const oxen_construct_tx_params &tx_params = {});
  bool construct_tx_with_tx_key   (const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout = NULL, bool shuffle_outs = true, oxen_construct_tx_params const &tx_params = {});
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time,       crypto::secret_key &tx_key,       std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout = NULL, oxen_construct_tx_params const &tx_params = {});
  bool generate_output_ephemeral_keys(const size_t tx_version, bool &found_change,
                                      const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const std::optional<cryptonote::tx_destination_entry> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key);

  bool generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const std::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key) ;

  bool generate_genesis_block(block& bl, network_type nettype);

  struct randomx_longhash_context
  {
    uint64_t     seed_height;
    crypto::hash seed_block_hash;
    uint64_t     current_blockchain_height;
    randomx_longhash_context() = default;
    randomx_longhash_context(const Blockchain *pbc, const block& b /*block to longhash*/, const uint64_t height);
  };

  class Blockchain;
  crypto::hash get_block_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height, int miners);
  crypto::hash get_altblock_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height);
  crypto::hash get_block_longhash_w_blockchain(cryptonote::network_type nettype, const Blockchain *pb, const block& b, uint64_t height, int miners);
  void get_block_longhash_reorg(const uint64_t split_height);

}

BOOST_CLASS_VERSION(cryptonote::tx_source_entry, 1)
BOOST_CLASS_VERSION(cryptonote::tx_destination_entry, 2)

namespace boost
{
  namespace serialization
  {
    template <class Archive>
    inline void serialize(Archive &a, cryptonote::tx_source_entry &x, const boost::serialization::version_type ver)
    {
      a & x.outputs;
      a & x.real_output;
      a & x.real_out_tx_key;
      a & x.real_output_in_tx_index;
      a & x.amount;
      a & x.rct;
      a & x.mask;
      if (ver < 1)
        return;
      a & x.multisig_kLRki;
      a & x.real_out_additional_tx_keys;
    }

    template <class Archive>
    inline void serialize(Archive& a, cryptonote::tx_destination_entry& x, const boost::serialization::version_type ver)
    {
      a & x.amount;
      a & x.addr;
      if (ver < 1)
        return;
      a & x.is_subaddress;
      if (ver < 2)
      {
        x.is_integrated = false;
        return;
      }
      a & x.original;
      a & x.is_integrated;
    }
  }
}
