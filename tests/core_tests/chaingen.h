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

#pragma once

#include <vector>
#include <iostream>
#include <cstdint>
#include <optional>
#include <regex>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/program_options.hpp>
#include <boost/serialization/vector.hpp>

#include "cryptonote_protocol/quorumnet.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"

#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_protocol/quorumnet.h"
#include "serialization/boost_std_variant.h"
#include "serialization/boost_std_optional.h"
#include "epee/misc_language.h"

#include "blockchain_db/testdb.h"
#include "blockchain_db/sqlite/types.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "tests.core"

#define TESTS_DEFAULT_FEE ((uint64_t)200000000) // 2 * pow(10, 8)
#define TEST_DEFAULT_DIFFICULTY 1

#if defined(__GNUG__) && !defined(__clang__) && __GNUC__ < 6
namespace service_nodes {
  const std::vector<payout_entry> dummy; // help GCC 5 realize it needs to generate a default constructor
}
#endif

struct oxen_block_with_checkpoint
{
  cryptonote::block        block;
  bool                     has_checkpoint;
  cryptonote::checkpoint_t checkpoint;
};

struct oxen_transaction
{
  cryptonote::transaction tx;
  bool                    kept_by_block;
};

// TODO(oxen): Deperecate other methods of doing polymorphism for items to be
// added to test_event_entry.  Right now, adding a block and checking for
// failure requires you to add a member field to mark the event index that
// should of failed, and you must add a member function that checks at run-time
// if at the marked index the block failed or not.

// Doing this way lets you write the failure case inline to when you create the
// test_event_entry, which means less book-keeping and boilerplate code of
// tracking event indexes and making member functions to detect the failure cases.
template <typename T>
struct oxen_blockchain_addable
{
  oxen_blockchain_addable() = default;
  oxen_blockchain_addable(T const &data, bool can_be_added_to_blockchain = true, std::string const &fail_msg = {})
  : data(data)
  , can_be_added_to_blockchain(can_be_added_to_blockchain)
  , fail_msg(fail_msg)
  {
  }

  T data;
  bool can_be_added_to_blockchain;
  std::string fail_msg;

  private: // TODO(doyle): Not implemented properly. Just copy pasta. Do we even need serialization?
  friend class boost::serialization::access;
  template<class Archive> void serialize(Archive & /*ar*/, const unsigned int /*version*/) { }
};

typedef std::function<bool (cryptonote::core& c, size_t ev_index)> oxen_callback;
struct oxen_callback_entry
{
  std::string   name;
  oxen_callback callback;

private: // TODO(doyle): Not implemented properly. Just copy pasta. Do we even need serialization?
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/) { ar & name; }
};

//
// NOTE: Monero
//
struct callback_entry
{
  std::string callback_name;
  BEGIN_SERIALIZE_OBJECT()
    FIELD(callback_name)
  END_SERIALIZE()

private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & callback_name;
  }
};

template<typename T>
struct serialized_object
{
  serialized_object() { }

  serialized_object(const cryptonote::blobdata& a_data)
    : data(a_data)
  {
  }

  cryptonote::blobdata data;
  BEGIN_SERIALIZE_OBJECT()
    FIELD(data)
    END_SERIALIZE()

private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & data;
  }
};

typedef serialized_object<cryptonote::block> serialized_block;
typedef serialized_object<cryptonote::transaction> serialized_transaction;

struct event_visitor_settings
{
  int valid_mask;
  bool txs_keeped_by_block;
  crypto::secret_key service_node_key;

  enum settings
  {
    set_txs_keeped_by_block = 1 << 0,
  };

  event_visitor_settings(int a_valid_mask = 0, bool a_txs_keeped_by_block = false)
    : valid_mask(a_valid_mask)
    , txs_keeped_by_block(a_txs_keeped_by_block)
  {
  }

private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & valid_mask;
    ar & txs_keeped_by_block;
    ar & service_node_key;
  }
};

struct event_replay_settings
{
  event_replay_settings() = default;
  std::optional<std::vector<cryptonote::hard_fork>> hard_forks;

private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & hard_forks;
  }
};


BINARY_VARIANT_TAG(callback_entry, 0xcb);
BINARY_VARIANT_TAG(cryptonote::account_base, 0xcc);
BINARY_VARIANT_TAG(serialized_block, 0xcd);
BINARY_VARIANT_TAG(serialized_transaction, 0xce);
BINARY_VARIANT_TAG(event_visitor_settings, 0xcf);
BINARY_VARIANT_TAG(event_replay_settings, 0xda);

typedef   std::variant<cryptonote::block,
                       cryptonote::transaction,
                       std::vector<cryptonote::transaction>,
                       cryptonote::account_base,
                       callback_entry,
                       serialized_block,
                       serialized_transaction,
                       event_visitor_settings,
                       event_replay_settings,

                       std::string,
                       oxen_callback_entry,
                       oxen_blockchain_addable<oxen_block_with_checkpoint>,
                       oxen_blockchain_addable<cryptonote::block>,
                       oxen_blockchain_addable<oxen_transaction>,
                       oxen_blockchain_addable<service_nodes::quorum_vote_t>,
                       oxen_blockchain_addable<serialized_block>,
                       oxen_blockchain_addable<cryptonote::checkpoint_t>
                       > test_event_entry;
typedef std::unordered_map<crypto::hash, const cryptonote::transaction*> map_hash2tx_t;

class test_chain_unit_base
{
public:
  typedef std::function<bool (cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)> verify_callback;
  typedef std::map<std::string, verify_callback> callbacks_map;

  void register_callback(const std::string& cb_name, verify_callback cb);
  bool verify(const std::string& cb_name, cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events);
  bool check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*blk*/);
  bool check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool /*tx_added*/, size_t /*event_index*/, const cryptonote::transaction& /*tx*/);
  bool check_tx_verification_context_array(const std::vector<cryptonote::tx_verification_context>& tvcs, size_t /*tx_added*/, size_t /*event_index*/, const std::vector<cryptonote::transaction>& /*txs*/);
  bool was_vote_meant_to_be_successfully_added(size_t event_index, bool vote_was_added) { (void)event_index; return vote_was_added; }

private:
  callbacks_map m_callbacks;
};

class test_generator
{
public:
  struct block_info
  {
    block_info()
      : prev_id()
      , already_generated_coins(0)
      , block_weight(0)
    {
    }

    block_info(crypto::hash a_prev_id, uint64_t an_already_generated_coins, size_t a_block_weight, cryptonote::block a_block)
      : prev_id(a_prev_id)
      , already_generated_coins(an_already_generated_coins)
      , block_weight(a_block_weight)
      , block(a_block)
    {
    }

    crypto::hash prev_id;
    uint64_t already_generated_coins;
    size_t block_weight;
    cryptonote::block block;

  private:
    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int /*version*/)
    {
      ar & prev_id;
      ar & already_generated_coins;
      ar & block_weight;
      ar & block;
    }
  };

  enum block_fields
  {
    bf_none      = 0,
    bf_major_ver = 1 << 0,
    bf_minor_ver = 1 << 1,
    bf_timestamp = 1 << 2,
    bf_prev_id   = 1 << 3,
    bf_miner_tx  = 1 << 4,
    bf_tx_hashes = 1 << 5,
    bf_diffic    = 1 << 6,
    bf_hf_version= 1 << 8
  };

  explicit test_generator(int hf_version = 7) : m_hf_version(hf_version) {}
  void get_block_chain(std::vector<block_info>& blockchain,        const crypto::hash& head, size_t n) const;
  void get_block_chain(std::vector<cryptonote::block>& blockchain, const crypto::hash& head, size_t n) const;
  void get_last_n_block_weights(std::vector<uint64_t>& block_weights, const crypto::hash& head, size_t n) const;
  uint64_t get_already_generated_coins(const crypto::hash& blk_id) const;
  uint64_t get_already_generated_coins(const cryptonote::block& blk) const;

  void add_block(const cryptonote::block& blk, size_t tsx_size, std::vector<uint64_t>& block_weights, uint64_t already_generated_coins);
  bool construct_block(cryptonote::block& blk, uint64_t height, const crypto::hash& prev_id,
    const cryptonote::account_base& miner_acc, uint64_t timestamp, uint64_t already_generated_coins,
    std::vector<uint64_t>& block_weights, const std::list<cryptonote::transaction>& tx_list, const service_nodes::payout &block_leader = {});
  bool construct_block(cryptonote::block& blk, const cryptonote::account_base& miner_acc, uint64_t timestamp);
  bool construct_block(cryptonote::block& blk, const cryptonote::block& blk_prev, const cryptonote::account_base& miner_acc,
    const std::list<cryptonote::transaction>& tx_list = std::list<cryptonote::transaction>(), const service_nodes::payout &block_leader = {});

  bool construct_block_manually(cryptonote::block& blk, const cryptonote::block& prev_block,
    const cryptonote::account_base& miner_acc, int actual_params = bf_none, uint8_t major_ver = 0,
    uint8_t minor_ver = 0, uint64_t timestamp = 0, const crypto::hash& prev_id = crypto::hash(),
    const cryptonote::difficulty_type& diffic = 1, const cryptonote::transaction& miner_tx = cryptonote::transaction(),
    const std::vector<crypto::hash>& tx_hashes = std::vector<crypto::hash>(), size_t txs_sizes = 0, size_t txn_fee = 0);
  bool construct_block_manually_tx(cryptonote::block& blk, const cryptonote::block& prev_block,
    const cryptonote::account_base& miner_acc, const std::vector<crypto::hash>& tx_hashes, size_t txs_size);


  int m_hf_version;
  std::unordered_map<crypto::hash, block_info> m_blocks_info;

  private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & m_blocks_info;
  }
};

template<typename T>
std::string dump_keys(T * buff32)
{
  std::ostringstream ss;
  char buff[10];

  ss << "[";
  for(int i = 0; i < 32; i++)
  {
    snprintf(buff, 10, "0x%02x", ((uint8_t)buff32[i] & 0xff));
    ss << buff;
    if (i < 31)
      ss << ",";
  }
  ss << "]";
  return ss.str();
}

struct output_index {
  cryptonote::txout_target_v out;
  uint64_t amount;
  size_t blk_height; // block height
  size_t tx_no; // index of transaction in block
  size_t out_no; // index of out in transaction
  size_t idx;
  uint64_t unlock_time;
  bool is_coin_base;
  bool deterministic_key_pair;
  bool spent;
  bool rct;
  rct::key comm;
  rct::key mask; // TODO(oxen): I dont know if this is still meant to be here. Monero removed and replaced with commitment, whereas we use the mask in our tests?
  cryptonote::block const *p_blk;
  cryptonote::transaction const *p_tx;

  output_index() = default;
  output_index(const cryptonote::txout_target_v &_out, uint64_t _a, size_t _h, size_t tno, size_t ono, const cryptonote::block *_pb, const cryptonote::transaction *_pt)
  {
    *this = {};
    out = _out;
    amount = _a;
    blk_height = _h;
    tx_no = tno;
    out_no = ono;
    p_blk = _pb;
    p_tx = _pt;
  }

#if 0
  output_index(const output_index &other)
      : out(other.out), amount(other.amount), blk_height(other.blk_height), tx_no(other.tx_no), rct(other.rct),
      out_no(other.out_no), idx(other.idx), unlock_time(other.unlock_time), is_coin_base(other.is_coin_base),
      spent(other.spent), comm(other.comm), p_blk(other.p_blk), p_tx(other.p_tx) {  }
#endif

  void set_rct(bool arct) {
    rct = arct;
    if (rct &&  p_tx->rct_signatures.outPk.size() > out_no)
      comm = p_tx->rct_signatures.outPk[out_no].mask;
    else
      comm = rct::commit(amount, rct::identity());
  }

  rct::key commitment() const {
    return comm;
  }

  const std::string toString() const {
    std::stringstream ss;

    ss << "output_index{blk_height=" << blk_height
       << " tx_no=" << tx_no
       << " out_no=" << out_no
       << " amount=" << amount
       << " idx=" << idx
       << " unlock_time=" << unlock_time
       << " spent=" << spent
       << " is_coin_base=" << is_coin_base
       << " rct=" << rct
       << " comm=" << dump_keys(comm.bytes)
       << "}";

    return ss.str();
  }

  output_index(const output_index &) = default;
  output_index& operator=(const output_index& other)
  {
    new(this) output_index(other);
    return *this;
  }
};

typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;
typedef std::pair<crypto::hash, size_t> output_hasher;
struct output_hasher_hasher { size_t operator()(const output_hasher &h) const { return *reinterpret_cast<const size_t *>(h.first.data) + h.second; } };
typedef std::map<uint64_t, std::vector<size_t> > map_output_t;
typedef std::map<uint64_t, std::vector<output_index> > map_output_idx_t;
typedef std::unordered_map<crypto::hash, cryptonote::block> map_block_t;
typedef std::unordered_map<output_hasher, output_index, output_hasher_hasher> map_txid_output_t;
typedef std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses_t;
typedef std::pair<uint64_t, size_t>  outloc_t;

typedef std::variant<cryptonote::account_public_address, cryptonote::account_keys, cryptonote::account_base, cryptonote::tx_destination_entry> var_addr_t;
cryptonote::account_public_address get_address(const var_addr_t& inp);

typedef struct {
  const var_addr_t addr;
  bool is_subaddr;
  uint64_t amount;
} dest_wrapper_t;

// Daemon functionality
class block_tracker
{
public:
  map_output_idx_t m_outs;
  map_txid_output_t m_map_outs;  // mapping (txid, out) -> output_index
  map_block_t m_blocks;

  block_tracker() = default;
  block_tracker(const block_tracker &bt): m_outs(bt.m_outs), m_map_outs(bt.m_map_outs), m_blocks(bt.m_blocks) {};
  map_txid_output_t::iterator find_out(const crypto::hash &txid, size_t out);
  map_txid_output_t::iterator find_out(const output_hasher &id);
  void process(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx);
  void process(const std::vector<const cryptonote::block*>& blockchain, const map_hash2tx_t& mtx);
  void process(const cryptonote::block* blk, const cryptonote::transaction * tx, size_t i);
  void global_indices(const cryptonote::transaction *tx, std::vector<uint64_t> &indices);
  void get_fake_outs(size_t num_outs, uint64_t amount, uint64_t global_index, uint64_t cur_height, std::vector<get_outs_entry> &outs);

  std::string dump_data();
  void dump_data(const std::string & fname);

private:
  friend class boost::serialization::access;

  template<class Archive>
  void serialize(Archive & ar, const unsigned int /*version*/)
  {
    ar & m_outs;
    ar & m_map_outs;
    ar & m_blocks;
  }
};

std::string dump_data(const cryptonote::transaction &tx);

cryptonote::tx_destination_entry build_dst(const var_addr_t& to, bool is_subaddr=false, uint64_t amount=0);
std::vector<cryptonote::tx_destination_entry> build_dsts(const var_addr_t& to1, bool sub1=false, uint64_t am1=0);
std::vector<cryptonote::tx_destination_entry> build_dsts(std::initializer_list<dest_wrapper_t> inps);
uint64_t sum_amount(const std::vector<cryptonote::tx_destination_entry>& destinations);
uint64_t sum_amount(const std::vector<cryptonote::tx_source_entry>& sources);

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx,
                         const cryptonote::block& blk_head, const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         uint64_t fee, size_t nmix, rct::RangeProofType range_proof_type=rct::RangeProofType::Borromean, int bp_version = 0);

bool construct_tx_to_key(const std::vector<test_event_entry>& events, cryptonote::transaction& tx, const cryptonote::block& blk_head,
                         const cryptonote::account_base& from, std::vector<cryptonote::tx_destination_entry> destinations,
                         uint64_t fee, size_t nmix, rct::RangeProofType range_proof_type=rct::RangeProofType::Borromean, int bp_version = 0);

bool construct_tx_to_key(cryptonote::transaction& tx, const cryptonote::account_base& from, const var_addr_t& to, uint64_t amount,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, rct::RangeProofType range_proof_type=rct::RangeProofType::Borromean, int bp_version = 0);

bool construct_tx_to_key(cryptonote::transaction& tx, const cryptonote::account_base& from, const std::vector<cryptonote::tx_destination_entry>& destinations,
                         std::vector<cryptonote::tx_source_entry> &sources,
                         uint64_t fee, rct::RangeProofType range_proof_type, int bp_version = 0);

cryptonote::transaction construct_tx_with_fee(std::vector<test_event_entry>& events, const cryptonote::block& blk_head,
                                            const cryptonote::account_base& acc_from, const cryptonote::account_base& acc_to,
                                            uint64_t amount, uint64_t fee);

bool construct_tx_rct(const cryptonote::account_keys& sender_account_keys,
    std::vector<cryptonote::tx_source_entry>& sources,
    const std::vector<cryptonote::tx_destination_entry>& destinations,
    const std::optional<cryptonote::tx_destination_entry>& change_addr,
    std::vector<uint8_t> extra, cryptonote::transaction& tx, uint64_t unlock_time,
    rct::RangeProofType range_proof_type=rct::RangeProofType::Borromean, int bp_version = 0);


uint64_t num_blocks(const std::vector<test_event_entry>& events);
cryptonote::block get_head_block(const std::vector<test_event_entry>& events);

void get_confirmed_txs(const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx, map_hash2tx_t& confirmed_txs);
bool trim_block_chain(std::vector<cryptonote::block>& blockchain, const crypto::hash& tail);
bool trim_block_chain(std::vector<const cryptonote::block*>& blockchain, const crypto::hash& tail);
bool find_block_chain(const std::vector<test_event_entry>& events, std::vector<cryptonote::block>& blockchain, map_hash2tx_t& mtx, const crypto::hash& head);

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
                                            bool always_add_change_output = false,
                                            uint64_t *change_amount = nullptr);

bool find_block_chain(const std::vector<test_event_entry>& events, std::vector<const cryptonote::block*>& blockchain, map_hash2tx_t& mtx, const crypto::hash& head);

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations, bool always_change=false);

void fill_tx_destinations(const var_addr_t& from, const std::vector<cryptonote::tx_destination_entry>& dests,
                          uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations,
                          bool always_change);

void fill_tx_destinations(const var_addr_t& from, const cryptonote::account_public_address& to,
                          uint64_t amount, uint64_t fee,
                          const std::vector<cryptonote::tx_source_entry> &sources,
                          std::vector<cryptonote::tx_destination_entry>& destinations,
                          std::vector<cryptonote::tx_destination_entry>& destinations_pure,
                          bool always_change=false);


void fill_tx_sources_and_destinations(const std::vector<test_event_entry>& events, const cryptonote::block& blk_head,
                                      const cryptonote::account_base& from, const cryptonote::account_public_address& to,
                                      uint64_t amount, uint64_t fee, size_t nmix,
                                      std::vector<cryptonote::tx_source_entry>& sources,
                                      std::vector<cryptonote::tx_destination_entry>& destinations, uint64_t *change_amount = nullptr);

/// Get the amount transferred to `account` in `tx` as output `i`
uint64_t get_amount(const cryptonote::account_base& account, const cryptonote::transaction& tx, int i);

uint64_t get_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx);
uint64_t get_unlocked_balance(const cryptonote::account_base& addr, const std::vector<cryptonote::block>& blockchain, const map_hash2tx_t& mtx);

bool extract_hard_forks(const std::vector<test_event_entry>& events, std::vector<cryptonote::hard_fork>& hard_forks);
/************************************************************************/
/*                                                                      */
/************************************************************************/
template<class t_test_class>
struct push_core_event_visitor
{
private:
  cryptonote::core& m_c;
  const std::vector<test_event_entry>& m_events;
  t_test_class& m_validator;
  size_t m_ev_index;

  bool m_txs_keeped_by_block;

public:
  push_core_event_visitor(cryptonote::core& c, const std::vector<test_event_entry>& events, t_test_class& validator)
    : m_c(c)
    , m_events(events)
    , m_validator(validator)
    , m_ev_index(0)
    , m_txs_keeped_by_block(false)
  {
  }

  void event_index(size_t ev_index)
  {
    m_ev_index = ev_index;
  }

  bool operator()(const event_replay_settings& settings)
  {
    log_event("event_replay_settings");
    return true;
  }

  bool operator()(const event_visitor_settings& settings)
  {
    log_event("event_visitor_settings");

    if (settings.valid_mask & event_visitor_settings::set_txs_keeped_by_block)
    {
      m_txs_keeped_by_block = settings.txs_keeped_by_block;
    }

    return true;
  }

  bool operator()(const cryptonote::transaction& tx) const
  {
    log_event("cryptonote::transaction");
    cryptonote::tx_verification_context tvc{};
    size_t pool_size = m_c.get_pool().get_transactions_count();
    cryptonote::tx_pool_options opts;
    opts.kept_by_block = m_txs_keeped_by_block;
    m_c.handle_incoming_tx(t_serializable_object_to_blob(tx), tvc, opts);
    bool tx_added = pool_size + 1 == m_c.get_pool().get_transactions_count();
    bool r = m_validator.check_tx_verification_context(tvc, tx_added, m_ev_index, tx);
    CHECK_AND_NO_ASSERT_MES(r, false, "tx verification context check failed");
    return true;
  }

  bool operator()(const std::vector<cryptonote::transaction>& txs) const
  {
    log_event("cryptonote::transaction");
    std::vector<cryptonote::blobdata> tx_blobs;
    for (const auto &tx: txs)
      tx_blobs.push_back(t_serializable_object_to_blob(tx));
    size_t pool_size = m_c.get_pool().get_transactions_count();
    cryptonote::tx_pool_options opts;
    opts.kept_by_block = m_txs_keeped_by_block;
    auto parsed = m_c.handle_incoming_txs(tx_blobs, opts);
    std::vector<cryptonote::tx_verification_context> tvcs;
    tvcs.reserve(parsed.size());
    for (auto &i : parsed)
        tvcs.push_back(i.tvc);
    size_t tx_added = m_c.get_pool().get_transactions_count() - pool_size;
    bool r = m_validator.check_tx_verification_context_array(tvcs, tx_added, m_ev_index, txs);
    CHECK_AND_NO_ASSERT_MES(r, false, "tx verification context check failed");
    return true;
  }

  bool operator()(const cryptonote::block& b) const
  {
    log_event("cryptonote::block");
    cryptonote::block_verification_context bvc{};
    cryptonote::blobdata bd = t_serializable_object_to_blob(b);
    std::vector<cryptonote::block> pblocks;
    if (m_c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, {bd, {}, {}}), pblocks))
    {
      m_c.handle_incoming_block(bd, &b, bvc, nullptr);
      m_c.cleanup_handle_incoming_blocks();
    }
    else
      bvc.m_verifivation_failed = true;
    bool r = m_validator.check_block_verification_context(bvc, m_ev_index, b);
    CHECK_AND_NO_ASSERT_MES(r, false, "block verification context check failed");
    return r;
  }

  // TODO(oxen): Deprecate callback_entry for oxen_callback_entry, why don't you
  // just include the callback routine in the callback entry instead of going
  // down into the validator and then have to do a string->callback (map) lookup
  // for the callback?
  bool operator()(const callback_entry& cb) const
  {
    log_event(std::string("callback_entry ") + cb.callback_name);
    return m_validator.verify(cb.callback_name, m_c, m_ev_index, m_events);
  }

  bool operator()(const cryptonote::account_base& ab) const
  {
    log_event("cryptonote::account_base");
    return true;
  }

  bool operator()(const serialized_block& sr_block) const
  {
    log_event("serialized_block");

    cryptonote::block_verification_context bvc{};
    std::vector<cryptonote::block> pblocks;
    if (m_c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, {sr_block.data, {}, {}}), pblocks))
    {
      m_c.handle_incoming_block(sr_block.data, NULL, bvc, nullptr);
      m_c.cleanup_handle_incoming_blocks();
    }
    else
      bvc.m_verifivation_failed = true;

    cryptonote::block blk;
    serialization::binary_string_unarchiver ba{sr_block.data};
    try {
      serialization::serialize(ba, blk);
    } catch (...) {
      blk = cryptonote::block();
    }
    bool r = m_validator.check_block_verification_context(bvc, m_ev_index, blk);
    CHECK_AND_NO_ASSERT_MES(r, false, "block verification context check failed");
    return true;
  }

  bool operator()(const serialized_transaction& sr_tx) const
  {
    log_event("serialized_transaction");

    cryptonote::tx_verification_context tvc{};
    size_t pool_size = m_c.get_pool().get_transactions_count();
    cryptonote::tx_pool_options opts;
    opts.kept_by_block = m_txs_keeped_by_block;
    m_c.handle_incoming_tx(sr_tx.data, tvc, opts);
    bool tx_added = pool_size + 1 == m_c.get_pool().get_transactions_count();

    cryptonote::transaction tx;
    serialization::binary_string_unarchiver ba{sr_tx.data};
    try {
      serialization::serialize(ba, tx);
    } catch (...) {
      tx = cryptonote::transaction();
    }

    bool r = m_validator.check_tx_verification_context(tvc, tx_added, m_ev_index, tx);
    CHECK_AND_NO_ASSERT_MES(r, false, "transaction verification context check failed");
    return true;
  }

  //
  // NOTE: Loki
  //
  bool operator()(const oxen_blockchain_addable<cryptonote::checkpoint_t> &entry) const
  {
    log_event("oxen_blockchain_addable<cryptonote::checkpoint_t>");
    cryptonote::Blockchain &blockchain = m_c.get_blockchain_storage();
    bool added = blockchain.update_checkpoint(entry.data);
    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg : "Failed to add checkpoint (no reason given)"));
    return true;
  }

  bool operator()(const oxen_blockchain_addable<service_nodes::quorum_vote_t> &entry) const
  {
    log_event("oxen_blockchain_addable<service_nodes::quorum_vote_t>");
    cryptonote::vote_verification_context vvc = {};
    bool added                                = m_c.add_service_node_vote(entry.data, vvc);
    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg : "Failed to add service node vote (no reason given)"));
    return true;
  }

  bool operator()(const oxen_blockchain_addable<oxen_block_with_checkpoint> &entry) const
  {
    log_event("oxen_blockchain_addable<oxen_block_with_checkpoint>");
    cryptonote::block const &block = entry.data.block;

    // TODO(oxen): Need to make a copy because we still need modify checkpoints
    // in handle_incoming_blocks but that is because of temporary forking code
    cryptonote::checkpoint_t checkpoint_copy = entry.data.checkpoint;

    cryptonote::block_verification_context bvc = {};
    cryptonote::blobdata bd                    = t_serializable_object_to_blob(block);
    std::vector<cryptonote::block> pblocks;
    if (m_c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, {bd, {}, {}}), pblocks))
    {
      m_c.handle_incoming_block(bd, &block, bvc, &checkpoint_copy);
      m_c.cleanup_handle_incoming_blocks();
    }
    else
      bvc.m_verifivation_failed = true;

    bool added = !bvc.m_verifivation_failed;
    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg : "Failed to add block with checkpoint (no reason given)"));
    return true;
  }
  
  bool operator()(const oxen_blockchain_addable<cryptonote::block> &entry) const
  {
    log_event("oxen_blockchain_addable<cryptonote::block>");
    cryptonote::block const &block             = entry.data;
    cryptonote::block_verification_context bvc = {};
    cryptonote::blobdata bd                    = t_serializable_object_to_blob(block);
    std::vector<cryptonote::block> pblocks;
    if (m_c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, {bd, {}, {}}), pblocks))
    {
      m_c.handle_incoming_block(bd, &block, bvc, nullptr);
      m_c.cleanup_handle_incoming_blocks();
    }
    else
      bvc.m_verifivation_failed = true;

    bool added = !bvc.m_verifivation_failed;
    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg : "Failed to add block (no reason given)"));
    return true;
  }

  bool operator()(const oxen_blockchain_addable<serialized_block> &entry) const
  {
    log_event("oxen_blockchain_addable<serialized_block>");
    serialized_block const &block              = entry.data;
    cryptonote::block_verification_context bvc = {};
    std::vector<cryptonote::block> pblocks;
    if (m_c.prepare_handle_incoming_blocks(std::vector<cryptonote::block_complete_entry>(1, {block.data, {}, {}}), pblocks))
    {
      m_c.handle_incoming_block(block.data, nullptr, bvc, nullptr);
      m_c.cleanup_handle_incoming_blocks();
    }
    else
      bvc.m_verifivation_failed = true;

    bool added = !bvc.m_verifivation_failed;
    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg : "Failed to add block (no reason given)"));
    return true;
  }

  bool operator()(const oxen_blockchain_addable<oxen_transaction> &entry) const
  {
    log_event("oxen_blockchain_addable<oxen_transaction>");
    cryptonote::tx_verification_context tvc = {};
    size_t pool_size = m_c.get_pool().get_transactions_count();
    cryptonote::tx_pool_options opts;
    opts.kept_by_block = entry.data.kept_by_block;
    m_c.handle_incoming_tx(t_serializable_object_to_blob(entry.data.tx), tvc, opts);

    bool added = (pool_size + 1) == m_c.get_pool().get_transactions_count();

    CHECK_AND_NO_ASSERT_MES(added == entry.can_be_added_to_blockchain, false, (entry.fail_msg.size() ? entry.fail_msg :
                entry.can_be_added_to_blockchain ? "Failed to add transaction that should have been accepted" : "TX adding should have failed, but didn't"));
    return true;
  }

  bool operator()(const oxen_callback_entry& entry) const
  {
    log_event(std::string("oxen_callback_entry ") + entry.name);
    bool result = entry.callback(m_c, m_ev_index);
    return result;
  }

  bool operator()(const std::string &msg) const
  {
    log_event("event_msgevent_marker");
    MGINFO_MAGENTA(msg);
    return true;
  }

private:
  void log_event(const std::string& event_type) const
  {
    if (LOG_ENABLED(Info))
      MGINFO_YELLOW("=== EVENT # " << m_ev_index << ": " << event_type);
  }
};
//--------------------------------------------------------------------------
template<class t_test_class>
inline bool replay_events_through_core_plain(cryptonote::core& cr, const std::vector<test_event_entry>& events, t_test_class& validator, bool reinit=true)
{
  TRY_ENTRY();
  // start with a clean pool
  std::vector<crypto::hash> pool_txs;
  cr.get_pool().get_transaction_hashes(pool_txs);
  cr.get_blockchain_storage().flush_txes_from_pool(pool_txs);

  //init core here
  if (reinit) {
    CHECK_AND_ASSERT_MES(std::holds_alternative<cryptonote::block>(events[0]), false,
                         "First event must be genesis block creation");
    cr.set_genesis_block(var::get<cryptonote::block>(events[0]));
  }

  bool r = true;
  push_core_event_visitor<t_test_class> visitor(cr, events, validator);
  for(size_t i = 1; i < events.size() && r; ++i)
  {
    visitor.event_index(i);
    r = var::visit(visitor, events[i]);
  }

  return r;

  CATCH_ENTRY_L0("replay_events_through_core", false);
}
//--------------------------------------------------------------------------
template<typename t_test_class>
struct get_test_options {
  const std::vector<cryptonote::hard_fork> hard_forks = {{7, 0, 0, 0}};
  const cryptonote::test_options test_options = {
    hard_forks, 0
  };
};
//--------------------------------------------------------------------------
template<class t_test_class>
inline bool do_replay_events_get_core(std::vector<test_event_entry>& events, cryptonote::core *core, t_test_class &validator)
{
  boost::program_options::options_description desc("Allowed options");
  cryptonote::core::init_options(desc);
  cryptonote::long_poll_trigger = [](cryptonote::tx_memory_pool&) {};
  boost::program_options::variables_map vm;
  bool r = command_line::handle_error_helper(desc, [&]()
  {
    boost::program_options::store(boost::program_options::basic_parsed_options<char>(&desc), vm);
    boost::program_options::notify(vm);
    return true;
  });
  if (!r)
    return false;

  auto & c = *core;
  quorumnet::init_core_callbacks();

  // TODO(oxen): Deprecate having to specify hardforks in a templated struct. This
  // puts an unecessary level of indirection that makes it hard to follow the
  // code. Hardforks should just be declared next to the testing code in the
  // generate function. Inlining code and localizing declarations so that we read
  // as much as possible top-to-bottom in linear sequences makes things easier to
  // follow

  // But changing this now means that all the other tests would break.
  get_test_options<t_test_class> gto;

  // TODO(oxen): Hard forks should always be specified in events OR do replay
  // events should be passed a testing context which should have this specific
  // testing situation
  // Hardforks can be specified in events.
  std::vector<cryptonote::hard_fork> derived_hardforks;
  bool use_derived_hardforks = extract_hard_forks(events, derived_hardforks);
  const cryptonote::test_options derived_test_options =
  {
    derived_hardforks,
    gto.test_options.long_term_block_weight_window,
  };

  // FIXME: make sure that vm has arg_testnet_on set to true or false if
  // this test needs for it to be so.
  cryptonote::test_options const *testing_options = (use_derived_hardforks) ? &derived_test_options : &gto.test_options;
  if (!c.init(vm, testing_options))
  {
    MERROR("Failed to init core");
    return false;
  }
  c.get_blockchain_storage().get_db().set_batch_transactions(true);
  bool ret = replay_events_through_core_plain<t_test_class>(c, events, validator, true);
  tools::threadpool::getInstance().recycle();
  return ret;
}
//--------------------------------------------------------------------------
template<class t_test_class>
inline bool do_replay_file(const std::string& filename)
{
  std::vector<test_event_entry> events;
  if (!tools::unserialize_obj_from_file(events, filename))
  {
    MERROR("Failed to deserialize data from file: ");
    return false;
  }

  cryptonote::core core;
  t_test_class validator;
  bool result = do_replay_events_get_core<t_test_class>(events, &core, validator);
  core.deinit();
  return result;
}

//--------------------------------------------------------------------------
#define DEFAULT_HARDFORKS(HARDFORKS) do { \
  HARDFORKS.push_back(std::make_pair((uint8_t)1, (uint64_t)0)); \
} while(0)

#define ADD_HARDFORK(HARDFORKS, FORK, HEIGHT) HARDFORKS.push_back(std::make_pair((uint8_t)FORK, (uint64_t)HEIGHT))

#define GENERATE_ACCOUNT(account) \
    cryptonote::account_base account; \
    account.generate();

#define GENERATE_MULTISIG_ACCOUNT(account, threshold, total) \
    CHECK_AND_ASSERT_MES(threshold >= 2 && threshold <= total, false, "Invalid multisig scheme"); \
    std::vector<cryptonote::account_base> account(total); \
    do \
    { \
      for (size_t msidx = 0; msidx < total; ++msidx) \
        account[msidx].generate(); \
      make_multisig_accounts(account, threshold); \
    } while(0)

#define MAKE_ACCOUNT(VEC_EVENTS, account) \
  cryptonote::account_base account; \
  account.generate(); \
  VEC_EVENTS.push_back(account);

#define DO_CALLBACK(VEC_EVENTS, CB_NAME) \
{ \
  callback_entry CALLBACK_ENTRY; \
  CALLBACK_ENTRY.callback_name = CB_NAME; \
  VEC_EVENTS.push_back(CALLBACK_ENTRY); \
}

#define REGISTER_CALLBACK(METHOD) \
  register_callback(#METHOD, [this](auto&&... x) { return METHOD(std::forward<decltype(x)>(x)...); });

#define MAKE_GENESIS_BLOCK(VEC_EVENTS, BLK_NAME, MINER_ACC, TS)                       \
  test_generator generator;                                               \
  cryptonote::block BLK_NAME;                                                           \
  generator.construct_block(BLK_NAME, MINER_ACC, TS);                                 \
  VEC_EVENTS.push_back(BLK_NAME);

/// TODO: use hf_ver from test options
#define MAKE_GENESIS_BLOCK_WITH_HF_VERSION(VEC_EVENTS, BLK_NAME, MINER_ACC, TS, HF_VER)                       \
  test_generator generator(HF_VER);                                               \
  cryptonote::block BLK_NAME;                                                           \
  generator.construct_block(BLK_NAME, MINER_ACC, TS);                                 \
  VEC_EVENTS.push_back(BLK_NAME);

#define MAKE_NEXT_BLOCK(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC)                  \
  cryptonote::block BLK_NAME;                                                           \
  generator.construct_block(BLK_NAME, PREV_BLOCK, MINER_ACC);                         \
  VEC_EVENTS.push_back(BLK_NAME);

#define MAKE_NEXT_BLOCK_V2(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, WINNER, SN_INFO)            \
  cryptonote::block BLK_NAME;                                                           \
  generator.construct_block(BLK_NAME, PREV_BLOCK, MINER_ACC, {}, WINNER, SN_INFO);                   \
  VEC_EVENTS.push_back(BLK_NAME);

#define MAKE_NEXT_BLOCK_TX1(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, TX1)         \
  cryptonote::block BLK_NAME;                                                           \
  {                                                                                   \
    std::list<cryptonote::transaction> tx_list;                                         \
    tx_list.push_back(TX1);                                                           \
    generator.construct_block(BLK_NAME, PREV_BLOCK, MINER_ACC, tx_list);              \
  }                                                                                   \
  VEC_EVENTS.push_back(BLK_NAME);

#define MAKE_NEXT_BLOCK_TX_LIST(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, TXLIST)  \
  cryptonote::block BLK_NAME;                                                           \
  generator.construct_block(BLK_NAME, PREV_BLOCK, MINER_ACC, TXLIST);                 \
  VEC_EVENTS.push_back(BLK_NAME);

#define REWIND_BLOCKS_N(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, COUNT)    \
  cryptonote::block BLK_NAME;                                                         \
  {                                                                                   \
    cryptonote::block blk_last = PREV_BLOCK;                                          \
    for (size_t i = 0; i < COUNT; ++i)                                                \
    {                                                                                 \
      MAKE_NEXT_BLOCK(VEC_EVENTS, blk, blk_last, MINER_ACC);                   \
      blk_last = blk;                                                                 \
    }                                                                                 \
    BLK_NAME = blk_last;                                                              \
  }

#define REWIND_BLOCKS_N_V2(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, COUNT, WINNER, SN_INFO) \
  cryptonote::block BLK_NAME;                                                           \
  {                                                                                   \
    cryptonote::block blk_last = PREV_BLOCK;                                            \
    for (size_t i = 0; i < COUNT; ++i)                                                \
    {                                                                                 \
      MAKE_NEXT_BLOCK_V2(VEC_EVENTS, blk, blk_last, MINER_ACC, WINNER, SN_INFO);      \
      blk_last = blk;                                                                 \
    }                                                                                 \
    BLK_NAME = blk_last;                                                              \
  }

#define REWIND_BLOCKS(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC) REWIND_BLOCKS_N(VEC_EVENTS, BLK_NAME, PREV_BLOCK, MINER_ACC, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW)

// NOTE(oxen): These macros assume hardfork version 7 and are from the old Monero testing code
#define MAKE_TX_MIX(VEC_EVENTS, TX_NAME, FROM, TO, AMOUNT, NMIX, HEAD)                       \
  cryptonote::transaction TX_NAME;                                                           \
  oxen_tx_builder(VEC_EVENTS, TX_NAME, HEAD, FROM, TO.get_keys().m_account_address, AMOUNT, cryptonote::network_version_7).build(); \
  VEC_EVENTS.push_back(TX_NAME);

#define MAKE_TX_MIX_RCT(VEC_EVENTS, TX_NAME, FROM, TO, AMOUNT, NMIX, HEAD)                       \
  cryptonote::transaction TX_NAME;                                                             \
  construct_tx_to_key(VEC_EVENTS, TX_NAME, HEAD, FROM, TO, AMOUNT, TESTS_DEFAULT_FEE, NMIX, rct::RangeProofType::PaddedBulletproof); \
  VEC_EVENTS.push_back(TX_NAME);

#define MAKE_TX(VEC_EVENTS, TX_NAME, FROM, TO, AMOUNT, HEAD) MAKE_TX_MIX(VEC_EVENTS, TX_NAME, FROM, TO, AMOUNT, 9, HEAD)

#define MAKE_TX_MIX_LIST(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD)             \
  {                                                                                      \
    cryptonote::transaction t;                                                             \
    oxen_tx_builder(VEC_EVENTS, t, HEAD, FROM, TO.get_keys().m_account_address, AMOUNT, cryptonote::network_version_7).build(); \
    SET_NAME.push_back(t);                                                               \
    VEC_EVENTS.push_back(t);                                                             \
  }


#define MAKE_TX_MIX_LIST_RCT(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD) \
        MAKE_TX_MIX_LIST_RCT_EX(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD, rct::RangeProofType::PaddedBulletproof, 1)
#define MAKE_TX_MIX_LIST_RCT_EX(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD, RCT_TYPE, BP_VER)  \
  {                                                                                      \
    cryptonote::transaction t;                                                           \
    construct_tx_to_key(VEC_EVENTS, t, HEAD, FROM, TO, AMOUNT, TESTS_DEFAULT_FEE, NMIX, RCT_TYPE, BP_VER); \
    SET_NAME.push_back(t);                                                               \
    VEC_EVENTS.push_back(t);                                                             \
  }

#define MAKE_TX_MIX_DEST_LIST_RCT(VEC_EVENTS, SET_NAME, FROM, TO, NMIX, HEAD)            \
        MAKE_TX_MIX_DEST_LIST_RCT_EX(VEC_EVENTS, SET_NAME, FROM, TO, NMIX, HEAD, rct::RangeProofType::PaddedBulletproof, 1)
#define MAKE_TX_MIX_DEST_LIST_RCT_EX(VEC_EVENTS, SET_NAME, FROM, TO, NMIX, HEAD, RCT_TYPE, BP_VER)  \
  {                                                                                      \
    cryptonote::transaction t;                                                           \
    construct_tx_to_key(VEC_EVENTS, t, HEAD, FROM, TO, TESTS_DEFAULT_FEE, NMIX, RCT_TYPE, BP_VER); \
    SET_NAME.push_back(t);                                                               \
    VEC_EVENTS.push_back(t);                                                             \
  }

#define MAKE_TX_LIST(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, HEAD) MAKE_TX_MIX_LIST(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, 9, HEAD)

#define MAKE_TX_LIST_START(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, HEAD) \
    std::list<cryptonote::transaction> SET_NAME; \
    MAKE_TX_LIST(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, HEAD);

#define MAKE_MINER_TX_MANUALLY(TX, BLK)                                                                                \
  transaction TX;                                                                                                      \
  std::optional<std::vector<cryptonote::batch_sn_payment>> sn_rwds;                                                       \
  uint64_t block_rewards = 0;                                                                                          \
  bool r;                                                                                                              \
  std::tie(r, block_rewards) = construct_miner_tx(get_block_height(BLK) + 1,                                           \
                          0,                                                                                           \
                          generator.get_already_generated_coins(BLK),                                                  \
                          0,                                                                                           \
                          0,                                                                                           \
                          TX,                                                                                          \
                          cryptonote::oxen_miner_tx_context::miner_block(cryptonote::FAKECHAIN, miner_account.get_keys().m_account_address), \
                          sn_rwds,                                                                                     \
                          {}                                                                                           \
                          );                                                                                           \
  if (!r)                                                                                                              \
    return false;

#define MAKE_TX_LIST_START_RCT(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD) \
    std::list<cryptonote::transaction> SET_NAME; \
    MAKE_TX_MIX_LIST_RCT(VEC_EVENTS, SET_NAME, FROM, TO, AMOUNT, NMIX, HEAD);

#define SET_EVENT_VISITOR_SETT(VEC_EVENTS, SETT, VAL) VEC_EVENTS.push_back(event_visitor_settings(SETT, VAL));


#define PLAY(filename, generator_class) \
    if(!do_replay_file<generator_class>(filename)) \
    { \
      MERROR("Failed to pass test : " << #generator_class); \
      return 1; \
    }

#define CATCH_REPLAY(generator_class)                                                                                  \
  catch (const std::exception &ex) { MERROR(#generator_class << " generation failed: what=" << ex.what()); }           \
  catch (...) { MERROR(#generator_class << " generation failed: generic exception"); }

#define REPLAY_CORE(generator_class, generator_class_instance)                                                         \
  {                                                                                                                    \
    cryptonote::core core;                                                                                             \
    if (generated && do_replay_events_get_core<generator_class>(events, &core, generator_class_instance))              \
    {                                                                                                                  \
      MGINFO_GREEN("#TEST# Succeeded " << #generator_class);                                                           \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
      MERROR("#TEST# Failed " << #generator_class);                                                                    \
      failed_tests.push_back(#generator_class);                                                                        \
    }                                                                                                                  \
    core.deinit();                                                                                                     \
  }

#define REPLAY_WITH_CORE(generator_class, generator_class_instance, CORE)                                              \
  {                                                                                                                    \
    if (generated &&                                                                                                   \
        replay_events_through_core_plain<generator_class>(events, CORE, generator_class_instance, false /*reinit*/))   \
    {                                                                                                                  \
      MGINFO_GREEN("#TEST# Succeeded " << #generator_class);                                                           \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
      MERROR("#TEST# Failed " << #generator_class);                                                                    \
      failed_tests.push_back(#generator_class);                                                                        \
    }                                                                                                                  \
  }

#define CATCH_GENERATE_REPLAY(generator_class, generator_class_instance)                                               \
  CATCH_REPLAY(generator_class);                                                                                       \
  REPLAY_CORE(generator_class, generator_class_instance);

#define CATCH_GENERATE_REPLAY_CORE(generator_class, generator_class_instance, CORE)                                    \
  CATCH_REPLAY(generator_class);                                                                                       \
  REPLAY_WITH_CORE(generator_class, generator_class_instance, CORE);

#define GENERATE_AND_PLAY(generator_class)                                                                             \
  if (list_tests)                                                                                                      \
    std::cout << #generator_class << std::endl;                                                                        \
  else if (std::cmatch m; filter.empty() || std::regex_match(#generator_class, m, std::regex(filter)))                 \
  {                                                                                                                    \
    std::vector<test_event_entry> events;                                                                              \
    ++tests_count;                                                                                                     \
    bool generated = false;                                                                                            \
    generator_class generator_class_instance;                                                                          \
    try                                                                                                                \
    {                                                                                                                  \
      generated = generator_class_instance.generate(events);                                                           \
    }                                                                                                                  \
    CATCH_GENERATE_REPLAY(generator_class, generator_class_instance);                                                  \
  }

#define GENERATE_AND_PLAY_INSTANCE(generator_class, generator_class_instance, CORE)                                    \
  if (std::cmatch m; filter.empty() || std::regex_match(#generator_class, m, std::regex(filter)))                      \
  {                                                                                                                    \
    std::vector<test_event_entry> events;                                                                              \
    ++tests_count;                                                                                                     \
    bool generated = false;                                                                                            \
    try                                                                                                                \
    {                                                                                                                  \
      generated = ins.generate(events);                                                                                \
    }                                                                                                                  \
    CATCH_GENERATE_REPLAY_CORE(generator_class, generator_class_instance, CORE);                                       \
  }

#define QUOTEME(x) #x
#define DEFINE_TESTS_ERROR_CONTEXT(text) const char* perr_context = text;
#define CHECK_TEST_CONDITION(cond) CHECK_AND_ASSERT_MES(cond, false, "[" << perr_context << "] failed: \"" << QUOTEME(cond) << "\"")
#define CHECK_TEST_CONDITION_MSG(cond, msg) CHECK_AND_ASSERT_MES(cond, false, "[" << perr_context << "] failed: \"" << QUOTEME(cond) << "\", msg: " << msg)
#define CHECK_EQ(v1, v2) CHECK_AND_ASSERT_MES(v1 == v2, false, "[" << perr_context << "] failed: \"" << QUOTEME(v1) << " == " << QUOTEME(v2) << "\", " << v1 << " != " << v2)
#define CHECK_NOT_EQ(v1, v2) CHECK_AND_ASSERT_MES(!(v1 == v2), false, "[" << perr_context << "] failed: \"" << QUOTEME(v1) << " != " << QUOTEME(v2) << "\", " << v1 << " == " << v2)
#define MK_COINS(amount) (UINT64_C(amount) * COIN)

inline std::string make_junk() {
  std::string junk;
  junk.reserve(1024);
  for (size_t i = 0; i < 256; i++)
    junk += (char) i;
  junk += junk;
  junk += junk;
  return junk;
}

//
// NOTE: Loki
//
class oxen_tx_builder {

  /// required fields
  const std::vector<test_event_entry>& m_events;
  cryptonote::transaction& m_tx;
  const cryptonote::block& m_head;
  const cryptonote::account_base& m_from;
  const cryptonote::account_public_address& m_to;

  uint64_t m_amount;
  uint64_t m_fee;
  uint64_t m_unlock_time;
  uint64_t m_junk_size = 0;
  std::vector<uint8_t> m_extra;
  cryptonote::oxen_construct_tx_params m_tx_params;

  /// this makes sure we didn't forget to build it
  bool m_finished = false;

public:
  oxen_tx_builder(const std::vector<test_event_entry>& events,
            cryptonote::transaction& tx,
            const cryptonote::block& head,
            const cryptonote::account_base& from,
            const cryptonote::account_public_address& to,
            uint64_t amount,
            uint8_t hf_version)
    : m_events(events)
    , m_tx(tx)
    , m_head(head)
    , m_from(from)
    , m_to(to)
    , m_amount(amount)
    , m_fee(TESTS_DEFAULT_FEE)
    , m_unlock_time(0)
  {
    m_tx_params.hf_version = hf_version;
  }

  oxen_tx_builder&& with_fee(uint64_t fee) {
    m_fee = fee;
    return std::move(*this);
  }

  oxen_tx_builder&& with_extra(const std::vector<uint8_t>& extra) {
    m_extra = extra;
    return std::move(*this);
  }

  oxen_tx_builder&& with_unlock_time(uint64_t val) {
    m_unlock_time = val;
    return std::move(*this);
  }

  oxen_tx_builder&& with_tx_type(cryptonote::txtype val) {
    m_tx_params.tx_type = val;
    return std::move(*this);
  }

  oxen_tx_builder&& with_junk(size_t size) {
    m_junk_size = size;
    return std::move(*this);
  }

  ~oxen_tx_builder() {
    if (!m_finished) {
      std::cerr << "Tx building not finished\n";
      abort();
    }
  }

  inline static const std::string junk1k = make_junk();

  bool build()
  {
    m_finished = true;

    std::vector<cryptonote::tx_source_entry> sources;
    std::vector<cryptonote::tx_destination_entry> destinations;
    uint64_t change_amount;

    constexpr size_t nmix = 9;
    if (m_tx_params.tx_type == cryptonote::txtype::oxen_name_system) // ONS txes only have change
    {
      fill_tx_sources_and_multi_destinations(
          m_events, m_head, m_from, m_to, nullptr /*amounts*/, 0 /*num_amounts*/, m_fee, nmix, sources, destinations, true /*add change*/, &change_amount);
    }
    else
    {
      // TODO(oxen): Eww we still depend on monero land test code
      fill_tx_sources_and_destinations(
        m_events, m_head, m_from, m_to, m_amount, m_fee, nmix, sources, destinations, &change_amount);
    }

    if (m_junk_size > 0) {
      std::string junk;
      junk.reserve(m_junk_size + 10);
      tools::write_varint(std::back_inserter(junk), m_junk_size);
      m_junk_size += junk.size(); // we just added some bytes for the varint
      std::string_view junk_piece{junk1k};
      while (junk.size() < m_junk_size) {
        if (junk.size() + junk_piece.size() > m_junk_size)
          junk_piece = junk_piece.substr(0, m_junk_size - junk.size());
        junk += junk_piece;
      }
      cryptonote::add_tagged_data_to_tx_extra(m_extra, cryptonote::TX_EXTRA_MYSTERIOUS_MINERGATE_TAG, junk);
    }

    cryptonote::tx_destination_entry change_addr{ change_amount, m_from.get_keys().m_account_address, false /*is_subaddr*/ };
    bool result = cryptonote::construct_tx(
      m_from.get_keys(), sources, destinations, change_addr, m_extra, m_tx, m_unlock_time, m_tx_params);
    return result;
  }
};

void fill_nonce_with_oxen_generator(struct oxen_chain_generator const *generator, cryptonote::block& blk, const cryptonote::difficulty_type& diffic, uint64_t height);
void oxen_register_callback(std::vector<test_event_entry> &events, std::string const &callback_name, oxen_callback callback);
std::vector<cryptonote::hard_fork> oxen_generate_hard_fork_table(uint8_t hf_version = cryptonote::network_version_count - 1, uint64_t pos_delay = 60);

struct oxen_blockchain_entry
{
  cryptonote::block                          block;
  std::vector<cryptonote::transaction>       txs;
  uint64_t                                   block_weight;
  uint64_t                                   already_generated_coins;
  service_nodes::service_node_list::state_t  service_node_state{nullptr};
  bool                                       checkpointed;
  cryptonote::checkpoint_t                   checkpoint;
};

struct oxen_chain_generator_db : public cryptonote::BaseTestDB
{
  std::vector<oxen_blockchain_entry>                        blocks;
  std::unordered_map<crypto::hash, cryptonote::transaction> tx_table;
  std::unordered_map<crypto::hash, oxen_blockchain_entry>   block_table;

  uint64_t                              get_block_height(crypto::hash const &hash) const override;
  cryptonote::block_header              get_block_header_from_height(uint64_t height) const override;
  cryptonote::block                     get_block_from_height(uint64_t height) const override;
  bool                                  get_tx(const crypto::hash& h, cryptonote::transaction &tx) const override;
  std::vector<cryptonote::checkpoint_t> get_checkpoints_range(uint64_t start, uint64_t end, size_t num_desired_checkpoints) const override;
  std::vector<cryptonote::block>        get_blocks_range(const uint64_t& h1, const uint64_t& h2) const override;
  uint64_t height() const override { return blocks.size(); }
};

struct oxen_service_node_contribution
{
    cryptonote::account_public_address contributor;
    uint64_t                           portions;
};

enum struct oxen_create_block_type
{
  automatic,
  pulse,
  miner,
};

struct oxen_create_block_params
{
  oxen_create_block_type               type;
  uint8_t                              hf_version;
  oxen_blockchain_entry                prev;
  cryptonote::account_base             miner_acc;
  uint64_t                             timestamp;
  std::vector<uint64_t>                block_weights;
  std::vector<cryptonote::transaction> tx_list;
  service_nodes::payout                block_leader;
  uint64_t                             total_fee;
  uint8_t                              pulse_round;
};

struct oxen_chain_generator
{
  // TODO(oxen): I want to store pointers to transactions but I get some memory corruption somewhere. Pls fix.
  // We already store blockchain_entries in block_ vector which stores the actual backing transaction entries.
  std::unordered_map<crypto::hash, cryptonote::transaction>          tx_table_;
  mutable std::unordered_map<crypto::public_key, crypto::secret_key> service_node_keys_;
  std::unordered_map<crypto::public_key, std::vector<std::pair<cryptonote::account_public_address, uint64_t>>> service_node_contributors_;
  service_nodes::service_node_list::state_set                        state_history_;
  uint64_t                                                           last_cull_height_ = 0;
  std::shared_ptr<ons::name_system_db>                               ons_db_ = std::make_shared<ons::name_system_db>();
  //TODO sean
  std::shared_ptr<cryptonote::BlockchainSQLite>                      sqlite_db_ = std::make_shared<cryptonote::BlockchainSQLite>();
  oxen_chain_generator_db                                            db_;
  uint8_t                                                            hf_version_ = cryptonote::network_version_7;
  std::vector<test_event_entry>&                                     events_;
  const std::vector<cryptonote::hard_fork>                           hard_forks_;
  cryptonote::account_base                                           first_miner_;

  oxen_chain_generator(std::vector<test_event_entry> &events, const std::vector<cryptonote::hard_fork>& hard_forks);

  uint64_t                                             height()       const { return cryptonote::get_block_height(db_.blocks.back().block); }
  uint64_t                                             chain_height() const { return height() + 1; }
  const std::vector<oxen_blockchain_entry>&            blocks()       const { return db_.blocks; }
  size_t                                               event_index()  const { return events_.size() - 1; }
  uint8_t                                              hardfork()     const { return get_hf_version_at(height()); }

  const oxen_blockchain_entry&                         top() const { return db_.blocks.back(); }
  service_nodes::quorum_manager                        top_quorum() const;
  service_nodes::quorum_manager                        quorum(uint64_t height) const;
  std::shared_ptr<const service_nodes::quorum>         get_quorum(service_nodes::quorum_type type, uint64_t height) const;
  service_nodes::service_node_keys                     get_cached_keys(const crypto::public_key &pubkey) const;

  cryptonote::account_base                             add_account();
  oxen_blockchain_entry                               &add_block(oxen_blockchain_entry const &entry, bool can_be_added_to_blockchain = true, std::string const &fail_msg = {});
  void                                                 add_blocks_until_version(uint8_t hf_version);
  void                                                 add_n_blocks(int n);
  bool                                                 add_blocks_until_next_checkpointable_height();
  void                                                 add_service_node_checkpoint(uint64_t block_height, size_t num_votes);
  void                                                 add_mined_money_unlock_blocks(); // NOTE: Unlock all Loki generated from mining prior to this call i.e. CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
  void                                                 add_transfer_unlock_blocks(); // Unlock funds from (standard) transfers prior to this call, i.e. CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE

  // NOTE: Add an event that is just a user specified message to signify progress in the test
  void                                                 add_event_msg(std::string const &msg) { events_.push_back(msg); }
  void                                                 add_tx(cryptonote::transaction const &tx, bool can_be_added_to_blockchain = true, std::string const &fail_msg = {}, bool kept_by_block = false);

  oxen_create_block_params                             next_block_params() const;

  // NOTE: Add constructed TX to events_ and assume that it is valid to add to the blockchain. If the TX is meant to be unaddable to the blockchain use the individual create + add functions to
  // be able to mark the add TX event as something that should trigger a failure.
  cryptonote::transaction                              create_and_add_oxen_name_system_tx(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, ons::mapping_value const &value, ons::generic_owner const *owner = nullptr, ons::generic_owner const *backup_owner = nullptr, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_oxen_name_system_tx_update(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, ons::mapping_value const *value, ons::generic_owner const *owner = nullptr, ons::generic_owner const *backup_owner = nullptr, ons::generic_signature *signature = nullptr, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_oxen_name_system_tx_renew(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_tx                 (const cryptonote::account_base& src, const cryptonote::account_public_address& dest, uint64_t amount, uint64_t fee = TESTS_DEFAULT_FEE, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_state_change_tx(service_nodes::new_state state, const crypto::public_key& pub_key, uint16_t reasons_all, uint16_t reasons_any, uint64_t height = -1, const std::vector<uint64_t>& voters = {}, uint64_t fee = 0, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_registration_tx(const cryptonote::account_base& src, const cryptonote::keypair& sn_keys = cryptonote::keypair{hw::get_device("default")}, bool kept_by_block = false);
  cryptonote::transaction                              create_and_add_staking_tx     (const crypto::public_key &pub_key, const cryptonote::account_base &src, uint64_t amount, bool kept_by_block = false);
  oxen_blockchain_entry                               &create_and_add_next_block     (const std::vector<cryptonote::transaction>& txs = {}, cryptonote::checkpoint_t const *checkpoint = nullptr, bool can_be_added_to_blockchain = true, std::string const &fail_msg = {});
  // Same as create_and_add_tx, but also adds 95kB of junk into tx_extra to bloat up the tx size.
  cryptonote::transaction create_and_add_big_tx(const cryptonote::account_base& src, const cryptonote::account_public_address& dest, uint64_t amount, uint64_t junk_size = 95000, uint64_t fee = TESTS_DEFAULT_FEE, bool kept_by_block = false);

  // NOTE: Create transactions but don't add to events_
  cryptonote::transaction                              create_tx(const cryptonote::account_base &src, const cryptonote::account_public_address &dest, uint64_t amount, uint64_t fee) const;
  cryptonote::transaction                              create_registration_tx(const cryptonote::account_base &src,
                                                                              const cryptonote::keypair &service_node_keys = cryptonote::keypair{hw::get_device("default")},
                                                                              uint64_t src_portions = STAKING_PORTIONS,
                                                                              uint64_t src_operator_cut = 0,
                                                                              std::array<oxen_service_node_contribution, 3> const &contributors = {},
                                                                              int num_contributors = 0) const;
  cryptonote::transaction                              create_staking_tx     (const crypto::public_key& pub_key, const cryptonote::account_base &src, uint64_t amount) const;
  cryptonote::transaction                              create_state_change_tx(service_nodes::new_state state, const crypto::public_key& pub_key, uint16_t reasons_all, uint16_t reasons_any, uint64_t height = -1, const std::vector<uint64_t>& voters = {}, uint64_t fee = 0) const;
  cryptonote::checkpoint_t                             create_service_node_checkpoint(uint64_t block_height, size_t num_votes) const;

  // value: Takes the binary value NOT the human readable version, of the name->value mapping
  static const uint64_t ONS_AUTO_BURN = static_cast<uint64_t>(-1);
  cryptonote::transaction                              create_oxen_name_system_tx(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, ons::mapping_value const &value, ons::generic_owner const *owner = nullptr, ons::generic_owner const *backup_owner = nullptr, std::optional<uint64_t> burn_override = std::nullopt) const;
  cryptonote::transaction                              create_oxen_name_system_tx_update(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, ons::mapping_value const *value, ons::generic_owner const *owner = nullptr, ons::generic_owner const *backup_owner = nullptr, ons::generic_signature *signature = nullptr, bool use_asserts = false) const;
  cryptonote::transaction                              create_oxen_name_system_tx_update_w_extra(cryptonote::account_base const &src, uint8_t hf_version, cryptonote::tx_extra_oxen_name_system const &ons_extra) const;
  cryptonote::transaction                              create_oxen_name_system_tx_renew(cryptonote::account_base const &src, uint8_t hf_version, ons::mapping_type type, std::string const &name, std::optional<uint64_t> burn_override = std::nullopt) const;

  oxen_blockchain_entry                                create_genesis_block(const cryptonote::account_base &miner, uint64_t timestamp);
  oxen_blockchain_entry                                create_next_block(const std::vector<cryptonote::transaction>& txs = {}, cryptonote::checkpoint_t const *checkpoint = nullptr);
  bool                                                 create_block(oxen_blockchain_entry &entry, oxen_create_block_params &params, const std::vector<cryptonote::transaction> &tx_list) const;

  bool                                                 block_begin(oxen_blockchain_entry &entry, oxen_create_block_params &params, const std::vector<cryptonote::transaction> &tx_list) const;
  void                                                 block_fill_pulse_data(oxen_blockchain_entry &entry, oxen_create_block_params const &params, uint8_t round) const;
  void                                                 block_end(oxen_blockchain_entry &entry, oxen_create_block_params const &params) const;
  bool                                                 process_registration_tx(cryptonote::transaction& tx, uint64_t block_height, uint8_t hf_version);

  uint8_t                                              get_hf_version_at(uint64_t height) const;
  std::vector<uint64_t>                                last_n_block_weights(uint64_t height, uint64_t num) const;
  const cryptonote::account_base&                      first_miner() const { return first_miner_; }
};
