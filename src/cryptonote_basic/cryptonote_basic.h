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

#include <vector>
#include <sstream>
#include <atomic>
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/crypto.h"
#include "epee/serialization/keyvalue_serialization.h" // eepe named serialization
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "device/device.hpp"
#include "txtypes.h"

namespace service_nodes
{
  struct quorum_signature
  {
    uint16_t voter_index;
    char padding[6] = {0};
    crypto::signature signature;

    quorum_signature() = default;
    quorum_signature(uint16_t voter_index, crypto::signature const &signature) :
        voter_index(voter_index),
        signature(signature)
    {}

    BEGIN_SERIALIZE_OBJECT()
      FIELD(voter_index)
      FIELD(signature)
    END_SERIALIZE()
  };
};

namespace cryptonote
{
  /* outputs */
  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() = default;
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };


  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };


  using txin_v = std::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key>;

  using txout_target_v = std::variant<txout_to_script, txout_to_scripthash, txout_to_key>;

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()


  };

  // Blink quorum statuses.  Note that the underlying numeric values is used in the RPC.  `none` is
  // only used in places like the RPC where we return a value even if not a blink at all.
  enum class blink_result { none = 0, rejected, accepted, timeout };

  class transaction_prefix
  {

  public:
    static char const* version_to_string(txversion v);
    static char const* type_to_string(txtype type);

    static constexpr txversion get_min_version_for_hf(uint8_t hf_version);
    static           txversion get_max_version_for_hf(uint8_t hf_version);
    static constexpr txtype    get_max_type_for_hf   (uint8_t hf_version);

    // tx information
    txversion version;
    txtype type;

    bool is_transfer() const { return type == txtype::standard || type == txtype::stake || type == txtype::oxen_name_system; }

    // not used after version 2, but remains for compatibility
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time
    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    std::vector<uint8_t> extra;
    std::vector<uint64_t> output_unlock_times;

    BEGIN_SERIALIZE()
      ENUM_FIELD(version, version >= txversion::v1 && version < txversion::_count);
      if (version >= txversion::v3_per_output_unlock_times)
      {
        FIELD(output_unlock_times)
        if (version == txversion::v3_per_output_unlock_times) {
          bool is_state_change = type == txtype::state_change;
          FIELD(is_state_change)
          type = is_state_change ? txtype::state_change : txtype::standard;
        }
      }
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      if (version >= txversion::v3_per_output_unlock_times && vout.size() != output_unlock_times.size())
      {
        throw std::invalid_argument{"v3 tx without correct unlock times"};
      }
      FIELD(extra)
      if (version >= txversion::v4_tx_types)
        ENUM_FIELD_N("type", type, type < txtype::_count);
    END_SERIALIZE()

    transaction_prefix() { set_null(); }
    void set_null();

    // This function is inlined because device_ledger code needs to call it, but doesn't link
    // against cryptonote_basic.
    uint64_t get_unlock_time(size_t out_index) const {
      if (version >= txversion::v3_per_output_unlock_times)
      {
        if (out_index >= output_unlock_times.size())
        {
          LOG_ERROR("Tried to get unlock time of a v3 transaction with missing output unlock time");
          return unlock_time;
        }
        return output_unlock_times[out_index];
      }
      return unlock_time;
    }

  };

  class transaction final : public transaction_prefix
  {
  private:
    // hash cache
    mutable std::atomic<bool> hash_valid;
    mutable std::atomic<bool> blob_size_valid;

  public:
    std::vector<std::vector<crypto::signature>> signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    // hash cache
    mutable crypto::hash hash;
    mutable size_t blob_size;

    bool pruned;

    std::atomic<unsigned int> unprunable_size;
    std::atomic<unsigned int> prefix_size;

    transaction() { set_null(); }
    transaction(const transaction &t);
    transaction& operator=(const transaction& t);
    void set_null();
    void invalidate_hashes();
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    bool is_blob_size_valid() const { return blob_size_valid.load(std::memory_order_acquire); }
    void set_blob_size_valid(bool v) const { blob_size_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) { hash = h; set_hash_valid(true); }
    void set_blob_size(size_t sz) { blob_size = sz; set_blob_size_valid(true); }

    BEGIN_SERIALIZE_OBJECT()
      constexpr bool Binary = serialization::is_binary<Archive>;

      if (Archive::is_deserializer)
      {
        set_hash_valid(false);
        set_blob_size_valid(false);
      }

      const unsigned int start_pos = Binary ? ar.streampos() : 0;

      serialization::value(ar, static_cast<transaction_prefix&>(*this));

      if (Binary)
        prefix_size = ar.streampos() - start_pos;

      if (version == txversion::v1)
      {
        if (Binary)
          unprunable_size = ar.streampos() - start_pos;

        ar.tag("signatures");
        auto arr = ar.begin_array();
        if (Archive::is_deserializer)
          signatures.resize(vin.size());
        bool signatures_expected = !signatures.empty();
        if (signatures_expected && vin.size() != signatures.size())
          throw std::invalid_argument{"Incorrect number of signatures"};

        const size_t vin_sigs = pruned ? 0 : vin.size();
        for (size_t i = 0; i < vin_sigs; ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (!signatures_expected)
          {
            if (signature_size > 0)
              throw std::invalid_argument{"Invalid unexpected signature"};
            continue;
          }

          if (Archive::is_deserializer)
            signatures[i].resize(signature_size);
          else if (signature_size != signatures[i].size())
            throw std::invalid_argument{"Invalid signature size (expected " + std::to_string(signature_size) + ", have " + std::to_string(signatures[i].size()) + ")"};

          value(arr.element(), signatures[i]);
        }
      }
      else
      {
        if (!vin.empty())
        {
          {
            ar.tag("rct_signatures");
            auto obj = ar.begin_object();
            rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          }

          if (Binary)
            unprunable_size = ar.streampos() - start_pos;

          if (!pruned && rct_signatures.type != rct::RCTType::Null)
          {
            ar.tag("rctsig_prunable");
            auto obj = ar.begin_object();
            rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout.size(),
                vin.size() > 0 && std::holds_alternative<txin_to_key>(vin[0]) ? var::get<txin_to_key>(vin[0]).key_offsets.size() - 1 : 0);
          }
        }
      }
      if (Archive::is_deserializer)
        pruned = false;
    END_SERIALIZE()

    template<class Archive>
    void serialize_base(Archive& ar)
    {
      serialization::value(ar, static_cast<transaction_prefix&>(*this));

      if (version != txversion::v1)
      {
        if (!vin.empty())
        {
          ar.tag("rct_signatures");
          auto obj = ar.begin_object();
          rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
        }
      }
      if (Archive::is_deserializer)
        pruned = true;
    }

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct pulse_random_value
  {
    unsigned char data[16];
    bool operator==(pulse_random_value const &other) const { return std::memcmp(data, other.data, sizeof(data)) == 0; }

    static constexpr bool binary_serializable = true;
  };

  struct pulse_header
  {
    pulse_random_value random_value;
    uint8_t            round;
    uint16_t           validator_bitset;
  };

  template <typename Archive>
  void serialize_value(Archive& ar, pulse_header& p)
  {
    auto obj = ar.begin_object();
    serialization::field(ar, "random_value", p.random_value);
    serialization::field(ar, "round", p.round);
    serialization::field(ar, "validator_bitset", p.validator_bitset);
  }

  struct block_header
  {
    uint8_t major_version = cryptonote::network_version_7;
    uint8_t minor_version = cryptonote::network_version_7;  // now used as a voting mechanism, rather than how this particular block is built
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;
    pulse_header pulse = {};

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
      if (major_version >= cryptonote::network_version_16_pulse)
        FIELD(pulse)
    END_SERIALIZE()
  };

  struct block: public block_header
  {
  private:
    // hash cache
    mutable std::atomic<bool> hash_valid{false};
    void copy_hash(const block &b) { bool v = b.is_hash_valid(); hash = b.hash; set_hash_valid(v); }

  public:
    block() = default;
    block(const block& b);
    block(block&& b);
    block& operator=(const block& b);
    block& operator=(block&& b);
    void invalidate_hashes() { set_hash_valid(false); }
    bool is_hash_valid() const;
    void set_hash_valid(bool v) const;

    transaction miner_tx;
    size_t height;
    crypto::public_key service_node_winner_key;
    uint64_t reward;
    std::vector<crypto::hash> tx_hashes;

    // hash cache
    mutable crypto::hash hash;
    std::vector<service_nodes::quorum_signature> signatures;

    BEGIN_SERIALIZE_OBJECT()
      if (Archive::is_deserializer)
        set_hash_valid(false);

      FIELDS(static_cast<block_header&>(*this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
      if (tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK)
        throw std::invalid_argument{"too many txs in block"};
      if (major_version >= cryptonote::network_version_16_pulse)
        FIELD(signatures)
      if (major_version >= cryptonote::network_version_19)
      {
        VARINT_FIELD(height)
        FIELD(service_node_winner_key)
        VARINT_FIELD(reward) 
      }
    END_SERIALIZE()
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()

    bool operator==(const account_public_address& rhs) const
    {
      return m_spend_public_key == rhs.m_spend_public_key &&
             m_view_public_key == rhs.m_view_public_key;
    }

    bool operator!=(const account_public_address& rhs) const
    {
      return !(*this == rhs);
    }
  };
  inline constexpr account_public_address null_address{};

  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    keypair() = default;

    // Constructs from a copied public/secret key
    keypair(const crypto::public_key& pub, const crypto::secret_key& sec) : pub{pub}, sec{sec} {}
    // Default copy and move
    keypair(const keypair&) = default;
    keypair(keypair&&) = default;
    keypair& operator=(const keypair&) = default;
    keypair& operator=(keypair&&) = default;

    // Constructs by generating a keypair via the given hardware device:
    explicit keypair(hw::device& hwdev) { hwdev.generate_keys(pub, sec); }
  };

  using byte_and_output_fees = std::pair<uint64_t, uint64_t>;

  //---------------------------------------------------------------
  constexpr txversion transaction_prefix::get_min_version_for_hf(uint8_t hf_version)
  {
    if (hf_version >= cryptonote::network_version_7 && hf_version <= cryptonote::network_version_10_bulletproofs)
      return txversion::v2_ringct;
    return txversion::v4_tx_types;
  }

  // Used in the test suite to disable the older max version values below so that some test suite
  // tests can still use particular hard forks without needing to actually generate pre-v4 txes.
  namespace hack { inline bool test_suite_permissive_txes = false; }

  inline txversion transaction_prefix::get_max_version_for_hf(uint8_t hf_version)
  {
    if (!hack::test_suite_permissive_txes) {
      if (hf_version >= cryptonote::network_version_7 && hf_version <= cryptonote::network_version_8)
        return txversion::v2_ringct;

      if (hf_version >= cryptonote::network_version_9_service_nodes && hf_version <= cryptonote::network_version_10_bulletproofs)
        return txversion::v3_per_output_unlock_times;
    }

    return txversion::v4_tx_types;
  }

  constexpr txtype transaction_prefix::get_max_type_for_hf(uint8_t hf_version)
  {
    txtype result = txtype::standard;
    if      (hf_version >= network_version_15_ons)              result = txtype::oxen_name_system;
    else if (hf_version >= network_version_14_blink)            result = txtype::stake;
    else if (hf_version >= network_version_11_infinite_staking) result = txtype::key_image_unlock;
    else if (hf_version >= network_version_9_service_nodes)     result = txtype::state_change;

    return result;
  }

  inline const char* transaction_prefix::version_to_string(txversion v)
  {
    switch(v)
    {
      case txversion::v1:                         return "1";
      case txversion::v2_ringct:                  return "2_ringct";
      case txversion::v3_per_output_unlock_times: return "3_per_output_unlock_times";
      case txversion::v4_tx_types:                return "4_tx_types";
      default: assert(false);                     return "xx_unhandled_version";
    }
  }

  inline const char* transaction_prefix::type_to_string(txtype type)
  {
    switch(type)
    {
      case txtype::standard:                return "standard";
      case txtype::state_change:            return "state_change";
      case txtype::key_image_unlock:        return "key_image_unlock";
      case txtype::stake:                   return "stake";
      case txtype::oxen_name_system:        return "oxen_name_system";
      default: assert(false);               return "xx_unhandled_type";
    }
  }

  inline std::ostream &operator<<(std::ostream &os, txtype t) {
    return os << transaction::type_to_string(t);
  }
  inline std::ostream &operator<<(std::ostream &os, txversion v) {
    return os << transaction::version_to_string(v);
  }
}

namespace std {
  template <>
  struct hash<cryptonote::account_public_address>
  {
    std::size_t operator()(const cryptonote::account_public_address& addr) const
    {
      // https://stackoverflow.com/a/17017281
      size_t res = 17;
      res = res * 31 + hash<crypto::public_key>()(addr.m_spend_public_key);
      res = res * 31 + hash<crypto::public_key>()(addr.m_view_public_key);
      return res;
    }
  };
}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(cryptonote::txin_gen, "gen", 0xff);
VARIANT_TAG(cryptonote::txin_to_script, "script", 0x0);
VARIANT_TAG(cryptonote::txin_to_scripthash, "scripthash", 0x1);
VARIANT_TAG(cryptonote::txin_to_key, "key", 0x2);
VARIANT_TAG(cryptonote::txout_to_script, "script", 0x0);
VARIANT_TAG(cryptonote::txout_to_scripthash, "scripthash", 0x1);
VARIANT_TAG(cryptonote::txout_to_key, "key", 0x2);
VARIANT_TAG(cryptonote::transaction, "tx", 0xcc);
VARIANT_TAG(cryptonote::block, "block", 0xbb);
