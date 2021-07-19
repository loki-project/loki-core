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

#include <atomic>
#include <boost/algorithm/string.hpp>
#include <limits>
#include <oxenmq/hex.h>
#include <variant>
#include "common/hex.h"
#include "epee/wipeable_string.h"
#include "epee/string_tools.h"
#include "common/i18n.h"
#include "common/meta.h"
#include "serialization/string.h"
#include "serialization/binary_utils.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_core/service_node_voting.h"
#include "cryptonote_core/oxen_name_system.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "cn"

using namespace crypto;

static std::atomic<uint64_t> tx_hashes_calculated_count(0);
static std::atomic<uint64_t> tx_hashes_cached_count(0);
static std::atomic<uint64_t> block_hashes_calculated_count(0);
static std::atomic<uint64_t> block_hashes_cached_count(0);

#define CHECK_AND_ASSERT_THROW_MES_L1(expr, message) {if(!(expr)) {MWARNING(message); throw std::runtime_error(message);}}

namespace cryptonote
{
  static inline unsigned char *operator &(ec_point &point) {
    return &reinterpret_cast<unsigned char &>(point);
  }
  static inline const unsigned char *operator &(const ec_point &point) {
    return &reinterpret_cast<const unsigned char &>(point);
  }

  // a copy of rct::addKeys, since we can't link to libringct to avoid circular dependencies
  static void add_public_key(crypto::public_key &AB, const crypto::public_key &A, const crypto::public_key &B) {
      ge_p3 B2, A2;
      CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&B2, &B) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
      CHECK_AND_ASSERT_THROW_MES_L1(ge_frombytes_vartime(&A2, &A) == 0, "ge_frombytes_vartime failed at "+boost::lexical_cast<std::string>(__LINE__));
      ge_cached tmp2;
      ge_p3_to_cached(&tmp2, &B2);
      ge_p1p1 tmp3;
      ge_add(&tmp3, &A2, &tmp2);
      ge_p1p1_to_p3(&A2, &tmp3);
      ge_p3_tobytes(&AB, &A2);
  }

  uint64_t get_transaction_weight_clawback(const transaction &tx, size_t n_padded_outputs)
  {
    const rct::rctSig &rv = tx.rct_signatures;
    const uint64_t bp_base = 368;
    const size_t n_outputs = tx.vout.size();
    if (n_padded_outputs <= 2)
      return 0;
    size_t nlr = 0;
    while ((1u << nlr) < n_padded_outputs)
      ++nlr;
    nlr += 6;
    const size_t bp_size = 32 * (9 + 2 * nlr);
    CHECK_AND_ASSERT_THROW_MES_L1(n_outputs <= BULLETPROOF_MAX_OUTPUTS, "maximum number of outputs is " + std::to_string(BULLETPROOF_MAX_OUTPUTS) + " per transaction");
    CHECK_AND_ASSERT_THROW_MES_L1(bp_base * n_padded_outputs >= bp_size, "Invalid bulletproof clawback: bp_base " + std::to_string(bp_base) + ", n_padded_outputs "
        + std::to_string(n_padded_outputs) + ", bp_size " + std::to_string(bp_size));
    const uint64_t bp_clawback = (bp_base * n_padded_outputs - bp_size) * 4 / 5;
    return bp_clawback;
  }
  //---------------------------------------------------------------
}

namespace cryptonote
{
  //---------------------------------------------------------------
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h, hw::device &hwdev)
  {
    hwdev.get_transaction_prefix_hash(tx,h);    
  }

  //---------------------------------------------------------------  
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx, hw::device &hwdev)
  {
    crypto::hash h = null_hash;
    get_transaction_prefix_hash(tx, h, hwdev);
    return h;
  }
  
  //---------------------------------------------------------------
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx)
  {
    crypto::hash h = null_hash;
    get_transaction_prefix_hash(tx, h);
    return h;
  }
  //---------------------------------------------------------------
  bool expand_transaction_1(transaction &tx, bool base_only)
  {
    if (tx.version >= txversion::v2_ringct && !is_coinbase(tx))
    {
      rct::rctSig &rv = tx.rct_signatures;
      if (rv.type == rct::RCTType::Null)
        return true;
      if (rv.outPk.size() != tx.vout.size())
      {
        LOG_PRINT_L1("Failed to parse transaction from blob, bad outPk size in tx " << get_transaction_hash(tx));
        return false;
      }
      for (size_t n = 0; n < tx.rct_signatures.outPk.size(); ++n)
      {
        if (!std::holds_alternative<txout_to_key>(tx.vout[n].target))
        {
          LOG_PRINT_L1("Unsupported output type in tx " << get_transaction_hash(tx));
          return false;
        }
        rv.outPk[n].dest = rct::pk2rct(var::get<txout_to_key>(tx.vout[n].target).key);
      }

      if (!base_only)
      {
        const bool bulletproof = rct::is_rct_bulletproof(rv.type);
        if (bulletproof)
        {
          if (rv.p.bulletproofs.size() != 1)
          {
            LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs size in tx " << get_transaction_hash(tx));
            return false;
          }
          if (rv.p.bulletproofs[0].L.size() < 6)
          {
            LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs L size in tx " << get_transaction_hash(tx));
            return false;
          }
          const size_t max_outputs = 1 << (rv.p.bulletproofs[0].L.size() - 6);
          if (max_outputs < tx.vout.size())
          {
            LOG_PRINT_L1("Failed to parse transaction from blob, bad bulletproofs max outputs in tx " << get_transaction_hash(tx));
            return false;
          }
          const size_t n_amounts = tx.vout.size();
          CHECK_AND_ASSERT_MES(n_amounts == rv.outPk.size(), false, "Internal error filling out V");
          rv.p.bulletproofs[0].V.resize(n_amounts);
          for (size_t i = 0; i < n_amounts; ++i)
            rv.p.bulletproofs[0].V[i] = rct::scalarmultKey(rv.outPk[i].mask, rct::INV_EIGHT);
        }
      }
    }
    return true;
  }

#if defined(_LIBCPP_VERSION)
  #define BINARY_ARCHIVE_STREAM(stream_name, blob) \
    std::stringstream stream_name; \
    stream_name.write(reinterpret_cast<const char *>(blob.data()), blob.size())
#else
  #define BINARY_ARCHIVE_STREAM(stream_name, blob) \
    auto buf = tools::one_shot_read_buffer{reinterpret_cast<const char *>(blob.data()), blob.size()}; \
    std::istream stream_name{&buf}
#endif

  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx)
  {
    serialization::binary_string_unarchiver ba{tx_blob};
    try {
      serialization::serialize(ba, tx);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse and validate transaction from blob: " << e.what());
      return false;
    }
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    tx.set_blob_size(tx_blob.size());
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_base_from_blob(const std::string_view tx_blob, transaction& tx)
  {
    serialization::binary_string_unarchiver ba{tx_blob};
    try {
      tx.serialize_base(ba);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse transaction base from blob: " << e.what());
      return false;
    }
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, true), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_prefix_from_blob(const std::string_view tx_blob, transaction_prefix& tx)
  {
    serialization::binary_string_unarchiver ba{tx_blob};
    try {
      serialization::value(ba, tx);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse transaction prefix from blob: " << e.what());
      return false;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx, crypto::hash& tx_hash)
  {
    serialization::binary_string_unarchiver ba{tx_blob};
    try {
      serialization::serialize(ba, tx);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse and validate transaction from blob + hash: " << e.what());
      return false;
    }
    CHECK_AND_ASSERT_MES(expand_transaction_1(tx, false), false, "Failed to expand transaction data");
    tx.invalidate_hashes();
    //TODO: validate tx

    return get_transaction_hash(tx, tx_hash);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash)
  {
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash))
      return false;
    get_transaction_prefix_hash(tx, tx_prefix_hash);
    return true;
  }
  //---------------------------------------------------------------
  bool is_v1_tx(const std::string_view tx_blob)
  {
    uint64_t version;
    if (tools::read_varint(tx_blob, version) <= 0)
      throw std::runtime_error("Internal error getting transaction version");
    return version <= 1;
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper(const account_keys& ack, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::public_key& tx_public_key, const std::vector<crypto::public_key>& additional_tx_public_keys, size_t real_output_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev)
  {
    crypto::key_derivation recv_derivation{};
    bool r = hwdev.generate_key_derivation(tx_public_key, ack.m_view_secret_key, recv_derivation);
    if (!r)
    {
      MWARNING("key image helper: failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
      memcpy(&recv_derivation, rct::identity().bytes, sizeof(recv_derivation));
    }

    std::vector<crypto::key_derivation> additional_recv_derivations;
    for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
    {
      crypto::key_derivation additional_recv_derivation{};
      r = hwdev.generate_key_derivation(additional_tx_public_keys[i], ack.m_view_secret_key, additional_recv_derivation);
      if (!r)
      {
        MWARNING("key image helper: failed to generate_key_derivation(" << additional_tx_public_keys[i] << ", " << ack.m_view_secret_key << ")");
      }
      else
      {
        additional_recv_derivations.push_back(additional_recv_derivation);
      }
    }

    std::optional<subaddress_receive_info> subaddr_recv_info = is_out_to_acc_precomp(subaddresses, out_key, recv_derivation, additional_recv_derivations, real_output_index,hwdev);
    CHECK_AND_ASSERT_MES(subaddr_recv_info, false, "key image helper: given output pubkey doesn't seem to belong to this address");

    return generate_key_image_helper_precomp(ack, out_key, subaddr_recv_info->derivation, real_output_index, subaddr_recv_info->index, in_ephemeral, ki, hwdev);
  }
  //---------------------------------------------------------------
  bool generate_key_image_helper_precomp(const account_keys& ack, const crypto::public_key& out_key, const crypto::key_derivation& recv_derivation, size_t real_output_index, const subaddress_index& received_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev)
  {
    if (hwdev.compute_key_image(ack, out_key, recv_derivation, real_output_index, received_index, in_ephemeral, ki))
    {
      return true;
    }

    if (ack.m_spend_secret_key == crypto::null_skey)
    {
      // for watch-only wallet, simply copy the known output pubkey
      in_ephemeral.pub = out_key;
      in_ephemeral.sec = crypto::null_skey;
    }
    else
    {
      // derive secret key with subaddress - step 1: original CN derivation
      crypto::secret_key scalar_step1;
      hwdev.derive_secret_key(recv_derivation, real_output_index, ack.m_spend_secret_key, scalar_step1); // computes Hs(a*R || idx) + b

      // step 2: add Hs(a || index_major || index_minor)
      crypto::secret_key subaddr_sk;
      crypto::secret_key scalar_step2;
      if (received_index.is_zero())
      {
        scalar_step2 = scalar_step1;    // treat index=(0,0) as a special case representing the main address
      }
      else
      {
        subaddr_sk = hwdev.get_subaddress_secret_key(ack.m_view_secret_key, received_index);
        hwdev.sc_secret_add(scalar_step2, scalar_step1,subaddr_sk);
      }

      in_ephemeral.sec = scalar_step2;

      if (ack.m_multisig_keys.empty())
      {
        // when not in multisig, we know the full spend secret key, so the output pubkey can be obtained by scalarmultBase
        CHECK_AND_ASSERT_MES(hwdev.secret_key_to_public_key(in_ephemeral.sec, in_ephemeral.pub), false, "Failed to derive public key");
      }
      else
      {
        // when in multisig, we only know the partial spend secret key. but we do know the full spend public key, so the output pubkey can be obtained by using the standard CN key derivation
        CHECK_AND_ASSERT_MES(hwdev.derive_public_key(recv_derivation, real_output_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub), false, "Failed to derive public key");
        // and don't forget to add the contribution from the subaddress part
        if (!received_index.is_zero())
        {
          crypto::public_key subaddr_pk;
          CHECK_AND_ASSERT_MES(hwdev.secret_key_to_public_key(subaddr_sk, subaddr_pk), false, "Failed to derive public key");
          add_public_key(in_ephemeral.pub, in_ephemeral.pub, subaddr_pk);
        }
      }

      CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_key,
           false, "key image helper precomp: given output pubkey doesn't match the derived one");
    }

    hwdev.generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki);
    return true;
  }
  //---------------------------------------------------------------
  uint64_t power_integral(uint64_t a, uint64_t b)
  {
    if(b == 0)
      return 1;
    uint64_t total = a;
    for(uint64_t i = 1; i != b; i++)
      total *= a;
    return total;
  }
  //---------------------------------------------------------------
  bool parse_amount(uint64_t& amount, std::string_view str_amount)
  {
    tools::trim(str_amount);

    auto parts = tools::split(str_amount, "."sv);
    if (parts.size() > 2)
      return false; // 123.456.789 no thanks.

    if (parts.size() == 2 && parts[1].empty())
      parts.pop_back(); // allow "123." (treat it as as "123")

    if (parts[0].find_first_not_of("0123456789"sv) != std::string::npos)
      return false; // whole part contains non-digit

    if (parts[0].empty()) {
      // Only allow an empty whole number part if there is a fractional part.
      if (parts.size() == 1)
        return false;
      amount = 0;
    }
    else
    {
      if (!tools::parse_int(parts[0], amount))
        return false;

      // Scale up the number (e.g. 12 from "12.45") to atomic units.
      //
      // TODO: get rid of the user-configurable default_decimal_point nonsense and just multiply
      // this value by the `COIN` constant.
      for (size_t i = 0; i < CRYPTONOTE_DISPLAY_DECIMAL_POINT; i++)
      {
        if (amount > std::numeric_limits<uint64_t>::max() / 10)
          return false; // would overflow
        amount *= 10;
      }
    }

    if (parts.size() == 1)
      return true;

    if (parts[1].find_first_not_of("0123456789"sv) != std::string::npos)
      return false; // fractional part contains non-digit

    // If too long, but with insignificant 0's, trim them off
    while (parts[1].size() > CRYPTONOTE_DISPLAY_DECIMAL_POINT && parts[1].back() == '0')
      parts[1].remove_suffix(1);

    if (parts[1].size() > CRYPTONOTE_DISPLAY_DECIMAL_POINT)
      return false; // fractional part has too many significant digits

    uint64_t fractional;
    if (!tools::parse_int(parts[1], fractional))
      return false;

    // Scale up the value if it wasn't a full fractional value, e.g. if we have "10.45" then we
    // need to convert the 45 we just parsed to 450'000'000.
    for (size_t i = parts[1].size(); i < CRYPTONOTE_DISPLAY_DECIMAL_POINT; i++)
      fractional *= 10;

    if (fractional > std::numeric_limits<uint64_t>::max() - amount)
      return false; // would overflow

    amount += fractional;
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx, size_t blob_size)
  {
    CHECK_AND_ASSERT_MES(!tx.pruned, std::numeric_limits<uint64_t>::max(), "get_transaction_weight does not support pruned txes");
    if (tx.version < txversion::v2_ringct)
      return blob_size;
    const rct::rctSig &rv = tx.rct_signatures;
    if (!rct::is_rct_bulletproof(rv.type))
      return blob_size;
    const size_t n_padded_outputs = rct::n_bulletproof_max_amounts(rv.p.bulletproofs);
    uint64_t bp_clawback = get_transaction_weight_clawback(tx, n_padded_outputs);
    CHECK_AND_ASSERT_THROW_MES_L1(bp_clawback <= std::numeric_limits<uint64_t>::max() - blob_size, "Weight overflow");
    return blob_size + bp_clawback;
  }
  //---------------------------------------------------------------
  uint64_t get_pruned_transaction_weight(const transaction &tx)
  {
    CHECK_AND_ASSERT_MES(tx.pruned, std::numeric_limits<uint64_t>::max(), "get_pruned_transaction_weight does not support non pruned txes");
    CHECK_AND_ASSERT_MES(tx.version >= txversion::v2_ringct, std::numeric_limits<uint64_t>::max(), "get_pruned_transaction_weight does not support v1 txes");
    CHECK_AND_ASSERT_MES(tx.rct_signatures.type >= rct::RCTType::Bulletproof2,
        std::numeric_limits<uint64_t>::max(), "get_pruned_transaction_weight does not support older range proof types");
    CHECK_AND_ASSERT_MES(!tx.vin.empty(), std::numeric_limits<uint64_t>::max(), "empty vin");
    CHECK_AND_ASSERT_MES(std::holds_alternative<cryptonote::txin_to_key>(tx.vin[0]), std::numeric_limits<uint64_t>::max(), "empty vin");

    // get pruned data size
    uint64_t weight = serialization::dump_binary(const_cast<transaction&>(tx)).size();

    // nbps (technically varint)
    weight += 1;

    // calculate deterministic bulletproofs size (assumes canonical BP format)
    size_t nrl = 0, n_padded_outputs;
    while ((n_padded_outputs = (1u << nrl)) < tx.vout.size())
      ++nrl;
    nrl += 6;
    uint64_t extra = 32 * (9 + 2 * nrl) + 2;
    weight += extra;

    // calculate deterministic CLSAG/MLSAG data size
    const size_t ring_size = var::get<cryptonote::txin_to_key>(tx.vin[0]).key_offsets.size();
    if (tx.rct_signatures.type == rct::RCTType::CLSAG)
      extra = tx.vin.size() * (ring_size + 2) * 32;
    else
      extra = tx.vin.size() * (ring_size * (1 + 1) * 32 + 32 /* cc */);
    weight += extra;

    // calculate deterministic pseudoOuts size
    extra =  32 * (tx.vin.size());
    weight += extra;

    // clawback
    uint64_t bp_clawback = get_transaction_weight_clawback(tx, n_padded_outputs);
    CHECK_AND_ASSERT_THROW_MES_L1(bp_clawback <= std::numeric_limits<uint64_t>::max() - weight, "Weight overflow");
    weight += bp_clawback;

    return weight;
  }
  //---------------------------------------------------------------
  uint64_t get_transaction_weight(const transaction &tx)
  {
    size_t blob_size =
      tx.is_blob_size_valid()
        ? tx.blob_size
        : serialization::dump_binary(const_cast<transaction&>(tx)).size();

    return get_transaction_weight(tx, blob_size);
  }
  //---------------------------------------------------------------
  bool get_tx_miner_fee(const transaction& tx, uint64_t & fee, bool burning_enabled, uint64_t *burned)
  {
    if (burned)
      *burned = 0;
    if (tx.version >= txversion::v2_ringct)
    {
      fee = tx.rct_signatures.txnFee;
      if (burning_enabled)
      {
        uint64_t fee_burned = get_burned_amount_from_tx_extra(tx.extra);
        fee -= std::min(fee, fee_burned);
        if (burned)
            *burned = fee_burned;
      }
      return true;
    }
    uint64_t amount_in;
    if (!get_inputs_money_amount(tx, amount_in)) return false;
    uint64_t amount_out = get_outs_money_amount(tx);

    CHECK_AND_ASSERT_MES(amount_in >= amount_out, false, "transaction spend (" <<amount_in << ") more than it has (" << amount_out << ")");
    fee = amount_in - amount_out;
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_tx_miner_fee(const transaction& tx, bool burning_enabled)
  {
    uint64_t r = 0;
    if(!get_tx_miner_fee(tx, r, burning_enabled))
      return 0;
    return r;
  }
  //---------------------------------------------------------------
  [[nodiscard]] bool parse_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<tx_extra_field>& tx_extra_fields)
  {
    tx_extra_fields.clear();

    if(tx_extra.empty())
      return true;

    serialization::binary_string_unarchiver ar{tx_extra};

    try {
      serialization::deserialize_all(ar, tx_extra_fields);
    } catch (const std::exception& e) {
      MWARNING(__func__ << ": failed to deserialize extra field: " << e.what() << "; extra = " << oxenmq::to_hex(tx_extra.begin(), tx_extra.end()));
      return false;
    }

    return true;
  }
  //---------------------------------------------------------------
  [[nodiscard]] bool sort_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<uint8_t> &sorted_tx_extra)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    if (!parse_tx_extra(tx_extra, tx_extra_fields))
      return false;

    // Sort according to the order of variant alternatives in the variant itself
    std::stable_sort(tx_extra_fields.begin(), tx_extra_fields.end(), [](auto& a, auto& b) { return a.index() < b.index(); });

    serialization::binary_string_archiver ar;
    try {
      for (auto& f : tx_extra_fields)
        serialization::value(ar, f);
    } catch (const std::exception& e) {
      LOG_PRINT_L1("failed to serialize tx extra field: " << e.what());
      return false;
    }

    std::string extrastr = ar.str();
    sorted_tx_extra = std::vector<uint8_t>(extrastr.begin(), extrastr.end());
    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra, size_t pk_index)
  {
    tx_extra_pub_key pub_key_field;
    if (get_field_from_tx_extra(tx_extra, pub_key_field, pk_index))
      return pub_key_field.pub_key;
    return null_pkey;
  }
  //---------------------------------------------------------------
  crypto::public_key get_tx_pub_key_from_extra(const transaction_prefix& tx_prefix, size_t pk_index)
  {
    return get_tx_pub_key_from_extra(tx_prefix.extra, pk_index);
  }
  //---------------------------------------------------------------
  void add_tagged_data_to_tx_extra(std::vector<uint8_t>& tx_extra, uint8_t tag, std::string_view data)
  {
    tx_extra.reserve(tx_extra.size() + 1 + data.size());
    tx_extra.push_back(tag);
    tx_extra.insert(tx_extra.end(), data.begin(), data.end());
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra)
  {
    tx_extra_additional_pub_keys additional_pub_keys;
    if (get_field_from_tx_extra(tx_extra, additional_pub_keys))
      return additional_pub_keys.data;
    return {};
  }
  //---------------------------------------------------------------
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const transaction_prefix& tx)
  {
    return get_additional_tx_pub_keys_from_extra(tx.extra);
  }
  //---------------------------------------------------------------
  static bool add_tx_extra_field_to_tx_extra(std::vector<uint8_t>& tx_extra, tx_extra_field& field)
  {
    std::string tx_extra_str;
    try {
      tx_extra_str = serialization::dump_binary(field);
    } catch (...) {
      return false;
    }

    tx_extra.reserve(tx_extra.size() + tx_extra_str.size());
    tx_extra.insert(tx_extra.end(), tx_extra_str.begin(), tx_extra_str.end());

    return true;
  }
  //---------------------------------------------------------------
  bool add_additional_tx_pub_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& additional_pub_keys)
  {
    tx_extra_field field = tx_extra_additional_pub_keys{ additional_pub_keys };
    bool r = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to serialize tx extra additional tx pub keys");
    return true;
  }
  //---------------------------------------------------------------
  bool add_extra_nonce_to_tx_extra(std::vector<uint8_t>& tx_extra, const blobdata& extra_nonce)
  {
    CHECK_AND_ASSERT_MES(extra_nonce.size() <= TX_EXTRA_NONCE_MAX_COUNT, false, "extra nonce could be 255 bytes max");
    tx_extra.reserve(tx_extra.size() + 2 + extra_nonce.size());
    tx_extra.push_back(TX_EXTRA_NONCE); // write tag
    tx_extra.push_back(static_cast<uint8_t>(extra_nonce.size())); // write len
    std::copy(extra_nonce.begin(), extra_nonce.end(), std::back_inserter(tx_extra));
    return true;
  }

  bool add_service_node_state_change_to_tx_extra(std::vector<uint8_t>& tx_extra, const tx_extra_service_node_state_change& state_change, const uint8_t hf_version)
  {
    tx_extra_field field;
    if (hf_version < network_version_12_checkpointing)
    {
      CHECK_AND_ASSERT_MES(state_change.state == service_nodes::new_state::deregister, false, "internal error: cannot construct an old deregistration for a non-deregistration state change (before hardfork v12)");
      field = tx_extra_service_node_deregister_old{state_change};
    }
    else
    {
      field = state_change;
    }

    bool r = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_ASSERT_MES(r, false, "failed to serialize tx extra service node state change");
    return true;
  }

  //---------------------------------------------------------------
  void add_service_node_pubkey_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& pubkey)
  {
    add_tx_extra<tx_extra_service_node_pubkey>(tx_extra, pubkey);
  }
  //---------------------------------------------------------------
  bool get_service_node_pubkey_from_tx_extra(const std::vector<uint8_t>& tx_extra, crypto::public_key& pubkey)
  {
    tx_extra_service_node_pubkey pk;
    if (!get_field_from_tx_extra(tx_extra, pk))
      return false;
    pubkey = pk.m_service_node_key;
    return true;
  }
  //---------------------------------------------------------------
  void add_service_node_contributor_to_tx_extra(std::vector<uint8_t>& tx_extra, const cryptonote::account_public_address& address)
  {
    add_tx_extra<tx_extra_service_node_contributor>(tx_extra, address);
  }
  //---------------------------------------------------------------
  bool get_tx_secret_key_from_tx_extra(const std::vector<uint8_t>& tx_extra, crypto::secret_key& key)
  {
    tx_extra_tx_secret_key seckey;
    if (!get_field_from_tx_extra(tx_extra, seckey))
      return false;
    key = seckey.key;
    return true;
  }
  //---------------------------------------------------------------
  void add_tx_secret_key_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::secret_key& key)
  {
    add_tx_extra<tx_extra_tx_secret_key>(tx_extra, key);
  }
  //---------------------------------------------------------------
  bool add_tx_key_image_proofs_to_tx_extra(std::vector<uint8_t>& tx_extra, const tx_extra_tx_key_image_proofs& proofs)
  {
    tx_extra_field field = proofs;
    bool result = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_NO_ASSERT_MES_L1(result, false, "failed to serialize tx extra tx key image proof");
    return result;
  }
  //---------------------------------------------------------------
  bool add_tx_key_image_unlock_to_tx_extra(std::vector<uint8_t>& tx_extra, const tx_extra_tx_key_image_unlock& unlock)
  {
    tx_extra_field field = unlock;
    bool result = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_NO_ASSERT_MES_L1(result, false, "failed to serialize tx extra tx key image unlock");
    return result;
  }
  //---------------------------------------------------------------
  bool get_service_node_contributor_from_tx_extra(const std::vector<uint8_t>& tx_extra, cryptonote::account_public_address& address)
  {
    tx_extra_service_node_contributor contributor;
    if (!get_field_from_tx_extra(tx_extra, contributor))
      return false;
    address.m_spend_public_key = contributor.m_spend_public_key;
    address.m_view_public_key = contributor.m_view_public_key;
    return true;
  }
  //---------------------------------------------------------------
  bool add_service_node_register_to_tx_extra(
      std::vector<uint8_t>& tx_extra,
      const std::vector<cryptonote::account_public_address>& addresses,
      uint64_t portions_for_operator,
      const std::vector<uint64_t>& portions,
      uint64_t expiration_timestamp,
      const crypto::signature& service_node_signature)
  {
    if (addresses.size() != portions.size())
    {
      LOG_ERROR("Tried to serialize registration with more addresses than portions, this should never happen");
      return false;
    }
    std::vector<crypto::public_key> public_view_keys(addresses.size());
    std::vector<crypto::public_key> public_spend_keys(addresses.size());
    for (size_t i = 0; i < addresses.size(); i++)
    {
      public_view_keys[i] = addresses[i].m_view_public_key;
      public_spend_keys[i] = addresses[i].m_spend_public_key;
    }
    // convert to variant
    tx_extra_field field =
      tx_extra_service_node_register{
        public_spend_keys,
        public_view_keys,
        portions_for_operator,
        portions,
        expiration_timestamp,
        service_node_signature
      };

    bool r = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_NO_ASSERT_MES_L1(r, false, "failed to serialize tx extra registration tx");
    return true;
  }
  //---------------------------------------------------------------
  void add_service_node_winner_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& winner)
  {
    add_tx_extra<tx_extra_service_node_winner>(tx_extra, winner);
  }
  //---------------------------------------------------------------
  bool get_service_node_state_change_from_tx_extra(const std::vector<uint8_t>& tx_extra, tx_extra_service_node_state_change &state_change, const uint8_t hf_version)
  {
    if (hf_version >= cryptonote::network_version_12_checkpointing) {
      // Look for a new-style state change field:
      return get_field_from_tx_extra(tx_extra, state_change);
    }

    // v11 or earlier; parse the old style and copy into a new style
    tx_extra_service_node_deregister_old dereg;
    if (!get_field_from_tx_extra(tx_extra, dereg))
      return false;

    state_change = tx_extra_service_node_state_change{
      tx_extra_service_node_state_change::version_t::v0,
      service_nodes::new_state::deregister, dereg.block_height, dereg.service_node_index, 0, 0, {dereg.votes.begin(), dereg.votes.end()}};
    return true;
  }
  //---------------------------------------------------------------
  crypto::public_key get_service_node_winner_from_tx_extra(const std::vector<uint8_t>& tx_extra)
  {
    // find corresponding field
    tx_extra_service_node_winner winner;
    if (get_field_from_tx_extra(tx_extra, winner))
      return winner.m_service_node_key;
    return crypto::null_pkey;
  }
  //---------------------------------------------------------------
  void add_oxen_name_system_to_tx_extra(std::vector<uint8_t> &tx_extra, tx_extra_oxen_name_system const &entry)
  {
    tx_extra_field field = entry;
    add_tx_extra_field_to_tx_extra(tx_extra, field);
  }
  //---------------------------------------------------------------
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra, const size_t variant_index)
  {
    if (tx_extra.empty())
      return true;

    serialization::binary_string_unarchiver ar{tx_extra};
    serialization::binary_string_archiver newar;

    try {
      do
      {
        tx_extra_field field;
        value(ar, field);

        if (field.index() != variant_index)
          value(newar, field);
      } while (ar.remaining_bytes() > 0);
    } catch (const std::exception& e) {
      LOG_PRINT_L1(__func__ << ": failed to deserialize extra field: " << e.what() << "; extra = " << oxenmq::to_hex(tx_extra.begin(), tx_extra.end()));
      return false;
    }

    std::string s = newar.str();
    tx_extra.clear();
    tx_extra.reserve(s.size());
    std::copy(s.begin(), s.end(), std::back_inserter(tx_extra));
    return true;
  }
  //---------------------------------------------------------------
  void set_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash& payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_PAYMENT_ID);
    const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }
  //---------------------------------------------------------------
  void set_encrypted_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash8& payment_id)
  {
    extra_nonce.clear();
    extra_nonce.push_back(TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID);
    const uint8_t* payment_id_ptr = reinterpret_cast<const uint8_t*>(&payment_id);
    std::copy(payment_id_ptr, payment_id_ptr + sizeof(payment_id), std::back_inserter(extra_nonce));
  }
  //---------------------------------------------------------------
  bool get_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash& payment_id)
  {
    if(sizeof(crypto::hash) + 1 != extra_nonce.size())
      return false;
    if(TX_EXTRA_NONCE_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const crypto::hash*>(extra_nonce.data() + 1);
    return true;
  }
  //---------------------------------------------------------------
  bool get_encrypted_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash8& payment_id)
  {
    if(sizeof(crypto::hash8) + 1 != extra_nonce.size())
      return false;
    if (TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID != extra_nonce[0])
      return false;
    payment_id = *reinterpret_cast<const crypto::hash8*>(extra_nonce.data() + 1);
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_burned_amount_from_tx_extra(const std::vector<uint8_t>& tx_extra)
  {
    tx_extra_burn burn;
    if (get_field_from_tx_extra(tx_extra, burn))
      return burn.amount;
    return 0;
  }
  //---------------------------------------------------------------
  bool add_burned_amount_to_tx_extra(std::vector<uint8_t>& tx_extra, uint64_t burn)
  {
    tx_extra_field field = tx_extra_burn{burn};
    bool result = add_tx_extra_field_to_tx_extra(tx_extra, field);
    CHECK_AND_NO_ASSERT_MES_L1(result, false, "failed to serialize tx extra burn amount");
    return result;
  }
  //---------------------------------------------------------------
  bool get_inputs_money_amount(const transaction& tx, uint64_t& money)
  {
    money = 0;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, false);
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_block_height(const block& b)
  {
    //TODO sean miner size
    cryptonote::block bl = b;
    if (b.miner_tx.vout.size() > 0)
    {
      CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, 0, "wrong miner tx in block: " << get_block_hash(b) << ", b.miner_tx.vin.size() != 1 (size is: " << b.miner_tx.vin.size() << ")");
      CHECKED_GET_SPECIFIC_VARIANT(b.miner_tx.vin[0], txin_gen, coinbase_in, 0);
      if(b.major_version >= cryptonote::network_version_19)
      {
        CHECK_AND_ASSERT_MES(coinbase_in.height == b.height, 0, "wrong miner tx in block: " << get_block_hash(b));
      }
      return coinbase_in.height;
    } else {
      return b.height;
    }
  }
  //---------------------------------------------------------------
  bool check_inputs_types_supported(const transaction& tx)
  {
    for(const auto& in: tx.vin)
    {
      CHECK_AND_ASSERT_MES(std::holds_alternative<txin_to_key>(in), false, "wrong variant type: "
        << tools::type_name(tools::variant_type(in)) << ", expected " << tools::type_name<txin_to_key>()
        << ", in transaction id=" << get_transaction_hash(tx));
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_outs_valid(const transaction& tx)
  {
    if (!tx.is_transfer())
    {
      CHECK_AND_NO_ASSERT_MES(tx.vout.size() == 0, false, "tx type: " << tx.type << " must have 0 outputs, received: " << tx.vout.size() << ", id=" << get_transaction_hash(tx));
    }

    if (tx.version >= txversion::v3_per_output_unlock_times)
    {
      CHECK_AND_NO_ASSERT_MES(tx.vout.size() == tx.output_unlock_times.size(), false, "tx version: " << tx.version << "must have equal number of output unlock times and outputs");
    }

    for(const tx_out& out: tx.vout)
    {
      CHECK_AND_ASSERT_MES(std::holds_alternative<txout_to_key>(out.target), false, "wrong variant type: "
        << tools::type_name(tools::variant_type(out.target)) << ", expected " << tools::type_name<txout_to_key>()
        << ", in transaction id=" << get_transaction_hash(tx));

      if (tx.version == txversion::v1)
      {
        CHECK_AND_NO_ASSERT_MES(0 < out.amount, false, "zero amount output in transaction id=" << get_transaction_hash(tx));
      }

      if(!check_key(var::get<txout_to_key>(out.target).key))
        return false;
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------
  bool check_money_overflow(const transaction& tx)
  {
    return check_inputs_overflow(tx) && check_outs_overflow(tx);
  }
  //---------------------------------------------------------------
  bool check_inputs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, false);
      if(money > tokey_in.amount + money)
        return false;
      money += tokey_in.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  bool check_outs_overflow(const transaction& tx)
  {
    uint64_t money = 0;
    for(const auto& o: tx.vout)
    {
      if(money > o.amount + money)
        return false;
      money += o.amount;
    }
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_outs_money_amount(const transaction& tx)
  {
    uint64_t outputs_amount = 0;
    for(const auto& o: tx.vout)
      outputs_amount += o.amount;
    return outputs_amount;
  }
  //---------------------------------------------------------------
  std::string short_hash_str(const crypto::hash& h)
  {
    return oxenmq::to_hex(tools::view_guts(h).substr(0, 4)) + "....";
  }
  //---------------------------------------------------------------
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& out_key, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, size_t output_index)
  {
    crypto::key_derivation derivation;
    bool r = acc.get_device().generate_key_derivation(tx_pub_key, acc.m_view_secret_key, derivation);
    CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
    crypto::public_key pk;
    r = acc.get_device().derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
    CHECK_AND_ASSERT_MES(r, false, "Failed to derive public key");
    if (pk == out_key.key)
      return true;
    // try additional tx pubkeys if available
    if (!additional_tx_pub_keys.empty())
    {
      CHECK_AND_ASSERT_MES(output_index < additional_tx_pub_keys.size(), false, "wrong number of additional tx pubkeys");
      r = acc.get_device().generate_key_derivation(additional_tx_pub_keys[output_index], acc.m_view_secret_key, derivation);
      CHECK_AND_ASSERT_MES(r, false, "Failed to generate key derivation");
      r = acc.get_device().derive_public_key(derivation, output_index, acc.m_account_address.m_spend_public_key, pk);
      CHECK_AND_ASSERT_MES(r, false, "Failed to derive public key");
      return pk == out_key.key;
    }
    return false;
  }
  //---------------------------------------------------------------
  std::optional<subaddress_receive_info> is_out_to_acc_precomp(const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::key_derivation& derivation, const std::vector<crypto::key_derivation>& additional_derivations, size_t output_index, hw::device &hwdev)
  {
    // try the shared tx pubkey
    crypto::public_key subaddress_spendkey;
    hwdev.derive_subaddress_public_key(out_key, derivation, output_index, subaddress_spendkey);
    auto found = subaddresses.find(subaddress_spendkey);
    if (found != subaddresses.end())
      return subaddress_receive_info{ found->second, derivation };
    // try additional tx pubkeys if available
    if (!additional_derivations.empty())
    {
      CHECK_AND_ASSERT_MES(output_index < additional_derivations.size(), std::nullopt, "wrong number of additional derivations");
      hwdev.derive_subaddress_public_key(out_key, additional_derivations[output_index], output_index, subaddress_spendkey);
      found = subaddresses.find(subaddress_spendkey);
      if (found != subaddresses.end())
        return subaddress_receive_info{ found->second, additional_derivations[output_index] };
    }
    return std::nullopt;
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    if(null_pkey == tx_pub_key)
      return false;
    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    return lookup_acc_outs(acc, tx, tx_pub_key, additional_tx_pub_keys, outs, money_transfered);
  }
  //---------------------------------------------------------------
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_pub_keys, std::vector<size_t>& outs, uint64_t& money_transfered)
  {
    CHECK_AND_ASSERT_MES(additional_tx_pub_keys.empty() || additional_tx_pub_keys.size() == tx.vout.size(), false, "wrong number of additional pubkeys" );
    money_transfered = 0;
    size_t i = 0;
    for(const tx_out& o:  tx.vout)
    {
      CHECK_AND_ASSERT_MES(std::holds_alternative<txout_to_key>(o.target), false, "wrong type id in transaction out" );
      if(is_out_to_acc(acc, var::get<txout_to_key>(o.target), tx_pub_key, additional_tx_pub_keys, i))
      {
        outs.push_back(i);
        money_transfered += o.amount;
      }
      i++;
    }
    return true;
  }
  //---------------------------------------------------------------
  void get_blob_hash(const std::string_view blob, crypto::hash& res)
  {
    cn_fast_hash(blob.data(), blob.size(), res);
  }
  //---------------------------------------------------------------
  std::string get_unit(unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
    switch (decimal_point)
    {
      case 9:
        return "oxen";
      case 6:
        return "megarok";
      case 3:
        return "kilorok";
      case 0:
        return "rok";
      default:
        ASSERT_MES_AND_THROW("Invalid decimal point specification: " << decimal_point);
    }
  }
  //---------------------------------------------------------------
  std::string print_money(uint64_t amount, unsigned int decimal_point)
  {
    if (decimal_point == (unsigned int)-1)
      decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT;
    std::string s = std::to_string(amount);
    if(s.size() < decimal_point+1)
    {
      s.insert(0, decimal_point+1 - s.size(), '0');
    }
    if (decimal_point > 0)
      s.insert(s.size() - decimal_point, ".");
    return s;
  }
  //---------------------------------------------------------------
  std::string print_tx_verification_context(tx_verification_context const &tvc, transaction const *tx)
  {
    std::ostringstream os;

    if (tvc.m_verbose_error.size())
        os << tvc.m_verbose_error << "\n";

    if (tvc.m_verifivation_failed)       os << "Verification failed, connection should be dropped, "; //bad tx, should drop connection
    if (tvc.m_verifivation_impossible)   os << "Verification impossible, related to alt chain, "; //the transaction is related with an alternative blockchain
    if (tvc.m_should_be_relayed)         os << "TX should be relayed, ";
    if (tvc.m_added_to_pool)             os << "TX added to pool, ";
    if (tvc.m_low_mixin)                 os << "Insufficient mixin, ";
    if (tvc.m_double_spend)              os << "Double spend TX, ";
    if (tvc.m_invalid_input)             os << "Invalid inputs, ";
    if (tvc.m_invalid_output)            os << "Invalid outputs, ";
    if (tvc.m_too_few_outputs)           os << "Need at least 2 outputs, ";
    if (tvc.m_too_big)                   os << "TX too big, ";
    if (tvc.m_overspend)                 os << "Overspend, ";
    if (tvc.m_fee_too_low)               os << "Fee too low, ";
    if (tvc.m_invalid_version)           os << "TX has invalid version, ";
    if (tvc.m_invalid_type)              os << "TX has invalid type, ";
    if (tvc.m_key_image_locked_by_snode) os << "Key image is locked by service node, ";
    if (tvc.m_key_image_blacklisted)     os << "Key image is blacklisted on the service node network, ";

    if (tx)
      os << "TX Version: " << tx->version << ", Type: " << tx->type;

    std::string buf = os.str();
    if (buf.size() >= 2 && buf[buf.size() - 2] == ',')
      buf.resize(buf.size() - 2);

    return buf;
  }
  //---------------------------------------------------------------
  std::string print_vote_verification_context(vote_verification_context const &vvc, service_nodes::quorum_vote_t const *vote)
  {
    std::ostringstream os;

    if (vvc.m_invalid_block_height)          os << "Invalid block height: " << (vote ? std::to_string(vote->block_height) : "??") << ", ";
    if (vvc.m_duplicate_voters)              os << "Index in group was duplicated: " << (vote ? std::to_string(vote->index_in_group) : "??") << ", ";
    if (vvc.m_validator_index_out_of_bounds) os << "Validator index out of bounds";
    if (vvc.m_worker_index_out_of_bounds)    os << "Worker index out of bounds: " << (vote ? std::to_string(vote->state_change.worker_index) : "??") << ", ";
    if (vvc.m_signature_not_valid)           os << "Signature not valid, ";
    if (vvc.m_added_to_pool)                 os << "Added to pool, ";
    if (vvc.m_not_enough_votes)              os << "Not enough votes, ";
    if (vvc.m_incorrect_voting_group)
    {
      os << "Incorrect voting group specified";
      if (vote)
      {
        if (vote->group == service_nodes::quorum_group::validator)
          os << ": validator";
        else if (vote->group == service_nodes::quorum_group::worker)
          os << ": worker";
        else
          os << ": " << static_cast<int>(vote->group);
      }
      os << ", ";
    }
    if (vvc.m_invalid_vote_type)             os << "Vote type has invalid value: " << (vote ? std::to_string((uint8_t)vote->type) : "??") << ", ";
    if (vvc.m_votes_not_sorted)              os << "Votes are not stored in ascending order";

    std::string buf = os.str();
    if (buf.size() >= 2 && buf[buf.size() - 2] == ',')
      buf.resize(buf.size() - 2);

    return buf;
  }
  //---------------------------------------------------------------
  bool is_valid_address(const std::string address, cryptonote::network_type nettype, bool allow_subaddress, bool allow_integrated)
  {
    cryptonote::address_parse_info addr_info;
    bool valid = false;
    if(get_account_address_from_str(addr_info, nettype, address))
    {
      if (addr_info.is_subaddress)
        valid = allow_subaddress;
      else if (addr_info.has_payment_id)
        valid = allow_integrated;
      else
        valid = true;
    }
    return valid;
  }
  //---------------------------------------------------------------
  crypto::hash get_blob_hash(const std::string_view blob)
  {
    crypto::hash h;
    get_blob_hash(blob, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_hash(const transaction& t)
  {
    crypto::hash h = null_hash;
    get_transaction_hash(t, h, NULL);
    CHECK_AND_ASSERT_THROW_MES(get_transaction_hash(t, h, NULL), "Failed to calculate transaction hash");
    return h;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res)
  {
    return get_transaction_hash(t, res, NULL);
  }
  //---------------------------------------------------------------
  [[nodiscard]] bool calculate_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata *blob, crypto::hash& res)
  {
    if (t.version == txversion::v1)
      return false;
    const unsigned int unprunable_size = t.unprunable_size;
    if (blob && unprunable_size)
    {
      CHECK_AND_ASSERT_MES(unprunable_size <= blob->size(), false, "Inconsistent transaction unprunable and blob sizes");
      cryptonote::get_blob_hash(std::string_view{*blob}.substr(unprunable_size), res);
    }
    else
    {
      serialization::binary_string_archiver ba;
      size_t mixin = 0;
      if (t.vin.size() > 0 && std::holds_alternative<txin_to_key>(t.vin[0]))
        mixin = var::get<txin_to_key>(t.vin[0]).key_offsets.size() - 1;
      try {
        const_cast<transaction&>(t).rct_signatures.p.serialize_rctsig_prunable(
                ba, t.rct_signatures.type, t.vin.size(), t.vout.size(), mixin);
      } catch (const std::exception& e) {
        LOG_ERROR("Failed to serialize rct signatures (prunable): " << e.what());
        return false;
      }
      cryptonote::get_blob_hash(ba.str(), res);
    }
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata *blobdata)
  {
    crypto::hash res;
    CHECK_AND_ASSERT_THROW_MES(calculate_transaction_prunable_hash(t, blobdata, res), "Failed to calculate tx prunable hash");
    return res;
  }
  //---------------------------------------------------------------
  crypto::hash get_pruned_transaction_hash(const transaction& t, const crypto::hash &pruned_data_hash)
  {
    // v1 transactions hash the entire blob
    if (t.version < txversion::v2_ringct)
      throw std::runtime_error("Hash for pruned v1 tx cannot be calculated");

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    get_transaction_prefix_hash(t, hashes[0]);

    transaction &tt = const_cast<transaction&>(t);

    // base rct
    {
      serialization::binary_string_archiver ba;
      const size_t inputs = t.vin.size();
      const size_t outputs = t.vout.size();
      tt.rct_signatures.serialize_rctsig_base(ba, inputs, outputs); // throws on error (good)
      cryptonote::get_blob_hash(ba.str(), hashes[1]);
    }

    // prunable rct
    if (t.rct_signatures.type == rct::RCTType::Null)
      hashes[2] = crypto::null_hash;
    else
      hashes[2] = pruned_data_hash;

    // the tx hash is the hash of the 3 hashes
    crypto::hash res = cn_fast_hash(hashes, sizeof(hashes));
    return res;
  }
  //---------------------------------------------------------------
  bool calculate_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size)
  {
    // v1 transactions hash the entire blob
    if (t.version == txversion::v1)
    {
      size_t ignored_blob_size, &blob_size_ref = blob_size ? *blob_size : ignored_blob_size;
      return get_object_hash(t, res, blob_size_ref);
    }

    // v2 transactions hash different parts together, than hash the set of those hashes
    crypto::hash hashes[3];

    // prefix
    get_transaction_prefix_hash(t, hashes[0]);

    const blobdata blob = tx_to_blob(t);
    CHECK_AND_ASSERT_MES(!blob.empty(), false, "Failed to convert tx to blob");

    // TODO(oxen): Not sure if this is the right fix, we may just want to set
    // unprunable size to the size of the prefix because technically that is
    // what it is and then keep this code path.
    if (t.is_transfer())
    {
      const unsigned int unprunable_size = t.unprunable_size;
      const unsigned int prefix_size = t.prefix_size;

      // base rct
      CHECK_AND_ASSERT_MES(prefix_size <= unprunable_size && unprunable_size <= blob.size(), false,
              "Inconsistent transaction prefix (" << prefix_size << "), unprunable (" << unprunable_size << ") and blob (" << blob.size() << ") sizes in: " << __func__);
      cryptonote::get_blob_hash(std::string_view{blob}.substr(prefix_size, unprunable_size - prefix_size), hashes[1]);
    }
    else
    {
      transaction &tt = const_cast<transaction&>(t);
      serialization::binary_string_archiver ba;
      try {
        tt.rct_signatures.serialize_rctsig_base(ba, t.vin.size(), t.vout.size());
      } catch (const std::exception& e) {
        LOG_ERROR("Failed to serialize rct signatures base: " << e.what());
        return false;
      }
      cryptonote::get_blob_hash(ba.str(), hashes[1]);
    }

    // prunable rct
    if (t.rct_signatures.type == rct::RCTType::Null)
    {
      hashes[2] = crypto::null_hash;
    }
    else if (!calculate_transaction_prunable_hash(t, &blob, hashes[2]))
    {
      LOG_ERROR("Failed to get tx prunable hash");
      return false;
    }

    // the tx hash is the hash of the 3 hashes
    res = cn_fast_hash(hashes, sizeof(hashes));

    // we still need the size
    if (blob_size)
    {
      if (!t.is_blob_size_valid())
      {
        t.blob_size = blob.size();
        t.set_blob_size_valid(true);
      }
      *blob_size = t.blob_size;
    }

    return true;
  }
  //---------------------------------------------------------------
  bool get_registration_hash(const std::vector<cryptonote::account_public_address>& addresses, uint64_t operator_portions, const std::vector<uint64_t>& portions, uint64_t expiration_timestamp, crypto::hash& hash)
  {
    if (addresses.size() != portions.size())
    {
      LOG_ERROR("get_registration_hash addresses.size() != portions.size()");
      return false;
    }
    uint64_t portions_left = STAKING_PORTIONS;
    for (uint64_t portion : portions)
    {
      if (portion > portions_left)
      {
        LOG_ERROR(tr("Your registration has more than ") << STAKING_PORTIONS << tr(" portions, this registration is invalid!"));
        return false;
      }
      portions_left -= portion;
    }
    size_t size = sizeof(uint64_t) + addresses.size() * (sizeof(cryptonote::account_public_address) + sizeof(uint64_t)) + sizeof(uint64_t);
    std::string buffer;
    buffer.reserve(size);
    buffer += tools::view_guts(operator_portions);
    for (size_t i = 0; i < addresses.size(); i++)
    {
      buffer += tools::view_guts(addresses[i]);
      buffer += tools::view_guts(portions[i]);
    }
    buffer += tools::view_guts(expiration_timestamp);
    assert(buffer.size() == size);
    crypto::cn_fast_hash(buffer.data(), buffer.size(), hash);
    return true;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size)
  {
    if (t.is_hash_valid())
    {
      res = t.hash;
      if (blob_size)
      {
        if (!t.is_blob_size_valid())
        {
          t.blob_size = get_object_blobsize(t);
          t.set_blob_size_valid(true);
        }
        *blob_size = t.blob_size;
      }
      ++tx_hashes_cached_count;
      return true;
    }
    ++tx_hashes_calculated_count;
    bool ret = calculate_transaction_hash(t, res, blob_size);
    if (!ret)
      return false;
    t.hash = res;
    t.set_hash_valid(true);
    if (blob_size)
    {
      t.blob_size = *blob_size;
      t.set_blob_size_valid(true);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t& blob_size)
  {
    return get_transaction_hash(t, res, &blob_size);
  }
  //---------------------------------------------------------------
  blobdata get_block_hashing_blob(const block& b)
  {
    blobdata blob = t_serializable_object_to_blob(static_cast<block_header>(b));
    crypto::hash tree_root_hash = get_tx_tree_hash(b);
    blob.append(reinterpret_cast<const char*>(&tree_root_hash), sizeof(tree_root_hash));
    blob.append(tools::get_varint_data(b.tx_hashes.size()+1));
    return blob;
  }
  //---------------------------------------------------------------
  bool calculate_block_hash(const block& b, crypto::hash& res)
  {
    bool hash_result = get_object_hash(get_block_hashing_blob(b), res);
    return hash_result;
  }
  //---------------------------------------------------------------
  bool get_block_hash(const block& b, crypto::hash& res)
  {
    if (b.is_hash_valid())
    {
      res = b.hash;
      ++block_hashes_cached_count;
      return true;
    }
    ++block_hashes_calculated_count;
    bool ret = calculate_block_hash(b, res);
    if (!ret)
      return false;
    b.hash = res;
    b.set_hash_valid(true);
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_block_hash(const block& b)
  {
    crypto::hash p = null_hash;
    get_block_hash(b, p);
    return p;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    for(size_t i = 1; i < res.size(); i++)
      res[i] += res[i-1];
    return res;
  }
  //---------------------------------------------------------------
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off)
  {
    std::vector<uint64_t> res = off;
    if(!off.size())
      return res;
    std::sort(res.begin(), res.end());//just to be sure, actually it is already should be sorted
    for(size_t i = res.size()-1; i != 0; i--)
      res[i] -= res[i-1];

    return res;
  }
  //---------------------------------------------------------------
  [[nodiscard]] bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b, crypto::hash* block_hash)
  {
    serialization::binary_string_unarchiver ba{b_blob};
    try {
      serialization::serialize(ba, b);
    } catch (const std::exception& e) {
      LOG_ERROR("Failed to parse block from blob: " << e.what());
      return false;
    }
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();
    if (block_hash)
    {
      calculate_block_hash(b, *block_hash);
      ++block_hashes_calculated_count;
      b.hash = *block_hash;
      b.set_hash_valid(true);
    }
    return true;
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b)
  {
    return parse_and_validate_block_from_blob(b_blob, b, nullptr);
  }
  //---------------------------------------------------------------
  bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b, crypto::hash& block_hash)
  {
    return parse_and_validate_block_from_blob(b_blob, b, &block_hash);
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b)
  {
    return t_serializable_object_to_blob(b);
  }
  //---------------------------------------------------------------
  bool block_to_blob(const block& b, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(b, b_blob);
  }
  //---------------------------------------------------------------
  blobdata tx_to_blob(const transaction& tx)
  {
    return t_serializable_object_to_blob(tx);
  }
  //---------------------------------------------------------------
  bool tx_to_blob(const transaction& tx, blobdata& b_blob)
  {
    return t_serializable_object_to_blob(tx, b_blob);
  }
  //---------------------------------------------------------------
  void get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes, crypto::hash& h)
  {
    tree_hash(tx_hashes.data(), tx_hashes.size(), h);
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes)
  {
    crypto::hash h = null_hash;
    get_tx_tree_hash(tx_hashes, h);
    return h;
  }
  //---------------------------------------------------------------
  crypto::hash get_tx_tree_hash(const block& b)
  {
    std::vector<crypto::hash> txs_ids;
    txs_ids.reserve(1 + b.tx_hashes.size());
    crypto::hash h = null_hash;
    size_t bl_sz = 0;
    CHECK_AND_ASSERT_THROW_MES(get_transaction_hash(b.miner_tx, h, bl_sz), "Failed to calculate transaction hash");
    txs_ids.push_back(h);
    for(auto& th: b.tx_hashes)
      txs_ids.push_back(th);
    return get_tx_tree_hash(txs_ids);
  }
  //---------------------------------------------------------------
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached)
  {
    tx_hashes_calculated = tx_hashes_calculated_count;
    tx_hashes_cached = tx_hashes_cached_count;
    block_hashes_calculated = block_hashes_calculated_count;
    block_hashes_cached = block_hashes_cached_count;
  }
  //---------------------------------------------------------------
  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_slow_hash(passphrase.data(), passphrase.size(), hash, crypto::cn_slow_hash_type::heavy_v1);
    sc_add((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }
  //---------------------------------------------------------------
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase)
  {
    crypto::hash hash;
    crypto::cn_slow_hash(passphrase.data(), passphrase.size(), hash, crypto::cn_slow_hash_type::heavy_v1);
    sc_sub((unsigned char*)key.data, (const unsigned char*)key.data, (const unsigned char*)hash.data);
    return key;
  }

}

std::string ons::generic_owner::to_string(cryptonote::network_type nettype) const
{
  if (type == ons::generic_owner_sig_type::monero)
    return cryptonote::get_account_address_as_str(nettype, wallet.is_subaddress, wallet.address);
  else
    return tools::type_to_hex(ed25519);
}

bool ons::generic_owner::operator==(generic_owner const &other) const
{
  if (type != other.type)
    return false;

  if (type == ons::generic_owner_sig_type::monero)
    return wallet.is_subaddress == other.wallet.is_subaddress && wallet.address == other.wallet.address;
  else
    return ed25519 == other.ed25519;
}
