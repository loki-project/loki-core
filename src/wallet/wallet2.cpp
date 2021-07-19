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

#include <iterator>
#include <numeric>
#include <tuple>
#include <optional>
#include <mutex>
#include <boost/format.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <type_traits>
#include <cpr/parameters.h>
#include <oxenmq/base64.h>
#include "common/password.h"
#include "common/string_util.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/oxen_name_system.h"
#include "common/rules.h"
#include "cryptonote_config.h"
#include "cryptonote_core/tx_sanity_check.h"
#include "wallet/wallet_errors.h"
#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "epee/misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/hardfork.h"
#include "multisig/multisig.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "epee/profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "serialization/boost_std_variant.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/file.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "epee/memwipe.h"
#include "common/base58.h"
#include "common/combinator.h"
#include "common/dns_utils.h"
#include "common/notify.h"
#include "common/perf_timer.h"
#include "common/hex.h"
#include "ringct/rctSigs.h"
#include "ringdb.h"
#include "device/device_cold.hpp"
#include "device_trezor/device_trezor.hpp"

#include "cryptonote_core/service_node_list.h"
#include "cryptonote_core/service_node_rules.h"
#include "common/oxen.h"
#include "common/oxen_integration_test_hooks.h"
#include "oxen_economy.h"
#include "epee/string_coding.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
#include <sodium.h>
}

using namespace crypto;
using namespace cryptonote;

namespace string_tools = epee::string_tools;

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "wallet.wallet2"

namespace {

  constexpr std::string_view UNSIGNED_TX_PREFIX = "Loki unsigned tx set\004"sv;
  constexpr std::string_view SIGNED_TX_PREFIX = "Loki signed tx set\004"sv;
  constexpr std::string_view MULTISIG_UNSIGNED_TX_PREFIX = "Loki multisig unsigned tx set\001"sv;

  constexpr std::string_view UNSIGNED_TX_PREFIX_NOVER = UNSIGNED_TX_PREFIX.substr(0, UNSIGNED_TX_PREFIX.size()-1);
  constexpr std::string_view SIGNED_TX_PREFIX_NOVER = SIGNED_TX_PREFIX.substr(0, SIGNED_TX_PREFIX.size()-1);
  constexpr std::string_view MULTISIG_UNSIGNED_TX_PREFIX_NOVER = MULTISIG_UNSIGNED_TX_PREFIX.substr(0, MULTISIG_UNSIGNED_TX_PREFIX.size()-1);

  constexpr float RECENT_OUTPUT_RATIO = 0.5f; // 50% of outputs are from the recent zone
  constexpr float RECENT_OUTPUT_DAYS = 1.8f; // last 1.8 day makes up the recent zone (taken from monerolink.pdf, Miller et al)
  constexpr time_t RECENT_OUTPUT_ZONE = RECENT_OUTPUT_DAYS * 86400;
  constexpr uint64_t RECENT_OUTPUT_BLOCKS = BLOCKS_EXPECTED_IN_DAYS(RECENT_OUTPUT_DAYS);

  constexpr uint64_t FEE_ESTIMATE_GRACE_BLOCKS = 10; // estimate fee valid for that many blocks

  constexpr float SECOND_OUTPUT_RELATEDNESS_THRESHOLD = 0.0f;

  constexpr std::string_view KEY_IMAGE_EXPORT_FILE_MAGIC = "Loki key image export\002"sv;
  constexpr std::string_view MULTISIG_EXPORT_FILE_MAGIC = "Loki multisig export\001"sv;
  constexpr std::string_view OUTPUT_EXPORT_FILE_MAGIC = "Loki output export\003"sv;

  constexpr uint64_t SEGREGATION_FORK_HEIGHT = 99999999;
  constexpr uint64_t SEGREGATION_FORK_VICINITY = 1500; // blocks

  constexpr uint64_t FIRST_REFRESH_GRANULARITY = 1024;

  constexpr double GAMMA_SHAPE = 19.28;
  constexpr double GAMMA_SCALE = 1/1.61;

  constexpr uint32_t DEFAULT_MIN_OUTPUT_COUNT = 5;
  constexpr uint64_t DEFAULT_MIN_OUTPUT_VALUE = 2*COIN;

  constexpr auto DEFAULT_INACTIVITY_LOCK_TIMEOUT = 10min;

  constexpr uint8_t IGNORE_LONG_PAYMENT_ID_FROM_BLOCK_VERSION = 12;

  constexpr std::string_view SIG_MAGIC = "SigV1"sv;
  constexpr std::string_view MULTISIG_MAGIC = "MultisigV1"sv;
  constexpr std::string_view MULTISIG_SIGNATURE_MAGIC = "SigMultisigPkV1"sv;
  constexpr std::string_view MULTISIG_EXTRA_INFO_MAGIC = "MultisigxV1"sv;
  const std::string ASCII_OUTPUT_MAGIC = "MoneroAsciiDataV1"s; // not string_view because we need it as a c string
  constexpr std::string_view SPEND_PROOF_MAGIC = "SpendProofV1"sv;
  constexpr std::string_view OUTBOUND_PROOF_MAGIC = "OutProofV1"sv;
  constexpr std::string_view INBOUND_PROOF_MAGIC = "InProofV1"sv;
  constexpr std::string_view RESERVE_PROOF_MAGIC = "ReserveProofV1"sv;

  // used to target a given block weight (additional outputs may be added on top to build fee)
  constexpr uint64_t tx_weight_target(uint64_t bytes) { return bytes*2/3; }

  std::string get_default_ringdb_path()
  {
    // remove .oxen, replace with .shared-ringdb
    return tools::get_default_data_dir().replace_filename(".shared-ringdb").u8string();
  }

  std::string pack_multisignature_keys(const std::vector<crypto::public_key>& keys, const crypto::secret_key& signer_secret_key)
  {
    std::string data;
    crypto::public_key signer;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signer_secret_key, signer), "Failed to derive public spend key");
    data += std::string((const char *)&signer, sizeof(crypto::public_key));

    for (const auto &key: keys)
    {
      data += std::string((const char *)&key, sizeof(crypto::public_key));
    }

    data.resize(data.size() + sizeof(crypto::signature));

    crypto::hash hash;
    crypto::cn_fast_hash(data.data(), data.size() - sizeof(crypto::signature), hash);
    crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, signer, signer_secret_key, signature);

    return std::string{MULTISIG_EXTRA_INFO_MAGIC} + tools::base58::encode(data);
  }

  std::vector<crypto::public_key> secret_keys_to_public_keys(const std::vector<crypto::secret_key>& keys)
  {
    std::vector<crypto::public_key> public_keys;
    public_keys.reserve(keys.size());

    std::transform(keys.begin(), keys.end(), std::back_inserter(public_keys), [] (const crypto::secret_key& k) -> crypto::public_key {
      crypto::public_key p;
      CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, p), "Failed to derive public spend key");
      return p;
    });

    return public_keys;
  }

  bool keys_intersect(const std::unordered_set<crypto::public_key>& s1, const std::unordered_set<crypto::public_key>& s2)
  {
    if (s1.empty() || s2.empty())
      return false;

    for (const auto& e: s1)
    {
      if (s2.find(e) != s2.end())
        return true;
    }

    return false;
  }

  std::string get_text_reason(const rpc::SEND_RAW_TX::response &res, cryptonote::transaction const *tx, bool blink)
  {
    if (blink) {
      return res.reason;
    }
    else {
      std::string reason  = print_tx_verification_context  (res.tvc, tx);
      reason             += print_vote_verification_context(res.tvc.m_vote_ctx);
      return reason;
    }
  }

  size_t get_num_outputs(const std::vector<cryptonote::tx_destination_entry> &dsts, const std::vector<tools::wallet2::transfer_details> &transfers, const std::vector<size_t> &selected_transfers, const oxen_construct_tx_params& tx_params)
  {
    size_t outputs = dsts.size();
    uint64_t needed_money = 0;
    for (const auto& dt: dsts)
      needed_money += dt.amount;
    uint64_t found_money = 0;
    for(size_t idx: selected_transfers)
      found_money += transfers[idx].amount();
    if (found_money != needed_money)
      ++outputs; // change
    if (outputs < (tx_params.tx_type == cryptonote::txtype::oxen_name_system ? 1 : 2))
      ++outputs; // extra 0 dummy output
    return outputs;
  }

// Create on-demand to prevent static initialization order fiasco issues.
struct options {
  const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", tools::wallet2::tr("Use oxend RPC at [http://]<host>[:<port>]"), ""};
  const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", tools::wallet2::tr("Specify username[:password] for daemon RPC client"), "", true};
  const command_line::arg_descriptor<std::string> proxy = {"proxy", tools::wallet2::tr("Use socks proxy at [socks4a://]<ip>:<port> for daemon connections"), "", true};
  const command_line::arg_descriptor<bool> trusted_daemon = {"trusted-daemon", tools::wallet2::tr("Enable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<bool> untrusted_daemon = {"untrusted-daemon", tools::wallet2::tr("Disable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<std::string> daemon_ssl_private_key = {"daemon-ssl-private-key", tools::wallet2::tr("Path to a PEM format private key for HTTPS client authentication"), ""};
  const command_line::arg_descriptor<std::string> daemon_ssl_certificate = {"daemon-ssl-certificate", tools::wallet2::tr("Path to a PEM format certificate for HTTPS client authentication"), ""};
  const command_line::arg_descriptor<std::string> daemon_ssl_ca_certificates = {"daemon-ssl-ca-certificates", tools::wallet2::tr("Path to a CA certificate bundle to use to verify the remote node's HTTPS certificate instead of using your operating system CAs.")};
  const command_line::arg_descriptor<bool> daemon_ssl_allow_any_cert = {"daemon-ssl-allow-any-cert", tools::wallet2::tr("Make the HTTPS connection insecure by allowing any SSL certificate from the daemon."), false};

  // Deprecated and not listed in --help
  const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", tools::wallet2::tr("Deprecated. Use --daemon-address instead"), ""};
  const command_line::arg_descriptor<int> daemon_port = {"daemon-port", tools::wallet2::tr("Deprecated. Use --daemon-address instead"), 0};
  const command_line::arg_descriptor<std::string> daemon_ssl = {"daemon-ssl", tools::wallet2::tr("Deprecated. Use --daemon-address https://... instead"), ""};

  const command_line::arg_descriptor<std::string> password = {"password", tools::wallet2::tr("Wallet password (escape/quote as needed)"), "", true};
  const command_line::arg_descriptor<std::string> password_file = {"password-file", tools::wallet2::tr("Wallet password file"), "", true};

  const command_line::arg_descriptor<bool> testnet = {"testnet", tools::wallet2::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
  const command_line::arg_descriptor<bool> devnet = {"devnet", tools::wallet2::tr("For devnet. Daemon must also be launched with --devnet flag"), false};
  const command_line::arg_descriptor<bool> regtest = {"regtest", tools::wallet2::tr("For regression testing. Daemon must also be launched with --regtest flag"), false};
  const command_line::arg_descriptor<bool> disable_rpc_long_poll = {"disable-rpc-long-poll", tools::wallet2::tr("Disable TX pool long polling functionality for instantaneous TX detection"), false};

  const command_line::arg_descriptor<std::string, false, true, 3> shared_ringdb_dir = {
    "shared-ringdb-dir", tools::wallet2::tr("Set shared ring database path"),
    get_default_ringdb_path(),
    {{ &testnet, &devnet, &regtest }},
    [](std::array<bool, 3> test_dev_fake, bool defaulted, std::string val)->std::string {
      if (test_dev_fake[0])
        return (fs::u8path(val) / "testnet").u8string();
      else if (test_dev_fake[1])
        return (fs::u8path(val) / "devnet").u8string();
      else if (test_dev_fake[2])
        return (fs::u8path(val) / "fake").u8string();
      return val;
    }
  };
  const command_line::arg_descriptor<uint64_t> kdf_rounds = {"kdf-rounds", tools::wallet2::tr("Number of rounds for the key derivation function"), 1};
  const command_line::arg_descriptor<std::string> hw_device = {"hw-device", tools::wallet2::tr("HW device to use"), ""};
  const command_line::arg_descriptor<std::string> hw_device_derivation_path = {"hw-device-deriv-path", tools::wallet2::tr("HW device wallet derivation path (e.g., SLIP-10)"), ""};
  const command_line::arg_descriptor<std::string> tx_notify = { "tx-notify" , "Run a program for each new incoming transaction, '%s' will be replaced by the transaction hash" , "" };
  const command_line::arg_descriptor<bool> offline = {"offline", tools::wallet2::tr("Do not connect to a daemon"), false};
  const command_line::arg_descriptor<std::string> extra_entropy = {"extra-entropy", tools::wallet2::tr("File containing extra entropy to initialize the PRNG (any data, aim for 256 bits of entropy to be useful, wihch typically means more than 256 bits of data)")};
};

void do_prepare_file_names(const fs::path& file_path, fs::path& keys_file, fs::path& wallet_file, fs::path &mms_file)
{
  keys_file = file_path;
  wallet_file = file_path;

  if (keys_file.extension() == ".keys") // provided keys file name
    wallet_file.replace_extension();
  else // provided wallet file name
    keys_file += ".keys";

  (mms_file = keys_file).replace_extension(".mms");
}

uint64_t calculate_fee_from_weight(byte_and_output_fees base_fees, uint64_t weight, uint64_t outputs, uint64_t fee_percent, uint64_t fee_fixed, uint64_t fee_quantization_mask)
{
  uint64_t fee = (weight * base_fees.first + outputs * base_fees.second) * fee_percent / 100;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask + fee_fixed;
  return fee;
}

std::string get_weight_string(size_t weight)
{
  return std::to_string(weight) + " weight";
}

std::string get_weight_string(const cryptonote::transaction &tx, size_t blob_size)
{
  return get_weight_string(get_transaction_weight(tx, blob_size));
}

static const std::regex protocol_re{R"(^([a-zA-Z][a-zA-Z0-9+.-]*):)"};

std::unique_ptr<tools::wallet2> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool devnet = command_line::get_arg(vm, opts.devnet);
  const bool fakenet = command_line::get_arg(vm, opts.regtest);
  network_type nettype = testnet ? TESTNET : devnet ? DEVNET : fakenet ? FAKECHAIN : MAINNET;

  THROW_WALLET_EXCEPTION_IF(testnet + devnet + fakenet > 1, tools::error::wallet_internal_error, "At most one of --testnet, --devnet, or --regtest may be specified");

  const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
  THROW_WALLET_EXCEPTION_IF(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

  const bool use_proxy = command_line::has_arg(vm, opts.proxy);
  auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
  // Deprecated:
  auto daemon_host = command_line::get_arg(vm, opts.daemon_host);
  auto daemon_port = command_line::get_arg(vm, opts.daemon_port);

  auto device_name = command_line::get_arg(vm, opts.hw_device);
  auto device_derivation_path = command_line::get_arg(vm, opts.hw_device_derivation_path);

  THROW_WALLET_EXCEPTION_IF(!daemon_address.empty() && (!daemon_host.empty() || 0 != daemon_port),
      tools::error::wallet_internal_error, tools::wallet2::tr("--daemon-host/--daemon-port options are deprecated and cannot be combined with --daemon-address"));

  std::optional<tools::login> login;
  if (command_line::has_arg(vm, opts.daemon_login))
  {
    login = tools::login::parse(
      command_line::get_arg(vm, opts.daemon_login), false, [password_prompter](bool verify) {
        if (!password_prompter)
        {
          MERROR("Password needed without prompt function");
          return std::optional<tools::password_container>();
        }
        return password_prompter("Daemon client password", verify);
      }
    );
    if (!login)
      return nullptr;
  }

  // if no daemon settings are given and we have a previous one, reuse that one
  if (command_line::is_arg_defaulted(vm, opts.daemon_host) && command_line::is_arg_defaulted(vm, opts.daemon_port) && command_line::is_arg_defaulted(vm, opts.daemon_address))
    daemon_address = tools::wallet2::get_default_daemon_address();

  if (daemon_address.empty())
  {
    daemon_address = (daemon_host.empty() ? "localhost" : daemon_host) + ':' +
      std::to_string(daemon_port > 0 ? daemon_port : get_config(nettype).RPC_DEFAULT_PORT);
  }

  // Deprecated --daemon-ssl option: prepend https:// if there is no protocol on the daemon address
  if (command_line::get_arg(vm, opts.daemon_ssl) == "enabled") {
    THROW_WALLET_EXCEPTION_IF(tools::starts_with(daemon_address, "http://"), tools::error::wallet_internal_error,
        "Deprecated --daemon-ssl=enabled option conflicts with http://... daemon URL");
    if (!std::regex_search(daemon_address, protocol_re))
      daemon_address.insert(0, "https://"sv);
  }

  std::string proxy;
  if (use_proxy)
  {
    proxy = command_line::get_arg(vm, opts.proxy);
    try {
      rpc::http_client::parse_url(proxy);
    } catch (const std::exception& e) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, "Failed to parse proxy address: "s + e.what());
    }
  }

  bool trusted_daemon = false;
  try {
    auto [proto, host, port, url] = rpc::http_client::parse_url(daemon_address);
    trusted_daemon = tools::is_local_address(host);
  } catch (const std::exception& e) {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Invalid daemon address ") + "'"s + daemon_address + "': " + e.what());
  }

  THROW_WALLET_EXCEPTION_IF(!command_line::is_arg_defaulted(vm, opts.trusted_daemon) && !command_line::is_arg_defaulted(vm, opts.untrusted_daemon),
    tools::error::wallet_internal_error, tools::wallet2::tr("--trusted-daemon and --untrusted-daemon cannot both be specified"));
  if (!command_line::is_arg_defaulted(vm, opts.trusted_daemon) || !command_line::is_arg_defaulted(vm, opts.untrusted_daemon))
    trusted_daemon = command_line::get_arg(vm, opts.trusted_daemon) && !command_line::get_arg(vm, opts.untrusted_daemon);
  else if (trusted_daemon)
    MINFO(tools::wallet2::tr("Daemon is local, assuming trusted"));

  auto wallet = std::make_unique<tools::wallet2>(nettype, kdf_rounds, unattended);
  wallet->init(std::move(daemon_address), std::move(login), std::move(proxy), 0, trusted_daemon);
  auto ringdb_path = fs::u8path(command_line::get_arg(vm, opts.shared_ringdb_dir));
  wallet->set_ring_database(ringdb_path);
  wallet->get_message_store().set_options(vm);
  wallet->device_name(device_name);
  wallet->device_derivation_path(device_derivation_path);
  wallet->m_long_poll_disabled = command_line::get_arg(vm, opts.disable_rpc_long_poll);
  wallet->m_http_client.set_https_client_cert(command_line::get_arg(vm, opts.daemon_ssl_certificate), command_line::get_arg(vm, opts.daemon_ssl_private_key));
  wallet->m_http_client.set_insecure_https(command_line::get_arg(vm, opts.daemon_ssl_allow_any_cert));
  wallet->m_http_client.set_https_cainfo(command_line::get_arg(vm, opts.daemon_ssl_ca_certificates));

  if (command_line::get_arg(vm, opts.offline))
    wallet->set_offline();

  const std::string extra_entropy = command_line::get_arg(vm, opts.extra_entropy);
  if (!extra_entropy.empty())
  {
    std::string data;
    THROW_WALLET_EXCEPTION_IF(!tools::slurp_file(fs::u8path(extra_entropy), data),
        tools::error::wallet_internal_error, "Failed to load extra entropy from " + extra_entropy);
    add_extra_entropy_thread_safe(data.data(), data.size());
  }

  try
  {
    if (!command_line::is_arg_defaulted(vm, opts.tx_notify))
      wallet->set_tx_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, opts.tx_notify).c_str())));
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to parse tx notify spec");
  }

  return wallet;
}

std::optional<tools::password_container> get_password(const boost::program_options::variables_map& vm, const options& opts, const std::function<std::optional<tools::password_container>(const char*, bool)> &password_prompter, const bool verify)
{
  if (command_line::has_arg(vm, opts.password) && command_line::has_arg(vm, opts.password_file))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("can't specify more than one of --password and --password-file"));
  }

  if (command_line::has_arg(vm, opts.password))
  {
    return tools::password_container{command_line::get_arg(vm, opts.password)};
  }

  if (command_line::has_arg(vm, opts.password_file))
  {
    std::string password;
    bool r = tools::slurp_file(fs::u8path(command_line::get_arg(vm, opts.password_file)), password);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, tools::wallet2::tr("the password file specified could not be read"));

    // Remove line breaks the user might have inserted
    while (!password.empty() && (password.back() == '\r' || password.back() == '\n'))
      password.pop_back();
    return {tools::password_container{std::move(password)}};
  }

  THROW_WALLET_EXCEPTION_IF(!password_prompter, tools::error::wallet_internal_error, tools::wallet2::tr("no password specified; use --prompt-for-password to prompt for a password"));

  return password_prompter(verify ? tools::wallet2::tr("Enter a new password for the wallet") : tools::wallet2::tr("Wallet password"), verify);
}

std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> generate_from_json(const fs::path& json_file, const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool devnet = command_line::get_arg(vm, opts.devnet);
  const network_type nettype = testnet ? TESTNET : devnet ? DEVNET : MAINNET;

  /* GET_FIELD_FROM_JSON_RETURN_ON_ERROR Is a generic macro that can return
  false. Gcc will coerce this into unique_ptr(nullptr), but clang correctly
  fails. This large wrapper is for the use of that macro */
  std::unique_ptr<tools::wallet2> wallet;
  epee::wipeable_string password;
  const auto do_generate = [&]() -> bool {
    std::string buf;
    if (!tools::slurp_file(json_file, buf)) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("Failed to load file ")) + json_file.u8string());
      return false;
    }

    rapidjson::Document json;
    if (json.Parse(buf.c_str()).HasParseError()) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Failed to parse JSON"));
      return false;
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, version, unsigned, Uint, true, 0);
    const int current_version = 1;
    THROW_WALLET_EXCEPTION_IF(field_version > current_version, tools::error::wallet_internal_error,
      ((boost::format(tools::wallet2::tr("Version %u too new, we can only grok up to %u")) % field_version % current_version)).str());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, filename, std::string, String, true, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, scan_from_height, uint64_t, Uint64, false, 0);
    const bool recover = true;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, password, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, viewkey, std::string, String, false, std::string());
    crypto::secret_key viewkey;
    if (field_viewkey_found)
    {
      if(!tools::hex_to_type(field_viewkey, viewkey))
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse view key secret key"));
      crypto::public_key pkey;
      if (viewkey == crypto::null_skey)
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("view secret key may not be all zeroes"));
      if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, spendkey, std::string, String, false, std::string());
    crypto::secret_key spendkey;
    if (field_spendkey_found)
    {
      if(!tools::hex_to_type(field_spendkey, spendkey))
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse spend key secret key"));
      crypto::public_key pkey;
      if (spendkey == crypto::null_skey)
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("spend secret key may not be all zeroes"));
      if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed, std::string, String, false, std::string());
    std::string old_language;
    crypto::secret_key recovery_key;
    bool restore_deterministic_wallet = false;
    if (field_seed_found)
    {
      if (!crypto::ElectrumWords::words_to_bytes(field_seed, recovery_key, old_language))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Electrum-style word list failed verification"));
      }
      restore_deterministic_wallet = true;

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_passphrase, std::string, String, false, std::string());
      if (field_seed_passphrase_found)
      {
        if (!field_seed_passphrase.empty())
          recovery_key = cryptonote::decrypt_key(recovery_key, field_seed_passphrase);
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, address, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, create_address_file, int, Int, false, false);
    bool create_address_file = field_create_address_file;

    // compatibility checks
    if (!field_seed_found && !field_viewkey_found && !field_spendkey_found)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("At least one of either an Electrum-style word list, private view key, or private spend key must be specified"));
    }
    if (field_seed_found && (field_viewkey_found || field_spendkey_found))
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Both Electrum-style word list and private key(s) specified"));
    }

    // if an address was given, we check keys against it, and deduce the spend
    // public key if it was not given
    if (field_address_found)
    {
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, field_address))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("invalid address"));
      }
      if (field_viewkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
        }
        if (info.address.m_view_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("view key does not match standard address"));
        }
      }
      if (field_spendkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
        }
        if (info.address.m_spend_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("spend key does not match standard address"));
        }
      }
    }

    const bool deprecated_wallet = restore_deterministic_wallet && ((old_language == crypto::ElectrumWords::old_language_name) ||
      crypto::ElectrumWords::get_is_old_style_seed(field_seed));
    THROW_WALLET_EXCEPTION_IF(deprecated_wallet, tools::error::wallet_internal_error,
      tools::wallet2::tr("Cannot generate deprecated wallets from JSON"));

    wallet.reset(make_basic(vm, unattended, opts, password_prompter).release());
    wallet->set_refresh_from_block_height(field_scan_from_height);
    wallet->explicit_refresh_from_block_height(field_scan_from_height_found);
    if (!old_language.empty())
      wallet->set_seed_language(old_language);

    try
    {
      if (!field_seed.empty())
      {
        wallet->generate(field_filename, field_password, recovery_key, recover, false, create_address_file);
        password = field_password;
      }
      else if (field_viewkey.empty() && !field_spendkey.empty())
      {
        wallet->generate(field_filename, field_password, spendkey, recover, false, create_address_file);
        password = field_password;
      }
      else
      {
        cryptonote::account_public_address address;
        if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
        }

        if (field_spendkey.empty())
        {
          // if we have an address but no spend key, we can deduce the spend public key
          // from the address
          if (field_address_found)
          {
            cryptonote::address_parse_info info;
            if(!get_account_address_from_str(info, nettype, field_address))
            {
              THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to parse address: ")) + field_address);
            }
            address.m_spend_public_key = info.address.m_spend_public_key;
          }
          else
          {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Address must be specified in order to create watch-only wallet"));
          }
          wallet->generate(field_filename, field_password, address, viewkey, create_address_file);
          password = field_password;
        }
        else
        {
          if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
          }
          wallet->generate(field_filename, field_password, address, spendkey, viewkey, create_address_file);
          password = field_password;
        }
      }
    }
    catch (const std::exception& e)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to generate new wallet: ")) + e.what());
    }
    return true;
  };

  if (do_generate())
  {
    return {std::move(wallet), tools::password_container(password)};
  }
  return {nullptr, tools::password_container{}};
}

std::string strjoin(const std::vector<size_t> &V, const char *sep)
{
  std::stringstream ss;
  bool first = true;
  for (const auto &v: V)
  {
    if (!first)
      ss << sep;
    ss << std::to_string(v);
    first = false;
  }
  return ss.str();
}

bool emplace_or_replace(std::unordered_multimap<crypto::hash, tools::wallet2::pool_payment_details> &container,
  const crypto::hash &key, const tools::wallet2::pool_payment_details &pd)
{
  auto range = container.equal_range(key);
  for (auto i = range.first; i != range.second; ++i)
  {
    if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
    {
      i->second = pd;
      return false;
    }
  }
  container.emplace(key, pd);
  return true;
}

void drop_from_short_history(std::list<crypto::hash> &short_chain_history, size_t N)
{
  std::list<crypto::hash>::iterator right;
  // drop early N off, skipping the genesis block
  if (short_chain_history.size() > N) {
    right = short_chain_history.end();
    std::advance(right,-1);
    std::list<crypto::hash>::iterator left = right;
    std::advance(left, -N);
    short_chain_history.erase(left, right);
  }
}

size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool clsag)
{
  size_t size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += n_inputs * (1+6+(mixin+1)*2+32);

  // vout
  size += n_outputs * (6+32);

  // extra
  size += extra_size;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  size_t log_padded_outputs = 0;
  while ((1<<log_padded_outputs) < n_outputs)
    ++log_padded_outputs;
  size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;

  // MGs/CLSAGs
  if (clsag)
    size += n_inputs * (32 * (mixin+1) + 64);
  else
    size += n_inputs * (64 * (mixin+1) + 32);

  // mixRing - not serialized, can be reconstructed
  /* size += 2 * 32 * (mixin+1) * n_inputs; */

  // pseudoOuts
  size += 32 * n_inputs;
  // ecdhInfo
  size += 8 * n_outputs;
  // outPk - only commitment is saved
  size += 32 * n_outputs;
  // txnFee
  size += 4;

  LOG_PRINT_L2("estimated bulletproof rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
  return size;
}

uint64_t estimate_tx_weight(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool clsag)
{
  size_t size = estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, clsag);
  if (n_outputs > 2)
  {
    const uint64_t bp_base = 368;
    size_t log_padded_outputs = 2;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    uint64_t nlr = 2 * (6 + log_padded_outputs);
    const uint64_t bp_size = 32 * (9 + nlr);
    const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
    MDEBUG("clawback on size " << size << ": " << bp_clawback);
    size += bp_clawback;
  }
  return size;
}

uint64_t estimate_fee(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool clsag, byte_and_output_fees base_fees, uint64_t fee_percent, uint64_t fee_fixed, uint64_t fee_quantization_mask)
{
  const size_t estimated_tx_weight = estimate_tx_weight(n_inputs, mixin, n_outputs, extra_size, clsag);
  return calculate_fee_from_weight(base_fees, estimated_tx_weight, n_outputs, fee_percent, fee_fixed, fee_quantization_mask);
}

uint64_t calculate_fee(const cryptonote::transaction &tx, size_t blob_size, byte_and_output_fees base_fees, uint64_t fee_percent, uint64_t fee_fixed, uint64_t fee_quantization_mask)
{
  return calculate_fee_from_weight(base_fees, cryptonote::get_transaction_weight(tx, blob_size), tx.vout.size(), fee_percent, fee_fixed, fee_quantization_mask);
}

bool get_short_payment_id(crypto::hash8 &payment_id8, const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  cryptonote::tx_extra_nonce extra_nonce;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return false;
      }
      return hwdev.decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key);
    }
  }
  return false;
}

wallet::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  wallet::tx_construction_data construction_data = ptx.construction_data;
  crypto::hash8 payment_id = null_hash8;
  if (get_short_payment_id(payment_id, ptx, hwdev))
  {
    // Remove encrypted
    remove_field_from_tx_extra<cryptonote::tx_extra_nonce>(construction_data.extra);
    // Add decrypted
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    THROW_WALLET_EXCEPTION_IF(!add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce),
        tools::error::wallet_internal_error, "Failed to add decrypted payment id to tx extra");
    LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
  }
  return construction_data;
}

uint32_t get_subaddress_clamped_sum(uint32_t idx, uint32_t extra)
{
  constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
  if (idx > uint32_max - extra)
    return uint32_max;
  return idx + extra;
}

void setup_shim(hw::wallet_shim * shim, tools::wallet2 * wallet)
{
  shim->get_tx_pub_key_from_received_outs = [wallet] (const auto& td) { return wallet->get_tx_pub_key_from_received_outs(td); };
}

bool get_pruned_tx(const rpc::GET_TRANSACTIONS::entry &entry, cryptonote::transaction &tx, crypto::hash &tx_hash)
{
  cryptonote::blobdata bd;

  // easy case if we have the whole tx
  if (entry.as_hex || (entry.prunable_as_hex && entry.pruned_as_hex))
  {
    CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(entry.as_hex ? *entry.as_hex : *entry.pruned_as_hex + *entry.prunable_as_hex, bd), false, "Failed to parse tx data");
    CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_tx_from_blob(bd, tx), false, "Invalid tx data");
    tx_hash = cryptonote::get_transaction_hash(tx);
    // if the hash was given, check it matches
    CHECK_AND_ASSERT_MES(entry.tx_hash.empty() || tools::type_to_hex(tx_hash) == entry.tx_hash, false,
        "Response claims a different hash than the data yields");
    return true;
  }
  // case of a pruned tx with its prunable data hash
  if (entry.pruned_as_hex && entry.prunable_hash)
  {
    crypto::hash ph;
    CHECK_AND_ASSERT_MES(tools::hex_to_type(*entry.prunable_hash, ph), false, "Failed to parse prunable hash");
    CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(*entry.pruned_as_hex, bd), false, "Failed to parse pruned data");
    CHECK_AND_ASSERT_MES(parse_and_validate_tx_base_from_blob(bd, tx), false, "Invalid base tx data");
    // only v2 txes can calculate their txid after pruned
    if (bd[0] > 1)
    {
      tx_hash = cryptonote::get_pruned_transaction_hash(tx, ph);
    }
    else
    {
      // for v1, we trust the dameon
      CHECK_AND_ASSERT_MES(tools::hex_to_type(entry.tx_hash, tx_hash), false, "Failed to parse tx hash");
    }
    return true;
  }
  return false;
}

  //-----------------------------------------------------------------
} //namespace

namespace tools
{

const char* wallet2::tr(const char* str) { return i18n_translate(str, "tools::wallet2"); }

gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets, double shape, double scale):
    rct_offsets(rct_offsets)
{
  gamma = std::gamma_distribution<double>(shape, scale);
  THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, error::wallet_internal_error, "Bad offset calculation");
  const size_t blocks_in_a_year = BLOCKS_EXPECTED_IN_YEARS(1);
  const size_t blocks_to_consider = std::min<size_t>(rct_offsets.size(), blocks_in_a_year);
  const size_t outputs_to_consider = rct_offsets.back() - (blocks_to_consider < rct_offsets.size() ? rct_offsets[rct_offsets.size() - blocks_to_consider - 1] : 0);
  begin = rct_offsets.data();
  end = rct_offsets.data() + rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
  num_rct_outputs = *(end - 1);
  THROW_WALLET_EXCEPTION_IF(num_rct_outputs == 0, error::wallet_internal_error, "No rct outputs");
  average_output_time = tools::to_seconds(TARGET_BLOCK_TIME) * blocks_to_consider / outputs_to_consider; // this assumes constant target over the whole rct range
};

gamma_picker::gamma_picker(const std::vector<uint64_t> &rct_offsets): gamma_picker(rct_offsets, GAMMA_SHAPE, GAMMA_SCALE) {}

uint64_t gamma_picker::pick()
{
  double x = gamma(engine);
  x = exp(x);
  uint64_t output_index = x / average_output_time;
  if (output_index >= num_rct_outputs)
    return std::numeric_limits<uint64_t>::max(); // bad pick
  output_index = num_rct_outputs - 1 - output_index;

  const uint64_t *it = std::lower_bound(begin, end, output_index);
  THROW_WALLET_EXCEPTION_IF(it == end, error::wallet_internal_error, "output_index not found");
  uint64_t index = std::distance(begin, it);

  const uint64_t first_rct = index == 0 ? 0 : rct_offsets[index - 1];
  const uint64_t n_rct = rct_offsets[index] - first_rct;
  if (n_rct == 0)
    return std::numeric_limits<uint64_t>::max(); // bad pick
  MTRACE("Picking 1/" << n_rct << " in block " << index);
  return first_rct + crypto::rand_idx(n_rct);
};

std::mutex wallet_keys_unlocker::lockers_mutex;
unsigned int wallet_keys_unlocker::lockers = 0;
wallet_keys_unlocker::wallet_keys_unlocker(wallet2 &w, const std::optional<tools::password_container> &password):
  w(w),
  locked((bool) password)
{
  std::lock_guard lock{lockers_mutex};
  if (lockers++ > 0)
    locked = false;
  if (!locked || w.is_unattended() || w.ask_password() != tools::wallet2::AskPasswordToDecrypt || w.watch_only())
  {
    locked = false;
    return;
  }
  const epee::wipeable_string pass = password->password();
  w.generate_chacha_key_from_password(pass, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::wallet_keys_unlocker(wallet2 &w, bool locked, const epee::wipeable_string &password):
  w(w),
  locked(locked)
{
  std::lock_guard lock{lockers_mutex};
  if (lockers++ > 0)
    locked = false;
  if (!locked)
    return;
  w.generate_chacha_key_from_password(password, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::~wallet_keys_unlocker()
{
  try
  {
    std::lock_guard lock{lockers_mutex};
    if (lockers == 0)
    {
      MERROR("There are no lockers in wallet_keys_unlocker dtor");
      return;
    }
    --lockers;
    if (!locked)
      return;
    w.encrypt_keys(key);
  }
  catch (...)
  {
    MERROR("Failed to re-encrypt wallet keys");
    // do not propagate through dtor, we'd crash
  }
}

void wallet_device_callback::on_button_request(uint64_t code)
{
  if (wallet)
    wallet->on_device_button_request(code);
}

void wallet_device_callback::on_button_pressed()
{
  if (wallet)
    wallet->on_device_button_pressed();
}

std::optional<epee::wipeable_string> wallet_device_callback::on_pin_request()
{
  if (wallet)
    return wallet->on_device_pin_request();
  return std::nullopt;
}

std::optional<epee::wipeable_string> wallet_device_callback::on_passphrase_request(bool& on_device)
{
  if (wallet)
    return wallet->on_device_passphrase_request(on_device);
  else
    on_device = true;
  return std::nullopt;
}

void wallet_device_callback::on_progress(const hw::device_progress& event)
{
  if (wallet)
    wallet->on_device_progress(event);
}

wallet2::wallet2(network_type nettype, uint64_t kdf_rounds, bool unattended):
  m_multisig_rescan_info(NULL),
  m_multisig_rescan_k(NULL),
  m_upper_transaction_weight_limit(0),
  m_run(true),
  m_callback(0),
  m_trusted_daemon(false),
  m_nettype(nettype),
  m_multisig_rounds_passed(0),
  m_always_confirm_transfers(true),
  m_print_ring_members(false),
  m_store_tx_info(true),
  m_default_priority(0),
  m_refresh_type(RefreshOptimizeCoinbase),
  m_auto_refresh(true),
  m_first_refresh_done(false),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_confirm_non_default_ring_size(true),
  m_ask_password(AskPasswordToDecrypt),
  m_min_output_count(0),
  m_min_output_value(0),
  m_merge_destinations(false),
  m_confirm_backlog(true),
  m_confirm_backlog_threshold(0),
  m_confirm_export_overwrite(true),
  m_segregate_pre_fork_outputs(true),
  m_key_reuse_mitigation2(true),
  m_segregation_height(0),
  m_ignore_outputs_above(MONEY_SUPPLY),
  m_ignore_outputs_below(0),
  m_track_uses(false),
  m_inactivity_lock_timeout(m_nettype == MAINNET ? DEFAULT_INACTIVITY_LOCK_TIMEOUT : 0s),
  m_is_initialized(false),
  m_kdf_rounds(kdf_rounds),
  is_old_file_format(false),
  m_watch_only(false),
  m_multisig(false),
  m_multisig_threshold(0),
  m_node_rpc_proxy(m_http_client),
  m_account_public_address{crypto::null_pkey, crypto::null_pkey},
  m_subaddress_lookahead_major(SUBADDRESS_LOOKAHEAD_MAJOR),
  m_subaddress_lookahead_minor(SUBADDRESS_LOOKAHEAD_MINOR),
  m_light_wallet(false),
  m_light_wallet_scanned_block_height(0),
  m_light_wallet_blockchain_height(0),
  m_light_wallet_connected(false),
  m_light_wallet_balance(0),
  m_light_wallet_unlocked_balance(0),
  m_original_keys_available(false),
  m_message_store(),
  m_key_device_type(hw::device::device_type::SOFTWARE),
  m_ring_history_saved(false),
  m_ringdb(),
  m_last_block_reward(0),
  m_encrypt_keys_after_refresh(std::nullopt),
  m_decrypt_keys_lockers(0),
  m_unattended(unattended),
  m_devices_registered(false),
  m_device_last_key_image_sync(0),
  m_offline(false),
  m_rpc_version(0),
  m_export_format(ExportFormat::Binary)
{
}

wallet2::~wallet2()
{
}

bool wallet2::has_testnet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().testnet);
}

bool wallet2::has_disable_rpc_long_poll(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().disable_rpc_long_poll);
}

bool wallet2::has_devnet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().devnet);
}

std::vector<std::string> wallet2::has_deprecated_options(const boost::program_options::variables_map& vm)
{
  std::vector<std::string> warnings;

  // These are deprecated as of oxen 8.x:
  if (!command_line::is_arg_defaulted(vm, options().daemon_host))
    warnings.emplace_back("--daemon-host. Use '--daemon-address http://HOSTNAME' instead");
  if (!command_line::is_arg_defaulted(vm, options().daemon_port))
    warnings.emplace_back("--daemon-port. Use '--daemon-address http://HOSTNAME:PORT' instead");
  if (!command_line::is_arg_defaulted(vm, options().daemon_ssl))
    warnings.emplace_back("--daemon-ssl has no effect. Use '--daemon-address https://...' instead");

  return warnings;
}

std::string wallet2::device_name_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().hw_device);
}

std::string wallet2::device_derivation_path_option(const boost::program_options::variables_map &vm)
{
  return command_line::get_arg(vm, options().hw_device_derivation_path);
}

void wallet2::init_options(boost::program_options::options_description& desc_params, boost::program_options::options_description& hidden_params)
{
  const options opts{};
  command_line::add_arg(desc_params, opts.daemon_address);
  // deprecated:
  command_line::add_arg(hidden_params, opts.daemon_host);
  command_line::add_arg(hidden_params, opts.daemon_port);
  command_line::add_arg(hidden_params, opts.daemon_ssl);

  command_line::add_arg(desc_params, opts.daemon_login);
  command_line::add_arg(desc_params, opts.proxy);
  command_line::add_arg(desc_params, opts.trusted_daemon);
  command_line::add_arg(desc_params, opts.untrusted_daemon);
  command_line::add_arg(desc_params, opts.daemon_ssl_private_key);
  command_line::add_arg(desc_params, opts.daemon_ssl_certificate);
  command_line::add_arg(desc_params, opts.daemon_ssl_ca_certificates);
  command_line::add_arg(desc_params, opts.daemon_ssl_allow_any_cert);
  command_line::add_arg(desc_params, opts.password);
  command_line::add_arg(desc_params, opts.password_file);
  command_line::add_arg(desc_params, opts.testnet);
  command_line::add_arg(desc_params, opts.devnet);
  command_line::add_arg(desc_params, opts.regtest);
  command_line::add_arg(desc_params, opts.shared_ringdb_dir);
  command_line::add_arg(desc_params, opts.kdf_rounds);
  mms::message_store::init_options(desc_params);
  command_line::add_arg(desc_params, opts.hw_device);
  command_line::add_arg(desc_params, opts.hw_device_derivation_path);
  command_line::add_arg(desc_params, opts.tx_notify);
  command_line::add_arg(desc_params, opts.offline);
  command_line::add_arg(desc_params, opts.disable_rpc_long_poll);
  command_line::add_arg(desc_params, opts.extra_entropy);
}

std::pair<std::unique_ptr<wallet2>, tools::password_container> wallet2::make_from_json(const boost::program_options::variables_map& vm, bool unattended, const fs::path& json_file, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return generate_from_json(json_file, vm, unattended, opts, password_prompter);
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_from_file(
  const boost::program_options::variables_map& vm, bool unattended, const fs::path& wallet_file, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, false);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  auto wallet = make_basic(vm, unattended, opts, password_prompter);
  if (wallet && !wallet_file.empty())
  {
    wallet->load(wallet_file, pwd->password());
  }
  return {std::move(wallet), std::move(*pwd)};
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<std::optional<password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, true);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  return {make_basic(vm, unattended, opts, password_prompter), std::move(*pwd)};
}

std::unique_ptr<wallet2> wallet2::make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<std::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return make_basic(vm, unattended, opts, password_prompter);
}

std::string wallet2::get_default_daemon_address() {
  std::lock_guard lock{default_daemon_address_mutex};
  return default_daemon_address;
}

//----------------------------------------------------------------------------------------------------
bool wallet2::set_daemon(std::string daemon_address, std::optional<tools::login> daemon_login, std::string proxy, bool trusted_daemon)
{
  // If we're given a raw address, prepend http, and (possibly) append the default port
  if (!tools::starts_with(daemon_address, "http://") && !tools::starts_with(daemon_address, "https://"))
  {
    if (auto pos = daemon_address.find(':'); pos == std::string::npos)
      daemon_address += ":" + std::to_string(cryptonote::get_config(m_nettype).RPC_DEFAULT_PORT);
    daemon_address.insert(0, "http://"sv);
  }

  bool localhost = false;
  try {
    auto [proto, host, port, uri] = rpc::http_client::parse_url(daemon_address);
    localhost = tools::is_local_address(host);
  } catch (const rpc::http_client_error& e) {
    MWARNING("Invalid daemon URL: "s + e.what());
    return false;
  }

  m_http_client.set_base_url(daemon_address);
  m_http_client.set_timeout(rpc_timeout);
  if (daemon_login)
    m_http_client.set_auth(daemon_login->username, daemon_login->password.password().view());
  else
    m_http_client.set_auth();

  // If the proxy is given but starts with an address/hostname then prepend `socks4a://`.
  // Use a regex here rather than parsing the URL (as above) because you might want to specify
  // authentication info (e.g. with an HTTP or SOCKS5 proxy), which parse_url doesn't handle.
  if (!proxy.empty() && !std::regex_search(proxy, protocol_re))
    proxy.insert(0, "socks4a://"sv);
  m_http_client.set_proxy(std::move(proxy));

  m_trusted_daemon = trusted_daemon;

  // Copy everything to the long poll client as well:
  m_long_poll_client.copy_params_from(m_http_client);
  m_long_poll_local = localhost;

  m_node_rpc_proxy.invalidate();

  std::string url = m_http_client.get_base_url();
  MINFO("set daemon to " << (url.empty() ? "(none, offline)" : url));
  {
    std::lock_guard lock{default_daemon_address_mutex};
    default_daemon_address = std::move(url);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::init(std::string daemon_address, std::optional<tools::login> daemon_login, std::string proxy, uint64_t upper_transaction_weight_limit, bool trusted_daemon)
{
  if (!set_daemon(std::move(daemon_address), std::move(daemon_login), std::move(proxy), trusted_daemon))
    return false;

  m_is_initialized = true;
  m_upper_transaction_weight_limit = upper_transaction_weight_limit;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_deterministic() const
{
  crypto::secret_key second;
  keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
  sc_reduce32((uint8_t *)&second);
  return memcmp(second.data,get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) == 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase) const
{
  bool keys_deterministic = is_deterministic();
  if (!keys_deterministic)
  {
    std::cout << "This is not a deterministic wallet" << std::endl;
    return false;
  }
  if (seed_language.empty())
  {
    std::cout << "seed_language not set" << std::endl;
    return false;
  }

  crypto::secret_key key = get_account().get_keys().m_spend_secret_key;
  if (!passphrase.empty())
    key = cryptonote::encrypt_key(key, passphrase);
  if (!crypto::ElectrumWords::bytes_to_words(key, electrum_words, seed_language))
  {
    std::cout << "Failed to create seed from key for language: " << seed_language << std::endl;
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_multisig_seed(epee::wipeable_string& seed, const epee::wipeable_string &passphrase, bool raw) const
{
  bool ready;
  uint32_t threshold, total;
  if (!multisig(&ready, &threshold, &total))
  {
    std::cout << "This is not a multisig wallet" << std::endl;
    return false;
  }
  if (!ready)
  {
    std::cout << "This multisig wallet is not yet finalized" << std::endl;
    return false;
  }
  if (!raw && seed_language.empty())
  {
    std::cout << "seed_language not set" << std::endl;
    return false;
  }

  crypto::secret_key skey;
  crypto::public_key pkey;
  const account_keys &keys = get_account().get_keys();
  epee::wipeable_string data;
  data.append((const char*)&threshold, sizeof(uint32_t));
  data.append((const char*)&total, sizeof(uint32_t));
  skey = keys.m_spend_secret_key;
  data.append((const char*)&skey, sizeof(skey));
  pkey = keys.m_account_address.m_spend_public_key;
  data.append((const char*)&pkey, sizeof(pkey));
  skey = keys.m_view_secret_key;
  data.append((const char*)&skey, sizeof(skey));
  pkey = keys.m_account_address.m_view_public_key;
  data.append((const char*)&pkey, sizeof(pkey));
  for (const auto &skey: keys.m_multisig_keys)
    data.append((const char*)&skey, sizeof(skey));
  for (const auto &signer: m_multisig_signers)
    data.append((const char*)&signer, sizeof(signer));

  if (!passphrase.empty())
  {
    crypto::secret_key key;
    crypto::cn_slow_hash(passphrase.data(), passphrase.size(), (crypto::hash&)key, crypto::cn_slow_hash_type::heavy_v1);
    sc_reduce32((unsigned char*)key.data);
    data = encrypt(data.view(), key, true);
  }

  if (raw)
  {
    seed = epee::to_hex::wipeable_string({(const unsigned char*)data.data(), data.size()});
  }
  else
  {
    if (!crypto::ElectrumWords::bytes_to_words(data.data(), data.size(), seed, seed_language))
    {
      std::cout << "Failed to encode seed";
      return false;
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::reconnect_device()
{
  bool r = true;
  hw::device &hwdev = lookup_device(m_device_name);
  hwdev.set_name(m_device_name);
  hwdev.set_network_type(m_nettype);
  hwdev.set_derivation_path(m_device_derivation_path);
  hwdev.set_callback(get_device_callback());
  r = hwdev.init();
  if (!r){
    MERROR("Could not init device");
    return false;
  }

  r = hwdev.connect();
  if (!r){
    MERROR("Could not connect to the device");
    return false;
  }

  m_account.set_device(hwdev);
  return true;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Gets the seed language
 */
const std::string &wallet2::get_seed_language() const
{
  return seed_language;
}
/*!
 * \brief Sets the seed language
 * \param language  Seed language to set to
 */
void wallet2::set_seed_language(const std::string &language)
{
  seed_language = language;
}
//----------------------------------------------------------------------------------------------------
cryptonote::account_public_address wallet2::get_subaddress(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::optional<cryptonote::subaddress_index> wallet2::get_subaddress_index(const cryptonote::account_public_address& address) const
{
  auto index = m_subaddresses.find(address.m_spend_public_key);
  if (index == m_subaddresses.end())
    return std::nullopt;
  return index->second;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress_spend_public_key(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
{
  cryptonote::account_public_address address = get_subaddress(index);
  return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_integrated_address_as_str(const crypto::hash8& payment_id) const
{
  return cryptonote::get_account_integrated_address_as_str(m_nettype, get_address(), payment_id);
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress_account(const std::string& label)
{
  uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
  expand_subaddresses({index_major, 0});
  m_subaddress_labels[index_major][0] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress(uint32_t index_major, const std::string& label)
{
  THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
  uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
  expand_subaddresses({index_major, index_minor});
  m_subaddress_labels[index_major][index_minor] = label;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::should_expand(const cryptonote::subaddress_index &index) const
{
  const uint32_t last_major = m_subaddress_labels.size() - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_major) ? std::numeric_limits<uint32_t>::max()  : (m_subaddress_labels.size() + m_subaddress_lookahead_major - 1);
  if (index.major > last_major)
    return false;
  const size_t nsub = index.major < m_subaddress_labels.size() ? m_subaddress_labels[index.major].size() : 0;
  const uint32_t last_minor = nsub - 1 > (std::numeric_limits<uint32_t>::max() - m_subaddress_lookahead_minor) ? std::numeric_limits<uint32_t>::max()  : (nsub + m_subaddress_lookahead_minor - 1);
  if (index.minor > last_minor)
    return false;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::expand_subaddresses(const cryptonote::subaddress_index& index)
{
  hw::device &hwdev = m_account.get_device();
  if (m_subaddress_labels.size() <= index.major)
  {
    // add new accounts
    cryptonote::subaddress_index index2;
    const uint32_t major_end = get_subaddress_clamped_sum(index.major, m_subaddress_lookahead_major);
    for (index2.major = m_subaddress_labels.size(); index2.major < major_end; ++index2.major)
    {
      const uint32_t end = get_subaddress_clamped_sum((index2.major == index.major ? index.minor : 0), m_subaddress_lookahead_minor);
      const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, 0, end);
      for (index2.minor = 0; index2.minor < end; ++index2.minor)
      {
         const crypto::public_key &D = pkeys[index2.minor];
         m_subaddresses[D] = index2;
      }
    }
    m_subaddress_labels.resize(index.major + 1, {"Untitled account"});
    m_subaddress_labels[index.major].resize(index.minor + 1);
    get_account_tags();
  }
  else if (m_subaddress_labels[index.major].size() <= index.minor)
  {
    // add new subaddresses
    const uint32_t end = get_subaddress_clamped_sum(index.minor, m_subaddress_lookahead_minor);
    const uint32_t begin = m_subaddress_labels[index.major].size();
    cryptonote::subaddress_index index2 = {index.major, begin};
    const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, index2.minor, end);
    for (; index2.minor < end; ++index2.minor)
    {
       const crypto::public_key &D = pkeys[index2.minor - begin];
       m_subaddresses[D] = index2;
    }
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_label(const cryptonote::subaddress_index& index) const
{
  if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
  {
    MERROR("Subaddress label doesn't exist");
    return "";
  }
  return m_subaddress_labels[index.major][index.minor];
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
{
  THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
  THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
  m_subaddress_labels[index.major][index.minor] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_lookahead(size_t major, size_t minor)
{
  THROW_WALLET_EXCEPTION_IF(major == 0, error::wallet_internal_error, "Subaddress major lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(major > 0xffffffff, error::wallet_internal_error, "Subaddress major lookahead is too large");
  THROW_WALLET_EXCEPTION_IF(minor == 0, error::wallet_internal_error, "Subaddress minor lookahead may not be zero");
  THROW_WALLET_EXCEPTION_IF(minor > 0xffffffff, error::wallet_internal_error, "Subaddress minor lookahead is too large");
  m_subaddress_lookahead_major = major;
  m_subaddress_lookahead_minor = minor;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Tells if the wallet file is deprecated.
 */
bool wallet2::is_deprecated() const
{
  return is_old_file_format;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_spent(size_t idx, uint64_t height)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = true;
  td.m_spent_height = height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_unspent(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = false;
  td.m_spent_height = 0;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(const transfer_details &td, bool strict) const
{
  if (strict)
  {
    return td.m_spent && td.m_spent_height > 0;
  }
  else
  {
    return td.m_spent;
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_spent(size_t idx, bool strict) const
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid index");
  const transfer_details &td = m_transfers[idx];
  return is_spent(td, strict);
}
//----------------------------------------------------------------------------------------------------
void wallet2::freeze(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  transfer_details &td = m_transfers[idx];
  td.m_frozen = true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::thaw(size_t idx)
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  transfer_details &td = m_transfers[idx];
  td.m_frozen = false;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(size_t idx) const
{
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "Invalid transfer_details index");
  const transfer_details &td = m_transfers[idx];
  return td.m_frozen;
}
//----------------------------------------------------------------------------------------------------
void wallet2::freeze(const crypto::key_image &ki)
{
  freeze(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
void wallet2::thaw(const crypto::key_image &ki)
{
  thaw(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(const crypto::key_image &ki) const
{
  return frozen(get_transfer_details(ki));
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::get_transfer_details(const crypto::key_image &ki) const
{
  for (size_t idx = 0; idx < m_transfers.size(); ++idx)
  {
    const transfer_details &td = m_transfers[idx];
    if (td.m_key_image_known && td.m_key_image == ki)
      return idx;
  }
  CHECK_AND_ASSERT_THROW_MES(false, "Key image not found");
}
//----------------------------------------------------------------------------------------------------
bool wallet2::frozen(const transfer_details &td) const
{
  return td.m_frozen;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const
{
  hw::device &hwdev = m_account.get_device();
  std::unique_lock hwdev_lock{hwdev};
  hwdev.set_mode(hw::device::TRANSACTION_PARSE);
  if (!std::holds_alternative<txout_to_key>(o.target))
  {
     tx_scan_info.error = true;
     LOG_ERROR("wrong type id in transaction out");
     return;
  }
  tx_scan_info.received = is_out_to_acc_precomp(m_subaddresses, var::get<txout_to_key>(o.target).key, derivation, additional_derivations, i, hwdev);
  if(tx_scan_info.received)
  {
    tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
  }
  else
  {
    tx_scan_info.money_transfered = 0;
  }
  tx_scan_info.error = false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const
{
  if (!is_out_data || i >= is_out_data->received.size())
    return check_acc_out_precomp(o, derivation, additional_derivations, i, tx_scan_info);

  tx_scan_info.received = is_out_data->received[i];
  if(tx_scan_info.received)
  {
    tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
  }
  else
  {
    tx_scan_info.money_transfered = 0;
  }
  tx_scan_info.error = false;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp_once(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const
{
  tx_scan_info.received = std::nullopt;
  if (already_seen)
    return;
  check_acc_out_precomp(o, derivation, additional_derivations, i, is_out_data, tx_scan_info);
  if (tx_scan_info.received)
    already_seen = true;
}
//----------------------------------------------------------------------------------------------------
static uint64_t decodeRct(const rct::rctSig & rv, const crypto::key_derivation &derivation, unsigned int i, rct::key & mask, hw::device &hwdev)
{
  crypto::secret_key scalar1;
  hwdev.derivation_to_scalar(derivation, i, scalar1);
  try
  {
    switch (rv.type)
    {
    case rct::RCTType::Simple:
    case rct::RCTType::Bulletproof:
    case rct::RCTType::Bulletproof2:
    case rct::RCTType::CLSAG:
      return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    case rct::RCTType::Full:
      return rct::decodeRct(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    default:
      LOG_ERROR(__func__ << ": Unsupported rct type: " << (int)rv.type);
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Failed to decode input " << i);
    return 0;
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::scan_output(const cryptonote::transaction &tx, bool miner_tx, const crypto::public_key &tx_pub_key, size_t vout_index, tx_scan_info_t &tx_scan_info, std::vector<tx_money_got_in_out> &tx_money_got_in_outs, std::vector<size_t> &outs, bool pool, bool blink)
{
  THROW_WALLET_EXCEPTION_IF(vout_index >= tx.vout.size(), error::wallet_internal_error, "Invalid vout index");

  // if keys are encrypted, ask for password
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only && !m_multisig_rescan_k)
  {
    static std::recursive_mutex password_mutex;
    std::lock_guard lock{password_mutex};

    if (!m_encrypt_keys_after_refresh)
    {
      char const blink_reason[] = "(blink output received in pool) - use the refresh command";
      char const pool_reason[]  = "(output received in pool) - use the refresh, then show_transfers command";
      char const block_reason[] = "(output received) - use the refresh command";

      char const *reason = block_reason;
      if (pool) reason = (blink) ? blink_reason : pool_reason;

      std::optional<epee::wipeable_string> pwd = m_callback->on_get_password(reason);
      THROW_WALLET_EXCEPTION_IF(!pwd, error::password_needed, tr("Password is needed to compute key image for incoming OXEN"));
      THROW_WALLET_EXCEPTION_IF(!verify_password(*pwd), error::password_needed, tr("Invalid password: password is needed to compute key image for incoming OXEN"));
      decrypt_keys(*pwd);
      m_encrypt_keys_after_refresh = *pwd;
    }
  }

  if (m_multisig)
  {
    tx_scan_info.in_ephemeral.pub = var::get<cryptonote::txout_to_key>(tx.vout[vout_index].target).key;
    tx_scan_info.in_ephemeral.sec = crypto::null_skey;
    tx_scan_info.ki = rct::rct2ki(rct::zero());
  }
  else
  {
    bool r = cryptonote::generate_key_image_helper_precomp(m_account.get_keys(), var::get<cryptonote::txout_to_key>(tx.vout[vout_index].target).key, tx_scan_info.received->derivation, vout_index, tx_scan_info.received->index, tx_scan_info.in_ephemeral, tx_scan_info.ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(tx_scan_info.in_ephemeral.pub != var::get<cryptonote::txout_to_key>(tx.vout[vout_index].target).key,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");
  }

  THROW_WALLET_EXCEPTION_IF(std::find(outs.begin(), outs.end(), vout_index) != outs.end(), error::wallet_internal_error, "Same output cannot be added twice");
  if (tx_scan_info.money_transfered == 0 && !miner_tx)
  {
    tx_scan_info.money_transfered = tools::decodeRct(tx.rct_signatures, tx_scan_info.received->derivation, vout_index, tx_scan_info.mask, m_account.get_device());
  }

  if (tx_scan_info.money_transfered == 0)
  {
    MERROR("Invalid output amount, skipping");
    tx_scan_info.error = true;
    return;
  }

  outs.push_back(vout_index);
  uint64_t unlock_time = tx.get_unlock_time(vout_index);

  tx_money_got_in_out entry = {};
  entry.type                = wallet::pay_type::in;
  entry.index               = tx_scan_info.received->index;
  entry.amount              = tx_scan_info.money_transfered;
  entry.unlock_time         = unlock_time;

  if (cryptonote::is_coinbase(tx))
  {
    // TODO(doyle): When batched governance comes in, this needs to check that the TX has a governance output, can't assume last one is governance
    if      (vout_index == 0)                  entry.type = wallet::pay_type::miner;
    // else if (vout_index == tx.vout.size() - 1) entry.type = wallet::pay_type::governance;
    else                                       entry.type = wallet::pay_type::service_node;
  }

  tx_money_got_in_outs.push_back(entry);
  tx_scan_info.amount      = tx_scan_info.money_transfered;
  tx_scan_info.unlock_time = unlock_time;
}
//----------------------------------------------------------------------------------------------------
void wallet2::cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid, tx_cache_data &tx_cache_data) const
{
  if(!parse_tx_extra(tx.extra, tx_cache_data.tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
    LOG_PRINT_L0("Transaction extra has unsupported format: " << txid);
    if (tx_cache_data.tx_extra_fields.empty())
      return;
  }

  // Don't try to extract tx public key if tx has no ouputs
  const bool is_miner = tx.vin.size() == 1 && std::holds_alternative<cryptonote::txin_gen>(tx.vin[0]);
  if (!is_miner || m_refresh_type != RefreshType::RefreshNoCoinbase)
  {
    const size_t rec_size = is_miner && m_refresh_type == RefreshType::RefreshOptimizeCoinbase ? 1 : tx.vout.size();
    if (!tx.vout.empty())
    {
      // if tx.vout is not empty, we loop through all tx pubkeys
      const std::vector<std::optional<cryptonote::subaddress_receive_info>> rec(rec_size, std::nullopt);

      tx_extra_pub_key pub_key_field;
      size_t pk_index = 0;
      while (find_tx_extra_field_by_type(tx_cache_data.tx_extra_fields, pub_key_field, pk_index++))
        tx_cache_data.primary.push_back({pub_key_field.pub_key, {}, rec});

      // additional tx pubkeys and derivations for multi-destination transfers involving one or more subaddresses
      tx_extra_additional_pub_keys additional_tx_pub_keys;
      if (find_tx_extra_field_by_type(tx_cache_data.tx_extra_fields, additional_tx_pub_keys))
      {
        for (size_t i = 0; i < additional_tx_pub_keys.data.size(); ++i)
          tx_cache_data.additional.push_back({additional_tx_pub_keys.data[i], {}, {}});
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices,
    uint64_t height, uint8_t block_version, uint64_t ts, bool miner_tx, bool pool, bool blink, bool double_spend_seen,
    const tx_cache_data &tx_cache_data, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  if (!tx.is_transfer() || tx.version <= txversion::v1)
    return;

  PERF_TIMER(process_new_transaction);
  // In this function, tx (probably) only contains the base information
  // (that is, the prunable stuff may or may not be included)
  if (!miner_tx && !pool)
    process_unconfirmed(txid, tx, height);

  // NOTE: tx_scan_info contains the decoded amounts from the transaction destined for us
  //       tx_money_got_in_outs contains decoded amounts from the transaction,
  //       that removes amounts from our scanned outputs that got invalidated
  //       i.e. duplicated key images
  std::vector<tx_money_got_in_out> tx_money_got_in_outs;
  tx_money_got_in_outs.reserve(tx.vout.size());
  crypto::public_key tx_pub_key = null_pkey;
  bool notify = false;

  std::vector<tx_extra_field> local_tx_extra_fields;
  if (tx_cache_data.tx_extra_fields.empty())
  {
    if(!parse_tx_extra(tx.extra, local_tx_extra_fields))
    {
      // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
      LOG_PRINT_L0("Transaction extra has unsupported format: " << txid);
    }
  }
  const std::vector<tx_extra_field> &tx_extra_fields = tx_cache_data.tx_extra_fields.empty() ? local_tx_extra_fields : tx_cache_data.tx_extra_fields;

  // Don't try to extract tx public key if tx has no ouputs
  size_t pk_index = 0;
  std::vector<tx_scan_info_t> tx_scan_info(tx.vout.size());
  std::deque<bool> output_found(tx.vout.size(), false);
  uint64_t total_received_1 = 0;

  // NOTE: This handles the case where you have multiple outputs in the same
  // transaction with duplicated output keys. Unlock times is lost when it's
  // stored into m_transfers so we cannot determine if the entry in m_transfers
  // came from this transaction or a previous transaction.

  // TODO(oxen): This case might be feasible at all where a key image is
  // duplicated in the _same_ tx in different output indexes, because the
  // algorithm for making a key image uses the output index. Investigate, and if
  // it's not feasible to construct a malicious one without absolutely breaking
  // everything in the system then we can delete the code for it.
  using unlock_time_t = uint64_t;
  std::unordered_map<crypto::public_key, unlock_time_t> pk_to_unlock_times;
  std::vector<size_t> outs;

  // NOTE: The earliest index that we detected a TX, where we previously had
  // it as a blink sitting in the mempool was confirmed in this block.
  auto constexpr NO_BLINK_MINED_INDEX           = std::numeric_limits<int64_t>::max();
  auto earliest_blink_got_mined_transfers_index = NO_BLINK_MINED_INDEX;

  while (!tx.vout.empty())
  {
    // if tx.vout is not empty, we loop through all tx pubkeys
    outs.clear();

    tx_extra_pub_key pub_key_field;
    if(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++))
    {
      if (pk_index > 1)
        break;
      LOG_PRINT_L0("Public key wasn't found in the transaction extra. Skipping transaction " << txid);
      if(0 != m_callback)
        m_callback->on_skip_transaction(height, txid, tx);
      break;
    }
    if (!tx_cache_data.primary.empty())
    {
      THROW_WALLET_EXCEPTION_IF(tx_cache_data.primary.size() < pk_index || pub_key_field.pub_key != tx_cache_data.primary[pk_index - 1].pkey,
          error::wallet_internal_error, "tx_cache_data is out of sync");
    }

    tx_pub_key = pub_key_field.pub_key;
    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter;
    const cryptonote::account_keys& keys = m_account.get_keys();
    crypto::key_derivation derivation;

    std::vector<crypto::key_derivation> additional_derivations;
    tx_extra_additional_pub_keys additional_tx_pub_keys;
    const wallet2::is_out_data *is_out_data_ptr = NULL;
    if (tx_cache_data.primary.empty())
    {
      hw::device &hwdev = m_account.get_device();
      std::unique_lock hwdev_lock{hwdev};
      hw::mode_resetter rst{hwdev};

      hwdev.set_mode(hw::device::TRANSACTION_PARSE);
      if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
      {
        MWARNING("Failed to generate key derivation from tx pubkey in " << txid << ", skipping");
        static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
        memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
      }

      if (pk_index == 1)
      {
        // additional tx pubkeys and derivations for multi-destination transfers involving one or more subaddresses
        if (find_tx_extra_field_by_type(tx_extra_fields, additional_tx_pub_keys))
        {
          for (size_t i = 0; i < additional_tx_pub_keys.data.size(); ++i)
          {
            additional_derivations.push_back({});
            if (!hwdev.generate_key_derivation(additional_tx_pub_keys.data[i], keys.m_view_secret_key, additional_derivations.back()))
            {
              MWARNING("Failed to generate key derivation from additional tx pubkey in " << txid << ", skipping");
              memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
            }
          }
        }
      }
    }
    else
    {
      THROW_WALLET_EXCEPTION_IF(pk_index - 1 >= tx_cache_data.primary.size(),
          error::wallet_internal_error, "pk_index out of range of tx_cache_data");
      is_out_data_ptr = &tx_cache_data.primary[pk_index - 1];
      derivation = tx_cache_data.primary[pk_index - 1].derivation;
      if (pk_index == 1)
      {
        for (size_t n = 0; n < tx_cache_data.additional.size(); ++n)
        {
          additional_tx_pub_keys.data.push_back(tx_cache_data.additional[n].pkey);
          additional_derivations.push_back(tx_cache_data.additional[n].derivation);
        }
      }
    }

    if (miner_tx && m_refresh_type == RefreshNoCoinbase)
    {
      // assume coinbase isn't for us
      continue;
    }

    // NOTE(oxen): (miner_tx && m_refresh_type == RefreshOptimiseCoinbase) used
    // to be an optimisation step that checks if the first output was destined
    // for us otherwise skip. This is not possible for us because our
    // block-reward now always has more than 1 output, mining, service node
    // and governance rewards which can all have different dest addresses, so we
    // always need to check all outputs.
    if ((tx.vout.size() > 1 && tools::threadpool::getInstance().get_max_concurrency() > 1 && !is_out_data_ptr) ||
        (miner_tx && m_refresh_type == RefreshOptimizeCoinbase))
    {
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tpool.submit(&waiter,
                [&, i] { return check_acc_out_precomp_once(tx.vout[i], derivation, additional_derivations, i,  is_out_data_ptr, tx_scan_info[i], output_found[i]); },
                true);
      waiter.wait(&tpool);

      hw::device &hwdev = m_account.get_device();
      std::unique_lock hwdev_lock{hwdev};
      hwdev.set_mode(hw::device::NONE);
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
        if (tx_scan_info[i].received)
        {
          hwdev.conceal_derivation(tx_scan_info[i].received->derivation, tx_pub_key, additional_tx_pub_keys.data, derivation, additional_derivations);
          scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], tx_money_got_in_outs, outs, pool, blink);
        }
      }
    }
    else
    {
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        check_acc_out_precomp_once(tx.vout[i], derivation, additional_derivations, i, is_out_data_ptr, tx_scan_info[i], output_found[i]);
        THROW_WALLET_EXCEPTION_IF(tx_scan_info[i].error, error::acc_outs_lookup_error, tx, tx_pub_key, m_account.get_keys());
        if (tx_scan_info[i].received)
        {
          hw::device &hwdev = m_account.get_device();
          std::unique_lock hwdev_lock{hwdev};
          hwdev.set_mode(hw::device::NONE);
          hwdev.conceal_derivation(tx_scan_info[i].received->derivation, tx_pub_key, additional_tx_pub_keys.data, derivation, additional_derivations);
          scan_output(tx, miner_tx, tx_pub_key, i, tx_scan_info[i], tx_money_got_in_outs, outs, pool, blink);
        }
      }
    }

    if(!outs.empty())
    {
      //good news - got money! take care about it
      //usually we have only one transfer for user in transaction
      if (!pool)
      {
        THROW_WALLET_EXCEPTION_IF(tx.vout.size() != o_indices.size(), error::wallet_internal_error,
            "transactions outputs size=" + std::to_string(tx.vout.size()) +
            " not match with daemon response size=" + std::to_string(o_indices.size()));
      }

      for(size_t o: outs)
      {
        THROW_WALLET_EXCEPTION_IF(tx.vout.size() <= o, error::wallet_internal_error, "wrong out in transaction: internal index=" +
                                  std::to_string(o) + ", total_outs=" + std::to_string(tx.vout.size()));

        auto kit = m_pub_keys.find(tx_scan_info[o].in_ephemeral.pub);
        THROW_WALLET_EXCEPTION_IF(kit != m_pub_keys.end() && kit->second >= m_transfers.size(),
            error::wallet_internal_error, std::string("Unexpected transfer index from public key: ")
            + "got " + (kit == m_pub_keys.end() ? "<none>" : boost::lexical_cast<std::string>(kit->second))
            + ", m_transfers.size() is " + boost::lexical_cast<std::string>(m_transfers.size()));

        bool process_transaction = !pool || blink;
        bool unmined_blink       = pool && blink;
        if (kit == m_pub_keys.end())
        {
          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          if (process_transaction)
          {
            pk_to_unlock_times[tx_scan_info[o].in_ephemeral.pub] = tx_scan_info[o].unlock_time;

            m_transfers.emplace_back();
            transfer_details& td = m_transfers.back();
            td.m_block_height = height; // NB: will be zero for a blink; we update when the blink tx gets mined
            td.m_internal_output_index = o;
            td.m_global_output_index = unmined_blink ? 0 : o_indices[o]; // blink tx doesn't have this; will get updated when it gets into a block
            td.m_unmined_blink = unmined_blink;
            td.m_was_blink = blink;
            td.m_tx = (const cryptonote::transaction_prefix&)tx;
            td.m_txid = txid;
            td.m_key_image = tx_scan_info[o].ki;
            td.m_key_image_known = !m_watch_only && !m_multisig;
            if (!td.m_key_image_known)
            {
              // we might have cold signed, and have a mapping to key images
              std::unordered_map<crypto::public_key, crypto::key_image>::const_iterator i = m_cold_key_images.find(tx_scan_info[o].in_ephemeral.pub);
              if (i != m_cold_key_images.end())
              {
                td.m_key_image = i->second;
                td.m_key_image_known = true;
              }
            }
            if (m_watch_only)
            {
              // for view wallets, that flag means "we want to request it"
              td.m_key_image_request = true;
            }
            else
            {
              td.m_key_image_request = false;
            }
            td.m_key_image_partial = m_multisig;
            td.m_amount = amount;
            td.m_pk_index = pk_index - 1;
            td.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              td.m_mask = tx_scan_info[o].mask;
              td.m_rct = true;
            }
            else if (miner_tx && tx.version >= txversion::v2_ringct)
            {
              td.m_mask = rct::identity();
              td.m_rct = true;
            }
            else
            {
              td.m_mask = rct::identity();
              td.m_rct = false;
            }
            td.m_frozen = false;
	    set_unspent(m_transfers.size()-1);
            if (td.m_key_image_known)
              m_key_images[td.m_key_image] = m_transfers.size()-1;
            m_pub_keys[tx_scan_info[o].in_ephemeral.pub] = m_transfers.size()-1;
            if (output_tracker_cache)
              (*output_tracker_cache)[std::make_pair(tx.vout[o].amount, td.m_global_output_index)] = m_transfers.size() - 1;
            if (m_multisig)
            {
              THROW_WALLET_EXCEPTION_IF(!m_multisig_rescan_k && m_multisig_rescan_info,
                  error::wallet_internal_error, "NULL m_multisig_rescan_k");
              if (m_multisig_rescan_info && m_multisig_rescan_info->front().size() >= m_transfers.size())
                update_multisig_rescan_info(*m_multisig_rescan_k, *m_multisig_rescan_info, m_transfers.size() - 1);
            }
            LOG_PRINT_L0("Received money: " << print_money(td.amount()) << ", with tx: " << txid);
            if (0 != m_callback)
              m_callback->on_money_received(height, txid, tx, td.m_amount, td.m_subaddr_index, td.m_tx.unlock_time, blink);
          }
          total_received_1 += amount;
          notify = true;
          continue;
        }

        // NOTE: Pre-existing transfer already exists for the output
        auto &transfer = m_transfers[kit->second];
        THROW_WALLET_EXCEPTION_IF(blink && transfer.m_unmined_blink,
                                  error::wallet_internal_error,
                                  "Sanity check failed: A blink tx replacing an pre-existing wallet tx should not be possible; when a "
                                  "transaction is mined blink metadata is dropped and the TX should just be a normal TX");
        THROW_WALLET_EXCEPTION_IF(pool && transfer.m_unmined_blink,
                                  error::wallet_internal_error,
                                  "Sanity check failed: An output replacing a unmined blink output must not be from the pool.");

        if (transfer.m_spent || transfer.amount() >= tx_scan_info[o].amount)
        {
          if (transfer.amount() > tx_scan_info[o].amount)
          {
            LOG_ERROR("Public key " << tools::type_to_hex(kit->first)
                << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
                << (transfer.m_spent ? "spent" : "unspent") << " "
                << print_money(transfer.amount()) << " in tx " << transfer.m_txid << ", received output ignored");
          }

          if (transfer.m_unmined_blink)
          {
            earliest_blink_got_mined_transfers_index = std::min(earliest_blink_got_mined_transfers_index, static_cast<int64_t>(kit->second) /*index in m_transfers*/);
            THROW_WALLET_EXCEPTION_IF(transfer.amount() != tx_scan_info[o].amount, error::wallet_internal_error, "A blink should credit the amount exactly as we recorded it when it arrived in the mempool");
            THROW_WALLET_EXCEPTION_IF(transfer.m_spent, error::wallet_internal_error, "Blink can not be spent before it is mined, this should never happen");

            MINFO("Public key " << tools::type_to_hex(kit->first)
                << " of blink tx " << transfer.m_txid << " (for " << print_money(tx_scan_info[o].amount) << ")"
                << " status updated: now mined in block " << height);

            // We previous had this as a blink, but now it's been mined so update the tx status with the height and output index
            transfer.m_block_height = height;
            transfer.m_global_output_index = o_indices[o];
            transfer.m_unmined_blink = false;
          }

          auto iter = std::find_if(
              tx_money_got_in_outs.begin(),
              tx_money_got_in_outs.end(),
              [&tx_scan_info,&o](const tx_money_got_in_out& value)
              {
                return value.index == tx_scan_info[o].received->index &&
                  value.amount == tx_scan_info[o].amount &&
                  value.unlock_time == tx_scan_info[o].unlock_time;
              }
            );
          THROW_WALLET_EXCEPTION_IF(iter == tx_money_got_in_outs.end(), error::wallet_internal_error, "Could not find the output we just added, this should never happen");
          tx_money_got_in_outs.erase(iter);
        }
        else if (transfer.m_spent || transfer.amount() >= tx_scan_info[o].amount)
        {
          LOG_ERROR("Public key " << tools::type_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << (transfer.m_spent ? "spent" : "unspent") << " "
              << print_money(transfer.amount()) << " in tx " << transfer.m_txid << ", received output ignored");

          auto iter = std::find_if(
              tx_money_got_in_outs.begin(),
              tx_money_got_in_outs.end(),
              [&tx_scan_info,&o](const tx_money_got_in_out& value)
              {
                return value.index == tx_scan_info[o].received->index &&
                  value.amount == tx_scan_info[o].amount &&
                  value.unlock_time == tx_scan_info[o].unlock_time;
              }
            );

          THROW_WALLET_EXCEPTION_IF(iter == tx_money_got_in_outs.end(), error::wallet_internal_error, "Could not find the output we just added, this should never happen");
          tx_money_got_in_outs.erase(iter);
        }
        else
        {
          LOG_ERROR("Public key " << tools::type_to_hex(kit->first)
              << " from received " << print_money(tx_scan_info[o].amount) << " output already exists with "
              << print_money(transfer.amount()) << ", replacing with new output");

          // The new larger output replaced a previous smaller one
          auto unlock_time_it = pk_to_unlock_times.find(kit->first);
          if (unlock_time_it == pk_to_unlock_times.end())
          {
            // NOTE: This output previously existed in m_transfers before any
            // outputs in this transaction was processed, so we couldn't find.
            // That's fine, we don't need to modify tx_money_got_in_outs.
            //   - 27/09/2018 Doyle
          }
          else
          {
            tx_money_got_in_out smaller_output = {};
            smaller_output.unlock_time = unlock_time_it->second;
            smaller_output.amount = transfer.amount();
            smaller_output.index  = transfer.m_subaddr_index;

            auto iter = std::find_if(
                tx_money_got_in_outs.begin(),
                tx_money_got_in_outs.end(),
                [&smaller_output](const tx_money_got_in_out& value)
                {
                  return value.index == smaller_output.index &&
                    value.amount == smaller_output.amount &&
                    value.unlock_time == smaller_output.unlock_time;
                }
              );

            // Monero fix - 25/9/2018 rtharp, doyle, maxim
            THROW_WALLET_EXCEPTION_IF(transfer.amount() > iter->amount, error::wallet_internal_error, "Unexpected values of new and old outputs, new output is meant to be larger");
            THROW_WALLET_EXCEPTION_IF(iter == tx_money_got_in_outs.end(), error::wallet_internal_error, "Could not find the output we just added, this should never happen");
            tx_money_got_in_outs.erase(iter);

          }

          auto iter = std::find_if(
              tx_money_got_in_outs.begin(),
              tx_money_got_in_outs.end(),
              [&tx_scan_info, &o](const tx_money_got_in_out& value)
              {
                return value.index == tx_scan_info[o].received->index &&
                  value.amount == tx_scan_info[o].amount &&
                  value.unlock_time == tx_scan_info[o].unlock_time;
              }
            );
          THROW_WALLET_EXCEPTION_IF(transfer.amount() > iter->amount, error::wallet_internal_error, "Unexpected values of new and old outputs, new output is meant to be larger");
          THROW_WALLET_EXCEPTION_IF(iter == tx_money_got_in_outs.end(), error::wallet_internal_error, "Could not find the output we just added, this should never happen");
          iter->amount -= transfer.amount();

          if (iter->amount == 0)
            tx_money_got_in_outs.erase(iter);

          uint64_t amount = tx.vout[o].amount ? tx.vout[o].amount : tx_scan_info[o].amount;
          uint64_t extra_amount = amount - transfer.amount();
          if (process_transaction)
          {
            transfer.m_block_height = height;
            transfer.m_internal_output_index = o;
            transfer.m_global_output_index = unmined_blink ? 0 : o_indices[o]; // blink tx doesn't have this; will get updated when it gets into a block
            transfer.m_unmined_blink = unmined_blink;
            transfer.m_tx = (const cryptonote::transaction_prefix&)tx;
            transfer.m_txid = txid;
            transfer.m_amount = amount;
            transfer.m_pk_index = pk_index - 1;
            transfer.m_subaddr_index = tx_scan_info[o].received->index;
            if (should_expand(tx_scan_info[o].received->index))
              expand_subaddresses(tx_scan_info[o].received->index);
            if (tx.vout[o].amount == 0)
            {
              transfer.m_mask = tx_scan_info[o].mask;
              transfer.m_rct = true;
            }
            else if (miner_tx && tx.version >= txversion::v2_ringct)
            {
              transfer.m_mask = rct::identity();
              transfer.m_rct = true;
            }
            else
            {
              transfer.m_mask = rct::identity();
              transfer.m_rct = false;
            }
            if (output_tracker_cache)
              (*output_tracker_cache)[std::make_pair(tx.vout[o].amount, transfer.m_global_output_index)] = kit->second;
            if (m_multisig)
            {
              THROW_WALLET_EXCEPTION_IF(!m_multisig_rescan_k && m_multisig_rescan_info,
                  error::wallet_internal_error, "NULL m_multisig_rescan_k");
              if (m_multisig_rescan_info && m_multisig_rescan_info->front().size() >= m_transfers.size())
                update_multisig_rescan_info(*m_multisig_rescan_k, *m_multisig_rescan_info, m_transfers.size() - 1);
            }
            THROW_WALLET_EXCEPTION_IF(transfer.get_public_key() != tx_scan_info[o].in_ephemeral.pub, error::wallet_internal_error, "Inconsistent public keys");
            THROW_WALLET_EXCEPTION_IF(transfer.m_spent, error::wallet_internal_error, "Inconsistent spent status");

            LOG_PRINT_L0("Received money: " << print_money(transfer.amount()) << ", with tx: " << txid);
            if (0 != m_callback)
              m_callback->on_money_received(height, txid, tx, transfer.m_amount, transfer.m_subaddr_index, transfer.m_tx.unlock_time, blink);
          }
          total_received_1 += extra_amount;
          notify = true;
        }
      }
    }
  }

  uint64_t tx_money_spent_in_ins = 0;
  std::optional<uint32_t> subaddr_account;
  std::set<uint32_t> subaddr_indices;
  // check all outputs for spending (compare key images)
  for(auto& in: tx.vin)
  {
    if (!std::holds_alternative<cryptonote::txin_to_key>(in))
      continue;
    const cryptonote::txin_to_key &in_to_key = var::get<cryptonote::txin_to_key>(in);
    auto it = m_key_images.find(in_to_key.k_image);
    if(it != m_key_images.end())
    {
      transfer_details& td = m_transfers[it->second];
      uint64_t amount = in_to_key.amount;
      if (amount > 0)
      {
        if(amount != td.amount())
        {
          MERROR("Inconsistent amount in tx input: got " << print_money(amount) <<
            ", expected " << print_money(td.amount()));
          // this means:
          //   1) the same output pub key was used as destination multiple times,
          //   2) the wallet set the highest amount among them to transfer_details::m_amount, and
          //   3) the wallet somehow spent that output with an amount smaller than the above amount, causing inconsistency
          td.m_amount = amount;
        }
      }
      else
      {
        amount = td.amount();
      }
      tx_money_spent_in_ins += amount;
      if (subaddr_account && *subaddr_account != td.m_subaddr_index.major)
        LOG_ERROR("spent funds are from different subaddress accounts; count of incoming/outgoing payments will be incorrect");
      subaddr_account = td.m_subaddr_index.major;
      subaddr_indices.insert(td.m_subaddr_index.minor);
      if (!pool)
      {
        LOG_PRINT_L0("Spent money: " << print_money(amount) << ", with tx: " << txid);
        set_spent(it->second, height);
        if (0 != m_callback)
          m_callback->on_money_spent(height, txid, tx, amount, tx, td.m_subaddr_index);
      }
    }

    if (!pool && m_track_uses)
    {
      PERF_TIMER(track_uses);
      const uint64_t amount = in_to_key.amount;
      std::vector<uint64_t> offsets = cryptonote::relative_output_offsets_to_absolute(in_to_key.key_offsets);
      if (output_tracker_cache)
      {
        for (uint64_t offset: offsets)
        {
          const std::map<std::pair<uint64_t, uint64_t>, size_t>::const_iterator i = output_tracker_cache->find(std::make_pair(amount, offset));
          if (i != output_tracker_cache->end())
          {
            size_t idx = i->second;
            THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Output tracker cache index out of range");
            m_transfers[idx].m_uses.push_back(std::make_pair(height, txid));
          }
        }
      }
      else for (transfer_details &td: m_transfers)
      {
        if (amount != in_to_key.amount)
          continue;
        for (uint64_t offset: offsets)
          if (offset == td.m_global_output_index)
            td.m_uses.push_back(std::make_pair(height, txid));
      }
    }
  }

  uint64_t fee = miner_tx ? 0 : tx.version == txversion::v1 ? tx_money_spent_in_ins - get_outs_money_amount(tx) : tx.rct_signatures.txnFee;

  if (tx_money_spent_in_ins > 0 && !pool)
  {
    uint64_t self_received = std::accumulate<decltype(tx_money_got_in_outs.begin()), uint64_t>(tx_money_got_in_outs.begin(), tx_money_got_in_outs.end(), 0,
      [&subaddr_account] (uint64_t acc, const tx_money_got_in_out& p)
      {
        return acc + (p.index.major == *subaddr_account ? p.amount : 0);
      });
    process_outgoing(txid, tx, height, ts, tx_money_spent_in_ins, self_received, *subaddr_account, subaddr_indices);
    // if sending to yourself at the same subaddress account, set the outgoing payment amount to 0 so that it's less confusing
    if (tx_money_spent_in_ins == self_received + fee)
    {
      auto i = m_confirmed_txs.find(txid);
      THROW_WALLET_EXCEPTION_IF(i == m_confirmed_txs.end(), error::wallet_internal_error,
        "confirmed tx wasn't found: " + tools::type_to_hex(txid));
      i->second.m_change = self_received;
    }
  }

  // remove change sent to the spending subaddress account from the list of received funds
  uint64_t sub_change = 0;
  for (auto i = tx_money_got_in_outs.begin(); i != tx_money_got_in_outs.end();)
  {
    if (subaddr_account && i->index.major == *subaddr_account)
    {
      sub_change += i->amount;
      i = tx_money_got_in_outs.erase(i);
    }
    else
      ++i;
  }

  // create payment_details for each incoming transfer to a subaddress index
  crypto::hash payment_id = null_hash;
  if (tx_money_got_in_outs.size() > 0 || earliest_blink_got_mined_transfers_index != NO_BLINK_MINED_INDEX)
  {
    tx_extra_nonce extra_nonce;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      crypto::hash8 payment_id8 = null_hash8;
      if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
      {
        // We got a payment ID to go with this tx
        LOG_PRINT_L2("Found encrypted payment ID: " << payment_id8);
        MINFO("Consider using subaddresses instead of encrypted payment IDs");
        if (tx_pub_key != null_pkey)
        {
          if (!m_account.get_device().decrypt_payment_id(payment_id8, tx_pub_key, m_account.get_keys().m_view_secret_key))
          {
            LOG_PRINT_L0("Failed to decrypt payment ID: " << payment_id8);
          }
          else
          {
            LOG_PRINT_L2("Decrypted payment ID: " << payment_id8);
            // put the 64 bit decrypted payment id in the first 8 bytes
            memcpy(payment_id.data, payment_id8.data, 8);
            // rest is already 0, but guard against code changes above
            memset(payment_id.data + 8, 0, 24);
          }
        }
        else
        {
          LOG_PRINT_L1("No public key found in tx, unable to decrypt payment id");
        }
      }
      else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
      {
        bool ignore = block_version >= IGNORE_LONG_PAYMENT_ID_FROM_BLOCK_VERSION;
        if (ignore)
        {
          LOG_PRINT_L2("Found unencrypted payment ID in tx " << txid << " (ignored)");
          MWARNING("Found OBSOLETE AND IGNORED unencrypted payment ID: these are bad for privacy, use subaddresses instead");
          payment_id = crypto::null_hash;
        }
        else
        {
          LOG_PRINT_L2("Found unencrypted payment ID: " << payment_id);
          MWARNING("Found unencrypted payment ID: these are bad for privacy, consider using subaddresses instead");
        }
      }
    }
  }

  if (tx_money_got_in_outs.size() > 0)
  {
    uint64_t total_received_2 = sub_change;
    for (const auto& i : tx_money_got_in_outs)
      total_received_2 += i.amount;

    if (total_received_1 != total_received_2)
    {
      const el::Level level = el::Level::Warning;
      MCLOG_RED(level, "global", "**********************************************************************");
      MCLOG_RED(level, "global", "Consistency failure in amounts received");
      MCLOG_RED(level, "global", "Check transaction " << txid);
      MCLOG_RED(level, "global", "**********************************************************************");
      exit(1);
      return;
    }

    bool all_same = true;
    for (const auto& i : tx_money_got_in_outs)
    {
      payment_details payment;
      payment.m_tx_hash       = txid;
      payment.m_fee           = fee;
      payment.m_amount        = i.amount;
      payment.m_block_height  = height;
      payment.m_unlock_time   = i.unlock_time;
      payment.m_timestamp     = ts;
      payment.m_subaddr_index = i.index;
      payment.m_type          = i.type;
      payment.m_unmined_blink = pool && blink;
      payment.m_was_blink     = blink;
      if (pool && !blink) {
        if (emplace_or_replace(m_unconfirmed_payments, payment_id, pool_payment_details{payment, double_spend_seen}))
          all_same = false;
        if (0 != m_callback)
          m_callback->on_unconfirmed_money_received(height, txid, tx, payment.m_amount, payment.m_subaddr_index);
      }
      else
        m_payments.emplace(payment_id, payment);
      LOG_PRINT_L2("Payment found in " << (pool ? blink ? "blink pool" : "pool" : "block") << ": " << payment_id << " / " << payment.m_tx_hash << " / " << payment.m_amount);
    }

    // if it's a pool tx and we already had it, don't notify again
    if (pool && all_same)
      notify = false;
  }

  if (earliest_blink_got_mined_transfers_index != NO_BLINK_MINED_INDEX) {
    // If a blink tx that we already knew about moved from the mempool into a block then we have to
    // go back and fix up the heights in the payment_details because they'll have been set to 0 from
    // the initial blink.
    auto range = m_payments.equal_range(payment_id);
    for (auto it = range.first; it != range.second; ++it)
    {
      auto &pd = it->second;
      if (pd.m_tx_hash == txid && pd.m_unmined_blink)
      {
        pd.m_block_height = height;
        pd.m_unmined_blink = false;
      }
    }

    // All transfers from the earliest confirmed blink iterator needs to be
    // re-sorted since the blink was confirmed in the mempool and inserted
    // into our transfers container, but, it now has a output index assigned to
    // it, so it should be sorted via its real index. (Code that
    // uses m_transfers expects this)
    std::sort(m_transfers.begin() + earliest_blink_got_mined_transfers_index,
              m_transfers.end(),
              [](transfer_details const &a, transfer_details const &b) {
                return a.m_global_output_index < b.m_global_output_index;
              });

    // Update the weak indices the wallet holds into the transfers container
    size_t real_transfers_index = earliest_blink_got_mined_transfers_index;
    for (auto it = m_transfers.begin() + earliest_blink_got_mined_transfers_index;
         it != m_transfers.end();
         it++, real_transfers_index++)
    {
      m_key_images[it->m_key_image]    = real_transfers_index;
      m_pub_keys[it->get_public_key()] = real_transfers_index;
    }
  }

  if (notify)
  {
    std::shared_ptr<tools::Notify> tx_notify = m_tx_notify;
    if (tx_notify)
      tx_notify->notify("%s", tools::type_to_hex(txid).c_str(), NULL);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height)
{
  if (m_unconfirmed_txs.empty())
    return;

  auto unconf_it = m_unconfirmed_txs.find(txid);
  if(unconf_it != m_unconfirmed_txs.end()) {
    if (store_tx_info()) {
      try {
        m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details(unconf_it->second, height)));
      }
      catch (...) {
        // can fail if the tx has unexpected input types
        LOG_PRINT_L0("Failed to add outgoing transaction to confirmed transaction map");
      }
    }
    m_unconfirmed_txs.erase(unconf_it);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_outgoing(const crypto::hash &txid, const cryptonote::transaction &tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  std::pair<std::unordered_map<crypto::hash, confirmed_transfer_details>::iterator, bool> entry = m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details()));
  // fill with the info we know, some info might already be there
  if (entry.second)
  {
    // this case will happen if the tx is from our outputs, but was sent by another
    // wallet (eg, we're a cold wallet and the hot wallet sent it). For RCT transactions,
    // we only see 0 input amounts, so have to deduce amount out from other parameters.
    entry.first->second.m_amount_in = spent;
    if (tx.version == txversion::v1)
      entry.first->second.m_amount_out = get_outs_money_amount(tx);
    else
      entry.first->second.m_amount_out = spent - tx.rct_signatures.txnFee;
    entry.first->second.m_change = received;

    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx.extra, tx_extra_fields); // ok if partially parsed
    tx_extra_nonce extra_nonce;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
    {
      // we do not care about failure here
      get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, entry.first->second.m_payment_id);
    }
    entry.first->second.m_subaddr_account = subaddr_account;
    entry.first->second.m_subaddr_indices = subaddr_indices;
    entry.first->second.m_pay_type = wallet::pay_type_from_tx(tx);
  }

  entry.first->second.m_rings.clear();
  for (const auto &in: tx.vin)
  {
    if (!std::holds_alternative<cryptonote::txin_to_key>(in))
      continue;
    const auto &txin = var::get<cryptonote::txin_to_key>(in);
    entry.first->second.m_rings.push_back(std::make_pair(txin.k_image, txin.key_offsets));
  }
  entry.first->second.m_block_height = height;
  entry.first->second.m_timestamp = ts;
  entry.first->second.m_unlock_time = tx.unlock_time;
  entry.first->second.m_unlock_times = tx.output_unlock_times;

  add_rings(tx);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::should_skip_block(const cryptonote::block &b, uint64_t height) const
{
  // seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  return !(b.timestamp + 60*60*24 > m_account.get_createtime() && height >= m_refresh_from_block_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &parsed_block, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  THROW_WALLET_EXCEPTION_IF(bche.txs.size() + 1 != parsed_block.o_indices.indices.size(), error::wallet_internal_error,
      "block transactions=" + std::to_string(bche.txs.size()) +
      " not match with daemon response size=" + std::to_string(parsed_block.o_indices.indices.size()));

  //handle transactions from new block

  //optimization: seeking only for blocks that are not older then the wallet creation time plus 1 day. 1 day is for possible user incorrect time setup
  if (!should_skip_block(b, height))
  {
    TIME_MEASURE_START(miner_tx_handle_time);
    if (m_refresh_type != RefreshNoCoinbase)
      process_new_transaction(get_transaction_hash(b.miner_tx), b.miner_tx, parsed_block.o_indices.indices[0].indices, height, b.major_version, b.timestamp, true, false, false, false, tx_cache_data[tx_cache_data_offset], output_tracker_cache);
    ++tx_cache_data_offset;
    TIME_MEASURE_FINISH(miner_tx_handle_time);

    TIME_MEASURE_START(txs_handle_time);
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != b.tx_hashes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    THROW_WALLET_EXCEPTION_IF(bche.txs.size() != parsed_block.txes.size(), error::wallet_internal_error, "Wrong amount of transactions for block");
    for (size_t idx = 0; idx < b.tx_hashes.size(); ++idx)
    {
      process_new_transaction(b.tx_hashes[idx], parsed_block.txes[idx], parsed_block.o_indices.indices[idx+1].indices, height, b.major_version, b.timestamp, false, false, false, false, tx_cache_data[tx_cache_data_offset++], output_tracker_cache);
    }
    TIME_MEASURE_FINISH(txs_handle_time);
    m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);

    if (height > 0 && ((height % 2000) == 0))
      LOG_PRINT_L0("Blockchain sync progress: " << bl_id << ", height " << height);

    LOG_PRINT_L2("Processed block: " << bl_id << ", height " << height << ", " <<  miner_tx_handle_time + txs_handle_time << "(" << miner_tx_handle_time << "/" << txs_handle_time <<")ms");
  }else
  {
    if (!(height % 128))
      LOG_PRINT_L2( "Skipped block by timestamp, height: " << height << ", block time " << b.timestamp << ", account time " << m_account.get_createtime());
  }
  m_blockchain.push_back(bl_id);

  if (0 != m_callback)
    m_callback->on_new_block(height, b);
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_short_chain_history(std::list<crypto::hash>& ids, uint64_t granularity) const
{
  size_t i = 0;
  size_t current_multiplier = 1;
  size_t blockchain_size = std::max((size_t)(m_blockchain.size() / granularity * granularity), m_blockchain.offset());
  size_t sz = blockchain_size - m_blockchain.offset();
  if(!sz)
  {
    ids.push_back(m_blockchain.genesis());
    return;
  }
  size_t current_back_offset = 1;
  bool base_included = false;
  while(current_back_offset < sz)
  {
    ids.push_back(m_blockchain[m_blockchain.offset() + sz-current_back_offset]);
    if(sz-current_back_offset == 0)
      base_included = true;
    if(i < 10)
    {
      ++current_back_offset;
    }else
    {
      current_back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!base_included)
    ids.push_back(m_blockchain[m_blockchain.offset()]);
  if(m_blockchain.offset())
    ids.push_back(m_blockchain.genesis());
}
//----------------------------------------------------------------------------------------------------
void wallet2::parse_block_round(const cryptonote::blobdata &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const
{
  error = !cryptonote::parse_and_validate_block_from_blob(blob, bl, bl_id);
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_blocks(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::rpc::GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t &current_height)
{
  cryptonote::rpc::GET_BLOCKS_FAST::request req{};
  cryptonote::rpc::GET_BLOCKS_FAST::response res{};
  req.block_ids = short_chain_history;

  MDEBUG("Pulling blocks: start_height " << start_height);

  req.prune = true;
  req.start_height = start_height;
  req.no_miner_tx = m_refresh_type == RefreshNoCoinbase;
  bool r = invoke_http<rpc::GET_BLOCKS_FAST>(req, res);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "getblocks.bin");
  THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "getblocks.bin");
  THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::get_blocks_error, get_rpc_status(res.status));
  THROW_WALLET_EXCEPTION_IF(res.blocks.size() != res.output_indices.size(), error::wallet_internal_error,
      "mismatched blocks (" + boost::lexical_cast<std::string>(res.blocks.size()) + ") and output_indices (" +
      boost::lexical_cast<std::string>(res.output_indices.size()) + ") sizes from daemon");

  blocks_start_height = res.start_height;
  blocks = std::move(res.blocks);
  o_indices = std::move(res.output_indices);
  current_height = res.current_height;

  MDEBUG("Pulled blocks: blocks_start_height " << blocks_start_height << ", count " << blocks.size()
      << ", height " << blocks_start_height + blocks.size() << ", node height " << res.current_height);
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_hashes(uint64_t start_height, uint64_t &blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes)
{
  cryptonote::rpc::GET_HASHES_FAST::request req{};
  cryptonote::rpc::GET_HASHES_FAST::response res{};
  req.block_ids = short_chain_history;

  req.start_height = start_height;
  bool r = invoke_http<rpc::GET_HASHES_FAST>(req, res);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "gethashes.bin");
  THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "gethashes.bin");
  THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::get_hashes_error, get_rpc_status(res.status));

  blocks_start_height = res.start_height;
  hashes = std::move(res.m_block_ids);
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  size_t current_index = start_height;
  blocks_added = 0;

  THROW_WALLET_EXCEPTION_IF(blocks.size() != parsed_blocks.size(), error::wallet_internal_error, "size mismatch");
  THROW_WALLET_EXCEPTION_IF(!m_blockchain.is_in_bounds(current_index), error::out_of_hashchain_bounds_error);

  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;

  size_t num_txes = 0;
  std::vector<tx_cache_data> tx_cache_data;
  for (size_t i = 0; i < blocks.size(); ++i)
    num_txes += 1 + parsed_blocks[i].txes.size();
  tx_cache_data.resize(num_txes);
  size_t txidx = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    THROW_WALLET_EXCEPTION_IF(parsed_blocks[i].txes.size() != parsed_blocks[i].block.tx_hashes.size(),
        error::wallet_internal_error, "Mismatched parsed_blocks[i].txes.size() and parsed_blocks[i].block.tx_hashes.size()");
    if (should_skip_block(parsed_blocks[i].block, start_height + i))
    {
      txidx += 1 + parsed_blocks[i].block.tx_hashes.size();
      continue;
    }
    if (m_refresh_type != RefreshNoCoinbase)
      tpool.submit(&waiter, [&, i, txidx](){ cache_tx_data(parsed_blocks[i].block.miner_tx, get_transaction_hash(parsed_blocks[i].block.miner_tx), tx_cache_data[txidx]); });
    ++txidx;
    for (size_t idx = 0; idx < parsed_blocks[i].txes.size(); ++idx)
    {
      tpool.submit(&waiter, [&, i, idx, txidx](){ cache_tx_data(parsed_blocks[i].txes[idx], parsed_blocks[i].block.tx_hashes[idx], tx_cache_data[txidx]); });
      ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != num_txes, error::wallet_internal_error, "txidx does not match tx_cache_data size");
  waiter.wait(&tpool);

  hw::device &hwdev =  m_account.get_device();
  hw::mode_resetter rst{hwdev};
  hwdev.set_mode(hw::device::TRANSACTION_PARSE);
  const cryptonote::account_keys &keys = m_account.get_keys();

  auto gender = [&](wallet2::is_out_data &iod) {
    if (!hwdev.generate_key_derivation(iod.pkey, keys.m_view_secret_key, iod.derivation))
    {
      MWARNING("Failed to generate key derivation from tx pubkey, skipping");
      static_assert(sizeof(iod.derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&iod.derivation, rct::identity().bytes, sizeof(iod.derivation));
    }
  };

  for (size_t i = 0; i < tx_cache_data.size(); ++i)
  {
    if (tx_cache_data[i].empty())
      continue;
    tpool.submit(&waiter, [&hwdev, &gender, &tx_cache_data, i]() {
      auto &slot = tx_cache_data[i];
      std::unique_lock hwdev_lock{hwdev};
      for (auto &iod: slot.primary)
        gender(iod);
      for (auto &iod: slot.additional)
        gender(iod);
    }, true);
  }
  waiter.wait(&tpool);

  auto geniod = [&](const cryptonote::transaction &tx, size_t n_vouts, size_t txidx) {
    for (size_t k = 0; k < n_vouts; ++k)
    {
      const auto &o = tx.vout[k];
      if (std::holds_alternative<cryptonote::txout_to_key>(o.target))
      {
        std::vector<crypto::key_derivation> additional_derivations;
        additional_derivations.reserve(tx_cache_data[txidx].additional.size());
        for (const auto &iod: tx_cache_data[txidx].additional)
          additional_derivations.push_back(iod.derivation);
        const auto &key = var::get<txout_to_key>(o.target).key;
        for (size_t l = 0; l < tx_cache_data[txidx].primary.size(); ++l)
        {
          THROW_WALLET_EXCEPTION_IF(tx_cache_data[txidx].primary[l].received.size() != n_vouts,
              error::wallet_internal_error, "Unexpected received array size");
          tx_cache_data[txidx].primary[l].received[k] = is_out_to_acc_precomp(m_subaddresses, key, tx_cache_data[txidx].primary[l].derivation, additional_derivations, k, hwdev);
          additional_derivations.clear();
        }
      }
    }
  };

  txidx = 0;
  for (size_t i = 0; i < parsed_blocks.size(); ++i)
  {
    cryptonote::block blk = parsed_blocks[i].block;

    if (should_skip_block(parsed_blocks[i].block, start_height + i))
    {
      txidx += 1 + parsed_blocks[i].block.tx_hashes.size();
      continue;
    }

    if (m_refresh_type != RefreshType::RefreshNoCoinbase && parsed_blocks[i].block.miner_tx.vout.size() > 0)
    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      const size_t n_vouts = m_refresh_type == RefreshType::RefreshOptimizeCoinbase ? 1 : parsed_blocks[i].block.miner_tx.vout.size();
      tpool.submit(&waiter, [&, i, n_vouts, txidx](){ geniod(parsed_blocks[i].block.miner_tx, n_vouts, txidx); }, true);
    }
    ++txidx;
    for (size_t j = 0; j < parsed_blocks[i].txes.size(); ++j)
    {
      THROW_WALLET_EXCEPTION_IF(txidx >= tx_cache_data.size(), error::wallet_internal_error, "txidx out of range");
      tpool.submit(&waiter, [&, i, j, txidx](){ geniod(parsed_blocks[i].txes[j], parsed_blocks[i].txes[j].vout.size(), txidx); }, true);
    ++txidx;
    }
  }
  THROW_WALLET_EXCEPTION_IF(txidx != tx_cache_data.size(), error::wallet_internal_error, "txidx did not reach expected value");
  waiter.wait(&tpool);
  hwdev.set_mode(hw::device::NONE);

  size_t tx_cache_data_offset = 0;
  for (size_t i = 0; i < blocks.size(); ++i)
  {
    const crypto::hash &bl_id = parsed_blocks[i].hash;
    const cryptonote::block &bl = parsed_blocks[i].block;

    if(current_index >= m_blockchain.size())
    {
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index, tx_cache_data, tx_cache_data_offset, output_tracker_cache);
      ++blocks_added;
    }
    else if(bl_id != m_blockchain[current_index])
    {
      //split detected here !!!
      THROW_WALLET_EXCEPTION_IF(current_index == start_height, error::wallet_internal_error,
        "wrong daemon response: split starts from the first block in response " + tools::type_to_hex(bl_id) +
        " (height " + std::to_string(start_height) + "), local block id at this height: " +
        tools::type_to_hex(m_blockchain[current_index]));

      detach_blockchain(current_index, output_tracker_cache);
      process_new_blockchain_entry(bl, blocks[i], parsed_blocks[i], bl_id, current_index, tx_cache_data, tx_cache_data_offset, output_tracker_cache);
    }
    else
    {
      LOG_PRINT_L2("Block is already in blockchain: " << tools::type_to_hex(bl_id));
    }
    ++current_index;
    tx_cache_data_offset += 1 + parsed_blocks[i].txes.size();
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon)
{
  uint64_t blocks_fetched = 0;
  refresh(trusted_daemon, 0, blocks_fetched);
}
//----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched)
{
  bool received_money = false;
  refresh(trusted_daemon, start_height, blocks_fetched, received_money);
}
//----------------------------------------------------------------------------------------------------
void wallet2::pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &last, bool &error, std::exception_ptr &exception)
{
  error = false;
  last = false;
  exception = NULL;

  try
  {
    drop_from_short_history(short_chain_history, 3);

    THROW_WALLET_EXCEPTION_IF(prev_blocks.size() != prev_parsed_blocks.size(), error::wallet_internal_error, "size mismatch");

    // prepend the last 3 blocks, should be enough to guard against a block or two's reorg
    auto s = std::next(prev_parsed_blocks.rbegin(), std::min((size_t)3, prev_parsed_blocks.size())).base();
    for (; s != prev_parsed_blocks.end(); ++s)
    {
      short_chain_history.push_front(s->hash);
    }

    // pull the new blocks
    std::vector<cryptonote::rpc::GET_BLOCKS_FAST::block_output_indices> o_indices;
    uint64_t current_height;
    pull_blocks(start_height, blocks_start_height, short_chain_history, blocks, o_indices, current_height);
    THROW_WALLET_EXCEPTION_IF(blocks.size() != o_indices.size(), error::wallet_internal_error, "Mismatched sizes of blocks and o_indices");

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter;
    parsed_blocks.resize(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i)
      tpool.submit(&waiter,
              [&, i] { return parse_block_round(blocks[i].block, parsed_blocks[i].block, parsed_blocks[i].hash, parsed_blocks[i].error); },
              true);
    waiter.wait(&tpool);
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      if (parsed_blocks[i].error)
      {
        error = true;
        break;
      }
      parsed_blocks[i].o_indices = std::move(o_indices[i]);
    }

    std::mutex error_lock;
    for (size_t i = 0; i < blocks.size(); ++i)
    {
      parsed_blocks[i].txes.resize(blocks[i].txs.size());
      for (size_t j = 0; j < blocks[i].txs.size(); ++j)
      {
        tpool.submit(&waiter, [&, i, j](){
          if (!parse_and_validate_tx_base_from_blob(blocks[i].txs[j], parsed_blocks[i].txes[j]))
          {
            std::lock_guard lock{error_lock};
            error = true;
          }
        }, true);
      }
    }
    waiter.wait(&tpool);
    last = !blocks.empty() && cryptonote::get_block_height(parsed_blocks.back().block) + 1 == current_height;
  }
  catch(...)
  {
    error = true;
  }
}

void wallet2::remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes)
{
  // remove pool txes to us that aren't in the pool anymore
  std::unordered_multimap<crypto::hash, wallet2::pool_payment_details>::iterator uit = m_unconfirmed_payments.begin();
  while (uit != m_unconfirmed_payments.end())
  {
    const crypto::hash &txid = uit->second.m_pd.m_tx_hash;
    bool found = false;
    for (const auto &it2: tx_hashes)
    {
      if (it2 == txid)
      {
        found = true;
        break;
      }
    }
    auto pit = uit++;
    if (!found)
    {
      MDEBUG("Removing " << txid << " from unconfirmed payments, not found in pool");
      m_unconfirmed_payments.erase(pit);
      if (0 != m_callback)
        m_callback->on_pool_tx_removed(txid);
    }
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::long_poll_pool_state()
{
  // How long we sleep (and thus prevent retrying the connection) if we get an error
  const auto error_sleep = m_long_poll_local ? 500ms : 3s;
  // How long we wait for a long poll response before timing out; we add a 5s buffer to the usual
  // timeout to allow for network latency and oxend response time.
  m_long_poll_client.set_timeout(cryptonote::rpc::GET_TRANSACTION_POOL_HASHES_BIN::long_poll_timeout + 5s);

  using namespace cryptonote::rpc;

  GET_TRANSACTION_POOL_HASHES_BIN::request req  = {};
  req.long_poll        = true;
  req.tx_pool_checksum = get_long_poll_tx_pool_checksum();

  GET_TRANSACTION_POOL_HASHES_BIN::response res;
  try {
    res = m_long_poll_client.binary<GET_TRANSACTION_POOL_HASHES_BIN>(GET_TRANSACTION_POOL_HASHES_BIN::names()[0], req);
  } catch (const std::exception& e) {
    if (m_long_poll_disabled)
      MDEBUG("Long poll request cancelled");
    else
    {
      MWARNING("Long poll request failed: " << e.what());
      std::this_thread::sleep_for(error_sleep);
    }
    throw;
  }

  if (res.status == rpc::STATUS_TX_LONG_POLL_TIMED_OUT)
  {
    MINFO("Long poll replied with no pool change");
    return false;
  }

  THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "get_transaction_pool_hashes.bin");
  THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::get_tx_pool_error, res.status);

  crypto::hash checksum = crypto::null_hash;
  for (crypto::hash const &hash : res.tx_hashes)
    checksum ^= hash;
  {
    std::lock_guard lock{m_long_poll_tx_pool_checksum_mutex};
    m_long_poll_tx_pool_checksum = checksum;
  }

  return checksum != crypto::null_hash;
}

void wallet2::cancel_long_poll()
{
  m_long_poll_disabled = true;
  m_long_poll_client.cancel();
}

// Requests transactions transactions; throws a wallet exception on error.
rpc::GET_TRANSACTIONS::response wallet2::request_transactions(std::vector<std::string> txids_hex)
{
  rpc::GET_TRANSACTIONS::request req{};
  req.txs_hashes = std::move(txids_hex);
  req.decode_as_json = false;
  req.prune = true;

  rpc::GET_TRANSACTIONS::response res{};
  bool ok = invoke_http<rpc::GET_TRANSACTIONS>(req, res);

  THROW_WALLET_EXCEPTION_IF(!ok, error::no_connection_to_daemon, "Failed to get transaction(s) from daemon: HTTP request failed");
  THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "Failed to get transaction(s) from daemon: daemon busy");
  THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::wallet_internal_error, "Failed to get transaction(s) from daemon: daemon returned " + get_rpc_status(res.status));
  THROW_WALLET_EXCEPTION_IF(res.txs.size() != req.txs_hashes.size(), error::wallet_internal_error, "Failed to get transaction(s) from daemon: expected " + std::to_string(req.txs_hashes.size()) + " txes, got " + std::to_string(res.txs.size()));

  return res;
}

template <typename It, std::enable_if_t<std::is_same_v<crypto::hash, std::remove_const_t<typename It::value_type>>, int> = 0>
static std::vector<std::string> hashes_to_hex(It begin, It end)
{
  std::vector<std::string> hexes;
  if constexpr (std::is_base_of_v<std::random_access_iterator_tag, typename std::iterator_traits<It>::iterator_category>)
    hexes.reserve(std::distance(begin, end));
  while (begin != end)
    hexes.push_back(tools::type_to_hex(*begin++));
  return hexes;
}

rpc::GET_TRANSACTIONS::response wallet2::request_transactions(const std::vector<crypto::hash>& txids)
{
  return request_transactions(hashes_to_hex(txids.begin(), txids.end()));
}


//----------------------------------------------------------------------------------------------------
std::vector<wallet2::get_pool_state_tx> wallet2::get_pool_state(bool refreshed)
{
  std::vector<wallet2::get_pool_state_tx> process_txs;
  MTRACE("get_pool_state: take hashes from cache");
  std::vector<crypto::hash> blink_hashes, pool_hashes;
  {
    // We make two requests here: one for all pool txes, and then (assuming there are any) a second
    // one for blink txes.
    cryptonote::rpc::GET_TRANSACTION_POOL_HASHES_BIN::request req{};
    cryptonote::rpc::GET_TRANSACTION_POOL_HASHES_BIN::response res{};
    bool r = invoke_http<rpc::GET_TRANSACTION_POOL_HASHES_BIN>(req, res);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_transaction_pool_hashes.bin");
    THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "get_transaction_pool_hashes.bin");
    THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::get_tx_pool_error);
    MTRACE("get_pool_state got full pool");
    pool_hashes = std::move(res.tx_hashes);

    // NOTE: Only request blinked transactions, normal transactions will appear
    // in the wallet when it arrives in a block. This is to prevent pulling down
    // TX's that are awaiting blink approval being cached in the wallet as
    // non-blink and external applications failing to respect this.
    req.blinked_txs_only = true;
    res = {};
    r = invoke_http<rpc::GET_TRANSACTION_POOL_HASHES_BIN>(req, res);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_transaction_pool_hashes.bin");
    THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "get_transaction_pool_hashes.bin");
    THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::get_tx_pool_error);
    MTRACE("get_pool_state got blinks");
    blink_hashes = std::move(res.tx_hashes);
  }

  OXEN_DEFER {
    if (m_encrypt_keys_after_refresh)
    {
      encrypt_keys(*m_encrypt_keys_after_refresh);
      m_encrypt_keys_after_refresh = std::nullopt;
    }
  };

  // remove any pending tx that's not in the pool
  std::unordered_map<crypto::hash, wallet2::unconfirmed_transfer_details>::iterator it = m_unconfirmed_txs.begin();
  while (it != m_unconfirmed_txs.end())
  {
    const crypto::hash &txid = it->first;
    bool found = std::find(pool_hashes.begin(), pool_hashes.end(), txid) != pool_hashes.end();
    auto pit = it++;
    if (!found)
    {
      // we want to avoid a false positive when we ask for the pool just after
      // a tx is removed from the pool due to being found in a new block, but
      // just before the block is visible by refresh. So we keep a boolean, so
      // that the first time we don't see the tx, we set that boolean, and only
      // delete it the second time it is checked (but only when refreshed, so
      // we're sure we've seen the blockchain state first)
      if (pit->second.m_state == wallet2::unconfirmed_transfer_details::pending)
      {
        LOG_PRINT_L1("Pending txid " << txid << " not in pool, marking as not in pool");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::pending_not_in_pool;
      }
      else if (pit->second.m_state == wallet2::unconfirmed_transfer_details::pending_not_in_pool && refreshed)
      {
        LOG_PRINT_L1("Pending txid " << txid << " not in pool, marking as failed");
        pit->second.m_state = wallet2::unconfirmed_transfer_details::failed;

        // the inputs aren't spent anymore, since the tx failed
        for (size_t vini = 0; vini < pit->second.m_tx.vin.size(); ++vini)
        {
          if (std::holds_alternative<txin_to_key>(pit->second.m_tx.vin[vini]))
          {
            txin_to_key &tx_in_to_key = var::get<txin_to_key>(pit->second.m_tx.vin[vini]);
            for (size_t i = 0; i < m_transfers.size(); ++i)
            {
              const transfer_details &td = m_transfers[i];
              if (td.m_key_image == tx_in_to_key.k_image)
              {
                 LOG_PRINT_L1("Resetting spent status for output " << vini << ": " << td.m_key_image);
                 set_unspent(i);
                 break;
              }
            }
          }
        }
      }
    }
  }
  MTRACE("get_pool_state done first loop");

  // remove pool txes to us that aren't in the pool anymore
  // but only if we just refreshed, so that the tx can go in
  // the in transfers list instead (or nowhere if it just
  // disappeared without being mined)
  if (refreshed)
    remove_obsolete_pool_txs(pool_hashes);

  MTRACE("get_pool_state done second loop");

  // gather txids of new blink txes to us. We just ignore non-blinks here (we pick them up when they
  // get mined into a block).
  std::vector<std::pair<crypto::hash, bool>> txids;
  for (const auto &txid: blink_hashes)
  {
    bool txid_found_in_up = false;
    for (const auto &up: m_unconfirmed_payments)
    {
      if (up.second.m_pd.m_tx_hash == txid)
      {
        txid_found_in_up = true;
        break;
      }
    }
    if (m_scanned_pool_txs[0].find(txid) != m_scanned_pool_txs[0].end() || m_scanned_pool_txs[1].find(txid) != m_scanned_pool_txs[1].end())
    {
      // if it's for us, we want to keep track of whether we saw a double spend, so don't bail out
      if (!txid_found_in_up)
      {
        LOG_PRINT_L2("Already seen " << txid << ", and not for us, skipped");
        continue;
      }
    }
    if (!txid_found_in_up)
    {
      LOG_PRINT_L1("Found new pool tx: " << txid);
      bool found = false;
      for (const auto &i: m_unconfirmed_txs)
      {
        if (i.first == txid)
        {
          found = true;
          // if this is a payment to yourself at a different subaddress account, don't skip it
          // so that you can see the incoming pool tx with 'show_transfers' on that receiving subaddress account
          const unconfirmed_transfer_details& utd = i.second;
          for (const auto& dst : utd.m_dests)
          {
            auto subaddr_index = m_subaddresses.find(dst.addr.m_spend_public_key);
            if (subaddr_index != m_subaddresses.end() && subaddr_index->second.major != utd.m_subaddr_account)
            {
              found = false;
              break;
            }
          }
          break;
        }
      }
      if (!found)
      {
        // not one of those we sent ourselves
        txids.push_back({txid, false});
      }
      else
      {
        LOG_PRINT_L1("We sent that one");
      }
    }
  }

  // get those txes
  if (!txids.empty())
  {
    cryptonote::rpc::GET_TRANSACTIONS::response res;
    std::vector<std::string> hex_hashes;
    hex_hashes.reserve(txids.size());
    for (const auto &p: txids)
      hex_hashes.push_back(tools::type_to_hex(p.first));

    try {
      res = request_transactions(std::move(hex_hashes));
    } catch (const std::exception& e) {
      LOG_PRINT_L0("Failed to retrieve transactions: " << e.what());
      return process_txs;
    }
    for (const auto &tx_entry: res.txs)
    {
      if (tx_entry.in_pool)
      {
        cryptonote::transaction tx;
        cryptonote::blobdata bd;
        crypto::hash tx_hash;

        if (get_pruned_tx(tx_entry, tx, tx_hash))
        {
            auto i = std::find_if(txids.begin(), txids.end(),
                [tx_hash](const std::pair<crypto::hash, bool> &e) { return e.first == tx_hash; });
            if (i != txids.end())
            {
              process_txs.push_back({std::move(tx), tx_hash, tx_entry.double_spend_seen, tx_entry.blink});
            }
            else
            {
              MERROR("Got txid " << tx_hash << " which we did not ask for");
            }
        }
        else
        {
          LOG_PRINT_L0("Failed to parse transaction from daemon");
        }
      }
      else
      {
        LOG_PRINT_L1("Transaction from daemon was in pool, but is no more");
      }
    }
  }
  MTRACE("get_pool_state end");
  return process_txs;
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_pool_state(const std::vector<get_pool_state_tx> &txs)
{
  const time_t now = time(NULL);
  for (const auto &e: txs)
  {
    process_new_transaction(e.tx_hash, e.tx, std::vector<uint64_t>(), 0, 0, now, false, true, e.blink, e.double_spend_seen, {});
    m_scanned_pool_txs[0].insert(e.tx_hash);
    if (m_scanned_pool_txs[0].size() > 5000)
    {
      std::swap(m_scanned_pool_txs[0], m_scanned_pool_txs[1]);
      m_scanned_pool_txs[0].clear();
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force)
{
  std::vector<crypto::hash> hashes;

  uint64_t checkpoint_height          = 0;
  crypto::hash checkpoint_hash        = cryptonote::get_newest_hardcoded_checkpoint(nettype(), &checkpoint_height);
  if ((stop_height > checkpoint_height && m_blockchain.size()-1 < checkpoint_height) && !force)
  {
    // we will drop all these, so don't bother getting them
    uint64_t missing_blocks = checkpoint_height - m_blockchain.size();
    while (missing_blocks-- > 0)
      m_blockchain.push_back(crypto::null_hash); // maybe a bit suboptimal, but deque won't do huge reallocs like vector
    m_blockchain.push_back(checkpoint_hash);
    m_blockchain.trim(checkpoint_height);
    short_chain_history.clear();
    get_short_chain_history(short_chain_history);
  }

  size_t current_index = m_blockchain.size();
  while(m_run.load(std::memory_order_relaxed) && current_index < stop_height)
  {
    pull_hashes(0, blocks_start_height, short_chain_history, hashes);
    if (hashes.size() <= 3)
      return;
    if (blocks_start_height < m_blockchain.offset())
    {
      MERROR("Blocks start before blockchain offset: " << blocks_start_height << " " << m_blockchain.offset());
      return;
    }
    current_index = blocks_start_height;
    if (hashes.size() + current_index < stop_height) {
      drop_from_short_history(short_chain_history, 3);
      std::vector<crypto::hash>::iterator right = hashes.end();
      // prepend 3 more
      for (int i = 0; i<3; i++) {
        right--;
        short_chain_history.push_front(*right);
      }
    }
    for(auto& bl_id: hashes)
    {
      if(current_index >= m_blockchain.size())
      {
        if (!(current_index % 1024))
          LOG_PRINT_L2( "Skipped block by height: " << current_index);
        m_blockchain.push_back(bl_id);

        if (0 != m_callback)
        { // FIXME: this isn't right, but simplewallet just logs that we got a block.
          cryptonote::block dummy;
          m_callback->on_new_block(current_index, dummy);
        }
      }
      else if(bl_id != m_blockchain[current_index])
      {
        //split detected here !!!
        return;
      }
      ++current_index;
      if (current_index >= stop_height)
        return;
    }
  }
}


bool wallet2::add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress)
{
  wallet2::address_book_row a;
  a.m_address = address;
  a.m_has_payment_id = !!payment_id;
  a.m_payment_id = payment_id ? *payment_id : crypto::null_hash8;
  a.m_description = description;
  a.m_is_subaddress = is_subaddress;

  auto old_size = m_address_book.size();
  m_address_book.push_back(a);
  if(m_address_book.size() == old_size+1)
    return true;
  return false;
}

bool wallet2::set_address_book_row(size_t row_id, const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress)
{
  wallet2::address_book_row a;
  a.m_address = address;
  a.m_has_payment_id = !!payment_id;
  a.m_payment_id = payment_id ? *payment_id : crypto::null_hash8;
  a.m_description = description;
  a.m_is_subaddress = is_subaddress;

  const auto size = m_address_book.size();
  if (row_id >= size)
    return false;
  m_address_book[row_id] = a;
  return true;
}

bool wallet2::delete_address_book_row(std::size_t row_id) {
  if(m_address_book.size() <= row_id)
    return false;

  m_address_book.erase(m_address_book.begin()+row_id);

  return true;
}

//----------------------------------------------------------------------------------------------------
std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> wallet2::create_output_tracker_cache() const
{
  std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> cache{new std::map<std::pair<uint64_t, uint64_t>, size_t>()};
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[i];
    (*cache)[std::make_pair(td.is_rct() ? 0 : td.amount(), td.m_global_output_index)] = i;
  }
  return cache;
}

//----------------------------------------------------------------------------------------------------
void wallet2::refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool)
{
  if (m_offline)
  {
    blocks_fetched = 0;
    received_money = 0;
    return;
  }

  if(m_light_wallet) {

    // MyMonero get_address_info needs to be called occasionally to trigger wallet sync.
    // This call is not really needed for other purposes and can be removed if mymonero changes their backend.
    light_rpc::GET_ADDRESS_INFO::response res{};

    // Get basic info
    if(light_wallet_get_address_info(res)) {
      // Last stored block height
      uint64_t prev_height = m_light_wallet_blockchain_height;
      // Update lw heights
      m_light_wallet_scanned_block_height = res.scanned_block_height;
      m_light_wallet_blockchain_height = res.blockchain_height;
      // If new height - call new_block callback
      if(m_light_wallet_blockchain_height != prev_height)
      {
        MDEBUG("new block since last time!");
        m_callback->on_lw_new_block(m_light_wallet_blockchain_height - 1);
      }
      m_light_wallet_connected = true;
      MDEBUG("lw scanned block height: " <<  m_light_wallet_scanned_block_height);
      MDEBUG("lw blockchain height: " <<  m_light_wallet_blockchain_height);
      MDEBUG(m_light_wallet_blockchain_height-m_light_wallet_scanned_block_height << " blocks behind");
      // TODO: add wallet created block info

      light_wallet_get_address_txs();
    } else
      m_light_wallet_connected = false;

    // Lighwallet refresh done
    return;
  }
  received_money = false;
  blocks_fetched = 0;
  uint64_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers.size() ? m_transfers.back().m_txid : null_hash;
  std::list<crypto::hash> short_chain_history;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;
  uint64_t blocks_start_height;
  std::vector<cryptonote::block_complete_entry> blocks;
  std::vector<parsed_block> parsed_blocks;
  std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> output_tracker_cache;
  hw::device &hwdev = m_account.get_device();

  // pull the first set of blocks
  get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
  m_run.store(true, std::memory_order_relaxed);
  if (start_height > m_blockchain.size() || m_refresh_from_block_height > m_blockchain.size()) {
    if (!start_height)
      start_height = m_refresh_from_block_height;
    // we can shortcut by only pulling hashes up to the start_height
    fast_refresh(start_height, blocks_start_height, short_chain_history);
    // regenerate the history now that we've got a full set of hashes
    short_chain_history.clear();
    get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
    start_height = 0;
    // and then fall through to regular refresh processing
  }

  // If stop() is called during fast refresh we don't need to continue
  if(!m_run.load(std::memory_order_relaxed))
    return;
  // always reset start_height to 0 to force short_chain_ history to be used on
  // subsequent pulls in this refresh.
  start_height = 0;

  OXEN_DEFER {
    if (m_encrypt_keys_after_refresh)
    {
      encrypt_keys(*m_encrypt_keys_after_refresh);
      m_encrypt_keys_after_refresh = std::nullopt;
    }

    hwdev.computing_key_images(false);
  };


  // get updated pool state first, but do not process those txes just yet,
  // since that might cause a password prompt, which would introduce a data
  // leak allowing a passive adversary with traffic analysis capability to
  // infer when we get an incoming output
  std::vector<get_pool_state_tx> process_pool_txs;
  if (check_pool)
    process_pool_txs = get_pool_state(true /*refreshed*/);

  bool first = true, last = false;
  while(m_run.load(std::memory_order_relaxed))
  {
    uint64_t next_blocks_start_height;
    std::vector<cryptonote::block_complete_entry> next_blocks;
    std::vector<parsed_block> next_parsed_blocks;
    bool error;
    std::exception_ptr exception;
    try
    {
      // pull the next set of blocks while we're processing the current one
      error = false;
      next_blocks.clear();
      next_parsed_blocks.clear();
      added_blocks = 0;
      if (!first && blocks.empty())
        break;
      if (!last)
        tpool.submit(&waiter, [&]{pull_and_parse_next_blocks(start_height, next_blocks_start_height, short_chain_history, blocks, parsed_blocks, next_blocks, next_parsed_blocks, last, error, exception);});

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blocks, parsed_blocks, added_blocks, output_tracker_cache.get());
        }
        catch (const tools::error::out_of_hashchain_bounds_error&)
        {
          MINFO("Daemon claims next refresh block is out of hash chain bounds, resetting hash chain");
          uint64_t stop_height = m_blockchain.offset();
          std::vector<crypto::hash> tip(m_blockchain.size() - m_blockchain.offset());
          for (size_t i = m_blockchain.offset(); i < m_blockchain.size(); ++i)
            tip[i - m_blockchain.offset()] = m_blockchain[i];
          cryptonote::block b;
          generate_genesis(b);
          m_blockchain.clear();
          m_blockchain.push_back(get_block_hash(b));
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          fast_refresh(stop_height, blocks_start_height, short_chain_history, true);
          THROW_WALLET_EXCEPTION_IF((m_blockchain.size() == stop_height || (m_blockchain.size() == 1 && stop_height == 0) ? false : true), error::wallet_internal_error, "Unexpected hashchain size");
          THROW_WALLET_EXCEPTION_IF(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          start_height = stop_height;
          throw std::runtime_error(""); // loop again
        }
        catch (const std::exception &e)
        {
          MERROR("Error parsing blocks: " << e.what());
          error = true;
        }
        blocks_fetched += added_blocks;
      }
      waiter.wait(&tpool);
      if(!first && blocks_start_height == next_blocks_start_height)
      {
        m_node_rpc_proxy.set_height(m_blockchain.size());
        break;
      }

      first = false;

      // handle error from async fetching thread
      if (error)
      {
        throw std::runtime_error("proxy exception in refresh thread");
      }

      // if we've got at least 10 blocks to refresh, assume we're starting
      // a long refresh, and setup a tracking output cache if we need to
      if (m_track_uses && (!output_tracker_cache || output_tracker_cache->empty()) && next_blocks.size() >= 10)
        output_tracker_cache = create_output_tracker_cache();

      // switch to the new blocks from the daemon
      blocks_start_height = next_blocks_start_height;
      blocks = std::move(next_blocks);
      parsed_blocks = std::move(next_parsed_blocks);
    }
    catch (const tools::error::password_needed&)
    {
      blocks_fetched += added_blocks;
      waiter.wait(&tpool);
      throw;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      waiter.wait(&tpool);
      if(try_count < 3)
      {
        LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        start_height = 0;
        blocks.clear();
        parsed_blocks.clear();
        short_chain_history.clear();
        get_short_chain_history(short_chain_history, 1);
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers.size() ? m_transfers.back().m_txid : null_hash))
    received_money = true;

  uint64_t immutable_height = 0;
  if (m_node_rpc_proxy.get_immutable_height(immutable_height))
    m_immutable_height = immutable_height;

  try
  {
    // If stop() is called we don't need to check pending transactions
    if (check_pool && m_run.load(std::memory_order_relaxed) && !process_pool_txs.empty())
      process_pool_state(process_pool_txs);
  }
  catch (...)
  {
    LOG_PRINT_L1("Failed to check pending transactions");
  }

  m_first_refresh_done = true;

  LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance_all(false)) << ", unlocked: " << print_money(unlocked_balance_all(false)));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::refresh(bool trusted_daemon, uint64_t & blocks_fetched, bool& received_money, bool& ok)
{
  try
  {
    refresh(trusted_daemon, 0, blocks_fetched, received_money);
    ok = true;
  }
  catch (...)
  {
    ok = false;
  }
  return ok;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution)
{
  rpc::version_t rpc_version;
  if (!m_node_rpc_proxy.get_rpc_version(rpc_version))
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, "getversion");

  if (rpc_version < rpc::version_t{1, 19})
  {
    MWARNING("Daemon is too old, not requesting rct distribution");
    return false;
  }
  MDEBUG("Daemon is recent enough, requesting rct distribution");

  cryptonote::rpc::GET_OUTPUT_DISTRIBUTION_BIN::request req{};
  cryptonote::rpc::GET_OUTPUT_DISTRIBUTION_BIN::response res{};
  req.amounts.push_back(0);
  req.from_height = 0;
  req.cumulative = false;
  req.binary = true;
  req.compress = true;
  bool r = invoke_http<rpc::GET_OUTPUT_DISTRIBUTION_BIN>(req, res);
  if (!r)
  {
    MWARNING("Failed to request output distribution: no connection to daemon");
    return false;
  }
  if (res.status == rpc::STATUS_BUSY)
  {
    MWARNING("Failed to request output distribution: daemon is busy");
    return false;
  }
  if (res.status != rpc::STATUS_OK)
  {
    MWARNING("Failed to request output distribution: " << res.status);
    return false;
  }
  if (res.distributions.size() != 1)
  {
    MWARNING("Failed to request output distribution: not the expected single result");
    return false;
  }
  if (res.distributions[0].amount != 0)
  {
    MWARNING("Failed to request output distribution: results are not for amount 0");
    return false;
  }
  for (size_t i = 1; i < res.distributions[0].data.distribution.size(); ++i)
    res.distributions[0].data.distribution[i] += res.distributions[0].data.distribution[i-1];
  start_height = res.distributions[0].data.start_height;
  distribution = std::move(res.distributions[0].data.distribution);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_output_blacklist(std::vector<uint64_t> &blacklist)
{
  rpc::version_t rpc_version;
  if (!m_node_rpc_proxy.get_rpc_version(rpc_version))
  {
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, "getversion");
  }
  if (rpc_version < rpc::version_t{2, 3})
  {
    MWARNING("Daemon is too old, not requesting output blacklist");
    return false;
  }
  MDEBUG("Daemon is recent enough, requesting output blacklist");

  cryptonote::rpc::GET_OUTPUT_BLACKLIST::response res = {};
  bool r = invoke_http<rpc::GET_OUTPUT_BLACKLIST>({}, res);

  if (!r)
  {
    MWARNING("Failed to request output blacklist: no connection to daemon");
    return false;
  }

  blacklist = std::move(res.blacklist);
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::detach_blockchain(uint64_t height, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache)
{
  LOG_PRINT_L0("Detaching blockchain on height " << height);

  // size  1 2 3 4 5 6 7 8 9
  // block 0 1 2 3 4 5 6 7 8
  //               C
  THROW_WALLET_EXCEPTION_IF(height < m_blockchain.offset() && m_blockchain.size() > m_blockchain.offset(),
      error::wallet_internal_error, "Daemon claims reorg below last checkpoint");

  size_t transfers_detached = 0;

  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    wallet2::transfer_details &td = m_transfers[i];
    if (td.m_spent && td.m_spent_height >= height)
    {
      LOG_PRINT_L1("Resetting spent/frozen status for output " << i << ": " << td.m_key_image);
      set_unspent(i);
      thaw(i);
    }
  }

  for (transfer_details &td: m_transfers)
  {
    while (!td.m_uses.empty() && td.m_uses.back().first >= height)
      td.m_uses.pop_back();
  }

  if (output_tracker_cache)
    output_tracker_cache->clear();

  auto it = std::find_if(m_transfers.begin(), m_transfers.end(), [&](const transfer_details& td){return td.m_block_height >= height;});
  size_t i_start = it - m_transfers.begin();

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      continue;
    auto it_ki = m_key_images.find(m_transfers[i].m_key_image);
    THROW_WALLET_EXCEPTION_IF(it_ki == m_key_images.end(), error::wallet_internal_error, "key image not found: index " + std::to_string(i) + ", ki " + tools::type_to_hex(m_transfers[i].m_key_image) + ", " + std::to_string(m_key_images.size()) + " key images known");
    m_key_images.erase(it_ki);
  }

  for(size_t i = i_start; i!= m_transfers.size();i++)
  {
    auto it_pk = m_pub_keys.find(m_transfers[i].get_public_key());
    THROW_WALLET_EXCEPTION_IF(it_pk == m_pub_keys.end(), error::wallet_internal_error, "public key not found");
    m_pub_keys.erase(it_pk);
  }
  transfers_detached = std::distance(it, m_transfers.end());
  m_transfers.erase(it, m_transfers.end());

  size_t blocks_detached = m_blockchain.size() - height;
  m_blockchain.crop(height);

  for (auto it = m_payments.begin(); it != m_payments.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_payments.erase(it);
    else
      ++it;
  }

  for (auto it = m_confirmed_txs.begin(); it != m_confirmed_txs.end(); )
  {
    if(height <= it->second.m_block_height)
      it = m_confirmed_txs.erase(it);
    else
      ++it;
  }

  LOG_PRINT_L0("Detached blockchain on height " << height << ", transfers detached " << transfers_detached << ", blocks detached " << blocks_detached);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::deinit()
{
  m_is_initialized=false;
  unlock_keys_file();
  m_account.deinit();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::clear()
{
  m_blockchain.clear();
  m_transfers.clear();
  m_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_tx_keys.clear();
  m_additional_tx_keys.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();
  m_address_book.clear();
  m_subaddresses.clear();
  m_subaddress_labels.clear();
  m_multisig_rounds_passed = 0;
  m_device_last_key_image_sync = 0;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::clear_soft(bool keep_key_images)
{
  m_blockchain.clear();
  m_transfers.clear();
  if (!keep_key_images)
    m_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();

  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
  m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);
}

/*!
 * \brief Stores wallet information to wallet file.
 * \param  keys_file_name Name of wallet file
 * \param  password       Password of wallet file
 * \param  watch_only     true to save only view key, false to save both spend and view keys
 * \return                Whether it was successful.
 */
bool wallet2::store_keys(const fs::path& keys_file_name, const epee::wipeable_string& password, bool watch_only)
{
  std::optional<wallet2::keys_file_data> keys_file_data = get_keys_file_data(password, watch_only);
  CHECK_AND_ASSERT_MES(keys_file_data, false, "failed to generate wallet keys data");

  fs::path tmp_file_name = keys_file_name;
  tmp_file_name += ".new";
  std::string buf;
  bool r = false;
  try {
    buf = serialization::dump_binary(*keys_file_data);
    r = save_to_file(tmp_file_name, buf);
  } catch (...) {}
  CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << tmp_file_name);

  unlock_keys_file();
  std::error_code e;
#ifdef WIN32
  // std::filesystem::rename is broken on Windows and fails if the file already exists
  fs::remove(keys_file_name, e);
#endif
  fs::rename(tmp_file_name, keys_file_name, e);
  lock_keys_file();

  if (e) {
    fs::remove(tmp_file_name);
    LOG_ERROR("failed to update wallet keys file " << keys_file_name);
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
std::optional<wallet2::keys_file_data> wallet2::get_keys_file_data(const epee::wipeable_string& password, bool watch_only)
{
  std::string account_data;
  std::string multisig_signers;
  std::string multisig_derivations;
  cryptonote::account_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    account.encrypt_viewkey(key);
    account.decrypt_keys(key);
  }

  if (watch_only)
    account.forget_spend_key();

  account.encrypt_keys(key);

  bool r = epee::serialization::store_t_to_binary(account, account_data);
  CHECK_AND_ASSERT_MES(r, std::nullopt, "failed to serialize wallet keys");
  std::optional<wallet2::keys_file_data> keys_file_data = (wallet2::keys_file_data) {};

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(account_data.c_str(), account_data.length());
  json.AddMember("key_data", value, json.GetAllocator());
  if (!seed_language.empty())
  {
    value.SetString(seed_language.c_str(), seed_language.length());
    json.AddMember("seed_language", value, json.GetAllocator());
  }

  rapidjson::Value value2(rapidjson::kNumberType);

  value2.SetInt(m_key_device_type);
  json.AddMember("key_on_device", value2, json.GetAllocator());

  value2.SetInt(watch_only ? 1 :0); // WTF ? JSON has different true and false types, and not boolean ??
  json.AddMember("watch_only", value2, json.GetAllocator());

  value2.SetInt(m_multisig ? 1 :0);
  json.AddMember("multisig", value2, json.GetAllocator());

  value2.SetUint(m_multisig_threshold);
  json.AddMember("multisig_threshold", value2, json.GetAllocator());

  if (m_multisig)
  {
    try {
      multisig_signers = serialization::dump_binary(m_multisig_signers);
    } catch (const std::exception& e) {
      LOG_ERROR("failed to serialize wallet multisig signers: " << e.what());
      return std::nullopt;
    }
    value.SetString(multisig_signers.c_str(), multisig_signers.length());
    json.AddMember("multisig_signers", value, json.GetAllocator());

    try {
      multisig_derivations = serialization::dump_binary(m_multisig_derivations);
    } catch (const std::exception& e) {
      LOG_ERROR("failed to serialize wallet multisig derivations");
      return std::nullopt;
    }
    value.SetString(multisig_derivations.c_str(), multisig_derivations.length());
    json.AddMember("multisig_derivations", value, json.GetAllocator());

    value2.SetUint(m_multisig_rounds_passed);
    json.AddMember("multisig_rounds_passed", value2, json.GetAllocator());
  }

  value2.SetInt(m_always_confirm_transfers ? 1 :0);
  json.AddMember("always_confirm_transfers", value2, json.GetAllocator());

  value2.SetInt(m_print_ring_members ? 1 :0);
  json.AddMember("print_ring_members", value2, json.GetAllocator());

  value2.SetInt(m_store_tx_info ? 1 :0);
  json.AddMember("store_tx_info", value2, json.GetAllocator());

  value2.SetUint(m_default_priority);
  json.AddMember("default_priority", value2, json.GetAllocator());

  value2.SetInt(m_auto_refresh ? 1 :0);
  json.AddMember("auto_refresh", value2, json.GetAllocator());

  value2.SetInt(m_refresh_type);
  json.AddMember("refresh_type", value2, json.GetAllocator());

  value2.SetUint64(m_refresh_from_block_height);
  json.AddMember("refresh_height", value2, json.GetAllocator());

  value2.SetInt(m_confirm_non_default_ring_size ? 1 :0);
  json.AddMember("confirm_non_default_ring_size", value2, json.GetAllocator());

  value2.SetInt(m_ask_password);
  json.AddMember("ask_password", value2, json.GetAllocator());

  value2.SetUint(m_min_output_count);
  json.AddMember("min_output_count", value2, json.GetAllocator());

  value2.SetUint64(m_min_output_value);
  json.AddMember("min_output_value", value2, json.GetAllocator());

  value2.SetInt(CRYPTONOTE_DISPLAY_DECIMAL_POINT);
  json.AddMember("default_decimal_point", value2, json.GetAllocator());

  value2.SetInt(m_merge_destinations ? 1 :0);
  json.AddMember("merge_destinations", value2, json.GetAllocator());

  value2.SetInt(m_confirm_backlog ? 1 :0);
  json.AddMember("confirm_backlog", value2, json.GetAllocator());

  value2.SetUint(m_confirm_backlog_threshold);
  json.AddMember("confirm_backlog_threshold", value2, json.GetAllocator());

  value2.SetInt(m_confirm_export_overwrite ? 1 :0);
  json.AddMember("confirm_export_overwrite", value2, json.GetAllocator());

  value2.SetUint(m_nettype);
  json.AddMember("nettype", value2, json.GetAllocator());

  value2.SetInt(m_segregate_pre_fork_outputs ? 1 : 0);
  json.AddMember("segregate_pre_fork_outputs", value2, json.GetAllocator());

  value2.SetInt(m_key_reuse_mitigation2 ? 1 : 0);
  json.AddMember("key_reuse_mitigation2", value2, json.GetAllocator());

  value2.SetUint(m_segregation_height);
  json.AddMember("segregation_height", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_above);
  json.AddMember("ignore_outputs_above", value2, json.GetAllocator());

  value2.SetUint64(m_ignore_outputs_below);
  json.AddMember("ignore_outputs_below", value2, json.GetAllocator());

  value2.SetInt(m_track_uses ? 1 : 0);
  json.AddMember("track_uses", value2, json.GetAllocator());

  value2.SetInt(m_inactivity_lock_timeout.count());
  json.AddMember("inactivity_lock_timeout", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_major);
  json.AddMember("subaddress_lookahead_major", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_minor);
  json.AddMember("subaddress_lookahead_minor", value2, json.GetAllocator());

  value2.SetInt(m_original_keys_available ? 1 : 0);
  json.AddMember("original_keys_available", value2, json.GetAllocator());

  value2.SetInt(m_export_format);
  json.AddMember("export_format", value2, json.GetAllocator());

  value2.SetUint(1);
  json.AddMember("encrypted_secret_keys", value2, json.GetAllocator());

  value.SetString(m_device_name.c_str(), m_device_name.size());
  json.AddMember("device_name", value, json.GetAllocator());

  value.SetString(m_device_derivation_path.c_str(), m_device_derivation_path.size());
  json.AddMember("device_derivation_path", value, json.GetAllocator());

  std::string original_address;
  std::string original_view_secret_key;
  if (m_original_keys_available)
  {
    original_address = get_account_address_as_str(m_nettype, false, m_original_address);
    value.SetString(original_address.c_str(), original_address.length());
    json.AddMember("original_address", value, json.GetAllocator());
    original_view_secret_key = tools::type_to_hex(m_original_view_secret_key);
    value.SetString(original_view_secret_key.c_str(), original_view_secret_key.length());
    json.AddMember("original_view_secret_key", value, json.GetAllocator());
  }

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);
  account_data = buffer.GetString();

  // Encrypt the entire JSON object.
  std::string cipher;
  cipher.resize(account_data.size());
  keys_file_data->iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(account_data.data(), account_data.size(), key, keys_file_data->iv, &cipher[0]);
  keys_file_data->account_data = cipher;
  return keys_file_data;
}
//----------------------------------------------------------------------------------------------------
void wallet2::setup_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  // re-encrypt, but keep viewkey unencrypted
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    m_account.encrypt_keys(key);
    m_account.decrypt_viewkey(key);
  }

  static_assert(HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");
  epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE+1>> cache_key_data;
  memcpy(cache_key_data.data(), &key, HASH_SIZE);
  cache_key_data[HASH_SIZE] = config::HASH_KEY_WALLET_CACHE;
  cn_fast_hash(cache_key_data.data(), HASH_SIZE+1, (crypto::hash&)m_cache_key);
  get_ringdb_key();
}
//----------------------------------------------------------------------------------------------------
void wallet2::change_password(const fs::path& filename, const epee::wipeable_string& original_password, const epee::wipeable_string& new_password)
{
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
    decrypt_keys(original_password);
  setup_keys(new_password);
  rewrite(filename, new_password);
  if (!filename.empty())
    store();
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Load wallet information from wallet file.
 * \param keys_file_name Name of wallet file
 * \param password       Password of wallet file
 */
bool wallet2::load_keys(const fs::path& keys_file_name, const epee::wipeable_string& password)
{
  std::string keys_file_buf;
  bool r = load_from_file(keys_file_name, keys_file_buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Load keys from buffer
  std::optional<crypto::chacha_key> keys_to_encrypt;
  r = wallet2::load_keys_buf(keys_file_buf, password, keys_to_encrypt);

  // Rewrite with encrypted keys if unencrypted, ignore errors
  if (r && keys_to_encrypt)
  {
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
      encrypt_keys(*keys_to_encrypt);
    bool saved_ret = store_keys(keys_file_name, password, m_watch_only);
    if (!saved_ret)
    {
      // just moan a bit, but not fatal
      MERROR("Error saving keys file with encrypted keys, not fatal");
    }
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
      decrypt_keys(*keys_to_encrypt);
    m_keys_file_locker.reset();
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password) {
  std::optional<crypto::chacha_key> keys_to_encrypt;
  return wallet2::load_keys_buf(keys_buf, password, keys_to_encrypt);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, std::optional<crypto::chacha_key>& keys_to_encrypt) {

  // Decrypt the contents
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  bool encrypted_secret_keys = false;
  try {
    serialization::parse_binary(keys_buf, keys_file_data);
  } catch (const std::exception& e) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "internal error: failed to deserialize keys buffer: "s + e.what());
  }
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    is_old_file_format = true;
    m_watch_only = false;
    m_multisig = false;
    m_multisig_threshold = 0;
    m_multisig_signers.clear();
    m_multisig_rounds_passed = 0;
    m_multisig_derivations.clear();
    m_always_confirm_transfers = false;
    m_print_ring_members = false;
    m_store_tx_info = true;
    m_default_priority = 0;
    m_auto_refresh = true;
    m_refresh_type = RefreshType::RefreshDefault;
    m_refresh_from_block_height = 0;
    m_confirm_non_default_ring_size = true;
    m_ask_password = AskPasswordToDecrypt;
    m_min_output_count = 0;
    m_min_output_value = 0;
    m_merge_destinations = false;
    m_confirm_backlog = true;
    m_confirm_backlog_threshold = 0;
    m_confirm_export_overwrite = true;
    m_segregate_pre_fork_outputs = true;
    m_key_reuse_mitigation2 = true;
    m_segregation_height = 0;
    m_ignore_outputs_above = MONEY_SUPPLY;
    m_ignore_outputs_below = 0;
    m_track_uses = false;
    m_inactivity_lock_timeout = DEFAULT_INACTIVITY_LOCK_TIMEOUT;
    m_subaddress_lookahead_major = SUBADDRESS_LOOKAHEAD_MAJOR;
    m_subaddress_lookahead_minor = SUBADDRESS_LOOKAHEAD_MINOR;
    m_original_keys_available = false;
    m_export_format = ExportFormat::Binary;
    m_device_name = "";
    m_device_derivation_path = "";
    m_key_device_type = hw::device::device_type::SOFTWARE;
    encrypted_secret_keys = false;
  }
  else if(json.IsObject())
  {
    if (!json.HasMember("key_data"))
    {
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString())
    {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }
    const char *field_key_data = json["key_data"].GetString();
    account_data = std::string(field_key_data, field_key_data + json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      m_key_device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_language, std::string, String, false, std::string());
    if (field_seed_language_found)
    {
      set_seed_language(field_seed_language);
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, watch_only, int, Int, false, false);
    m_watch_only = field_watch_only;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig, int, Int, false, false);
    m_multisig = field_multisig;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig_threshold, unsigned int, Uint, m_multisig, 0);
    m_multisig_threshold = field_multisig_threshold;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig_rounds_passed, unsigned int, Uint, false, 0);
    m_multisig_rounds_passed = field_multisig_rounds_passed;
    if (m_multisig)
    {
      if (!json.HasMember("multisig_signers"))
      {
        LOG_ERROR("Field multisig_signers not found in JSON");
        return false;
      }
      if (!json["multisig_signers"].IsString())
      {
        LOG_ERROR("Field multisig_signers found in JSON, but not String");
        return false;
      }
      const char *field_multisig_signers = json["multisig_signers"].GetString();
      std::string multisig_signers = std::string(field_multisig_signers, field_multisig_signers + json["multisig_signers"].GetStringLength());
      try {
        serialization::parse_binary(multisig_signers, m_multisig_signers);
      } catch (const std::exception& e) {
        LOG_ERROR("Field multisig_signers found in JSON, but failed to parse: " << e.what());
        return false;
      }

      //previous version of multisig does not have this field
      if (json.HasMember("multisig_derivations"))
      {
        if (!json["multisig_derivations"].IsString())
        {
          LOG_ERROR("Field multisig_derivations found in JSON, but not String");
          return false;
        }
        const char *field_multisig_derivations = json["multisig_derivations"].GetString();
        std::string multisig_derivations = std::string(field_multisig_derivations, field_multisig_derivations + json["multisig_derivations"].GetStringLength());
        try {
          serialization::parse_binary(multisig_derivations, m_multisig_derivations);
        } catch (const std::exception& e) {
          LOG_ERROR("Field multisig_derivations found in JSON, but failed to parse: " << e.what());
          return false;
        }
      }
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, always_confirm_transfers, int, Int, false, true);
    m_always_confirm_transfers = field_always_confirm_transfers;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, print_ring_members, int, Int, false, true);
    m_print_ring_members = field_print_ring_members;
    if (json.HasMember("store_tx_info"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_info, int, Int, true, true);
      m_store_tx_info = field_store_tx_info;
    }
    else if (json.HasMember("store_tx_keys")) // backward compatibility
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_keys, int, Int, true, true);
      m_store_tx_info = field_store_tx_keys;
    }
    else
      m_store_tx_info = true;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_priority, unsigned int, Uint, false, 0);
    if (field_default_priority_found)
    {
      m_default_priority = field_default_priority;
    }
    else
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_fee_multiplier, unsigned int, Uint, false, 0);
      if (field_default_fee_multiplier_found)
        m_default_priority = field_default_fee_multiplier;
      else
        m_default_priority = 0;
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_refresh, int, Int, false, true);
    m_auto_refresh = field_auto_refresh;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_type, int, Int, false, RefreshType::RefreshDefault);
    m_refresh_type = RefreshType::RefreshDefault;
    if (field_refresh_type_found)
    {
      if (field_refresh_type == RefreshFull || field_refresh_type == RefreshOptimizeCoinbase || field_refresh_type == RefreshNoCoinbase)
        m_refresh_type = (RefreshType)field_refresh_type;
      else
        LOG_PRINT_L0("Unknown refresh-type value (" << field_refresh_type << "), using default");
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_height, uint64_t, Uint64, false, 0);
    m_refresh_from_block_height = field_refresh_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_non_default_ring_size, int, Int, false, true);
    m_confirm_non_default_ring_size = field_confirm_non_default_ring_size;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ask_password, AskPasswordType, Int, false, AskPasswordToDecrypt);
    m_ask_password = field_ask_password;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_count, uint32_t, Uint, false, 0);
    m_min_output_count = field_min_output_count;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_value, uint64_t, Uint64, false, 0);
    m_min_output_value = field_min_output_value;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, merge_destinations, int, Int, false, false);
    m_merge_destinations = field_merge_destinations;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog, int, Int, false, true);
    m_confirm_backlog = field_confirm_backlog;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog_threshold, uint32_t, Uint, false, 0);
    m_confirm_backlog_threshold = field_confirm_backlog_threshold;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_export_overwrite, int, Int, false, true);
    m_confirm_export_overwrite = field_confirm_export_overwrite;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, nettype, uint8_t, Uint, false, static_cast<uint8_t>(m_nettype));
    // The network type given in the program argument is inconsistent with the network type saved in the wallet
    THROW_WALLET_EXCEPTION_IF(static_cast<uint8_t>(m_nettype) != field_nettype, error::wallet_internal_error,
    (boost::format("%s wallet cannot be opened as %s wallet")
    % (field_nettype == 0 ? "Mainnet" : field_nettype == 1 ? "Testnet" : "Devnet")
    % (m_nettype == MAINNET ? "mainnet" : m_nettype == TESTNET ? "testnet" : "devnet")).str());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregate_pre_fork_outputs, int, Int, false, true);
    m_segregate_pre_fork_outputs = field_segregate_pre_fork_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_reuse_mitigation2, int, Int, false, true);
    m_key_reuse_mitigation2 = field_key_reuse_mitigation2;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregation_height, int, Uint, false, 0);
    m_segregation_height = field_segregation_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_outputs_above, uint64_t, Uint64, false, MONEY_SUPPLY);
    m_ignore_outputs_above = field_ignore_outputs_above;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_outputs_below, uint64_t, Uint64, false, 0);
    m_ignore_outputs_below = field_ignore_outputs_below;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, track_uses, int, Int, false, false);
    m_track_uses = field_track_uses;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, inactivity_lock_timeout, uint32_t, Uint, false,
            m_nettype == MAINNET ? std::chrono::seconds{DEFAULT_INACTIVITY_LOCK_TIMEOUT}.count() : 0);
    m_inactivity_lock_timeout = std::chrono::seconds{field_inactivity_lock_timeout};
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_major, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MAJOR);
    m_subaddress_lookahead_major = field_subaddress_lookahead_major;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_minor, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MINOR);
    m_subaddress_lookahead_minor = field_subaddress_lookahead_minor;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, export_format, ExportFormat, Int, false, Binary);
    m_export_format = field_export_format;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, device_name, std::string, String, false, std::string());
    if (m_device_name.empty())
    {
      if (field_device_name_found)
      {
        m_device_name = field_device_name;
      }
      else
      {
        m_device_name = m_key_device_type == hw::device::device_type::LEDGER ? "Ledger" : "default";
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, device_derivation_path, std::string, String, false, std::string());
    m_device_derivation_path = field_device_derivation_path;

    if (json.HasMember("original_keys_available"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_keys_available, int, Int, false, false);
      m_original_keys_available = field_original_keys_available;
      if (m_original_keys_available)
      {
        GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_address, std::string, String, true, std::string());
        address_parse_info info;
        bool ok = get_account_address_from_str(info, m_nettype, field_original_address);
        if (!ok)
        {
          LOG_ERROR("Failed to parse original_address from JSON");
          return false;
        }
        m_original_address = info.address;
        GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, original_view_secret_key, std::string, String, true, std::string());
        ok = tools::hex_to_type(field_original_view_secret_key, m_original_view_secret_key);
        if (!ok)
        {
          LOG_ERROR("Failed to parse original_view_secret_key from JSON");
          return false;
        }
      }
    }
    else
    {
      m_original_keys_available = false;
    }
  }
  else
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "invalid password");
    return false;
  }

  bool r = epee::serialization::load_t_from_binary(m_account, account_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);
  if (m_key_device_type == hw::device::device_type::LEDGER || m_key_device_type == hw::device::device_type::TREZOR) {
    LOG_PRINT_L0("Account on device. Initing device...");
    hw::device &hwdev = lookup_device(m_device_name);
    THROW_WALLET_EXCEPTION_IF(!hwdev.set_name(m_device_name), error::wallet_internal_error, "Could not set device name " + m_device_name);
    hwdev.set_network_type(m_nettype);
    hwdev.set_derivation_path(m_device_derivation_path);
    hwdev.set_callback(get_device_callback());
    THROW_WALLET_EXCEPTION_IF(!hwdev.init(), error::wallet_internal_error, "Could not initialize the device " + m_device_name);
    THROW_WALLET_EXCEPTION_IF(!hwdev.connect(), error::wallet_internal_error, "Could not connect to the device " + m_device_name);
    m_account.set_device(hwdev);

    account_public_address device_account_public_address;
    THROW_WALLET_EXCEPTION_IF(!hwdev.get_public_address(device_account_public_address), error::wallet_internal_error, "Cannot get a device address");
    THROW_WALLET_EXCEPTION_IF(device_account_public_address != m_account.get_keys().m_account_address, error::wallet_internal_error,
            "Device wallet does not match wallet address. "
            "Device address: " + cryptonote::get_account_address_as_str(m_nettype, false, device_account_public_address) +
            ", wallet address: " + m_account.get_public_address_str(m_nettype));
    LOG_PRINT_L0("Device initialized...");
  } else if (key_on_device()) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "hardware device not supported");
  }

  if (r)
  {
    if (encrypted_secret_keys)
    {
      m_account.decrypt_keys(key);
    }
    else
    {
      keys_to_encrypt = key;
    }
  }

  const cryptonote::account_keys& keys = m_account.get_keys();
  hw::device &hwdev = m_account.get_device();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if (!m_watch_only && !m_multisig && hwdev.device_protocol() != hw::device::PROTOCOL_COLD)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);

  if (r)
    setup_keys(password);

  return true;
}

/*!
 * \brief verify password for default wallet keys file.
 * \param password       Password to verify
 * \return               true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool wallet2::verify_password(const epee::wipeable_string& password)
{
  // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
  unlock_keys_file();
  bool r = verify_password(m_keys_file, password, m_account.get_device().device_protocol() == hw::device::PROTOCOL_COLD || m_watch_only || m_multisig, m_account.get_device(), m_kdf_rounds);
  lock_keys_file();
  return r;
}

/*!
 * \brief verify password for specified wallet keys file.
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \param no_spend_key    If set = only verify view keys, otherwise also spend keys
 * \param hwdev           The hardware device to use
 * \return                true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool wallet2::verify_password(const fs::path& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  std::string buf;
  bool encrypted_secret_keys = false;
  bool r = load_from_file(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  try {
    serialization::parse_binary(buf, keys_file_data);
  } catch (const std::exception& e) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name.u8string() + "\": " + e.what());
  }
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);

  if (encrypted_secret_keys)
    account_data_check.decrypt_keys(key);

  const cryptonote::account_keys& keys = account_data_check.get_keys();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if(!no_spend_key)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  return r;
}

void wallet2::encrypt_keys(const crypto::chacha_key &key)
{
  std::lock_guard lock{m_decrypt_keys_mutex};
  if (--m_decrypt_keys_lockers) // another lock left ?
    return;
  m_account.encrypt_keys(key);
  m_account.decrypt_viewkey(key);
}

void wallet2::decrypt_keys(const crypto::chacha_key &key)
{
  std::lock_guard lock{m_decrypt_keys_mutex};
  if (m_decrypt_keys_lockers++) // already unlocked ?
    return;
  m_account.encrypt_viewkey(key);
  m_account.decrypt_keys(key);
}

void wallet2::encrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  encrypt_keys(key);
}

void wallet2::decrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  decrypt_keys(key);
}

void wallet2::setup_new_blockchain()
{
  cryptonote::block b;
  generate_genesis(b);
  m_blockchain.push_back(get_block_hash(b));
  m_last_block_reward = cryptonote::get_outs_money_amount(b.miner_tx);
  add_subaddress_account(tr("Primary account"));
}

void wallet2::create_keys_file(const fs::path &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file)
{
  if (!wallet_.empty())
  {
    bool r = store_keys(m_keys_file, password, watch_only);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

    if (create_address_file)
    {
      auto addrfile = m_wallet_file;
      addrfile += ".address.txt";
      r = save_to_file(addrfile, m_account.get_public_address_str(m_nettype), true);
      if(!r) MERROR("String with address text not saved");
    }
  }
}


/*!
 * \brief determine the key storage for the specified wallet file
 * \param device_type     (OUT) wallet backend as enumerated in hw::device::device_type
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \return                true if password correct, else false
 *
 * for verification only - determines key storage hardware
 *
 */
bool wallet2::query_device(hw::device::device_type& device_type, const fs::path& keys_file_name, const epee::wipeable_string& password, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  wallet2::keys_file_data keys_file_data;
  std::string buf;
  bool r = load_from_file(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  try {
    serialization::parse_binary(buf, keys_file_data);
  } catch (const std::exception& e) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name.u8string() + "\": " + e.what());
  }
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  device_type = hw::device::device_type::SOFTWARE;
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);
  if (!r) return false;
  return true;
}

void wallet2::init_type(hw::device::device_type device_type)
{
  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_multisig = false;
  m_multisig_threshold = 0;
  m_multisig_signers.clear();
  m_original_keys_available = false;
  m_key_device_type = device_type;
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_              Name of wallet file
 * \param  password             Password of wallet file
 * \param  multisig_data        The multisig restore info and keys
 * \param  create_address_file  Whether to create an address file
 */
void wallet2::generate(const fs::path& wallet_, const epee::wipeable_string& password,
  const epee::wipeable_string& multisig_data, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.generate(rct::rct2sk(rct::zero()), true, false);

  THROW_WALLET_EXCEPTION_IF(multisig_data.size() < 32, error::invalid_multisig_seed);
  size_t offset = 0;
  uint32_t threshold = *(uint32_t*)(multisig_data.data() + offset);
  offset += sizeof(uint32_t);
  uint32_t total = *(uint32_t*)(multisig_data.data() + offset);
  offset += sizeof(uint32_t);
  THROW_WALLET_EXCEPTION_IF(threshold < 2, error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(total != threshold && total != threshold + 1, error::invalid_multisig_seed);
  const size_t n_multisig_keys =  total == threshold ? 1 : threshold;
  THROW_WALLET_EXCEPTION_IF(multisig_data.size() != 8 + 32 * (4 + n_multisig_keys + total), error::invalid_multisig_seed);

  std::vector<crypto::secret_key> multisig_keys;
  std::vector<crypto::public_key> multisig_signers;
  crypto::secret_key spend_secret_key = *(crypto::secret_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::secret_key);
  crypto::public_key spend_public_key = *(crypto::public_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::public_key);
  crypto::secret_key view_secret_key = *(crypto::secret_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::secret_key);
  crypto::public_key view_public_key = *(crypto::public_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::public_key);
  for (size_t n = 0; n < n_multisig_keys; ++n)
  {
    multisig_keys.push_back(*(crypto::secret_key*)(multisig_data.data() + offset));
    offset += sizeof(crypto::secret_key);
  }
  for (size_t n = 0; n < total; ++n)
  {
    multisig_signers.push_back(*(crypto::public_key*)(multisig_data.data() + offset));
    offset += sizeof(crypto::public_key);
  }

  crypto::public_key calculated_view_public_key;
  THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(view_secret_key, calculated_view_public_key), error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(view_public_key != calculated_view_public_key, error::invalid_multisig_seed);
  crypto::public_key local_signer;
  THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(spend_secret_key, local_signer), error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(std::find(multisig_signers.begin(), multisig_signers.end(), local_signer) == multisig_signers.end(), error::invalid_multisig_seed);
  rct::key skey = rct::zero();
  for (const auto &msk: multisig_keys)
    sc_add(skey.bytes, skey.bytes, rct::sk2rct(msk).bytes);
  THROW_WALLET_EXCEPTION_IF(!(rct::rct2sk(skey) == spend_secret_key), error::invalid_multisig_seed);
  memwipe(&skey, sizeof(rct::key));

  m_account.make_multisig(view_secret_key, spend_secret_key, spend_public_key, multisig_keys);
  m_account.finalize_multisig(spend_public_key);

  // Not possible to restore a multisig wallet that is able to activate the MMS
  // (because the original keys are not (yet) part of the restore info), so
  // keep m_original_keys_available to false
  init_type(hw::device::device_type::SOFTWARE);
  m_multisig = true;
  m_multisig_threshold = threshold;
  m_multisig_signers = multisig_signers;
  setup_keys(password);

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);
  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_                 Name of wallet file
 * \param  password                Password of wallet file
 * \param  recovery_param          If it is a restore, the recovery key
 * \param  recover                 Whether it is a restore
 * \param  two_random              Whether it is a non-deterministic wallet
 * \param  create_address_file     Whether to create an address file
 * \return                         The secret key of the generated wallet
 */
crypto::secret_key wallet2::generate(const fs::path& wallet_, const epee::wipeable_string& password,
  const crypto::secret_key& recovery_param, bool recover, bool two_random, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  crypto::secret_key retval = m_account.generate(recovery_param, recover, two_random);

  init_type(hw::device::device_type::SOFTWARE);
  setup_keys(password);

  // calculate a starting refresh height
  if(m_refresh_from_block_height == 0 && !recover){
    m_refresh_from_block_height = estimate_blockchain_height();
  }

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();

  return retval;
}

 uint64_t wallet2::estimate_blockchain_height()
 {
   const uint64_t blocks_per_month = BLOCKS_EXPECTED_IN_DAYS(30);

   // try asking the daemon first
   std::string err;
   uint64_t height = 0;

   // we get the max of approximated height and local height.
   // approximated height is the least of daemon target height
   // (the max of what the other daemons are claiming is their
   // height) and the theoretical height based on the local
   // clock. This will be wrong only if both the local clock
   // is bad *and* a peer daemon claims a highest height than
   // the real chain.
   // local height is the height the local daemon is currently
   // synced to, it will be lower than the real chain height if
   // the daemon is currently syncing.
   // If we use the approximate height we subtract one month as
   // a safety margin.
   height = get_approximate_blockchain_height();
   uint64_t target_height = get_daemon_blockchain_target_height(err);
   if (err.empty()) {
     if (target_height < height)
       height = target_height;
   } else {
     // if we couldn't talk to the daemon, check safety margin.
     if (height > blocks_per_month)
       height -= blocks_per_month;
     else
       height = 0;
   }
   uint64_t local_height = get_daemon_blockchain_height(err);
   if (err.empty() && local_height > height)
     height = local_height;
   return height;
 }

/*!
* \brief Creates a watch only wallet from a public address and a view secret key.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void wallet2::generate(const fs::path& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_viewkey(account_public_address, viewkey);
  init_type(hw::device::device_type::SOFTWARE);
  m_watch_only = true;
  m_account_public_address = account_public_address;
  setup_keys(password);

  create_keys_file(wallet_, true, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
* \brief Creates a wallet from a public address and a spend/view secret key pair.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  spendkey                spend secret key
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void wallet2::generate(const fs::path& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    std::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_keys(account_public_address, spendkey, viewkey);
  init_type(hw::device::device_type::SOFTWARE);
  m_account_public_address = account_public_address;
  setup_keys(password);

  create_keys_file(wallet_, false, password, create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

void wallet2::restore_from_device(const fs::path& wallet_, const epee::wipeable_string& password, const std::string &device_name,
    bool create_address_file, std::optional<std::string> hwdev_label, std::function<void(std::string msg)> progress_callback)
{
  clear();
  prepare_file_names(wallet_);

  std::error_code ignored_ec;
  if (!wallet_.empty()) {
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(fs::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  auto &hwdev = lookup_device(device_name);
  hwdev.set_name(device_name);
  hwdev.set_network_type(m_nettype);
  hwdev.set_derivation_path(m_device_derivation_path);
  hwdev.set_callback(get_device_callback());

  m_account.create_from_device(hwdev);
  init_type(m_account.get_device().get_type());
  setup_keys(password);
  if (progress_callback)
    progress_callback(tr("Retrieved wallet address from device: ") + m_account.get_public_address_str(m_nettype));
  m_device_name = device_name;

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);
  if (m_subaddress_lookahead_major == SUBADDRESS_LOOKAHEAD_MAJOR && m_subaddress_lookahead_minor == SUBADDRESS_LOOKAHEAD_MINOR)
  {
    // the default lookahead setting (50:200) is clearly too much for hardware wallet
    m_subaddress_lookahead_major = 5;
    m_subaddress_lookahead_minor = 20;
  }
  if (hwdev_label) {
    fs::path hwdev_txt = m_wallet_file;
    hwdev_txt += ".hwdev.txt";
    if (!save_to_file(hwdev_txt, *hwdev_label, true))
      MERROR("failed to write .hwdev.txt comment file");
  }
  if (progress_callback)
    progress_callback(tr("Setting up account and subaddresses"));
  setup_new_blockchain();
  if (!wallet_.empty()) {
    store();
  }
}

std::string wallet2::make_multisig(const epee::wipeable_string &password,
  const std::vector<crypto::secret_key> &view_keys,
  const std::vector<crypto::public_key> &spend_keys,
  uint32_t threshold)
{
  CHECK_AND_ASSERT_THROW_MES(!view_keys.empty(), "empty view keys");
  CHECK_AND_ASSERT_THROW_MES(view_keys.size() == spend_keys.size(), "Mismatched view/spend key sizes");
  CHECK_AND_ASSERT_THROW_MES(threshold > 1 && threshold <= spend_keys.size() + 1, "Invalid threshold");

  std::string extra_multisig_info;
  std::vector<crypto::secret_key> multisig_keys;
  rct::key spend_pkey = rct::identity();
  rct::key spend_skey;
  OXEN_DEFER { memwipe(&spend_skey, sizeof(spend_skey)); };
  std::vector<crypto::public_key> multisig_signers;

  // decrypt keys
  bool reencrypt = false;
  crypto::chacha_key chacha_key;
  auto keys_reencryptor = oxen::defer([&] {
    if (reencrypt)
    {
      m_account.encrypt_keys(chacha_key);
      m_account.decrypt_viewkey(chacha_key);
    }
  });

  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
    m_account.encrypt_viewkey(chacha_key);
    m_account.decrypt_keys(chacha_key);
    reencrypt = true;
  }

  // In common multisig scheme there are 4 types of key exchange rounds:
  // 1. First round is exchange of view secret keys and public spend keys.
  // 2. Middle round is exchange of derivations: Ki = b * Mj, where b - spend secret key,
  //    M - public multisig key (in first round it equals to public spend key), K - new public multisig key.
  // 3. Secret spend establishment round sets your secret multisig keys as follows: kl = H(Ml), where M - is *your* public multisig key,
  //    k - secret multisig key used to sign transactions. k and M are sets of keys, of course.
  //    And secret spend key as the sum of all participant's secret multisig keys
  // 4. Last round establishes multisig wallet's public spend key. Participants exchange their public multisig keys
  //    and calculate common spend public key as sum of all unique participants' public multisig keys.
  // Note that N/N scheme has only first round. N-1/N has 2 rounds: first and last. Common M/N has all 4 rounds.

  // IMPORTANT: wallet's public spend key is not equal to secret_spend_key * G!
  // Wallet's public spend key is the sum of unique public multisig keys of all participants.
  // secret_spend_key * G = public signer key

  if (threshold == spend_keys.size() + 1)
  {
    // In N / N case we only need to do one round and calculate secret multisig keys and new secret spend key
    MINFO("Creating spend key...");

    // Calculates all multisig keys and spend key
    cryptonote::generate_multisig_N_N(get_account().get_keys(), spend_keys, multisig_keys, spend_skey, spend_pkey);

    // Our signer key is b * G, where b is secret spend key.
    multisig_signers = spend_keys;
    multisig_signers.push_back(get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key));
  }
  else
  {
    // We just got public spend keys of all participants and deriving multisig keys (set of Mi = b * Bi).
    // note that derivations are public keys as DH exchange suppose it to be
    auto derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), spend_keys);

    spend_pkey = rct::identity();
    multisig_signers = std::vector<crypto::public_key>(spend_keys.size() + 1, crypto::null_pkey);

    if (threshold == spend_keys.size())
    {
      // N - 1 / N case

      // We need an extra step, so we package all the composite public keys
      // we know about, and make a signed string out of them
      MINFO("Creating spend key...");

      // Calculating set of our secret multisig keys as follows: mi = H(Mi),
      // where mi - secret multisig key, Mi - others' participants public multisig key
      multisig_keys = cryptonote::calculate_multisig_keys(derivations);

      // calculating current participant's spend secret key as sum of all secret multisig keys for current participant.
      // IMPORTANT: participant's secret spend key is not an entire wallet's secret spend!
      //            Entire wallet's secret spend is sum of all unique secret multisig keys
      //            among all of participants and is not held by anyone!
      spend_skey = rct::sk2rct(cryptonote::calculate_multisig_signer_key(multisig_keys));

      // Preparing data for the last round to calculate common public spend key. The data contains public multisig keys.
      extra_multisig_info = pack_multisignature_keys(secret_keys_to_public_keys(multisig_keys), rct::rct2sk(spend_skey));
    }
    else
    {
      // M / N case
      MINFO("Preparing keys for next exchange round...");

      // Preparing data for middle round - packing new public multisig keys to exchage with others.
      extra_multisig_info = pack_multisignature_keys(derivations, m_account.get_keys().m_spend_secret_key);
      spend_skey = rct::sk2rct(m_account.get_keys().m_spend_secret_key);

      // Need to store middle keys to be able to proceed in case of wallet shutdown.
      m_multisig_derivations = derivations;
    }
  }

  if (!m_original_keys_available)
  {
    // Save the original i.e. non-multisig keys so the MMS can continue to use them to encrypt and decrypt messages
    // (making a wallet multisig overwrites those keys, see account_base::make_multisig)
    m_original_address = m_account.get_keys().m_account_address;
    m_original_view_secret_key = m_account.get_keys().m_view_secret_key;
    m_original_keys_available = true;
  }

  clear();
  MINFO("Creating view key...");
  crypto::secret_key view_skey = cryptonote::generate_multisig_view_secret_key(get_account().get_keys().m_view_secret_key, view_keys);

  MINFO("Creating multisig address...");
  CHECK_AND_ASSERT_THROW_MES(m_account.make_multisig(view_skey, rct::rct2sk(spend_skey), rct::rct2pk(spend_pkey), multisig_keys),
      "Failed to create multisig wallet due to bad keys");
  memwipe(&spend_skey, sizeof(rct::key));

  init_type(hw::device::device_type::SOFTWARE);
  m_original_keys_available = true;
  m_multisig = true;
  m_multisig_threshold = threshold;
  m_multisig_signers = multisig_signers;
  ++m_multisig_rounds_passed;

  // re-encrypt keys
  keys_reencryptor.invoke();

  if (!m_wallet_file.empty())
  {
    fs::path addrfile = m_wallet_file;
    addrfile += ".address.txt";
    create_keys_file(m_wallet_file, false, password, fs::exists(addrfile));
  }

  setup_new_blockchain();

  if (!m_wallet_file.empty())
    store();

  return extra_multisig_info;
}

std::string wallet2::exchange_multisig_keys(const epee::wipeable_string &password,
  const std::vector<std::string> &info)
{
  THROW_WALLET_EXCEPTION_IF(info.empty(),
    error::wallet_internal_error, "Empty multisig info");

  if (!tools::starts_with(info[0], MULTISIG_EXTRA_INFO_MAGIC))
  {
    THROW_WALLET_EXCEPTION(
      error::wallet_internal_error, "Unsupported info string");
  }

  std::vector<crypto::public_key> signers;
  std::unordered_set<crypto::public_key> pkeys;

  THROW_WALLET_EXCEPTION_IF(!unpack_extra_multisig_info(info, signers, pkeys),
    error::wallet_internal_error, "Bad extra multisig info");

  return exchange_multisig_keys(password, pkeys, signers);
}

std::string wallet2::exchange_multisig_keys(const epee::wipeable_string &password,
  std::unordered_set<crypto::public_key> derivations,
  std::vector<crypto::public_key> signers)
{
  CHECK_AND_ASSERT_THROW_MES(!derivations.empty(), "empty pkeys");
  CHECK_AND_ASSERT_THROW_MES(!signers.empty(), "empty signers");

  bool ready = false;
  CHECK_AND_ASSERT_THROW_MES(multisig(&ready), "The wallet is not multisig");
  CHECK_AND_ASSERT_THROW_MES(!ready, "Multisig wallet creation process has already been finished");

  // keys are decrypted
  bool reencrypt = false;
  crypto::chacha_key chacha_key;
  epee::misc_utils::auto_scope_leave_caller keys_reencryptor;
  OXEN_DEFER {
    if (reencrypt)
    {
      m_account.encrypt_keys(chacha_key);
      m_account.decrypt_viewkey(chacha_key);
    }
  };
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
    m_account.encrypt_viewkey(chacha_key);
    m_account.decrypt_keys(chacha_key);
    reencrypt = true;
  }

  if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 1)
  {
    // the last round is passed and we have to calculate spend public key
    // add ours if not included
    crypto::public_key local_signer = get_multisig_signer_public_key();

    if (std::find(signers.begin(), signers.end(), local_signer) == signers.end())
    {
        signers.push_back(local_signer);
        for (const auto &msk: get_account().get_multisig_keys())
        {
            derivations.insert(rct::rct2pk(rct::scalarmultBase(rct::sk2rct(msk))));
        }
    }

    CHECK_AND_ASSERT_THROW_MES(signers.size() == m_multisig_signers.size(), "Bad signers size");

    // Summing all of unique public multisig keys to calculate common public spend key
    crypto::public_key spend_public_key = cryptonote::generate_multisig_M_N_spend_public_key(std::vector<crypto::public_key>(derivations.begin(), derivations.end()));
    m_account_public_address.m_spend_public_key = spend_public_key;
    m_account.finalize_multisig(spend_public_key);

    m_multisig_signers = signers;
    std::sort(m_multisig_signers.begin(), m_multisig_signers.end());

    ++m_multisig_rounds_passed;
    m_multisig_derivations.clear();

    // keys are encrypted again
    keys_reencryptor = epee::misc_utils::auto_scope_leave_caller();

    if (!m_wallet_file.empty())
    {
      bool r = store_keys(m_keys_file, password, false);
      THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

      fs::path addrfile = m_wallet_file;
      addrfile += ".address.txt";
      if (fs::exists(addrfile))
      {
        r = save_to_file(addrfile, m_account.get_public_address_str(m_nettype), true);
        if(!r) MERROR("String with address text not saved");
      }
    }

    m_subaddresses.clear();
    m_subaddress_labels.clear();
    add_subaddress_account(tr("Primary account"));

    if (!m_wallet_file.empty())
      store();

    return {};
  }

  // Below are either middle or secret spend key establishment rounds

  for (const auto& key: m_multisig_derivations)
    derivations.erase(key);

  // Deriving multisig keys (set of Mi = b * Bi) according to DH from other participants' multisig keys.
  auto new_derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), std::vector<crypto::public_key>(derivations.begin(), derivations.end()));

  std::string extra_multisig_info;
  if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 2) // next round is last
  {
    // Next round is last therefore we are performing secret spend establishment round as described above.
    MINFO("Creating spend key...");

    // Calculating our secret multisig keys by hashing our public multisig keys.
    auto multisig_keys = cryptonote::calculate_multisig_keys(std::vector<crypto::public_key>(new_derivations.begin(), new_derivations.end()));
    // And summing it to get personal secret spend key
    crypto::secret_key spend_skey = cryptonote::calculate_multisig_signer_key(multisig_keys);

    m_account.make_multisig(m_account.get_keys().m_view_secret_key, spend_skey, rct::rct2pk(rct::identity()), multisig_keys);

    // Packing public multisig keys to exchange with others and calculate common public spend key in the last round
    extra_multisig_info = pack_multisignature_keys(secret_keys_to_public_keys(multisig_keys), spend_skey);
  }
  else
  {
    // This is just middle round
    MINFO("Preparing keys for next exchange round...");
    extra_multisig_info = pack_multisignature_keys(new_derivations, m_account.get_keys().m_spend_secret_key);
    m_multisig_derivations = new_derivations;
  }

  ++m_multisig_rounds_passed;

  if (!m_wallet_file.empty())
  {
    fs::path addrfile = m_wallet_file;
    addrfile += ".address.txt";
    create_keys_file(m_wallet_file, false, password, fs::exists(addrfile));
  }

  return extra_multisig_info;
}

void wallet2::unpack_multisig_info(const std::vector<std::string>& info,
  std::vector<crypto::public_key> &public_keys,
  std::vector<crypto::secret_key> &secret_keys) const
{
  // parse all multisig info
  public_keys.resize(info.size());
  secret_keys.resize(info.size());
  for (size_t i = 0; i < info.size(); ++i)
  {
    THROW_WALLET_EXCEPTION_IF(!verify_multisig_info(info[i], secret_keys[i], public_keys[i]),
        error::wallet_internal_error, "Bad multisig info: " + info[i]);
  }

  // remove duplicates
  for (size_t i = 0; i < secret_keys.size(); ++i)
  {
    for (size_t j = i + 1; j < secret_keys.size(); ++j)
    {
      if (rct::sk2rct(secret_keys[i]) == rct::sk2rct(secret_keys[j]))
      {
        MDEBUG("Duplicate key found, ignoring");
        secret_keys[j] = secret_keys.back();
        public_keys[j] = public_keys.back();
        secret_keys.pop_back();
        public_keys.pop_back();
        --j;
      }
    }
  }

  // people may include their own, weed it out
  const crypto::secret_key local_skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
  const crypto::public_key local_pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
  for (size_t i = 0; i < secret_keys.size(); ++i)
  {
    if (secret_keys[i] == local_skey)
    {
      MDEBUG("Local key is present, ignoring");
      secret_keys[i] = secret_keys.back();
      public_keys[i] = public_keys.back();
      secret_keys.pop_back();
      public_keys.pop_back();
      --i;
    }
    else
    {
      THROW_WALLET_EXCEPTION_IF(public_keys[i] == local_pkey, error::wallet_internal_error,
          "Found local spend public key, but not local view secret key - something very weird");
    }
  }
}

std::string wallet2::make_multisig(const epee::wipeable_string &password,
  const std::vector<std::string> &info,
  uint32_t threshold)
{
  std::vector<crypto::secret_key> secret_keys(info.size());
  std::vector<crypto::public_key> public_keys(info.size());
  unpack_multisig_info(info, public_keys, secret_keys);
  return make_multisig(password, secret_keys, public_keys, threshold);
}

bool wallet2::finalize_multisig(const epee::wipeable_string &password, const std::unordered_set<crypto::public_key> &pkeys, std::vector<crypto::public_key> signers)
{
  bool ready;
  uint32_t threshold, total;
  if (!multisig(&ready, &threshold, &total))
  {
    MERROR("This is not a multisig wallet");
    return false;
  }
  if (ready)
  {
    MERROR("This multisig wallet is already finalized");
    return false;
  }
  if (threshold + 1 != total)
  {
    MERROR("finalize_multisig should only be used for N-1/N wallets, use exchange_multisig_keys instead");
    return false;
  }
  exchange_multisig_keys(password, pkeys, signers);
  return true;
}

bool wallet2::unpack_extra_multisig_info(const std::vector<std::string>& info,
  std::vector<crypto::public_key> &signers,
  std::unordered_set<crypto::public_key> &pkeys) const
{
  // parse all multisig info
  signers.resize(info.size(), crypto::null_pkey);
  for (size_t i = 0; i < info.size(); ++i)
  {
      if (!verify_extra_multisig_info(info[i], pkeys, signers[i]))
      {
          return false;
      }
  }

  return true;
}

bool wallet2::finalize_multisig(const epee::wipeable_string &password, const std::vector<std::string> &info)
{
  std::unordered_set<crypto::public_key> public_keys;
  std::vector<crypto::public_key> signers;
  if (!unpack_extra_multisig_info(info, signers, public_keys))
  {
    MERROR("Bad multisig info");
    return false;
  }

  return finalize_multisig(password, public_keys, signers);
}

std::string wallet2::get_multisig_info() const
{
  // It's a signed package of private view key and public spend key
  const crypto::secret_key skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
  const crypto::public_key pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
  crypto::hash hash;

  std::string data;
  data += std::string((const char *)&skey, sizeof(crypto::secret_key));
  data += std::string((const char *)&pkey, sizeof(crypto::public_key));

  data.resize(data.size() + sizeof(crypto::signature));
  crypto::cn_fast_hash(data.data(), data.size() - sizeof(signature), hash);
  crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
  crypto::generate_signature(hash, pkey, get_multisig_blinded_secret_key(get_account().get_keys().m_spend_secret_key), signature);

  return std::string{MULTISIG_MAGIC} + tools::base58::encode(data);
}

bool wallet2::verify_multisig_info(const std::string &data, crypto::secret_key &skey, crypto::public_key &pkey)
{
  if (!tools::starts_with(data, MULTISIG_MAGIC))
  {
    MERROR("Multisig info header check error");
    return false;
  }
  std::string decoded;
  if (!tools::base58::decode(data.substr(MULTISIG_MAGIC.size()), decoded))
  {
    MERROR("Multisig info decoding error");
    return false;
  }
  if (decoded.size() != sizeof(crypto::secret_key) + sizeof(crypto::public_key) + sizeof(crypto::signature))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }

  size_t offset = 0;
  skey = *(const crypto::secret_key*)(decoded.data() + offset);
  offset += sizeof(skey);
  pkey = *(const crypto::public_key*)(decoded.data() + offset);
  offset += sizeof(pkey);
  const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset);

  crypto::hash hash;
  crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
  if (!crypto::check_signature(hash, pkey, signature))
  {
    MERROR("Multisig info signature is invalid");
    return false;
  }

  return true;
}

bool wallet2::verify_extra_multisig_info(const std::string &data, std::unordered_set<crypto::public_key> &pkeys, crypto::public_key &signer)
{
  if (!tools::starts_with(data, MULTISIG_EXTRA_INFO_MAGIC))
  {
    MERROR("Multisig info header check error");
    return false;
  }
  std::string decoded;
  if (!tools::base58::decode(data.substr(MULTISIG_EXTRA_INFO_MAGIC.size()), decoded))
  {
    MERROR("Multisig info decoding error");
    return false;
  }
  if (decoded.size() < sizeof(crypto::public_key) + sizeof(crypto::signature))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }
  if ((decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) % sizeof(crypto::public_key))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }

  const size_t n_keys = (decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) / sizeof(crypto::public_key);
  size_t offset = 0;
  signer = *(const crypto::public_key*)(decoded.data() + offset);
  offset += sizeof(signer);
  const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset + n_keys * sizeof(crypto::public_key));

  crypto::hash hash;
  crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
  if (!crypto::check_signature(hash, signer, signature))
  {
    MERROR("Multisig info signature is invalid");
    return false;
  }

  for (size_t n = 0; n < n_keys; ++n)
  {
    crypto::public_key mspk = *(const crypto::public_key*)(decoded.data() + offset);
    pkeys.insert(mspk);
    offset += sizeof(mspk);
  }

  return true;
}

bool wallet2::multisig(bool *ready, uint32_t *threshold, uint32_t *total) const
{
  if (!m_multisig)
    return false;
  if (threshold)
    *threshold = m_multisig_threshold;
  if (total)
    *total = m_multisig_signers.size();
  if (ready)
    *ready = !(get_account().get_keys().m_account_address.m_spend_public_key == rct::rct2pk(rct::identity()));
  return true;
}

bool wallet2::has_multisig_partial_key_images() const
{
  if (!m_multisig)
    return false;
  for (const auto &td: m_transfers)
    if (td.m_key_image_partial)
      return true;
  return false;
}

bool wallet2::has_unknown_key_images() const
{
  for (const auto &td: m_transfers)
    if (!td.m_key_image_known)
      return true;
  return false;
}

/*!
 * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
 * \param wallet_name Name of wallet file (should exist)
 * \param password    Password for wallet file
 */
void wallet2::rewrite(const fs::path& wallet_name, const epee::wipeable_string& password)
{
  if (wallet_name.empty())
    return;
  prepare_file_names(wallet_name);
  std::error_code ignored_ec;
  THROW_WALLET_EXCEPTION_IF(!fs::exists(m_keys_file, ignored_ec), error::file_not_found, m_keys_file);
  bool r = store_keys(m_keys_file, password, m_watch_only);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
}
/*!
 * \brief Writes to a file named based on the normal wallet (doesn't generate key, assumes it's already there)
 * \param wallet_name       Base name of wallet file
 * \param password          Password for wallet file
 * \param new_keys_filename [OUT] Name of new keys file
 */
void wallet2::write_watch_only_wallet(const fs::path& wallet_name, const epee::wipeable_string& password, fs::path& new_keys_filename)
{
  prepare_file_names(wallet_name);
  std::error_code ec;
  new_keys_filename = m_wallet_file;
  new_keys_filename += "-watchonly.keys";
  THROW_WALLET_EXCEPTION_IF(fs::exists(new_keys_filename, ec), error::file_save_error, new_keys_filename);
  bool r = store_keys(new_keys_filename, password, true);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, new_keys_filename);
}
//----------------------------------------------------------------------------------------------------
void wallet2::wallet_exists(const fs::path& file_path, bool& keys_file_exists, bool& wallet_file_exists)
{
  fs::path keys_file, wallet_file, mms_file;
  do_prepare_file_names(file_path, keys_file, wallet_file, mms_file);

  std::error_code ignore;
  keys_file_exists = fs::exists(keys_file, ignore);
  wallet_file_exists = fs::exists(wallet_file, ignore);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_payment_id(std::string_view payment_id_str, crypto::hash& payment_id)
{
  if (tools::hex_to_type(payment_id_str, payment_id))
    return true;
  crypto::hash8 payment_id8;
  if (tools::hex_to_type(payment_id_str, payment_id8))
  {
    payment_id = crypto::null_hash;
    std::memcpy(payment_id.data, payment_id8.data, sizeof(payment_id8));
    return true;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::prepare_file_names(const fs::path& file_path)
{
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file, m_mms_file);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::check_connection(rpc::version_t *version, bool *ssl, bool throw_on_http_error)
{
  THROW_WALLET_EXCEPTION_IF(!m_is_initialized, error::wallet_not_initialized);
  if (version) *version = {};

  if (m_offline)
  {
    m_rpc_version = 0;
    if (version)
      *version = {};
    if (ssl)
      *ssl = false;
    return false;
  }

  // TODO: Add light wallet version check.
  if(m_light_wallet) {
      m_rpc_version = 0;
      if (version)
        *version = {};
      if (ssl)
        *ssl = m_light_wallet_connected; // light wallet is always SSL
      return m_light_wallet_connected;
  }

  if (ssl)
    *ssl = tools::starts_with(m_http_client.get_base_url(), "https://");

  if (!m_rpc_version)
  {
    cryptonote::rpc::GET_VERSION::response resp_t{};
    bool r = invoke_http<rpc::GET_VERSION>({}, resp_t, throw_on_http_error);
    if(!r || resp_t.status != rpc::STATUS_OK) return false;
    m_rpc_version = resp_t.version;
  }
  if (version)
    *version = rpc::make_version(m_rpc_version);

  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_offline(bool offline)
{
  m_offline = offline;
  m_node_rpc_proxy.set_offline(offline);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  hw::device &hwdev =  m_account.get_device();
  return hwdev.generate_chacha_key(m_account.get_keys(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const
{
  crypto::generate_chacha_key(pass.data(), pass.size(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void wallet2::load(const fs::path& wallet_, const epee::wipeable_string& password, const std::string& keys_buf, const std::string& cache_buf)
{
  clear();
  prepare_file_names(wallet_);

  // determine if loading from file system or string buffer
  bool use_fs = !wallet_.empty();
  THROW_WALLET_EXCEPTION_IF((use_fs && !keys_buf.empty()) || (!use_fs && keys_buf.empty()), error::file_read_error, "must load keys either from file system or from buffer");\

  std::error_code e;
  if (use_fs)
  {
    bool exists = fs::exists(m_keys_file, e);
    THROW_WALLET_EXCEPTION_IF(e || !exists, error::file_not_found, m_keys_file);
    lock_keys_file();
    THROW_WALLET_EXCEPTION_IF(!is_keys_file_locked(), error::wallet_internal_error, "internal error: \"" + m_keys_file.u8string() + "\" is opened by another wallet program");

    // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
    unlock_keys_file();
    if (!load_keys(m_keys_file, password))
    {
      THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, m_keys_file);
    }
    LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str(m_nettype));
    lock_keys_file();
  }
  else if (!load_keys_buf(keys_buf, password))
  {
    THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, "failed to load keys from buffer");
  }

  wallet_keys_unlocker unlocker(*this, m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only, password);

  //keys loaded ok!
  //try to load wallet file. but even if we failed, it is not big problem
  if (use_fs && (!fs::exists(m_wallet_file, e) || e))
  {
    LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
    m_account_public_address = m_account.get_keys().m_account_address;
  }
  else if (use_fs || !cache_buf.empty())
  {
    wallet2::cache_file_data cache_file_data;
    std::string cache_file_buf;
    bool r = true;
    if (use_fs)
    {
      load_from_file(m_wallet_file, cache_file_buf);
      THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, m_wallet_file);
    }

    // try to read it as an encrypted cache
    try
    {
      LOG_PRINT_L1("Trying to decrypt cache data");

      try {
        serialization::parse_binary(use_fs ? cache_file_buf : cache_buf, cache_file_data);
      } catch (const std::exception& e) {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "internal error: failed to deserialize \"" + m_wallet_file.u8string() + "\": " + e.what());
      }
      std::string cache_data;
      cache_data.resize(cache_file_data.cache_data.size());
      crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cache_data[0]);

      try {
        std::stringstream iss;
        iss << cache_data;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> *this;
      }
      catch(...)
      {
        // try with previous scheme: direct from keys
        crypto::chacha_key key;
        generate_chacha_key_from_secret_keys(key);
        crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
        try {
          std::stringstream iss;
          iss << cache_data;
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> *this;
        }
        catch (...)
        {
          crypto::chacha8(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
          try
          {
            std::stringstream iss;
            iss << cache_data;
            boost::archive::portable_binary_iarchive ar(iss);
            ar >> *this;
          }
          catch (...)
          {
            LOG_PRINT_L0("Failed to open portable binary, trying unportable");
            auto unportable = m_wallet_file;
            unportable += ".unportable";
            if (use_fs) fs::copy_file(m_wallet_file, unportable, fs::copy_options::overwrite_existing);
            std::stringstream iss;
            iss << cache_data;
            boost::archive::binary_iarchive ar(iss);
            ar >> *this;
          }
        }
      }
    }
    catch (...)
    {
      LOG_PRINT_L1("Failed to load encrypted cache, trying unencrypted");
      try {
        std::stringstream iss;
        iss << cache_file_buf;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> *this;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to open portable binary, trying unportable");
        auto unportable = m_wallet_file;
        unportable += ".unportable";
        if (use_fs) fs::copy_file(m_wallet_file, unportable, fs::copy_options::overwrite_existing);
        std::stringstream iss;
        iss << cache_file_buf;
        boost::archive::binary_iarchive ar(iss);
        ar >> *this;
      }
    }
    THROW_WALLET_EXCEPTION_IF(
      m_account_public_address.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
      m_account_public_address.m_view_public_key  != m_account.get_keys().m_account_address.m_view_public_key,
      error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);
  }

  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);

  if (m_blockchain.empty())
  {
    m_blockchain.push_back(genesis_hash);
    m_last_block_reward = cryptonote::get_outs_money_amount(genesis.miner_tx);
  }
  else
  {
    check_genesis(genesis_hash);
  }

  trim_hashchain();

  if (get_num_subaddress_accounts() == 0)
    add_subaddress_account(tr("Primary account"));

  try
  {
    find_and_save_rings(false);
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to save rings, will try again next time");
  }

  try
  {
    if (use_fs)
      m_message_store.read_from_file(get_multisig_wallet_state(), m_mms_file);
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to initialize MMS, it will be unusable");
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::trim_hashchain()
{
  uint64_t height = 0;
  cryptonote::get_newest_hardcoded_checkpoint(nettype(), &height);

  for (const transfer_details &td: m_transfers)
    if (td.m_block_height < height)
      height = td.m_block_height;

  if (!m_blockchain.empty() && m_blockchain.size() == m_blockchain.offset())
  {
    MINFO("Fixing empty hashchain");
    cryptonote::rpc::GET_BLOCK_HEADER_BY_HEIGHT::request req{};
    cryptonote::rpc::GET_BLOCK_HEADER_BY_HEIGHT::response res{};
    req.height = m_blockchain.size() - 1;
    bool r = invoke_http<rpc::GET_BLOCK_HEADER_BY_HEIGHT>(req, res);
    if (r && res.status == rpc::STATUS_OK)
    {
      crypto::hash hash;
      tools::hex_to_type(res.block_header->hash, hash);
      m_blockchain.refill(hash);
    }
    else
    {
      MERROR("Failed to request block header from daemon, hash chain may be unable to sync till the wallet is loaded with a usable daemon");
    }
  }
  if (height > 0 && m_blockchain.size() > height)
  {
    --height;
    MDEBUG("trimming to " << height << ", offset " << m_blockchain.offset());
    m_blockchain.trim(height);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_genesis(const crypto::hash& genesis_hash) const {
  std::string what("Genesis block mismatch. (Perhaps you forgot to use --testnet or --stagenet for a testnet/stagenet wallet?)");

  THROW_WALLET_EXCEPTION_IF(genesis_hash != m_blockchain.genesis(), error::wallet_internal_error, what);
}
//----------------------------------------------------------------------------------------------------
const fs::path& wallet2::path() const
{
  return m_wallet_file;
}
//----------------------------------------------------------------------------------------------------
void wallet2::store()
{
  if (!m_wallet_file.empty())
    store_to("", epee::wipeable_string());
}
//----------------------------------------------------------------------------------------------------
void wallet2::store_to(const fs::path &path, const epee::wipeable_string &password)
{
  trim_hashchain();

  // if file is the same, we do:
  // 1. save wallet to the *.new file
  // 2. remove old wallet file
  // 3. rename *.new to wallet_name

  // handle if we want just store wallet state to current files (ex store() replacement);
  std::error_code ec;
  bool same_file = path.empty() || (fs::exists(path, ec) && fs::equivalent(m_wallet_file, path, ec));

  if (!same_file)
  {
    // check if we want to store to directory which doesn't exists yet
    auto parent_path = path.parent_path();

    // if path is not exists, try to create it
    if (!parent_path.empty() &&  !fs::exists(parent_path))
      fs::create_directories(parent_path);
  }

  // get wallet cache data
  std::optional<wallet2::cache_file_data> cache_file_data = get_cache_file_data(password);
  THROW_WALLET_EXCEPTION_IF(!cache_file_data, error::wallet_internal_error, "failed to generate wallet cache data");

  const auto& old_file = m_wallet_file;
  const auto& old_keys_file = m_keys_file;
  fs::path old_address_file = m_wallet_file;
  old_address_file += ".address.txt";
  const auto& old_mms_file = m_mms_file;

  // save keys to the new file
  // if we here, main wallet file is saved and we only need to save keys and address files
  if (!same_file) {
    prepare_file_names(path);
    bool r = store_keys(m_keys_file, password, false);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
    if (fs::exists(old_address_file))
    {
      // save address to the new file
      fs::path address_file = path;
      address_file += ".address.txt";
      r = save_to_file(address_file, m_account.get_public_address_str(m_nettype), true);
      THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_wallet_file);
      // remove old address file
      if (!fs::remove(old_address_file, ec))
        LOG_ERROR("error removing file: " << old_address_file << ": " << ec.message());
    }
    // remove old wallet file
    if (!fs::remove(old_file, ec))
      LOG_ERROR("error removing file: " << old_file << ": " << ec.message());
    // remove old keys file
    if (!fs::remove(old_keys_file, ec))
      LOG_ERROR("error removing file: " << old_keys_file << ": " << ec.message());
    // remove old message store file
    if (fs::exists(old_mms_file, ec) && !fs::remove(old_mms_file, ec))
      LOG_ERROR("error removing file: " << old_mms_file << ": " << ec.message());
  } else {
    // save to new file
    fs::path new_file = m_wallet_file;
    new_file += ".new";

    try {
      fs::ofstream ostr{new_file, std::ios_base::binary | std::ios_base::trunc};
      serialization::binary_archiver oar{ostr};
      serialization::serialize(oar, *cache_file_data);
    } catch (const std::exception& e) {
      THROW_WALLET_EXCEPTION(error::file_save_error, new_file);
    }

    // here we have "*.new" file, we need to rename it to be without ".new"
    std::error_code e;
#ifdef WIN32
    // std::filesystem on Windows seems buggy: the standard requires that it overwrites
    // (atomically), but it doesn't and instead fails when the file already exists, so manually
    // remove it first.  If it fails then just ignore it and let the rename try anyway.
    fs::remove(m_wallet_file, e);
#endif
    fs::rename(new_file, m_wallet_file, e);
    THROW_WALLET_EXCEPTION_IF(e, error::file_save_error, m_wallet_file, e);
  }

  if (m_message_store.get_active())
  {
    // While the "m_message_store" object of course always exist, a file for the message
    // store should only exist if the MMS is really active
    m_message_store.write_to_file(get_multisig_wallet_state(), m_mms_file);
  }
}
//----------------------------------------------------------------------------------------------------
std::optional<wallet2::cache_file_data> wallet2::get_cache_file_data(const epee::wipeable_string &passwords)
{
  trim_hashchain();
  try
  {
    std::stringstream oss;
    boost::archive::portable_binary_oarchive ar(oss);
    ar << *this;

    std::optional<wallet2::cache_file_data> cache_file_data = (wallet2::cache_file_data) {};
    cache_file_data->cache_data = oss.str();
    std::string cipher;
    cipher.resize(cache_file_data->cache_data.size());
    cache_file_data->iv = crypto::rand<crypto::chacha_iv>();
    crypto::chacha20(cache_file_data->cache_data.data(), cache_file_data->cache_data.size(), m_cache_key, cache_file_data->iv, &cipher[0]);
    cache_file_data->cache_data = cipher;
    return cache_file_data;
  }
  catch(...)
  {
    return std::nullopt;
  }
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance(uint32_t index_major, bool strict) const
{
  uint64_t amount = 0;
  if(m_light_wallet)
    return m_light_wallet_unlocked_balance;
  for (const auto& i : balance_per_subaddress(index_major, strict))
    amount += i.second;
  return amount;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance(uint32_t index_major, bool strict, uint64_t *blocks_to_unlock, uint64_t *time_to_unlock) const
{
  uint64_t amount = 0;
  if (blocks_to_unlock)
    *blocks_to_unlock = 0;
  if (time_to_unlock)
    *time_to_unlock = 0;
  if(m_light_wallet)
    return m_light_wallet_balance;
  for (const auto& i : unlocked_balance_per_subaddress(index_major, strict))
  {
    amount += i.second.first;
    if (blocks_to_unlock && i.second.second.first > *blocks_to_unlock)
      *blocks_to_unlock = i.second.second.first;
    if (time_to_unlock && i.second.second.second > *time_to_unlock)
      *time_to_unlock = i.second.second.second;
  }
  return amount;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, uint64_t> wallet2::balance_per_subaddress(uint32_t index_major, bool strict) const
{
  std::map<uint32_t, uint64_t> amount_per_subaddr;
  for (const auto& td: m_transfers)
  {
    if (td.m_subaddr_index.major == index_major && !is_spent(td, strict) && !td.m_frozen)
    {
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
      else
        found->second += td.amount();
    }
  }
  if (!strict)
  {
   for (const auto& utx: m_unconfirmed_txs)
   {
    if (utx.second.m_subaddr_account == index_major && utx.second.m_state != wallet2::unconfirmed_transfer_details::failed)
    {
      // all changes go to 0-th subaddress (in the current subaddress account)
      auto found = amount_per_subaddr.find(0);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[0] = utx.second.m_change;
      else
        found->second += utx.second.m_change;
    }
   }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> wallet2::unlocked_balance_per_subaddress(uint32_t index_major, bool strict) const
{
  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> amount_per_subaddr;
  const uint64_t blockchain_height = get_blockchain_current_height();
  const uint64_t now = time(NULL);
  for(const transfer_details& td: m_transfers)
  {
    if(td.m_subaddr_index.major == index_major && !is_spent(td, strict) && !td.m_frozen)
    {
      uint64_t amount = 0, blocks_to_unlock = 0, time_to_unlock = 0;
      if (is_transfer_unlocked(td))
      {
        amount = td.amount();
        blocks_to_unlock = 0;
        time_to_unlock = 0;
      }
      else
      {
        uint64_t unlock_height = td.m_unmined_blink && td.m_block_height == 0 ? blockchain_height : td.m_block_height;
        unlock_height += std::max<uint64_t>(CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE, CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);
        if (td.m_tx.unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER && td.m_tx.unlock_time > unlock_height)
          unlock_height = td.m_tx.unlock_time;
        uint64_t unlock_time = td.m_tx.unlock_time >= CRYPTONOTE_MAX_BLOCK_NUMBER ? td.m_tx.unlock_time : 0;
        blocks_to_unlock = unlock_height > blockchain_height ? unlock_height - blockchain_height : 0;
        time_to_unlock = unlock_time > now ? unlock_time - now : 0;
        amount = 0;
      }
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = std::make_pair(amount, std::make_pair(blocks_to_unlock, time_to_unlock));
      else
      {
        found->second.first += amount;
        found->second.second.first = std::max(found->second.second.first, blocks_to_unlock);
        found->second.second.second = std::max(found->second.second.second, time_to_unlock);
      }
    }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance_all(bool strict) const
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
    r += balance(index_major, strict);
  return r;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance_all(bool strict, uint64_t *blocks_to_unlock, uint64_t *time_to_unlock) const
{
  uint64_t r = 0;
  if (blocks_to_unlock)
    *blocks_to_unlock = 0;
  if (time_to_unlock)
    *time_to_unlock = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
  {
    uint64_t local_blocks_to_unlock, local_time_to_unlock;
    r += unlocked_balance(index_major, strict, blocks_to_unlock ? &local_blocks_to_unlock : NULL, time_to_unlock ? &local_time_to_unlock : NULL);
    if (blocks_to_unlock)
      *blocks_to_unlock = std::max(*blocks_to_unlock, local_blocks_to_unlock);
    if (time_to_unlock)
      *time_to_unlock = std::max(*time_to_unlock, local_time_to_unlock);
  }
  return r;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_transfers(wallet2::transfer_container& incoming_transfers) const
{
  incoming_transfers = m_transfers;
}
//------------------------------------------------------------------------------------------------------------------------------
static void set_confirmations(wallet::transfer_view &entry, uint64_t blockchain_height, uint64_t block_reward)
{
  if (entry.height >= blockchain_height || (entry.height == 0 && (entry.blink_mempool || entry.type == "pending" || entry.type == "pool")))
    entry.confirmations = 0;
  else
    entry.confirmations = blockchain_height - entry.height;

  if (block_reward == 0 || entry.blink_mempool || entry.was_blink)
    entry.suggested_confirmations_threshold = 0;
  else
    entry.suggested_confirmations_threshold = (entry.amount + block_reward - 1) / block_reward;
}
//----------------------------------------------------------------------------------------------------
wallet::transfer_view wallet2::make_transfer_view(const crypto::hash &txid, const crypto::hash &payment_id, const tools::wallet2::payment_details &pd) const
{
  wallet::transfer_view result = {};
  result.txid = tools::type_to_hex(pd.m_tx_hash);
  result.hash = txid;
  result.payment_id = tools::type_to_hex(payment_id);
  if (result.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
    result.payment_id = result.payment_id.substr(0,16);
  result.height = pd.m_block_height;
  result.timestamp = pd.m_timestamp;
  result.amount = pd.m_amount;
  result.unlock_time = pd.m_unlock_time;
  result.fee = pd.m_fee;
  result.note = get_tx_note(pd.m_tx_hash);
  result.pay_type = pd.m_type;
  result.subaddr_index = pd.m_subaddr_index;
  result.subaddr_indices.push_back(pd.m_subaddr_index);
  result.address = get_subaddress_as_str(pd.m_subaddr_index);
  result.confirmed = true;
  result.blink_mempool = pd.m_unmined_blink;
  result.was_blink = pd.m_was_blink;
  // TODO(sacha): is this just for in or also coinbase?
  const bool unlocked = is_transfer_unlocked(result.unlock_time, result.height, result.blink_mempool);
  result.locked = !unlocked;
  result.lock_msg = unlocked ? "unlocked" : "locked";
  set_confirmations(result, get_blockchain_current_height(), get_last_block_reward());
  result.checkpointed = (result.height == 0 && pd.m_unmined_blink ? false : result.height <= m_immutable_height);
  return result;
}
//------------------------------------------------------------------------------------------------------------------------------
wallet::transfer_view wallet2::wallet2::make_transfer_view(const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd) const
{
  wallet::transfer_view result = {};
  result.txid = tools::type_to_hex(txid);
  result.hash = txid;
  result.payment_id = tools::type_to_hex(pd.m_payment_id);
  if (result.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
    result.payment_id = result.payment_id.substr(0,16);
  result.height = pd.m_block_height;
  result.timestamp = pd.m_timestamp;
  result.unlock_time = pd.m_unlock_time;
  result.locked = !is_transfer_unlocked(pd.m_unlock_time, pd.m_block_height, false);
  result.fee = pd.m_amount_in - pd.m_amount_out;
  uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
  result.amount = pd.m_amount_in - change - result.fee;
  result.note = get_tx_note(txid);

  for (const auto &d: pd.m_dests) {
    result.destinations.push_back({});
    auto& td = result.destinations.back();
    td.amount = d.amount;
    td.address = d.address(nettype(), pd.m_payment_id);
  }

  result.pay_type = pd.m_pay_type;
  result.subaddr_index = { pd.m_subaddr_account, 0 };
  for (uint32_t i: pd.m_subaddr_indices)
    result.subaddr_indices.push_back({pd.m_subaddr_account, i});
  result.address = get_subaddress_as_str({pd.m_subaddr_account, 0});
  result.confirmed = true;
  result.checkpointed = result.height <= m_immutable_height;
  set_confirmations(result, get_blockchain_current_height(), get_last_block_reward());
  return result;
}
//------------------------------------------------------------------------------------------------------------------------------
wallet::transfer_view wallet2::make_transfer_view(const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd) const
{
  wallet::transfer_view result = {};
  bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
  result.txid = tools::type_to_hex(txid);
  result.hash = txid;
  result.payment_id = tools::type_to_hex(pd.m_payment_id);
  result.payment_id = tools::type_to_hex(pd.m_payment_id);
  if (result.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
    result.payment_id = result.payment_id.substr(0,16);
  result.height = 0;
  result.timestamp = pd.m_timestamp;
  result.fee = pd.m_amount_in - pd.m_amount_out;
  result.amount = pd.m_amount_in - pd.m_change - result.fee;
  result.unlock_time = pd.m_tx.unlock_time;
  result.locked = true;
  result.note = get_tx_note(txid);

  for (const auto &d: pd.m_dests) {
    result.destinations.push_back({});
    auto& td = result.destinations.back();
    td.amount = d.amount;
    td.address = d.address(nettype(), pd.m_payment_id);
  }

  result.pay_type = pd.m_pay_type;
  result.type = is_failed ? "failed" : "pending";
  result.subaddr_index = { pd.m_subaddr_account, 0 };
  for (uint32_t i: pd.m_subaddr_indices)
    result.subaddr_indices.push_back({pd.m_subaddr_account, i});
  result.address = get_subaddress_as_str({pd.m_subaddr_account, 0});
  set_confirmations(result, get_blockchain_current_height(), get_last_block_reward());
  return result;
}
//------------------------------------------------------------------------------------------------------------------------------
wallet::transfer_view wallet2::make_transfer_view(const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &ppd) const
{
  wallet::transfer_view result = {};
  const tools::wallet2::payment_details &pd = ppd.m_pd;
  result.txid = tools::type_to_hex(pd.m_tx_hash);
  result.hash = pd.m_tx_hash;
  result.payment_id = tools::type_to_hex(payment_id);
  if (result.payment_id.substr(16).find_first_not_of('0') == std::string::npos)
    result.payment_id = result.payment_id.substr(0,16);
  result.height = 0;
  result.timestamp = pd.m_timestamp;
  result.amount = pd.m_amount;
  result.unlock_time = pd.m_unlock_time;
  result.locked = true;
  result.fee = pd.m_fee;
  result.note = get_tx_note(pd.m_tx_hash);
  result.double_spend_seen = ppd.m_double_spend_seen;
  result.pay_type = wallet::pay_type::unspecified;
  result.type = "pool";
  result.subaddr_index = pd.m_subaddr_index;
  result.subaddr_indices.push_back(pd.m_subaddr_index);
  result.address = get_subaddress_as_str(pd.m_subaddr_index);
  set_confirmations(result, get_blockchain_current_height(), get_last_block_reward());
  return result;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_transfers(get_transfers_args_t args, std::vector<wallet::transfer_view>& transfers)
{
  std::optional<uint32_t> account_index = args.account_index;
  if (args.all_accounts)
  {
    account_index = std::nullopt;
    args.subaddr_indices.clear();
  }
  if (args.filter_by_height)
  {
    args.max_height = std::max<uint64_t>(args.max_height, args.min_height);
    args.max_height = std::min<uint64_t>(args.max_height, CRYPTONOTE_MAX_BLOCK_NUMBER);
  }

  int args_count = args.in + args.out + args.stake + args.pending + args.failed + args.pool + args.coinbase;
  if (args_count == 0) args.in = args.out = args.stake = args.pending = args.failed = args.pool = args.coinbase = true;

  std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> in;
  std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> out;
  std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> pending_or_failed;
  std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> pool;

  MDEBUG("Getting transfers of type(s) " << (args.in ? "in " : "") << (args.out ? "out " : "") << (args.pending ? "pending " : "") << (args.failed ? "failed " : "")
      << (args.pool ? "pool " : "") << " for heights in [" << args.min_height << "," << args.max_height << "]");

  size_t size = 0;
  if (args.in)
  {
    get_payments(in, args.min_height, args.max_height, account_index, args.subaddr_indices);
    size += in.size();
  }

  if (args.out || args.stake)
  {
    get_payments_out(out, args.min_height, args.max_height, account_index, args.subaddr_indices);
    size += out.size();
  }

  if (args.pending || args.failed)
  {
    get_unconfirmed_payments_out(pending_or_failed, account_index, args.subaddr_indices);
    size += pending_or_failed.size();
  }

  if (args.pool)
  {
    get_unconfirmed_payments(pool, account_index, args.subaddr_indices);
    size += pool.size();
  }

  // Fill transfers
  transfers.reserve(size);
  for (const auto &i : in)
    transfers.push_back(make_transfer_view(i.second.m_tx_hash, i.first, i.second));
  for (const auto &o : out)
  {
    bool add_entry = true;
    if (args.stake && args_count == 1)
      add_entry = o.second.m_pay_type == wallet::pay_type::stake;
    if (args.ons && args_count == 1)
      add_entry = o.second.m_pay_type == wallet::pay_type::ons;

    if (add_entry)
      transfers.push_back(make_transfer_view(o.first, o.second));
  }
  for (const auto &pof : pending_or_failed)
  {
    bool is_failed = pof.second.m_state == tools::wallet2::unconfirmed_transfer_details::failed;
    if (is_failed ? args.failed : args.pending)
      transfers.push_back(make_transfer_view(pof.first, pof.second));
  }
  for (const auto &p : pool)
    transfers.push_back(make_transfer_view(p.first, p.second));

  std::sort(transfers.begin(), transfers.end(), [](const auto& a, const auto& b) -> bool {
    if (a.confirmed != b.confirmed)
      return a.confirmed;
    if (a.blink_mempool != b.blink_mempool)
      return b.blink_mempool;
    if (a.height != b.height)
      return a.height < b.height;
    if (a.timestamp != b.timestamp)
      return a.timestamp < b.timestamp;
    return a.hash < b.hash;
  });
}

std::string wallet2::transfers_to_csv(const std::vector<wallet::transfer_view>& transfers, bool formatting) const
{
  uint64_t running_balance = 0;
  auto data_formatter  = boost::format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'%s',%s");
  auto title_formatter = boost::format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s");
  if (formatting)
  {
    title_formatter = boost::format("%8.8s,%9.9s,%8.8s,%14.14s,%16.16s,%20.20s,%20.20s,%64.64s,%16.16s,%14.14s,%100.100s,%20.20s,%s,%s");
    data_formatter  = boost::format("%8.8s,%9.9s,%8.8s,%14.14s,%16.16s,%20.20s,%20.20s,%64.64s,%16.16s,%14.14s,%100.100s,%20.20s,\"%s\",%s");
  }

  auto new_line = [&](std::stringstream& output){
    if (formatting)
    {
      output << std::endl;
    } else
    {
      output << "\r\n";
    }
  };


  std::stringstream output;
  output << title_formatter
    % tr("block")
    % tr("type")
    % tr("lock")
    % tr("checkpointed")
    % tr("timestamp")
    % tr("amount")
    % tr("running balance")
    % tr("hash")
    % tr("payment ID")
    % tr("fee")
    % tr("destination")
    % tr("amount")
    % tr("index")
    % tr("note");
  new_line(output);

  for (const auto& transfer : transfers)
  {
    switch (transfer.pay_type)
    {
      case wallet::pay_type::in:
      case wallet::pay_type::miner:
      case wallet::pay_type::service_node:
      case wallet::pay_type::governance:
        running_balance += transfer.amount;
        break;
      case wallet::pay_type::stake:
      case wallet::pay_type::ons:
        running_balance -= transfer.fee;
        break;
      case wallet::pay_type::out:
        running_balance -= transfer.amount + transfer.fee;
        break;
      default:
        MERROR("Warning: Unhandled pay type, this is most likely a developer error, please report it to the Loki developers.");
        break;
    }

    std::string indices;
    for (auto &index : transfer.subaddr_indices) {
      if (!indices.empty()) indices += ", ";
      indices += std::to_string(index.minor);
    }

    output << data_formatter
      % (transfer.type.size() ? transfer.type : std::to_string(transfer.height))
      % pay_type_string(transfer.pay_type)
      % transfer.lock_msg
      % (transfer.checkpointed ? "checkpointed" : "no")
      % tools::get_human_readable_timestamp(transfer.timestamp)
      % cryptonote::print_money(transfer.amount)
      % cryptonote::print_money(running_balance)
      % transfer.txid
      % transfer.payment_id
      % cryptonote::print_money(transfer.fee)
      % (transfer.destinations.size() ? transfer.destinations.front().address : "-")
      % (transfer.destinations.size() ? cryptonote::print_money(transfer.destinations.front().amount) : "")
      % indices
      % transfer.note;
    new_line(output);

    if (transfer.destinations.size() <= 1)
      continue;

    // print subsequent destination addresses and amounts
    // (start at begin + 1 with std::next)
    for (auto it = std::next(transfer.destinations.cbegin()); it != transfer.destinations.cend(); ++it)
    {
      output << data_formatter
        % ""
        % ""
        % ""
        % ""
        % ""
        % ""
        % ""
        % ""
        % ""
        % ""
        % it->address
        % cryptonote::print_money(it->amount)
        % ""
        % "";
      new_line(output);
    }
  }
  return output.str();
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = m_payments.equal_range(payment_id);
  std::for_each(range.first, range.second, [&payments, &min_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
      if (min_height <= x.second.m_block_height &&
          (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
          (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
      {
      payments.push_back(x.second);
      }
      });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height, uint64_t max_height, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = std::make_pair(m_payments.begin(), m_payments.end());
  std::for_each(range.first, range.second, [&payments, &min_height, &max_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
      if (min_height <= x.second.m_block_height && max_height >= x.second.m_block_height &&
          (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
          (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
      {
      payments.push_back(x);
      }
      });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>>& confirmed_payments,
    uint64_t min_height, uint64_t max_height, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_confirmed_txs.begin(); i != m_confirmed_txs.end(); ++i) {
    if (i->second.m_block_height < min_height || i->second.m_block_height > max_height)
      continue;
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_txs.begin(); i != m_unconfirmed_txs.end(); ++i) {
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
std::optional<std::string> wallet2::resolve_address(std::string address, uint64_t height)
{

  // addr_response will have an encrypted value
  cryptonote::address_parse_info info;
  bool result = false;
  if (cryptonote::get_account_address_from_str(info, m_nettype, address))
  {
    result = true;
  } else {
    std::string name = tools::lowercase_ascii_string(std::move(address));
    std::string reason;
    if (ons::validate_ons_name(ons::mapping_type::wallet, name, &reason))
    {
      std::string b64_hashed_name = ons::name_to_base64_hash(name);
      rpc::ONS_RESOLVE::request lookup_req{1, b64_hashed_name};
      auto [success, addr_response] = resolve(lookup_req);
      if (success && addr_response.encrypted_value)
      {
        std::optional<cryptonote::address_parse_info> addr_info = ons::encrypted_wallet_value_to_info(name, *addr_response.encrypted_value, *addr_response.nonce);
        if (addr_info)
        {
          info = std::move(*addr_info);
          result = true;
          LOG_PRINT_L2("Resolved ONS name: "<< address << " to address: " << get_account_address_as_str(m_nettype, info.is_subaddress, info.address));
        }
      }

    } else {
      LOG_PRINT_L2("Invalid address format, could not resolve " << address);
    }
  }

  if (result)
    return get_account_address_as_str(m_nettype, info.is_subaddress, info.address);
  else 
    return std::nullopt;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet2::pool_payment_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_payments.begin(); i != m_unconfirmed_payments.end(); ++i) {
    if ((!subaddr_account || *subaddr_account == i->second.m_pd.m_subaddr_index.major) &&
        (subaddr_indices.empty() || subaddr_indices.count(i->second.m_pd.m_subaddr_index.minor) == 1))
      unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::rescan_spent()
{
  // This is RPC call that can take a long time if there are many outputs,
  // so we call it several times, in stripes, so we don't time out spuriously
  std::vector<int> spent_status;
  spent_status.reserve(m_transfers.size());
  const size_t chunk_size = 1000;
  for (size_t start_offset = 0; start_offset < m_transfers.size(); start_offset += chunk_size)
  {
    const size_t n_outputs = std::min<size_t>(chunk_size, m_transfers.size() - start_offset);
    MDEBUG("Calling is_key_image_spent on " << start_offset << " - " << (start_offset + n_outputs - 1) << ", out of " << m_transfers.size());
    rpc::IS_KEY_IMAGE_SPENT::request req{};
    rpc::IS_KEY_IMAGE_SPENT::response daemon_resp{};
    for (size_t n = start_offset; n < start_offset + n_outputs; ++n)
      req.key_images.push_back(tools::type_to_hex(m_transfers[n].m_key_image));
    bool r = invoke_http<rpc::IS_KEY_IMAGE_SPENT>(req, daemon_resp);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "is_key_image_spent");
    THROW_WALLET_EXCEPTION_IF(daemon_resp.status == rpc::STATUS_BUSY, error::daemon_busy, "is_key_image_spent");
    THROW_WALLET_EXCEPTION_IF(daemon_resp.status != rpc::STATUS_OK, error::is_key_image_spent_error, get_rpc_status(daemon_resp.status));
    THROW_WALLET_EXCEPTION_IF(daemon_resp.spent_status.size() != n_outputs, error::wallet_internal_error,
        "daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
        std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(n_outputs));
    std::copy(daemon_resp.spent_status.begin(), daemon_resp.spent_status.end(), std::back_inserter(spent_status));
  }

  // update spent status
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    transfer_details& td = m_transfers[i];
    // a view wallet may not know about key images
    if (!td.m_key_image_known || td.m_key_image_partial)
      continue;
    if (td.m_spent != (spent_status[i] != rpc::IS_KEY_IMAGE_SPENT::UNSPENT))
    {
      if (td.m_spent)
      {
        LOG_PRINT_L0("Marking output " << i << "(" << td.m_key_image << ") as unspent, it was marked as spent");
        set_unspent(i);
        td.m_spent_height = 0;
      }
      else
      {
        LOG_PRINT_L0("Marking output " << i << "(" << td.m_key_image << ") as spent, it was marked as unspent");
        set_spent(i, td.m_spent_height);
        // unknown height, if this gets reorged, it might still be missed
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::rescan_blockchain(bool hard, bool refresh, bool keep_key_images)
{
  CHECK_AND_ASSERT_THROW_MES(!hard || !keep_key_images, "Cannot preserve key images on hard rescan");
  const size_t transfers_cnt = m_transfers.size();
  crypto::hash transfers_hash{};

  if(hard)
  {
    clear();
    setup_new_blockchain();
  }
  else
  {
    if (keep_key_images && refresh)
      hash_m_transfers((int64_t) transfers_cnt, transfers_hash);
    clear_soft(keep_key_images);
  }

  if (refresh)
    this->refresh(false);

  if (refresh && keep_key_images)
    finish_rescan_bc_keep_key_images(transfers_cnt, transfers_hash);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(const transfer_details& td) const
{
  return is_transfer_unlocked(td.m_tx.get_unlock_time(td.m_internal_output_index), td.m_block_height, td.m_unmined_blink, &td.m_key_image);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height, bool unmined_blink, crypto::key_image const *key_image) const
{
  auto blockchain_height = get_blockchain_current_height();
  if (block_height == 0 && unmined_blink)
  {
    // TODO(oxen): this restriction will go away when we add Reblink support, but for now received
    // blinks still have to be mined and confirmed like regular transactions before they can be
    // spent (blink without reblink just gives you a guarantee that they will be mined).
    //
    // Guess that the blink will go into the next block (if we're wrong then the displayed
    // blocks-to-unlock count will be wrong, but that's not a huge deal).
    block_height = blockchain_height;
  }

  if(!is_tx_spendtime_unlocked(unlock_time, block_height))
    return false;

  if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > blockchain_height)
    return false;

  if (m_offline)
    return true;

  if (!key_image) // TODO(oxen): Try make all callees always pass in a key image for accuracy
    return true;

  {
    std::optional<std::string> failed;
    // FIXME: can just check one here by adding a is_key_image_blacklisted
    auto [success, blacklist] = m_node_rpc_proxy.get_service_node_blacklisted_key_images();
    if (!success)
    {
      // We'll already have a log message printed containing the request failure reason
      LOG_PRINT_L1("Failed to query service node for blacklisted transfers, assuming transfer not blacklisted");
      return true;
    }

    for (cryptonote::rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry const &entry : blacklist)
    {
      crypto::key_image check_image;
      if(!tools::hex_to_type(entry.key_image, check_image))
      {
        MERROR("Failed to parse hex representation of key image: " << entry.key_image);
        break;
      }

      if (*key_image == check_image)
        return false;
    }
  }

  {
    const std::string primary_address = get_address_as_str();
    std::optional<std::string> failed;
    auto [success, service_nodes_states] = m_node_rpc_proxy.get_contributed_service_nodes(primary_address);
    if (!success)
    {
      LOG_PRINT_L1("Failed to query service node for locked transfers, assuming transfer not locked");
      return true;
    }

    for (cryptonote::rpc::GET_SERVICE_NODES::response::entry const &entry : service_nodes_states)
    {
      for (auto const& contributor : entry.contributors)
      {
        if (primary_address != contributor.address)
          continue;

        for (auto const &contribution : contributor.locked_contributions)
        {
          crypto::key_image check_image;
          if(!tools::hex_to_type(contribution.key_image, check_image))
          {
            MERROR("Failed to parse hex representation of key image: " << contribution.key_image);
            break;
          }

          if (*key_image == check_image)
            return false;
        }
      }
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height) const
{
  return cryptonote::rules::is_output_unlocked(unlock_time, get_blockchain_current_height());
}
//----------------------------------------------------------------------------------------------------
namespace
{
  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = vec[idx];
    if (idx + 1 != vec.size())
    {
      vec[idx] = vec.back();
    }
    vec.resize(vec.size() - 1);

    return res;
  }

  template<typename T>
  T pop_random_value(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand_idx(vec.size());
    return pop_index (vec, idx);
  }

  template<typename T>
  T pop_back(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    T res = vec.back();
    vec.pop_back();
    return res;
  }

  template<typename T>
  void pop_if_present(std::vector<T>& vec, T e)
  {
    for (size_t i = 0; i < vec.size(); ++i)
    {
      if (e == vec[i])
      {
        pop_index (vec, i);
        return;
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
// This returns a handwavy estimation of how much two outputs are related
// If they're from the same tx, then they're fully related. From close block
// heights, they're kinda related. The actual values don't matter, just
// their ordering, but it could become more murky if we add scores later.
float wallet2::get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const
{
  int dh;

  // expensive test, and same tx will fall onto the same block height below
  if (td0.m_txid == td1.m_txid)
    return 1.0f;

  // same block height -> possibly tx burst, or same tx (since above is disabled)
  dh = td0.m_block_height > td1.m_block_height ? td0.m_block_height - td1.m_block_height : td1.m_block_height - td0.m_block_height;
  if (dh == 0)
    return 0.9f;

  // adjacent blocks -> possibly tx burst
  if (dh == 1)
    return 0.8f;

  // could extract the payment id, and compare them, but this is a bit expensive too

  // similar block heights
  if (dh < 10)
    return 0.2f;

  // don't think these are particularly related
  return 0.0f;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  std::vector<size_t> candidates;
  float best_relatedness = 1.0f;
  for (size_t n = 0; n < unused_indices.size(); ++n)
  {
    const transfer_details &candidate = transfers[unused_indices[n]];
    float relatedness = 0.0f;
    for (std::vector<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
    {
      float r = get_output_relatedness(candidate, transfers[*i]);
      if (r > relatedness)
      {
        relatedness = r;
        if (relatedness == 1.0f)
          break;
      }
    }

    if (relatedness < best_relatedness)
    {
      best_relatedness = relatedness;
      candidates.clear();
    }

    if (relatedness == best_relatedness)
      candidates.push_back(n);
  }

  // we have all the least related outputs in candidates, so we can pick either
  // the smallest, or a random one, depending on request
  size_t idx;
  if (smallest)
  {
    idx = 0;
    for (size_t n = 0; n < candidates.size(); ++n)
    {
      const transfer_details &td = transfers[unused_indices[candidates[n]]];
      if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
        idx = n;
    }
  }
  else
  {
    idx = crypto::rand_idx(candidates.size());
  }
  return pop_index (unused_indices, candidates[idx]);
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value(std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  return pop_best_value_from(m_transfers, unused_indices, selected_transfers, smallest);
}
//----------------------------------------------------------------------------------------------------
// Select random input sources for transaction.
// returns:
//    direct return: amount of money found
//    modified reference: selected_transfers, a list of iterators/indices of input sources
uint64_t wallet2::select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers) const
{
  uint64_t found_money = 0;
  selected_transfers.reserve(unused_transfers_indices.size());
  while (found_money < needed_money && !unused_transfers_indices.empty())
  {
    size_t idx = pop_best_value(unused_transfers_indices, selected_transfers);

    const transfer_container::const_iterator it = m_transfers.begin() + idx;
    selected_transfers.push_back(idx);
    found_money += it->amount();
  }

  return found_money;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  unconfirmed_transfer_details& utd = m_unconfirmed_txs[cryptonote::get_transaction_hash(tx)];
  utd.m_amount_in = amount_in;
  utd.m_amount_out = 0;
  for (const auto &d: dests)
    utd.m_amount_out += d.amount;
  utd.m_amount_out += change_amount; // dests does not contain change
  utd.m_change = change_amount;
  utd.m_sent_time = time(NULL);
  utd.m_tx = (const cryptonote::transaction_prefix&)tx;
  utd.m_dests = dests;
  utd.m_payment_id = payment_id;
  utd.m_state = wallet2::unconfirmed_transfer_details::pending;
  utd.m_timestamp = time(NULL);
  utd.m_subaddr_account = subaddr_account;
  utd.m_subaddr_indices = subaddr_indices;
  utd.m_pay_type = wallet::pay_type_from_tx(tx);
  for (const auto &in: tx.vin)
  {
    if (!std::holds_alternative<cryptonote::txin_to_key>(in))
      continue;
    const auto &txin = var::get<cryptonote::txin_to_key>(in);
    utd.m_rings.push_back(std::make_pair(txin.k_image, txin.key_offsets));
  }
}

//----------------------------------------------------------------------------------------------------
crypto::hash wallet2::get_payment_id(const pending_tx &ptx) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  tx_extra_nonce extra_nonce;
  crypto::hash payment_id = null_hash;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    crypto::hash8 payment_id8 = null_hash8;
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return crypto::null_hash;
      }
      if (m_account.get_device().decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key))
      {
        memcpy(payment_id.data, payment_id8.data, 8);
      }
    }
    else if (!get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
    {
      payment_id = crypto::null_hash;
    }
  }
  return payment_id;
}
//----------------------------------------------------------------------------------------------------
// take a pending tx and actually send it to the daemon
void wallet2::commit_tx(pending_tx& ptx, bool blink)
{
  if(m_light_wallet)
  {
    light_rpc::SUBMIT_RAW_TX::request oreq{};
    light_rpc::SUBMIT_RAW_TX::response ores{};
    oreq.address = get_account().get_public_address_str(m_nettype);
    oreq.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
    oreq.tx = oxenmq::to_hex(tx_to_blob(ptx.tx));
    oreq.blink = blink;
    bool r = invoke_http<light_rpc::SUBMIT_RAW_TX>(oreq, ores);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "submit_raw_tx");
    // MyMonero and OpenMonero use different status strings
    THROW_WALLET_EXCEPTION_IF(ores.status != "OK" && ores.status != "success" , error::tx_rejected, ptx.tx, get_rpc_status(ores.status), ores.error);
  }
  else
  {
    // Normal submit
    rpc::SEND_RAW_TX::request req{};
    req.tx_as_hex = oxenmq::to_hex(tx_to_blob(ptx.tx));
    req.do_not_relay = false;
    req.do_sanity_checks = true;
    req.blink = blink;
    rpc::SEND_RAW_TX::response daemon_send_resp{};
    bool r = invoke_http<rpc::SEND_RAW_TX>(req, daemon_send_resp);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "sendrawtransaction");
    THROW_WALLET_EXCEPTION_IF(daemon_send_resp.status == rpc::STATUS_BUSY, error::daemon_busy, "sendrawtransaction");
    if (blink)
      THROW_WALLET_EXCEPTION_IF(daemon_send_resp.status != rpc::STATUS_OK, error::tx_blink_rejected, ptx.tx, get_rpc_status(daemon_send_resp.status), get_text_reason(daemon_send_resp, &ptx.tx, blink));
    else
      THROW_WALLET_EXCEPTION_IF(daemon_send_resp.status != rpc::STATUS_OK, error::tx_rejected,       ptx.tx, get_rpc_status(daemon_send_resp.status), get_text_reason(daemon_send_resp, &ptx.tx, blink));
    // sanity checks
    for (size_t idx: ptx.selected_transfers)
    {
      THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error,
          "Bad output index in selected transfers: " + boost::lexical_cast<std::string>(idx));
    }
  }
  crypto::hash txid;

  txid = get_transaction_hash(ptx.tx);
  crypto::hash payment_id = crypto::null_hash;
  std::vector<cryptonote::tx_destination_entry> dests;
  uint64_t amount_in = 0;
  if (store_tx_info())
  {
    payment_id = get_payment_id(ptx);
    dests = ptx.dests;
    for(size_t idx: ptx.selected_transfers)
      amount_in += m_transfers[idx].amount();
  }
  add_unconfirmed_tx(ptx.tx, amount_in, dests, payment_id, ptx.change_dts.amount, ptx.construction_data.subaddr_account, ptx.construction_data.subaddr_indices);
  if (store_tx_info() && ptx.tx_key != crypto::null_skey)
  {
    m_tx_keys.insert(std::make_pair(txid, ptx.tx_key));
    m_additional_tx_keys.insert(std::make_pair(txid, ptx.additional_tx_keys));
  }

  LOG_PRINT_L2("transaction " << txid << " generated ok and sent to daemon, key_images: [" << ptx.key_images << "]");

  for(size_t idx: ptx.selected_transfers)
  {
    set_spent(idx, 0);
  }

  // tx generated, get rid of used k values
  for (size_t idx: ptx.selected_transfers)
    memwipe(m_transfers[idx].m_multisig_k.data(), m_transfers[idx].m_multisig_k.size() * sizeof(m_transfers[idx].m_multisig_k[0]));

  //fee includes dust if dust policy specified it.
  LOG_PRINT_L1("Transaction successfully " << (blink ? "blinked. " : "sent. ") << txid
            << "\nCommission: " << print_money(ptx.fee) << " (dust sent to dust addr: " << print_money((ptx.dust_added_to_fee ? 0 : ptx.dust)) << ")"
            << "\nBalance: " << print_money(balance(ptx.construction_data.subaddr_account, false))
            << "\nUnlocked: " << print_money(unlocked_balance(ptx.construction_data.subaddr_account, false))
            << "\nPlease, wait for confirmation for your balance to be unlocked.");
}

void wallet2::commit_tx(std::vector<pending_tx>& ptx_vector, bool blink)
{
  for (auto & ptx : ptx_vector)
  {
    commit_tx(ptx, blink);
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::save_tx(const std::vector<pending_tx>& ptx_vector, const fs::path& filename) const
{
  LOG_PRINT_L0("saving " << ptx_vector.size() << " transactions");
  std::string ciphertext = dump_tx_to_str(ptx_vector);
  if (ciphertext.empty())
    return false;
  return save_to_file(filename, ciphertext);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::dump_tx_to_str(const std::vector<pending_tx> &ptx_vector) const
{
  LOG_PRINT_L0("saving " << ptx_vector.size() << " transactions");
  unsigned_tx_set txs;
  for (auto &tx: ptx_vector)
  {
    // Short payment id is encrypted with tx_key.
    // Since sign_tx() generates new tx_keys and encrypts the payment id, we need to save the decrypted payment ID
    // Save tx construction_data to unsigned_tx_set
    txs.txes.push_back(get_construction_data_with_decrypted_short_payment_id(tx, m_account.get_device()));
  }

  txs.transfers = export_outputs();
  // save as binary
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << txs;
  }
  catch (...)
  {
    return std::string();
  }
  LOG_PRINT_L2("Saving unsigned tx data: " << oss.str());
  std::string ciphertext = encrypt_with_view_secret_key(oss.str());
  return std::string(UNSIGNED_TX_PREFIX) + ciphertext;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_unsigned_tx(const fs::path& unsigned_filename, unsigned_tx_set& exported_txs) const
{
  if (std::error_code ec; !fs::exists(unsigned_filename, ec))
  {
    LOG_PRINT_L0("File " << unsigned_filename << " does not exist: " << ec.message());
    return false;
  }

  std::string s;
  if (!load_from_file(unsigned_filename, s))
  {
    LOG_PRINT_L0("Failed to load from " << unsigned_filename);
    return false;
  }

  return parse_unsigned_tx_from_str(s, exported_txs);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_unsigned_tx_from_str(std::string_view s, unsigned_tx_set &exported_txs) const
{
  if (!tools::starts_with(s, UNSIGNED_TX_PREFIX_NOVER))
  {
    LOG_PRINT_L0("Bad magic from unsigned tx");
    return false;
  }
  s.remove_prefix(UNSIGNED_TX_PREFIX_NOVER.size());
  const char version = s[0];
  s = s.substr(1);
  if (version == '\003')
  {
    try
    {
      std::stringstream iss;
      iss << s;
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> exported_txs;
    }
    catch (...)
    {
      LOG_PRINT_L0("Failed to parse data from unsigned tx");
      return false;
    }
  }
  else if (version == '\004')
  {
    try
    {
      std::stringstream iss;
      iss << decrypt_with_view_secret_key(s).view();
      try
      {
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> exported_txs;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to parse data from unsigned tx");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt unsigned tx: " << e.what());
      return false;
    }
  }
  else
  {
    LOG_PRINT_L0("Unsupported version in unsigned tx");
    return false;
  }
  LOG_PRINT_L1("Loaded tx unsigned data from binary: " << exported_txs.txes.size() << " transactions");

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(const fs::path& unsigned_filename, const fs::path& signed_filename, std::vector<wallet2::pending_tx>& txs, std::function<bool(const unsigned_tx_set&)> accept_func, bool export_raw)
{
  unsigned_tx_set exported_txs;
  if(!load_unsigned_tx(unsigned_filename, exported_txs))
    return false;

  if (accept_func && !accept_func(exported_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }
  return sign_tx(exported_txs, signed_filename, txs, export_raw);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &txs, signed_tx_set &signed_txes)
{
  import_outputs(exported_txs.transfers);

  // sign the transactions
  for (size_t n = 0; n < exported_txs.txes.size(); ++n)
  {
    auto &sd = exported_txs.txes[n];
    THROW_WALLET_EXCEPTION_IF(sd.sources.empty(), error::wallet_internal_error, "Empty sources");
    LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, ring size " << sd.sources[0].outputs.size());
    signed_txes.ptx.push_back(pending_tx());
    tools::wallet2::pending_tx &ptx = signed_txes.ptx.back();
    rct::RCTConfig rct_config = sd.rct_config;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    rct::multisig_out msout;

    oxen_construct_tx_params tx_params;
    tx_params.hf_version = sd.hf_version;
    tx_params.tx_type    = sd.tx_type;
    bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sd.sources, sd.splitted_dsts, sd.change_dts, sd.extra, ptx.tx, sd.unlock_time, tx_key, additional_tx_keys, rct_config, m_multisig ? &msout : NULL, tx_params);
    THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sd.sources, sd.splitted_dsts, sd.unlock_time, m_nettype);
    // we don't test tx size, because we don't know the current limit, due to not having a blockchain,
    // and it's a bit pointless to fail there anyway, since it'd be a (good) guess only. We sign anyway,
    // and if we really go over limit, the daemon will reject when it gets submitted. Chances are it's
    // OK anyway since it was generated in the first place, and rerolling should be within a few bytes.

    // normally, the tx keys are saved in commit_tx, when the tx is actually sent to the daemon.
    // we can't do that here since the tx will be sent from the compromised wallet, which we don't want
    // to see that info, so we save it here
    if (store_tx_info() && tx_key != crypto::null_skey)
    {
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      m_tx_keys.insert(std::make_pair(txid, tx_key));
      m_additional_tx_keys.insert(std::make_pair(txid, additional_tx_keys));
    }

    std::ostringstream key_images;
    bool all_are_txin_to_key = std::all_of(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const txin_v& s_e) -> bool
    {
      CHECKED_GET_SPECIFIC_VARIANT(s_e, txin_to_key, in, false);
      key_images << in.k_image << ' ';
      return true;
    });
    THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, ptx.tx);

    ptx.key_images = key_images.str();
    ptx.fee = 0;
    for (const auto &i: sd.sources) ptx.fee += i.amount;
    for (const auto &i: sd.splitted_dsts) ptx.fee -= i.amount;
    ptx.dust = 0;
    ptx.dust_added_to_fee = false;
    ptx.change_dts = sd.change_dts;
    ptx.selected_transfers = sd.selected_transfers;
    ptx.tx_key = rct::rct2sk(rct::identity()); // don't send it back to the untrusted view wallet
    ptx.dests = sd.dests;
    ptx.construction_data = sd;

    txs.push_back(ptx);

    // add tx keys only to ptx
    txs.back().tx_key = tx_key;
    txs.back().additional_tx_keys = additional_tx_keys;
  }

  // add key image mapping for these txes
  const account_keys &keys = get_account().get_keys();
  hw::device &hwdev = m_account.get_device();
  for (size_t n = 0; n < exported_txs.txes.size(); ++n)
  {
    const cryptonote::transaction &tx = signed_txes.ptx[n].tx;

    crypto::key_derivation derivation;
    std::vector<crypto::key_derivation> additional_derivations;

    // compute public keys from out secret keys
    crypto::public_key tx_pub_key;
    crypto::secret_key_to_public_key(txs[n].tx_key, tx_pub_key);
    std::vector<crypto::public_key> additional_tx_pub_keys;
    for (const crypto::secret_key &skey: txs[n].additional_tx_keys)
    {
      additional_tx_pub_keys.resize(additional_tx_pub_keys.size() + 1);
      crypto::secret_key_to_public_key(skey, additional_tx_pub_keys.back());
    }

    // compute derivations
    hwdev.set_mode(hw::device::TRANSACTION_PARSE);
    if (!hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation))
    {
      MWARNING("Failed to generate key derivation from tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
      static_assert(sizeof(derivation) == sizeof(rct::key), "Mismatched sizes of key_derivation and rct::key");
      memcpy(&derivation, rct::identity().bytes, sizeof(derivation));
    }
    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      additional_derivations.push_back({});
      if (!hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back()))
      {
        MWARNING("Failed to generate key derivation from additional tx pubkey in " << cryptonote::get_transaction_hash(tx) << ", skipping");
        memcpy(&additional_derivations.back(), rct::identity().bytes, sizeof(crypto::key_derivation));
      }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      if (!std::holds_alternative<cryptonote::txout_to_key>(tx.vout[i].target))
        continue;
      const cryptonote::txout_to_key &out = var::get<cryptonote::txout_to_key>(tx.vout[i].target);
      // if this output is back to this wallet, we can calculate its key image already
      if (!is_out_to_acc_precomp(m_subaddresses, out.key, derivation, additional_derivations, i, hwdev))
        continue;
      crypto::key_image ki;
      cryptonote::keypair in_ephemeral;
      if (generate_key_image_helper(keys, m_subaddresses, out.key, tx_pub_key, additional_tx_pub_keys, i, in_ephemeral, ki, hwdev))
        signed_txes.tx_key_images[out.key] = ki;
      else
        MERROR("Failed to calculate key image");
    }
  }

  // add key images
  signed_txes.key_images.resize(m_transfers.size());
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    if (!m_transfers[i].m_key_image_known || m_transfers[i].m_key_image_partial)
      LOG_PRINT_L0("WARNING: key image not known in signing wallet at index " << i);
    signed_txes.key_images[i] = m_transfers[i].m_key_image;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_tx(unsigned_tx_set& exported_txs, const fs::path& signed_filename, std::vector<wallet2::pending_tx>& txs, bool export_raw)
{
  // sign the transactions
  signed_tx_set signed_txes;
  std::string ciphertext = sign_tx_dump_to_str(exported_txs, txs, signed_txes);
  if (ciphertext.empty())
  {
    LOG_PRINT_L0("Failed to sign unsigned_tx_set");
    return false;
  }

  if (!save_to_file(signed_filename, ciphertext))
  {
    LOG_PRINT_L0("Failed to save file to " << signed_filename);
    return false;
  }
  // export signed raw tx without encryption
  if (export_raw)
  {
    for (size_t i = 0; i < signed_txes.ptx.size(); ++i)
    {
      std::string tx_as_hex = oxenmq::to_hex(tx_to_blob(signed_txes.ptx[i].tx));
      fs::path raw_filename = signed_filename;
      raw_filename += "_raw";
      if (signed_txes.ptx.size() > 1) raw_filename += "_" + std::to_string(i);
      if (!save_to_file(raw_filename, tx_as_hex))
      {
        LOG_PRINT_L0("Failed to save file to " << raw_filename);
        return false;
      }
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::sign_tx_dump_to_str(unsigned_tx_set &exported_txs, std::vector<wallet2::pending_tx> &ptx, signed_tx_set &signed_txes)
{
  // sign the transactions
  bool r = sign_tx(exported_txs, ptx, signed_txes);
  if (!r)
  {
    LOG_PRINT_L0("Failed to sign unsigned_tx_set");
    return std::string();
  }

  // save as binary
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << signed_txes;
  }
  catch(...)
  {
    return std::string();
  }
  LOG_PRINT_L3("Saving signed tx data (with encryption): " << oss.str());
  std::string ciphertext = encrypt_with_view_secret_key(oss.str());
  return std::string(SIGNED_TX_PREFIX) + ciphertext;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_tx(const fs::path& signed_filename, std::vector<tools::wallet2::pending_tx>& ptx, std::function<bool(const signed_tx_set&)> accept_func)
{
  if (std::error_code ec; !fs::exists(signed_filename, ec))
  {
    LOG_PRINT_L0("File " << signed_filename << " does not exist: " << ec);
    return false;
  }

  std::string s;
  if (!load_from_file(signed_filename, s))
  {
    LOG_PRINT_L0("Failed to load from " << signed_filename);
    return false;
  }

  return parse_tx_from_str(s, ptx, accept_func);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_tx_from_str(std::string_view s, std::vector<tools::wallet2::pending_tx> &ptx, std::function<bool(const signed_tx_set &)> accept_func)
{

  if (!tools::starts_with(s, SIGNED_TX_PREFIX_NOVER))
  {
    LOG_PRINT_L0("Bad magic from signed transaction");
    return false;
  }
  s.remove_prefix(SIGNED_TX_PREFIX_NOVER.size());
  const char version = s[0];
  s.remove_prefix(1);
  signed_tx_set signed_txs;
  if (version == '\003')
  {
    try
    {
      std::stringstream iss;
      iss << s;
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> signed_txs;
    }
    catch (...)
    {
      LOG_PRINT_L0("Failed to parse data from signed transaction");
      return false;
    }
  }
  else if (version == '\004')
  {
    try
    {
      std::stringstream iss;
      iss << decrypt_with_view_secret_key(s).view();
      try
      {
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> signed_txs;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to parse decrypted data from signed transaction");
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt signed transaction: " << e.what());
      return false;
    }
  }
  else
  {
    LOG_PRINT_L0("Unsupported version in signed transaction");
    return false;
  }
  LOG_PRINT_L0("Loaded signed tx data from binary: " << signed_txs.ptx.size() << " transactions");
  for (auto &c_ptx: signed_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));

  if (accept_func && !accept_func(signed_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }

  // import key images
  bool r = import_key_images(signed_txs.key_images);
  if (!r) return false;

  // remember key images for this tx, for when we get those txes from the blockchain
  for (const auto &e: signed_txs.tx_key_images)
    m_cold_key_images.insert(e);

  ptx = signed_txs.ptx;

  return true;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::save_multisig_tx(multisig_tx_set txs)
{
  LOG_PRINT_L0("saving " << txs.m_ptx.size() << " multisig transactions");

  // txes generated, get rid of used k values
  for (size_t n = 0; n < txs.m_ptx.size(); ++n)
    for (size_t idx: txs.m_ptx[n].construction_data.selected_transfers)
      memwipe(m_transfers[idx].m_multisig_k.data(), m_transfers[idx].m_multisig_k.size() * sizeof(m_transfers[idx].m_multisig_k[0]));

  // zero out some data we don't want to share
  for (auto &ptx: txs.m_ptx)
  {
    for (auto &e: ptx.construction_data.sources)
      memwipe(&e.multisig_kLRki.k, sizeof(e.multisig_kLRki.k));
  }

  for (auto &ptx: txs.m_ptx)
  {
    // Get decrypted payment id from pending_tx
    ptx.construction_data = get_construction_data_with_decrypted_short_payment_id(ptx, m_account.get_device());
  }

  // save as binary
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  try
  {
    ar << txs;
  }
  catch (...)
  {
    return std::string();
  }
  LOG_PRINT_L2("Saving multisig unsigned tx data: " << oss.str());
  std::string ciphertext = encrypt_with_view_secret_key(oss.str());
  return std::string(MULTISIG_UNSIGNED_TX_PREFIX) + ciphertext;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::save_multisig_tx(const multisig_tx_set& txs, const fs::path& filename)
{
  std::string ciphertext = save_multisig_tx(txs);
  if (ciphertext.empty())
    return false;
  return save_to_file(filename, ciphertext);
}
//----------------------------------------------------------------------------------------------------
wallet2::multisig_tx_set wallet2::make_multisig_tx_set(const std::vector<pending_tx>& ptx_vector) const
{
  multisig_tx_set txs;
  txs.m_ptx = ptx_vector;

  for (const auto &msk: get_account().get_multisig_keys())
  {
    crypto::public_key pkey = get_multisig_signing_public_key(msk);
    for (auto &ptx: txs.m_ptx) for (auto &sig: ptx.multisig_sigs) sig.signing_keys.insert(pkey);
  }

  txs.m_signers.insert(get_multisig_signer_public_key());
  return txs;
}

std::string wallet2::save_multisig_tx(const std::vector<pending_tx>& ptx_vector)
{
  return save_multisig_tx(make_multisig_tx_set(ptx_vector));
}
//----------------------------------------------------------------------------------------------------
bool wallet2::save_multisig_tx(const std::vector<pending_tx>& ptx_vector, const fs::path& filename)
{
  std::string ciphertext = save_multisig_tx(ptx_vector);
  if (ciphertext.empty())
    return false;
  return save_to_file(filename, ciphertext);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_multisig_tx_from_str(std::string_view multisig_tx_st, multisig_tx_set &exported_txs) const
{
  if (!tools::starts_with(multisig_tx_st, MULTISIG_UNSIGNED_TX_PREFIX))
  {
    LOG_PRINT_L0("Bad magic from multisig tx data");
    return false;
  }
  std::stringstream iss;
  try
  {
    iss << decrypt_with_view_secret_key(multisig_tx_st.substr(MULTISIG_UNSIGNED_TX_PREFIX.size())).view();
  }
  catch (const std::exception &e)
  {
    LOG_PRINT_L0("Failed to decrypt multisig tx data: " << e.what());
    return false;
  }
  try
  {
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> exported_txs;
  }
  catch (...)
  {
    LOG_PRINT_L0("Failed to parse multisig tx data");
    return false;
  }

  // sanity checks
  for (const auto &ptx: exported_txs.m_ptx)
  {
    CHECK_AND_ASSERT_MES(ptx.selected_transfers.size() == ptx.tx.vin.size(), false, "Mismatched selected_transfers/vin sizes");
    for (size_t idx: ptx.selected_transfers)
      CHECK_AND_ASSERT_MES(idx < m_transfers.size(), false, "Transfer index out of range");
    CHECK_AND_ASSERT_MES(ptx.construction_data.selected_transfers.size() == ptx.tx.vin.size(), false, "Mismatched cd selected_transfers/vin sizes");
    for (size_t idx: ptx.construction_data.selected_transfers)
      CHECK_AND_ASSERT_MES(idx < m_transfers.size(), false, "Transfer index out of range");
    CHECK_AND_ASSERT_MES(ptx.construction_data.sources.size() == ptx.tx.vin.size(), false, "Mismatched sources/vin sizes");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_multisig_tx(cryptonote::blobdata s, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func)
{
  if(!parse_multisig_tx_from_str(s, exported_txs))
  {
    LOG_PRINT_L0("Failed to parse multisig transaction from string");
    return false;
  }

  LOG_PRINT_L1("Loaded multisig tx unsigned data from binary: " << exported_txs.m_ptx.size() << " transactions");
  for (auto &ptx: exported_txs.m_ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(ptx.tx));

  if (accept_func && !accept_func(exported_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }

  const bool is_signed = exported_txs.m_signers.size() >= m_multisig_threshold;
  if (is_signed)
  {
    for (const auto &ptx: exported_txs.m_ptx)
    {
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      if (store_tx_info())
      {
        m_tx_keys.insert(std::make_pair(txid, ptx.tx_key));
        m_additional_tx_keys.insert(std::make_pair(txid, ptx.additional_tx_keys));
      }
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::load_multisig_tx_from_file(const fs::path& filename, multisig_tx_set& exported_txs, std::function<bool(const multisig_tx_set&)> accept_func)
{
  if (std::error_code ec; !fs::exists(filename, ec))
  {
    LOG_PRINT_L0("File " << filename << " does not exist: " << ec.message());
    return false;
  }

  std::string s;
  if (!load_from_file(filename, s))
  {
    LOG_PRINT_L0("Failed to load from " << filename);
    return false;
  }

  if (!load_multisig_tx(s, exported_txs, accept_func))
  {
    LOG_PRINT_L0("Failed to parse multisig tx data from " << filename);
    return false;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_multisig_tx(multisig_tx_set &exported_txs, std::vector<crypto::hash> &txids)
{
  THROW_WALLET_EXCEPTION_IF(exported_txs.m_ptx.empty(), error::wallet_internal_error, "No tx found");

  const crypto::public_key local_signer = get_multisig_signer_public_key();

  THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.find(local_signer) != exported_txs.m_signers.end(),
      error::wallet_internal_error, "Transaction already signed by this private key");
  THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.size() > m_multisig_threshold,
      error::wallet_internal_error, "Transaction was signed by too many signers");
  THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.size() == m_multisig_threshold,
      error::wallet_internal_error, "Transaction is already fully signed");

  txids.clear();

  // sign the transactions
  for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n)
  {
    tools::wallet2::pending_tx &ptx = exported_txs.m_ptx[n];
    THROW_WALLET_EXCEPTION_IF(ptx.multisig_sigs.empty(), error::wallet_internal_error, "No signatures found in multisig tx");
    auto &sd = ptx.construction_data;
    LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, mixin " << (sd.sources[0].outputs.size()-1) <<
        ", signed by " << exported_txs.m_signers.size() << "/" << m_multisig_threshold);
    cryptonote::transaction tx;
    rct::multisig_out msout = ptx.multisig_sigs.front().msout;
    auto sources = sd.sources;

    oxen_construct_tx_params tx_params;
    tx_params.hf_version      = sd.hf_version;
    tx_params.tx_type         = sd.tx_type;
    rct::RCTConfig rct_config = sd.rct_config;
    bool r = cryptonote::construct_tx_with_tx_key(m_account.get_keys(), m_subaddresses, sources, sd.splitted_dsts, ptx.change_dts, sd.extra, tx, sd.unlock_time, ptx.tx_key, ptx.additional_tx_keys, rct_config, &msout, false /*shuffle_outs*/, tx_params);
    THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sd.sources, sd.splitted_dsts, sd.unlock_time, m_nettype);

    THROW_WALLET_EXCEPTION_IF(get_transaction_prefix_hash (tx) != get_transaction_prefix_hash(ptx.tx),
        error::wallet_internal_error, "Transaction prefix does not match data");

    // Tests passed, sign
    std::vector<unsigned int> indices;
    for (const auto &source: sources)
      indices.push_back(source.real_output);

    for (auto &sig: ptx.multisig_sigs)
    {
      if (sig.ignore.find(local_signer) == sig.ignore.end())
      {
        ptx.tx.rct_signatures = sig.sigs;

        rct::keyV k;
        rct::key skey = rct::zero();
        OXEN_DEFER {
          memwipe(k.data(), k.size() * sizeof(rct::key));
          memwipe(&skey, sizeof(skey));
        };

        k.reserve(sd.selected_transfers.size());
        for (size_t idx: sd.selected_transfers)
          k.push_back(get_multisig_k(idx, sig.used_L));

        for (const auto &msk: get_account().get_multisig_keys())
        {
          crypto::public_key pmsk = get_multisig_signing_public_key(msk);

          if (sig.signing_keys.find(pmsk) == sig.signing_keys.end())
          {
            sc_add(skey.bytes, skey.bytes, rct::sk2rct(msk).bytes);
            sig.signing_keys.insert(pmsk);
          }
        }
        THROW_WALLET_EXCEPTION_IF(!rct::signMultisig(ptx.tx.rct_signatures, indices, k, sig.msout, skey),
            error::wallet_internal_error, "Failed signing, transaction likely malformed");

        sig.sigs = ptx.tx.rct_signatures;
      }
    }

    const bool is_last = exported_txs.m_signers.size() + 1 >= m_multisig_threshold;
    if (is_last)
    {
      // when the last signature on a multisig tx is made, we select the right
      // signature to plug into the final tx
      bool found = false;
      for (const auto &sig: ptx.multisig_sigs)
      {
        if (sig.ignore.find(local_signer) == sig.ignore.end() && !keys_intersect(sig.ignore, exported_txs.m_signers))
        {
          THROW_WALLET_EXCEPTION_IF(found, error::wallet_internal_error, "More than one transaction is final");
          ptx.tx.rct_signatures = sig.sigs;
          found = true;
        }
      }
      THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error,
          "Final signed transaction not found: this transaction was likely made without our export data, so we cannot sign it");
      const crypto::hash txid = get_transaction_hash(ptx.tx);
      if (store_tx_info())
      {
        m_tx_keys.insert(std::make_pair(txid, ptx.tx_key));
        m_additional_tx_keys.insert(std::make_pair(txid, ptx.additional_tx_keys));
      }
      txids.push_back(txid);
    }
  }

  // txes generated, get rid of used k values
  for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n)
    for (size_t idx: exported_txs.m_ptx[n].construction_data.selected_transfers)
      memwipe(m_transfers[idx].m_multisig_k.data(), m_transfers[idx].m_multisig_k.size() * sizeof(m_transfers[idx].m_multisig_k[0]));

  exported_txs.m_signers.insert(get_multisig_signer_public_key());

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_multisig_tx_to_file(multisig_tx_set& exported_txs, const fs::path& filename, std::vector<crypto::hash>& txids)
{
  bool r = sign_multisig_tx(exported_txs, txids);
  if (!r)
    return false;
  return save_multisig_tx(exported_txs, filename);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::sign_multisig_tx_from_file(const fs::path& filename, std::vector<crypto::hash> &txids, std::function<bool(const multisig_tx_set&)> accept_func)
{
  multisig_tx_set exported_txs;
  if(!load_multisig_tx_from_file(filename, exported_txs))
    return false;

  if (accept_func && !accept_func(exported_txs))
  {
    LOG_PRINT_L1("Transactions rejected by callback");
    return false;
  }
  return sign_multisig_tx_to_file(exported_txs, filename, txids);
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_fee_percent(uint32_t priority, txtype type) const
{
  static constexpr std::array<uint64_t, 4> percents{{100, 500, 2500, 12500}};

  const bool blinkable = type == txtype::standard;

  if (priority == 0) // 0 means no explicit priority was given, so use the wallet default
  {
    priority = m_default_priority > 0 ? m_default_priority : (uint32_t) tx_priority_blink;
    if (priority == tx_priority_blink && !blinkable)
      priority = tx_priority_unimportant; // The blink default is unusable for this tx, so fall back to unimportant
  }

  // If it's a blinkable tx then we blink it for everything priority other than unimportant.
  if (blinkable && priority != tx_priority_unimportant)
    priority = tx_priority_blink;

  if (priority == tx_priority_blink)
  {
    if (!blinkable)
      THROW_WALLET_EXCEPTION(error::invalid_priority);

    uint64_t burn_pct = 0;
    // v9.2.0 introduced minor versions to forks, this use_fork_rules(18,0) will return the height
    // for HF18.1 when we want 18.0. Workaround this by allowing the use of 18 fork rules 4000
    // blocks before 18.1
    if (use_fork_rules(network_version_18, 4000))
      burn_pct = BLINK_BURN_TX_FEE_PERCENT_V18;
    else
      THROW_WALLET_EXCEPTION(error::invalid_priority);
    return BLINK_MINER_TX_FEE_PERCENT + burn_pct;
  }

  if (priority > percents.size())
    THROW_WALLET_EXCEPTION(error::invalid_priority);

  return percents[priority-1];
}
//----------------------------------------------------------------------------------------------------
byte_and_output_fees wallet2::get_dynamic_base_fee_estimate() const
{
  byte_and_output_fees fees;
  if (m_node_rpc_proxy.get_dynamic_base_fee_estimate(FEE_ESTIMATE_GRACE_BLOCKS, fees))
    return fees;

  if (use_fork_rules(cryptonote::network_version_18))
    fees = {FEE_PER_BYTE_V13, FEE_PER_OUTPUT_V18}; // v18 reduces fee
  if (use_fork_rules(HF_VERSION_PER_OUTPUT_FEE))
    fees = {FEE_PER_BYTE_V13, FEE_PER_OUTPUT_V13}; // v13 switches back from v12 per-byte fees, add per-output
  else
    fees = {FEE_PER_BYTE_V12, 0};

  LOG_PRINT_L1("Failed to query base fee, using " << print_money(fees.first) << "/byte + " << print_money(fees.second) << "/output");
  return fees;
}
//----------------------------------------------------------------------------------------------------
byte_and_output_fees wallet2::get_base_fees() const
{
  return get_dynamic_base_fee_estimate();
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_fee_quantization_mask() const
{
  if(m_light_wallet)
  {
    return 1; // TODO
  }

  uint64_t fee_quantization_mask;
  if (m_node_rpc_proxy.get_fee_quantization_mask(fee_quantization_mask))
    return fee_quantization_mask;
  return 1;
}

oxen_construct_tx_params wallet2::construct_params(uint8_t hf_version, txtype tx_type, uint32_t priority, uint64_t extra_burn, ons::mapping_type type)
{
  oxen_construct_tx_params tx_params;
  tx_params.hf_version = hf_version;
  tx_params.tx_type    = tx_type;

  if (tx_type == txtype::oxen_name_system)
  {
    assert(priority != tools::tx_priority_blink);
    tx_params.burn_fixed = ons::burn_needed(hf_version, type);
  }
  else if (priority == tools::tx_priority_blink)
  {
    tx_params.burn_fixed   = BLINK_BURN_FIXED;
    tx_params.burn_percent = BLINK_BURN_TX_FEE_PERCENT_V18;
  }
  if (extra_burn)
      tx_params.burn_fixed += extra_burn;

  return tx_params;
}


//----------------------------------------------------------------------------------------------------
bool wallet2::set_ring_database(fs::path filename)
{
  m_ring_database = std::move(filename);
  MINFO("ringdb path set to " << m_ring_database.u8string());
  m_ringdb.reset();
  if (!m_ring_database.empty())
  {
    try
    {
      cryptonote::block b;
      generate_genesis(b);
      m_ringdb = std::make_unique<tools::ringdb>(m_ring_database, tools::type_to_hex(get_block_hash(b)));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to initialize ringdb: " << e.what());
      m_ring_database.clear();
      return false;
    }
  }
  return true;
}

crypto::chacha_key wallet2::get_ringdb_key()
{
  if (!m_ringdb_key)
  {
    MINFO("caching ringdb key");
    crypto::chacha_key key;
    generate_chacha_key_from_secret_keys(key);
    m_ringdb_key = key;
  }
  return *m_ringdb_key;
}

void wallet2::register_devices(){
  hw::trezor::register_all();
}

hw::device& wallet2::lookup_device(const std::string & device_descriptor){
  if (!m_devices_registered){
    m_devices_registered = true;
    register_devices();
  }

  return hw::get_device(device_descriptor);
}

bool wallet2::add_rings(const crypto::chacha_key &key, const cryptonote::transaction_prefix &tx)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->add_rings(key, tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::add_rings(const cryptonote::transaction_prefix &tx)
{
  try { return add_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::remove_rings(const cryptonote::transaction_prefix &tx)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->remove_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::get_ring(const crypto::chacha_key &key, const crypto::key_image &key_image, std::vector<uint64_t> &outs)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->get_ring(key, key_image, outs); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::get_rings(const crypto::hash &txid, std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> &outs)
{
  for (auto i: m_confirmed_txs)
  {
    if (txid == i.first)
    {
      for (const auto &x: i.second.m_rings)
        outs.push_back({x.first, cryptonote::relative_output_offsets_to_absolute(x.second)});
      return true;
    }
  }
  for (auto i: m_unconfirmed_txs)
  {
    if (txid == i.first)
    {
      for (const auto &x: i.second.m_rings)
        outs.push_back({x.first, cryptonote::relative_output_offsets_to_absolute(x.second)});
      return true;
    }
  }
  return false;
}

bool wallet2::get_ring(const crypto::key_image &key_image, std::vector<uint64_t> &outs)
{
  try { return get_ring(get_ringdb_key(), key_image, outs); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::set_ring(const crypto::key_image &key_image, const std::vector<uint64_t> &outs, bool relative)
{
  if (!m_ringdb)
    return false;

  try { return m_ringdb->set_ring(get_ringdb_key(), key_image, outs, relative); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unset_ring(const std::vector<crypto::key_image> &key_images)
{
  if (!m_ringdb)
    return false;

  try { return m_ringdb->remove_rings(get_ringdb_key(), key_images); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unset_ring(const crypto::hash &txid)
{
  if (!m_ringdb)
    return false;

  auto res = request_transaction(txid);

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  if (!get_pruned_tx(res.txs.front(), tx, tx_hash))
    return false;
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  try { return m_ringdb->remove_rings(get_ringdb_key(), tx); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::find_and_save_rings(bool force)
{
  if (!force && m_ring_history_saved)
    return true;
  if (!m_ringdb)
    return false;

  MDEBUG("Finding and saving rings...");

  // get payments we made
  std::vector<crypto::hash> txs_hashes;
  std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>> payments;
  get_payments_out(payments, 0, std::numeric_limits<uint64_t>::max(), std::nullopt, std::set<uint32_t>());
  for (const auto& [txid, details]: payments)
    txs_hashes.push_back(txid);

  MDEBUG("Found " << std::to_string(txs_hashes.size()) << " transactions");

  // get those transactions from the daemon
  auto it = txs_hashes.begin();
  constexpr size_t SLICE_SIZE = 200;
  for (size_t slice = 0; slice < txs_hashes.size(); slice += SLICE_SIZE)
  {
    size_t ntxes = slice + SLICE_SIZE > txs_hashes.size() ? txs_hashes.size() - slice : SLICE_SIZE;
    auto res = request_transactions(hashes_to_hex(txs_hashes.begin() + slice, txs_hashes.begin() + ntxes));

    MDEBUG("Scanning " << res.txs.size() << " transactions");
    for (size_t i = 0; i < res.txs.size(); ++i, ++it)
    {
      const auto &tx_info = res.txs[i];
      cryptonote::transaction tx;
      crypto::hash tx_hash;
      THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(tx_info, tx, tx_hash), error::wallet_internal_error,
          "Failed to get transaction from daemon");
      THROW_WALLET_EXCEPTION_IF(!(tx_hash == *it), error::wallet_internal_error, "Wrong txid received");
      THROW_WALLET_EXCEPTION_IF(!add_rings(get_ringdb_key(), tx), error::wallet_internal_error, "Failed to save ring");
    }
  }

  MINFO("Found and saved rings for " << txs_hashes.size() << " transactions");
  m_ring_history_saved = true;
  return true;
}

bool wallet2::blackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackball(output); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::set_blackballed_outputs(const std::vector<std::pair<uint64_t, uint64_t>> &outputs, bool add)
{
  if (!m_ringdb)
    return false;
  try
  {
    bool ret = true;
    if (!add)
      ret &= m_ringdb->clear_blackballs();
    ret &= m_ringdb->blackball(outputs);
    return ret;
  }
  catch (const std::exception &e) { return false; }
}

bool wallet2::unblackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->unblackball(output); }
  catch (const std::exception &e) { return false; }
}

bool wallet2::is_output_blackballed(const std::pair<uint64_t, uint64_t> &output) const
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackballed(output); }
  catch (const std::exception &e) { return false; }
}

wallet2::stake_result wallet2::check_stake_allowed(const crypto::public_key& sn_key, const cryptonote::address_parse_info& addr_info, uint64_t& amount, double fraction)
{
  wallet2::stake_result result = {};
  result.status                = wallet2::stake_result_status::invalid;
  result.msg.reserve(128);

  if (addr_info.has_payment_id)
  {
    result.status = stake_result_status::payment_id_disallowed;
    result.msg    = tr("Payment IDs cannot be used in a staking transaction");
    return result;
  }

  if (addr_info.is_subaddress)
  {
    result.status = stake_result_status::subaddress_disallowed;
    result.msg    = tr("Subaddresses cannot be used in a staking transaction");
    return result;
  }

  cryptonote::account_public_address const primary_address = get_address();
  if (primary_address != addr_info.address)
  {
    result.status = stake_result_status::address_must_be_primary;
    result.msg    = tr("The specified address must be owned by this wallet and be the primary address of the wallet");
    return result;
  }

  /// check that the service node is registered
  const auto [success, response] = get_service_nodes({ tools::type_to_hex(sn_key) });
  if (!success)
  {
    result.status = stake_result_status::service_node_list_query_failed;
    result.msg    = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return result;
  }

  if (response.size() != 1)
  {
    result.status = stake_result_status::service_node_not_registered;
    result.msg    = tr("Could not find service node in service node list, please make sure it is registered first.");
    return result;
  }

  const std::optional<uint8_t> res = m_node_rpc_proxy.get_hardfork_version();
  if (!res)
  {
    result.status = stake_result_status::network_version_query_failed;
    result.msg    = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return result;
  }

  const auto& snode_info  = response.front();
  if (amount == 0) amount = snode_info.staking_requirement * fraction;

  size_t total_existing_contributions = 0; // Count both contributions and reserved spots
  for (auto const &contributor : snode_info.contributors)
  {
    total_existing_contributions += contributor.locked_contributions.size(); // contribution
    if (contributor.reserved > contributor.amount)
        total_existing_contributions++; // reserved contributor spot
  }

  uint8_t const hf_version   = *res;
  uint64_t max_contrib_total = snode_info.staking_requirement - snode_info.total_reserved;
  uint64_t min_contrib_total = service_nodes::get_min_node_contribution(hf_version, snode_info.staking_requirement, snode_info.total_reserved, total_existing_contributions);

  bool is_preexisting_contributor = false;
  for (const auto& contributor : snode_info.contributors)
  {
    address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_nettype, contributor.address))
      continue;

    if (info.address == addr_info.address)
    {
      uint64_t const reserved_amount_not_contributed_yet = contributor.reserved - contributor.amount;
      max_contrib_total  += reserved_amount_not_contributed_yet;
      is_preexisting_contributor = true;

      if (min_contrib_total == UINT64_MAX || reserved_amount_not_contributed_yet > min_contrib_total)
        min_contrib_total = reserved_amount_not_contributed_yet;
      break;
    }
  }

  if (max_contrib_total == 0)
  {
    result.status = stake_result_status::service_node_contribution_maxed;
    result.msg = tr("The service node cannot receive any more Loki from this wallet");
    return result;
  }

  const bool full = snode_info.contributors.size() >= MAX_NUMBER_OF_CONTRIBUTORS;
  if (full && !is_preexisting_contributor)
  {
    result.status = stake_result_status::service_node_contributors_maxed;
    result.msg = tr("The service node already has the maximum number of participants and this wallet is not one of them");
    return result;
  }

  if (amount < min_contrib_total)
  {
    const uint64_t DUST = MAX_NUMBER_OF_CONTRIBUTORS;
    if (min_contrib_total - amount <= DUST)
    {
      amount = min_contrib_total;
      result.msg += tr("Seeing as this is insufficient by dust amounts, amount was increased automatically to ");
      result.msg += print_money(min_contrib_total);
      result.msg += "\n";
    }
    else
    {
      result.status = stake_result_status::service_node_insufficient_contribution;
      result.msg.reserve(128);
      result.msg =  tr("You must contribute at least ");
      result.msg += print_money(min_contrib_total);
      result.msg += tr(" oxen to become a contributor for this service node.");
      return result;
    }
  }

  if (amount > max_contrib_total)
  {
    result.msg += tr("You may only contribute up to ");
    result.msg += print_money(max_contrib_total);
    result.msg += tr(" more oxen to this service node. ");
    result.msg += tr("Reducing your stake from ");
    result.msg += print_money(amount);
    result.msg += tr(" to ");
    result.msg += print_money(max_contrib_total);
    result.msg += tr("\n");
    amount = max_contrib_total;
  }

  result.status = stake_result_status::success;
  return result;
}

wallet2::stake_result wallet2::create_stake_tx(const crypto::public_key& service_node_key, uint64_t amount, double amount_fraction, uint32_t priority, std::set<uint32_t> subaddr_indices)
{
  wallet2::stake_result result = {};
  result.status                = wallet2::stake_result_status::invalid;

  cryptonote::address_parse_info addr_info = {};
  addr_info.address = this->get_address();
  //addr_info.address = this->get_account().get_keys().m_account_address;
  //addr_info.is_subaddress = false;

  try
  {
    result = check_stake_allowed(service_node_key, addr_info, amount, amount_fraction);
    if (result.status != stake_result_status::success)
      return result;
  }
  catch (const std::exception& e)
  {
    result.status = stake_result_status::exception_thrown;
    result.msg = ERR_MSG_EXCEPTION_THROWN;
    result.msg += e.what();
    return result;
  }

  const cryptonote::account_public_address& address = addr_info.address;

  std::vector<uint8_t> extra;
  add_service_node_pubkey_to_tx_extra(extra, service_node_key);
  add_service_node_contributor_to_tx_extra(extra, address);

  std::vector<cryptonote::tx_destination_entry> dsts;
  cryptonote::tx_destination_entry de = {};
  de.addr = address;
  de.is_subaddress = false;
  de.amount = amount;
  dsts.push_back(de);

  std::string err, err2;
  const uint64_t bc_height = std::max(get_daemon_blockchain_height(err),
                                      get_daemon_blockchain_target_height(err2));

  if (!err.empty() || !err2.empty())
  {
    result.msg = ERR_MSG_NETWORK_HEIGHT_QUERY_FAILED;
    result.msg += (err.empty() ? err2 : err);
    result.status = stake_result_status::network_height_query_failed;
    return result;
  }

  constexpr uint64_t unlock_at_block = 0; // Infinite staking, no time lock

  try
  {
    if (priority == tx_priority_blink)
    {
      result.status = stake_result_status::no_blink;
      result.msg += tr("Service node stakes cannot use blink priority");
      return result;
    }

    std::optional<uint8_t> hf_version = get_hard_fork_version();
    if (!hf_version)
    {
      result.status = stake_result_status::network_version_query_failed;
      result.msg    = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
      return result;
    }

    oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, txtype::stake, priority);
    auto ptx_vector      = create_transactions_2(dsts, CRYPTONOTE_DEFAULT_TX_MIXIN, unlock_at_block, priority, extra, 0, subaddr_indices, tx_params);
    if (ptx_vector.size() == 1)
    {
      result.status = stake_result_status::success;
      result.ptx    = ptx_vector[0];
    }
    else
    {
      result.status = stake_result_status::too_many_transactions_constructed;
      result.msg    = ERR_MSG_TOO_MANY_TXS_CONSTRUCTED;
    }
  }
  catch (const std::exception& e)
  {
    result.status = stake_result_status::exception_thrown;
    result.msg = ERR_MSG_EXCEPTION_THROWN;
    result.msg += e.what();
    return result;
  }

  assert(result.status != stake_result_status::invalid);
  return result;
}

wallet2::register_service_node_result wallet2::create_register_service_node_tx(const std::vector<std::string> &args_, uint32_t subaddr_account)
{
  std::vector<std::string> local_args = args_;
  register_service_node_result result = {};
  result.status                       = register_service_node_result_status::invalid;

  //
  // Parse Tx Args
  //
  std::set<uint32_t> subaddr_indices;
  uint32_t priority = 0;
  {
    if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
    {
      if (!tools::parse_subaddress_indices(local_args[0], subaddr_indices))
      {
        result.status = register_service_node_result_status::subaddr_indices_parse_fail;
        result.msg = tr("Could not parse subaddress indices argument: ") + local_args[0];
        return result;
      }

      local_args.erase(local_args.begin());
    }

    if (local_args.size() > 0 && parse_priority(local_args[0], priority))
      local_args.erase(local_args.begin());

    if (priority == tx_priority_blink)
    {
      result.status = register_service_node_result_status::no_blink;
      result.msg += tr("Service node registrations cannot use blink priority");
      return result;
    }

    if (local_args.size() < 6)
    {
      result.status = register_service_node_result_status::insufficient_num_args;
      result.msg += tr("\nPrepare this command in the daemon with the prepare_registration command");
      result.msg += tr("\nThis command must be run from the daemon that will be acting as a service node");
      return result;
    }
  }

  //
  // Parse Registration Contributor Args
  //
  std::optional<uint8_t> hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    result.status = register_service_node_result_status::network_version_query_failed;
    result.msg    = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return result;
  }

  uint64_t staking_requirement = 0, bc_height = 0;
  service_nodes::contributor_args_t contributor_args = {};
  {
    std::string err, err2;
    bc_height = std::max(get_daemon_blockchain_height(err),
                         get_daemon_blockchain_target_height(err2));
    {
      if (!err.empty() || !err2.empty())
      {
        result.msg = ERR_MSG_NETWORK_HEIGHT_QUERY_FAILED;
        result.msg += (err.empty() ? err2 : err);
        result.status = register_service_node_result_status::network_height_query_failed;
        return result;
      }

      if (!is_synced(1))
      {
        result.status = register_service_node_result_status::wallet_not_synced;
        result.msg    = tr("Wallet is not synced. Please synchronise your wallet to the blockchain");
        return result;
      }
    }

    staking_requirement = service_nodes::get_staking_requirement(nettype(), bc_height);
    std::vector<std::string> const args(local_args.begin(), local_args.begin() + local_args.size() - 3);
    contributor_args = service_nodes::convert_registration_args(nettype(), args, staking_requirement, *hf_version);

    if (!contributor_args.success)
    {
      result.status = register_service_node_result_status::convert_registration_args_failed;
      result.msg = tr("Could not convert registration args, reason: ") + contributor_args.err_msg;
      return result;
    }
  }

  cryptonote::account_public_address address = contributor_args.addresses[0];
  if (!contains_address(address))
  {
    result.status = register_service_node_result_status::first_address_must_be_primary_address;
    result.msg = tr(
                    "The first reserved address for this registration does not belong to this wallet.\n"
                    "Service node operator must specify an address owned by this wallet for service node registration."
                   );
    return result;
  }


  //
  // Parse Registration Metadata Args
  //
  size_t const timestamp_index  = local_args.size() - 3;
  size_t const key_index        = local_args.size() - 2;
  size_t const signature_index  = local_args.size() - 1;
  const std::string &service_node_key_as_str = local_args[key_index];

  crypto::public_key service_node_key;
  crypto::signature signature;
  uint64_t expiration_timestamp = 0;
  {
    try
    {
      expiration_timestamp = boost::lexical_cast<uint64_t>(local_args[timestamp_index]);
      if (expiration_timestamp <= (uint64_t)time(nullptr) + 600 /* 10 minutes */)
      {
        result.status = register_service_node_result_status::registration_timestamp_expired;
        result.msg    = tr("The registration timestamp has expired.");
        return result;
      }
    }
    catch (const std::exception &e)
    {
      result.status = register_service_node_result_status::registration_timestamp_expired;
      result.msg = tr("The registration timestamp failed to parse: ") + local_args[timestamp_index];
      return result;
    }

    if (!tools::hex_to_type(local_args[key_index], service_node_key))
    {
      result.status = register_service_node_result_status::service_node_key_parse_fail;
      result.msg = tr("Failed to parse service node pubkey");
      return result;
    }

    if (!tools::hex_to_type(local_args[signature_index], signature))
    {
      result.status = register_service_node_result_status::service_node_signature_parse_fail;
      result.msg = tr("Failed to parse service node signature");
      return result;
    }
  }

  try
  {
      service_nodes::validate_contributor_args(*hf_version, contributor_args);
      service_nodes::validate_contributor_args_signature(contributor_args, expiration_timestamp, service_node_key, signature);
  }
  catch(const service_nodes::invalid_contributions &e)
  {
    result.status = register_service_node_result_status::validate_contributor_args_fail;
    result.msg    = e.what();
    return result;
  }

  std::vector<uint8_t> extra;
  add_service_node_contributor_to_tx_extra(extra, address);
  add_service_node_pubkey_to_tx_extra(extra, service_node_key);
  if (!add_service_node_register_to_tx_extra(extra, contributor_args.addresses, contributor_args.portions_for_operator, contributor_args.portions, expiration_timestamp, signature))
  {
    result.status = register_service_node_result_status::service_node_register_serialize_to_tx_extra_fail;
    result.msg    = tr("Failed to serialize service node registration tx extra");
    return result;
  }

  //
  // Check service is able to be registered
  //
  refresh(false);
  {
    const auto [success, response] = get_service_nodes({service_node_key_as_str});
    if (!success)
    {
      result.status = register_service_node_result_status::service_node_list_query_failed;
      result.msg    = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
      return result;
    }

    if (response.size() >= 1)
    {
      result.status = register_service_node_result_status::service_node_cannot_reregister;
      result.msg    = tr("This service node is already registered");
      return result;
    }
  }

  //
  // Create Register Transaction
  //
  {
    uint64_t amount_payable_by_operator = 0;
    {
      const uint64_t DUST                 = MAX_NUMBER_OF_CONTRIBUTORS;
      uint64_t amount_left                = staking_requirement;
      for (size_t i = 0; i < contributor_args.portions.size(); i++)
      {
        uint64_t amount = service_nodes::portions_to_amount(staking_requirement, contributor_args.portions[i]);
        if (i == 0) amount_payable_by_operator += amount;
        amount_left -= amount;
      }

      if (amount_left <= DUST)
        amount_payable_by_operator += amount_left;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::tx_destination_entry de;
    de.addr = address;
    de.is_subaddress = false;
    de.amount = amount_payable_by_operator;
    dsts.push_back(de);

    try
    {
      // NOTE(oxen): We know the address should always be a primary address and has no payment id, so we can ignore the subaddress/payment id field here
      cryptonote::address_parse_info dest = {};
      dest.address                        = address;

      oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, txtype::stake, priority);
      auto ptx_vector = create_transactions_2(dsts, CRYPTONOTE_DEFAULT_TX_MIXIN, 0 /* unlock_time */, priority, extra, subaddr_account, subaddr_indices, tx_params);
      if (ptx_vector.size() == 1)
      {
        result.status = register_service_node_result_status::success;
        result.ptx    = ptx_vector[0];
      }
      else
      {
        result.status = register_service_node_result_status::too_many_transactions_constructed;
        result.msg    = ERR_MSG_TOO_MANY_TXS_CONSTRUCTED;
      }
    }
    catch (const std::exception& e)
    {
      result.status = register_service_node_result_status::exception_thrown;
      result.msg    = ERR_MSG_EXCEPTION_THROWN;
      result.msg += e.what();
      return result;
    }
  }

  assert(result.status != register_service_node_result_status::invalid);
  return result;
}

wallet2::request_stake_unlock_result wallet2::can_request_stake_unlock(const crypto::public_key &sn_key)
{
  request_stake_unlock_result result = {};
  result.ptx.tx.version = cryptonote::txversion::v4_tx_types;
  result.ptx.tx.type    = cryptonote::txtype::key_image_unlock;

  std::string const sn_key_as_str = tools::type_to_hex(sn_key);
  {
    const auto [success, response] = get_service_nodes({{sn_key_as_str}});
    if (!success)
    {
      result.msg = tr("Failed to retrieve service node data from daemon");
      return result;
    }

    if (response.empty())
    {
      result.msg = tr("No service node is known for: ") + sn_key_as_str;
      return result;
    }

    cryptonote::account_public_address const primary_address = get_address();
    std::vector<rpc::service_node_contribution> const *contributions = nullptr;
    rpc::GET_SERVICE_NODES::response::entry const &node_info = response[0];
    for (auto const &contributor : node_info.contributors)
    {
      address_parse_info address_info = {};
      cryptonote::get_account_address_from_str(address_info, nettype(), contributor.address);

      if (address_info.address != primary_address)
        continue;

      contributions = &contributor.locked_contributions;
      break;
    }

    if (!contributions)
    {
      result.msg = tr("No contributions recognised by this wallet in service node: ") + sn_key_as_str;
      return result;
    }

    if (contributions->empty())
    {
      result.msg = tr("Unexpected 0 contributions in service node for this wallet ") + sn_key_as_str;
      return result;
    }

    cryptonote::tx_extra_tx_key_image_unlock unlock = {};
    {
      uint64_t curr_height = 0;
      {
        std::string err_msg;
        curr_height = get_daemon_blockchain_height(err_msg);
        if (!err_msg.empty())
        {
          result.msg = tr("unable to get network blockchain height from daemon: ") + err_msg;
          return result;
        }
      }

      result.msg.reserve(1024);
      auto const &contribution = (*contributions)[0];
      if (node_info.requested_unlock_height != 0)
      {
        result.msg.append("Key image: ");
        result.msg.append(contribution.key_image);
        result.msg.append(" has already been requested to be unlocked, unlocking at height: ");
        result.msg.append(std::to_string(node_info.requested_unlock_height));
        result.msg.append(" (about ");
        result.msg.append(tools::get_human_readable_timespan(std::chrono::seconds((node_info.requested_unlock_height - curr_height) * TARGET_BLOCK_TIME)));
        result.msg.append(")");
        return result;
      }

      result.msg.append("You are requesting to unlock a stake of: ");
      result.msg.append(cryptonote::print_money(contribution.amount));
      result.msg.append(" Loki from the service node network.\nThis will schedule the service node: ");
      result.msg.append(node_info.service_node_pubkey);
      result.msg.append(" for deactivation.");
      if (node_info.contributors.size() > 1) {
          result.msg.append(" The stakes of the service node's ");
          result.msg.append(std::to_string(node_info.contributors.size() - 1));
          result.msg.append(" other contributors will unlock at the same time.");
      }
      result.msg.append("\n\n");

      uint64_t unlock_height = service_nodes::get_locked_key_image_unlock_height(nettype(), node_info.registration_height, curr_height);
      result.msg.append("You will continue receiving rewards until the service node expires at the estimated height: ");
      result.msg.append(std::to_string(unlock_height));
      result.msg.append(" (about ");
      result.msg.append(tools::get_human_readable_timespan(std::chrono::seconds((unlock_height - curr_height) * TARGET_BLOCK_TIME)));
      result.msg.append(")");

      if(!tools::hex_to_type(contribution.key_image, unlock.key_image))
      {
        result.msg = tr("Failed to parse hex representation of key image: ") + contribution.key_image;
        return result;
      }

      // We used to use a 32-byte time value concatenated to itself 8 times as a message hash, but
      // that accomplishes nothing (there is no point in using a nonce in the message itself: a
      // signature already has its own nonce), so now we just sign with a null hash and always send
      // out a nonce value of 0.  The nonce value, unfortunately, can't be easily removed from the
      // key image unlock tx_extra data without versioning/replacing it, so we still send this 0,
      // but this will hopefully make it easier in the future to eliminate from the tx extra.
      unlock.nonce = tx_extra_tx_key_image_unlock::FAKE_NONCE;
      try {
        if (!generate_signature_for_request_stake_unlock(unlock.key_image, unlock.signature))
        {
          result.msg = tr("Failed to generate signature to sign request. The key image: ") + contribution.key_image + tr(" doesn't belong to this wallet");
          return result;
        }
      } catch (const std::exception& e) {
        result.msg = tr("Failed to generate unlock signature: ") + std::string(e.what());
        return result;
      }
    }

    add_service_node_pubkey_to_tx_extra(result.ptx.tx.extra, sn_key);
    add_tx_key_image_unlock_to_tx_extra(result.ptx.tx.extra, unlock);
  }

  result.success = true;
  return result;
}

struct ons_prepared_args
{
  bool prepared;
  operator bool() const { return prepared; }
  ons::mapping_value      encrypted_value;
  crypto::hash            name_hash;
  ons::generic_owner      owner;
  ons::generic_owner      backup_owner;
  ons::generic_signature  signature;
  crypto::hash            prev_txid;
};

static bool try_generate_ons_signature(wallet2 const &wallet, std::string const &curr_owner, std::string const *new_owner, std::string const *new_backup_owner, ons_prepared_args &result)
{
  cryptonote::address_parse_info curr_owner_parsed = {};
  if (!cryptonote::get_account_address_from_str(curr_owner_parsed, wallet.nettype(), curr_owner))
      return false;

  std::optional<cryptonote::subaddress_index> index = wallet.get_subaddress_index(curr_owner_parsed.address);
  if (!index) return false;

  auto sig_data = ons::tx_extra_signature(
      result.encrypted_value.to_view(),
      new_owner ? &result.owner : nullptr,
      new_backup_owner ? &result.backup_owner : nullptr,
      result.prev_txid);
  if (sig_data.empty()) return false;

  auto& account = wallet.get_account();
  auto& hwdev = account.get_device();
  hw::mode_resetter rst{hwdev};
  hwdev.generate_ons_signature(sig_data, account.get_keys(), *index, result.signature.monero);
  result.signature.type = ons::generic_owner_sig_type::monero;

  return true;
}

static ons_prepared_args prepare_tx_extra_oxen_name_system_values(wallet2 const &wallet,
                                                                  ons::mapping_type type,
                                                                  uint32_t priority,
                                                                  std::string name,
                                                                  std::string const *value,
                                                                  std::string const *owner,
                                                                  std::string const *backup_owner,
                                                                  bool make_signature,
                                                                  ons::ons_tx_type txtype,
                                                                  uint32_t account_index,
                                                                  std::string *reason,
                                                                  std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> *response)
{
  ons_prepared_args result = {};
  if (priority == tools::tx_priority_blink)
  {
    if (reason) *reason = "Can not request a blink TX for Oxen Name Service transactions";
    return {};
  }

  name = tools::lowercase_ascii_string(name);
  if (!ons::validate_ons_name(type, name, reason))
    return {};

  result.name_hash = ons::name_to_hash(name);
  if (value)
  {
    if (!ons::mapping_value::validate(wallet.nettype(), type, *value, &result.encrypted_value, reason))
      return {};

    if (!result.encrypted_value.encrypt(name, &result.name_hash))
    {
      if (reason) *reason = "Fail to encrypt mapping value=" + *value;
      return {};
    }
  }

  if (owner && !ons::parse_owner_to_generic_owner(wallet.nettype(), *owner, result.owner, reason))
      return {};

  if (backup_owner && !ons::parse_owner_to_generic_owner(wallet.nettype(), *backup_owner, result.backup_owner, reason))
      return {};

  {
    cryptonote::rpc::ONS_NAMES_TO_OWNERS::request request = {};
    {
      auto &request_entry = request.entries.emplace_back();
      request_entry.name_hash = oxenmq::to_base64(tools::view_guts(result.name_hash));
      request_entry.types.push_back(ons::db_mapping_type(type));
    }

    auto [success, response_] = wallet.ons_names_to_owners(request);
    if (!response)
      response = &response_;
    else
      *response = std::move(response_);
    if (!success)
    {
      if (reason) *reason = "Failed to query previous owner for ONS entry: communication with daemon failed";
      return result;
    }

    if (response->size())
    {
      if (!tools::hex_to_type((*response)[0].txid, result.prev_txid))
      {
        if (reason) *reason = "Failed to convert response txid=" + (*response)[0].txid + " from the daemon into a 32 byte hash, it must be a 64 char hex string";
        return result;
      }
    }

    if (txtype == ons::ons_tx_type::update && make_signature)
    {
      if (response->empty())
      {
        if (reason) *reason = "Signature requested when preparing ONS TX but record to update does not exist";
        return result;
      }

      cryptonote::address_parse_info curr_owner_parsed        = {};
      cryptonote::address_parse_info curr_backup_owner_parsed = {};
      auto& rowner = response->front().owner;
      auto& rbackup_owner = response->front().backup_owner;
      bool curr_owner        = cryptonote::get_account_address_from_str(curr_owner_parsed, wallet.nettype(), rowner);
      bool curr_backup_owner = rbackup_owner && cryptonote::get_account_address_from_str(curr_backup_owner_parsed, wallet.nettype(), *rbackup_owner);
      if (!try_generate_ons_signature(wallet, rowner, owner, backup_owner, result))
      {
        if (!rbackup_owner || !try_generate_ons_signature(wallet, *rbackup_owner, owner, backup_owner, result))
        {
          if (reason)
          {
            *reason = "Signature requested when preparing ONS TX, but this wallet is not the owner of the record owner=" + rowner;
            if (rbackup_owner) *reason += ", backup_owner=" + *rbackup_owner;
          }
          return result;
        }
      }
    }
    else if (txtype == ons::ons_tx_type::renew)
    {
      if (response->empty())
      {
        if (reason) *reason = "Renewal requested but record to renew does not exist or has expired";
        return result;
      }
    }
  }

  result.prepared = true;
  return result;
}

std::vector<wallet2::pending_tx> wallet2::ons_create_buy_mapping_tx(ons::mapping_type type,
                                                                    std::string const *owner,
                                                                    std::string const *backup_owner,
                                                                    std::string name,
                                                                    std::string const &value,
                                                                    std::string *reason,
                                                                    uint32_t priority,
                                                                    uint32_t account_index,
                                                                    std::set<uint32_t> subaddr_indices)
{
  std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> response;
  constexpr bool make_signature = false;
  ons_prepared_args prepared_args = prepare_tx_extra_oxen_name_system_values(*this, type, priority, name, &value, owner, backup_owner, make_signature, ons::ons_tx_type::buy, account_index, reason, &response);
  if (!owner)
    prepared_args.owner = ons::make_monero_owner(get_subaddress({account_index, 0}), account_index != 0);

  if (!prepared_args)
    return {};

  std::vector<uint8_t> extra;
  auto entry = cryptonote::tx_extra_oxen_name_system::make_buy(
      prepared_args.owner,
      backup_owner ? &prepared_args.backup_owner : nullptr,
      type,
      prepared_args.name_hash,
      prepared_args.encrypted_value.to_string(),
      prepared_args.prev_txid);
  add_oxen_name_system_to_tx_extra(extra, entry);

  std::optional<uint8_t> hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    if (reason) *reason = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return {};
  }

  oxen_construct_tx_params tx_params = wallet2::construct_params(*hf_version, txtype::oxen_name_system, priority, 0, type);
  auto result = create_transactions_2({} /*dests*/,
                                      CRYPTONOTE_DEFAULT_TX_MIXIN,
                                      0 /*unlock_at_block*/,
                                      priority,
                                      extra,
                                      account_index,
                                      subaddr_indices,
                                      tx_params);
  return result;
}

std::optional<ons::mapping_type> wallet2::ons_validate_type(std::string_view type, ons::ons_tx_type ons_action, std::string *reason)
{
  std::optional<uint8_t> hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    if (reason) *reason = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return std::nullopt;
  }
  ons::mapping_type mapping_type;
  if (!ons::validate_mapping_type(type, *hf_version, ons_action, &mapping_type, reason))
    return std::nullopt;

  return mapping_type;
}

std::vector<wallet2::pending_tx> wallet2::ons_create_renewal_tx(
    ons::mapping_type type,
    std::string name,
    std::string *reason,
    uint32_t priority,
    uint32_t account_index,
    std::set<uint32_t> subaddr_indices,
    std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> *response
    )
{
  constexpr bool make_signature = false;
  ons_prepared_args prepared_args = prepare_tx_extra_oxen_name_system_values(*this, type, priority, name, nullptr, nullptr, nullptr, make_signature, ons::ons_tx_type::renew, account_index, reason, response);

  if (!prepared_args)
    return {};

  std::vector<uint8_t> extra;
  auto entry = cryptonote::tx_extra_oxen_name_system::make_renew(
      type,
      prepared_args.name_hash,
      prepared_args.prev_txid);
  add_oxen_name_system_to_tx_extra(extra, entry);

  std::optional<uint8_t> hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    if (reason) *reason = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return {};
  }

  oxen_construct_tx_params tx_params = wallet2::construct_params(*hf_version, txtype::oxen_name_system, priority, 0, type);
  auto result = create_transactions_2({} /*dests*/,
                                      CRYPTONOTE_DEFAULT_TX_MIXIN,
                                      0 /*unlock_at_block*/,
                                      priority,
                                      extra,
                                      account_index,
                                      subaddr_indices,
                                      tx_params);
  return result;
}


std::vector<wallet2::pending_tx> wallet2::ons_create_update_mapping_tx(ons::mapping_type type,
                                                                       std::string name,
                                                                       std::string const *value,
                                                                       std::string const *owner,
                                                                       std::string const *backup_owner,
                                                                       std::string const *signature,
                                                                       std::string *reason,
                                                                       uint32_t priority,
                                                                       uint32_t account_index,
                                                                       std::set<uint32_t> subaddr_indices,
                                                                       std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> *response)
{
  if (!value && !owner && !backup_owner)
  {
    if (reason) *reason = "Value, owner and backup owner are not specified. Atleast one field must be specified for updating the ONS record";
    return {};
  }

  bool make_signature = signature == nullptr;
  ons_prepared_args prepared_args = prepare_tx_extra_oxen_name_system_values(*this, type, priority, name, value, owner, backup_owner, make_signature, ons::ons_tx_type::update, account_index, reason, response);
  if (!prepared_args) return {};

  if (!make_signature)
  {
    if (!tools::hex_to_type(*signature, prepared_args.signature.ed25519))
    {
      if (reason) *reason = "Hex signature provided failed to convert to a signature, signature=" + *signature;
      return {};
    }
  }

  std::vector<uint8_t> extra;
  auto entry = cryptonote::tx_extra_oxen_name_system::make_update(prepared_args.signature,
                                                                  type,
                                                                  prepared_args.name_hash,
                                                                  prepared_args.encrypted_value.to_view(),
                                                                  owner ? &prepared_args.owner : nullptr,
                                                                  backup_owner ? &prepared_args.backup_owner : nullptr,
                                                                  prepared_args.prev_txid);
  add_oxen_name_system_to_tx_extra(extra, entry);
  std::optional<uint8_t> hf_version = get_hard_fork_version();
  if (!hf_version)
  {
    if (reason) *reason = ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return {};
  }
  oxen_construct_tx_params tx_params = wallet2::construct_params(*hf_version, txtype::oxen_name_system, priority, 0, ons::mapping_type::update_record_internal);

  auto result = create_transactions_2({} /*dests*/,
                                      CRYPTONOTE_DEFAULT_TX_MIXIN,
                                      0 /*unlock_at_block*/,
                                      priority,
                                      extra,
                                      account_index,
                                      subaddr_indices,
                                      tx_params);
  return result;
}

bool wallet2::lock_keys_file()
{
  if (m_wallet_file.empty())
    return true;
  if (m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already locked.");
    return false;
  }
  m_keys_file_locker.reset(new tools::file_locker(m_keys_file));
  return true;
}

bool wallet2::unlock_keys_file()
{
  if (m_wallet_file.empty())
    return true;
  if (!m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already unlocked.");
    return false;
  }
  m_keys_file_locker.reset();
  return true;
}

bool wallet2::ons_make_update_mapping_signature(ons::mapping_type type,
                                                std::string name,
                                                std::string const *value,
                                                std::string const *owner,
                                                std::string const *backup_owner,
                                                ons::generic_signature &signature,
                                                uint32_t account_index,
                                                std::string *reason)
{
  std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> response;
  constexpr bool make_signature = true;
  ons_prepared_args prepared_args = prepare_tx_extra_oxen_name_system_values(*this, type, tx_priority_unimportant, name, value, owner, backup_owner, make_signature, ons::ons_tx_type::update, account_index, reason, &response);
  if (!prepared_args) return false;

  if (prepared_args.prev_txid == crypto::null_hash)
  {
    if (reason) *reason = "name=\"" + name + std::string("\" does not have a corresponding ONS record, the mapping is available for purchase, update signature is not required.");
    return false;
  }

  signature = std::move(prepared_args.signature);
  return true;
}

bool wallet2::is_keys_file_locked() const
{
  if (m_wallet_file.empty())
    return false;
  return m_keys_file_locker->locked();
}

bool wallet2::tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& output_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const
{
  if (!unlocked) // don't add locked outs
    return false;
  if (global_index == real_index) // don't re-add real one
    return false;
  auto item = std::make_tuple(global_index, output_public_key, mask);
  CHECK_AND_ASSERT_MES(!outs.empty(), false, "internal error: outs is empty");
  if (std::find(outs.back().begin(), outs.back().end(), item) != outs.back().end()) // don't add duplicates
    return false;
  // check the keys are valid
  if (!rct::isInMainSubgroup(rct::pk2rct(output_public_key)))
  {
    // TODO(oxen): FIXME(oxen): Payouts to the null service node address are
    // transactions constructed with an invalid public key and fail this check.

    // Technically we should not be mixing them- but in test environments like
    // devnet/testnet where there may be extended periods of time where there
    // are many payouts to the null service node, then during fake output
    // selection they are considered invalid.

    // And upon removing all of them, we end up with insufficient outputs to
    // construct a valid mixin for the transaction. This causes construction to
    // spuriously fail reliably on such networks.

    // So for now, let it slide on test networks. Ideally we want to fix this,
    // such that we never include them for "correctness" of the network.

    // For mainnet though, enforce this check. If we start failing to construct
    // transaction(s) on the mainnet due to invalid keys then we want to know
    // and address it, as it is at the moment mainnet is not affected by this
    // and so we want the added correctness this check offers.
    if (nettype() == cryptonote::MAINNET)
    {
      MWARNING("Key " << output_public_key << " at index " << global_index << " is not in the main subgroup");
      return false;
    }
  }
  if (!rct::isInMainSubgroup(mask))
  {
    MWARNING("Commitment " << mask << " at index " << global_index << " is not in the main subgroup");
    return false;
  }
//  if (is_output_blackballed(output_public_key)) // don't add blackballed outputs
//    return false;
  outs.back().push_back(item);
  return true;
}

void wallet2::light_wallet_get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count) {

  MDEBUG("LIGHTWALLET - Getting random outs");

  light_rpc::GET_RANDOM_OUTS::request oreq{};
  light_rpc::GET_RANDOM_OUTS::response ores{};

  size_t light_wallet_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);

  // Amounts to ask for
  // MyMonero api handle amounts and fees as strings
  for(size_t idx: selected_transfers) {
    const uint64_t ask_amount = m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount();
    std::ostringstream amount_ss;
    amount_ss << ask_amount;
    oreq.amounts.push_back(amount_ss.str());
  }

  oreq.count = light_wallet_requested_outputs_count;
  bool r = invoke_http<light_rpc::GET_RANDOM_OUTS>(oreq, ores);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_random_outs");
  THROW_WALLET_EXCEPTION_IF(ores.amount_outs.empty() , error::wallet_internal_error, "No outputs received from light wallet node. Error: " + ores.Error);

  // Check if we got enough outputs for each amount
  for(auto& out: ores.amount_outs) {
    const uint64_t out_amount = boost::lexical_cast<uint64_t>(out.amount);
    THROW_WALLET_EXCEPTION_IF(out.outputs.size() < light_wallet_requested_outputs_count , error::wallet_internal_error, "Not enough outputs for amount: " + boost::lexical_cast<std::string>(out.amount));
    MDEBUG(out.outputs.size() << " outputs for amount "+ boost::lexical_cast<std::string>(out.amount) + " received from light wallet node");
  }

  MDEBUG("selected transfers size: " << selected_transfers.size());

  for(size_t idx: selected_transfers)
  {
    // Create new index
    outs.push_back(std::vector<get_outs_entry>());
    outs.back().reserve(fake_outputs_count + 1);

    // add real output first
    const transfer_details &td = m_transfers[idx];
    const uint64_t amount = td.is_rct() ? 0 : td.amount();
    outs.back().push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), rct::commit(td.amount(), td.m_mask)));
    MDEBUG("added real output " << tools::type_to_hex(td.get_public_key()));

    // Even if the lightwallet server returns random outputs, we pick them randomly.
    std::vector<size_t> order;
    order.resize(light_wallet_requested_outputs_count);
    for (size_t n = 0; n < order.size(); ++n)
      order[n] = n;
    std::shuffle(order.begin(), order.end(), crypto::random_device{});


    LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs with amounts " << print_money(td.is_rct() ? 0 : td.amount()));
    MDEBUG("OUTS SIZE: " << outs.back().size());
    for (size_t o = 0; o < light_wallet_requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
    {
      // Random pick
      size_t i = order[o];

      // Find which random output key to use
      bool found_amount = false;
      size_t amount_key;
      for(amount_key = 0; amount_key < ores.amount_outs.size(); ++amount_key)
      {
        if(boost::lexical_cast<uint64_t>(ores.amount_outs[amount_key].amount) == amount) {
          found_amount = true;
          break;
        }
      }
      THROW_WALLET_EXCEPTION_IF(!found_amount , error::wallet_internal_error, "Outputs for amount " + boost::lexical_cast<std::string>(ores.amount_outs[amount_key].amount) + " not found" );

      LOG_PRINT_L2("Index " << i << "/" << light_wallet_requested_outputs_count << ": idx " << ores.amount_outs[amount_key].outputs[i].global_index << " (real " << td.m_global_output_index << "), unlocked " << "(always in light)" << ", key " << ores.amount_outs[0].outputs[i].public_key);

      // Convert light wallet string data to proper data structures
      crypto::public_key tx_public_key;
      rct::key mask{}; // decrypted mask - not used here
      rct::key rct_commit{};
      const auto& pkey = ores.amount_outs[amount_key].outputs[i].public_key;
      THROW_WALLET_EXCEPTION_IF(pkey.size() != 64 || !oxenmq::is_hex(pkey), error::wallet_internal_error, "Invalid public_key");
      tools::hex_to_type(ores.amount_outs[amount_key].outputs[i].public_key, tx_public_key);
      const uint64_t global_index = ores.amount_outs[amount_key].outputs[i].global_index;
      if(!light_wallet_parse_rct_str(ores.amount_outs[amount_key].outputs[i].rct, tx_public_key, 0, mask, rct_commit, false))
        rct_commit = rct::zeroCommit(td.amount());

      if (tx_add_fake_output(outs, global_index, tx_public_key, rct_commit, td.m_global_output_index, true)) {
        MDEBUG("added fake output " << ores.amount_outs[amount_key].outputs[i].public_key);
        MDEBUG("index " << global_index);
      }
    }

    THROW_WALLET_EXCEPTION_IF(outs.back().size() < fake_outputs_count + 1 , error::wallet_internal_error, "Not enough fake outputs found" );

    // Real output is the first. Shuffle outputs
    MTRACE(outs.back().size() << " outputs added. Sorting outputs by index:");
    std::sort(outs.back().begin(), outs.back().end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });

    // Print output order
    for(auto added_out: outs.back())
      MTRACE(std::get<0>(added_out));

  }
}

std::pair<std::set<uint64_t>, size_t> outs_unique(const std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs)
{
  std::set<uint64_t> unique;
  size_t total = 0;

  for (const auto &it : outs)
  {
    for (const auto &out : it)
    {
      const uint64_t global_index = std::get<0>(out);
      unique.insert(global_index);
    }
    total += it.size();
  }

  return std::make_pair(std::move(unique), total);
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, bool has_rct)
{
  std::vector<uint64_t> rct_offsets;
  for (size_t attempts = 3; attempts > 0; --attempts)
  {
    get_outs(outs, selected_transfers, fake_outputs_count, rct_offsets, has_rct);

    const auto unique = outs_unique(outs);
    if (tx_sanity_check(unique.first, unique.second, rct_offsets.empty() ? 0 : rct_offsets.back()))
    {
      return;
    }

    std::vector<crypto::key_image> key_images;
    key_images.reserve(selected_transfers.size());
    std::for_each(selected_transfers.begin(), selected_transfers.end(), [this, &key_images](size_t index) {
      key_images.push_back(m_transfers[index].m_key_image);
    });
    unset_ring(key_images);
  }

  THROW_WALLET_EXCEPTION(error::wallet_internal_error, tr("Transaction sanity check failed"));
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets, bool has_rct)
{
  LOG_PRINT_L2("fake_outputs_count: " << fake_outputs_count);
  outs.clear();

  if(m_light_wallet && fake_outputs_count > 0) {
    light_wallet_get_outs(outs, selected_transfers, fake_outputs_count);
    return;
  }

  if (fake_outputs_count > 0)
  {
    uint64_t segregation_fork_height = get_segregation_fork_height();
    // check whether we're shortly after the fork
    uint64_t height;
    if (!m_node_rpc_proxy.get_height(height))
      THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, __func__);

    bool is_shortly_after_segregation_fork = height >= segregation_fork_height && height < segregation_fork_height + SEGREGATION_FORK_VICINITY;
    bool is_after_segregation_fork = height >= segregation_fork_height;

    // if we have at least one rct out, get the distribution, or fall back to the previous system
    uint64_t rct_start_height;
    std::vector<uint64_t> rct_offsets;
    const bool has_rct_distribution = has_rct && get_rct_distribution(rct_start_height, rct_offsets);

    // get histogram for the amounts we need
    cryptonote::rpc::GET_OUTPUT_HISTOGRAM::request req_t{};
    cryptonote::rpc::GET_OUTPUT_HISTOGRAM::response resp_t{};
    {
      uint64_t max_rct_index = 0;
      for (size_t idx: selected_transfers)
      {
        if (m_transfers[idx].is_rct())
        {
          max_rct_index = std::max(max_rct_index, m_transfers[idx].m_global_output_index);
        }

        // request histogram for all outputs, except 0 if we have the rct distribution
        if (!m_transfers[idx].is_rct() || !has_rct_distribution)
        {
          req_t.amounts.push_back(m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount());
        }
      }

      if (has_rct_distribution)
      {
        // check we're clear enough of rct start, to avoid corner cases below
        THROW_WALLET_EXCEPTION_IF(rct_offsets.size() <= CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
            error::get_output_distribution, "Not enough rct outputs");
        THROW_WALLET_EXCEPTION_IF(rct_offsets.back() <= max_rct_index,
            error::get_output_distribution, "Daemon reports suspicious number of rct outputs");
      }
    }

    std::vector<uint64_t> output_blacklist;
    if (!get_output_blacklist(output_blacklist))
      THROW_WALLET_EXCEPTION_IF(true, error::get_output_blacklist, "Couldn't retrive list of outputs that are to be excluded from selection");

    std::sort(output_blacklist.begin(), output_blacklist.end());
    if (output_blacklist.size() * 0.05 > (double)rct_offsets.size())
    {
      MWARNING("More than 5% of outputs are blacklisted ("
               << output_blacklist.size() << "/" << rct_offsets.size()
               << "), please notify the Loki developers");
    }

    if (!req_t.amounts.empty())
    {
      std::sort(req_t.amounts.begin(), req_t.amounts.end());
      auto end = std::unique(req_t.amounts.begin(), req_t.amounts.end());
      req_t.amounts.resize(std::distance(req_t.amounts.begin(), end));
      req_t.unlocked = true;
      req_t.recent_cutoff = time(NULL) - RECENT_OUTPUT_ZONE;
      bool r = invoke_http<rpc::GET_OUTPUT_HISTOGRAM>(req_t, resp_t);
      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "transfer_selected");
      THROW_WALLET_EXCEPTION_IF(resp_t.status == rpc::STATUS_BUSY, error::daemon_busy, "get_output_histogram");
      THROW_WALLET_EXCEPTION_IF(resp_t.status != rpc::STATUS_OK, error::get_histogram_error, get_rpc_status(resp_t.status));
    }

    // if we want to segregate fake outs pre or post fork, get distribution
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> segregation_limit;
    if (is_after_segregation_fork && (m_segregate_pre_fork_outputs || m_key_reuse_mitigation2))
    {
      cryptonote::rpc::GET_OUTPUT_DISTRIBUTION_BIN::request req_t{};
      cryptonote::rpc::GET_OUTPUT_DISTRIBUTION_BIN::response resp_t{};
      for(size_t idx: selected_transfers)
        req_t.amounts.push_back(m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount());
      std::sort(req_t.amounts.begin(), req_t.amounts.end());
      auto end = std::unique(req_t.amounts.begin(), req_t.amounts.end());
      req_t.amounts.resize(std::distance(req_t.amounts.begin(), end));
      req_t.from_height = std::max<uint64_t>(segregation_fork_height, RECENT_OUTPUT_BLOCKS) - RECENT_OUTPUT_BLOCKS;
      req_t.to_height = segregation_fork_height + 1;
      req_t.cumulative = true;
      req_t.binary = true;
      req_t.compress = true;
      bool r = invoke_http<rpc::GET_OUTPUT_DISTRIBUTION_BIN>(req_t, resp_t);
      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "transfer_selected");
      THROW_WALLET_EXCEPTION_IF(resp_t.status == rpc::STATUS_BUSY, error::daemon_busy, "get_output_distribution");
      THROW_WALLET_EXCEPTION_IF(resp_t.status != rpc::STATUS_OK, error::get_output_distribution, get_rpc_status(resp_t.status));

      // check we got all data
      for(size_t idx: selected_transfers)
      {
        const uint64_t amount = m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount();
        bool found = false;
        for (const auto &d: resp_t.distributions)
        {
          if (d.amount == amount)
          {
            THROW_WALLET_EXCEPTION_IF(d.data.start_height > segregation_fork_height, error::get_output_distribution, "Distribution start_height too high");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - d.data.start_height >= d.data.distribution.size(), error::get_output_distribution, "Distribution size too small");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - RECENT_OUTPUT_BLOCKS - d.data.start_height >= d.data.distribution.size(), error::get_output_distribution, "Distribution size too small");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height <= RECENT_OUTPUT_BLOCKS, error::wallet_internal_error, "Fork height too low");
            THROW_WALLET_EXCEPTION_IF(segregation_fork_height - RECENT_OUTPUT_BLOCKS < d.data.start_height, error::get_output_distribution, "Bad start height");
            uint64_t till_fork = d.data.distribution[segregation_fork_height - d.data.start_height];
            uint64_t recent = till_fork - d.data.distribution[segregation_fork_height - RECENT_OUTPUT_BLOCKS - d.data.start_height];
            segregation_limit[amount] = std::make_pair(till_fork, recent);
            found = true;
            break;
          }
        }
        THROW_WALLET_EXCEPTION_IF(!found, error::get_output_distribution, "Requested amount not found in response");
      }
    }

    // we ask for more, to have spares if some outputs are still locked
    size_t base_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);
    LOG_PRINT_L2("base_requested_outputs_count: " << base_requested_outputs_count);

    // generate output indices to request
    rpc::GET_OUTPUTS_BIN::request req{};
    decltype(req.outputs) get_outputs;

    std::unique_ptr<gamma_picker> gamma;
    if (has_rct_distribution)
      gamma.reset(new gamma_picker(rct_offsets));

    size_t num_selected_transfers = 0;
    for(size_t idx: selected_transfers)
    {
      ++num_selected_transfers;
      const transfer_details &td = m_transfers[idx];
      const uint64_t amount = td.is_rct() ? 0 : td.amount();
      std::unordered_set<uint64_t> seen_indices;
      // request more for rct in base recent (locked) coinbases are picked, since they're locked for longer
      size_t requested_outputs_count = base_requested_outputs_count + (td.is_rct() ? CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE : 0);
      size_t start = get_outputs.size();
      bool use_histogram = amount != 0 || !has_rct_distribution;

      const bool output_is_pre_fork = td.m_block_height < segregation_fork_height;
      uint64_t num_outs = 0, num_recent_outs = 0;
      uint64_t num_post_fork_outs = 0;
      float pre_fork_num_out_ratio = 0.0f;
      float post_fork_num_out_ratio = 0.0f;

      if (is_after_segregation_fork && m_segregate_pre_fork_outputs && output_is_pre_fork)
      {
        num_outs = segregation_limit[amount].first;
        num_recent_outs = segregation_limit[amount].second;
      }
      else
      {
        // if there are just enough outputs to mix with, use all of them.
        // Eventually this should become impossible.
        for (const auto &he: resp_t.histogram)
        {
          if (he.amount == amount)
          {
            LOG_PRINT_L2("Found " << print_money(amount) << ": " << he.total_instances << " total, "
                << he.unlocked_instances << " unlocked, " << he.recent_instances << " recent");
            num_outs = he.unlocked_instances;
            num_recent_outs = he.recent_instances;
            break;
          }
        }
        if (is_after_segregation_fork && m_key_reuse_mitigation2)
        {
          if (output_is_pre_fork)
          {
            if (is_shortly_after_segregation_fork)
            {
              pre_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
            else
            {
              pre_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
              post_fork_num_out_ratio = 33.4/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
          }
          else
          {
            if (is_shortly_after_segregation_fork)
            {
            }
            else
            {
              post_fork_num_out_ratio = 67.8/100.0f * (1.0f - RECENT_OUTPUT_RATIO);
            }
          }
        }
        num_post_fork_outs = num_outs - segregation_limit[amount].first;
      }

      if (use_histogram)
      {
        LOG_PRINT_L1("" << num_outs << " unlocked outputs of size " << print_money(amount));
        THROW_WALLET_EXCEPTION_IF(num_outs == 0, error::wallet_internal_error,
            "histogram reports no unlocked outputs for " + boost::lexical_cast<std::string>(amount) + ", not even ours");
        THROW_WALLET_EXCEPTION_IF(num_recent_outs > num_outs, error::wallet_internal_error,
            "histogram reports more recent outs than outs for " + boost::lexical_cast<std::string>(amount));
      }
      else
      {
        // the base offset of the first rct output in the first unlocked block (or the one to be if there's none)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];
        LOG_PRINT_L1("" << num_outs << " unlocked rct outputs");
        THROW_WALLET_EXCEPTION_IF(num_outs == 0, error::wallet_internal_error,
            "histogram reports no unlocked rct outputs, not even ours");
      }

      // how many fake outs to draw on a pre-fork distribution
      size_t pre_fork_outputs_count = requested_outputs_count * pre_fork_num_out_ratio;
      size_t post_fork_outputs_count = requested_outputs_count * post_fork_num_out_ratio;
      // how many fake outs to draw otherwise
      size_t normal_output_count = requested_outputs_count - pre_fork_outputs_count - post_fork_outputs_count;

      size_t recent_outputs_count = 0;
      if (use_histogram)
      {
        // X% of those outs are to be taken from recent outputs
        recent_outputs_count = normal_output_count * RECENT_OUTPUT_RATIO;
        if (recent_outputs_count == 0)
          recent_outputs_count = 1; // ensure we have at least one, if possible
        if (recent_outputs_count > num_recent_outs)
          recent_outputs_count = num_recent_outs;
        if (td.m_global_output_index >= num_outs - num_recent_outs && recent_outputs_count > 0)
          --recent_outputs_count; // if the real out is recent, pick one less recent fake out
      }
      LOG_PRINT_L1("Fake output makeup: " << requested_outputs_count << " requested: " << recent_outputs_count << " recent, " <<
          pre_fork_outputs_count << " pre-fork, " << post_fork_outputs_count << " post-fork, " <<
          (requested_outputs_count - recent_outputs_count - pre_fork_outputs_count - post_fork_outputs_count) << " full-chain");

      uint64_t num_found = 0;

      // if we have a known ring, use it
      if (td.m_key_image_known && !td.m_key_image_partial)
      {
        std::vector<uint64_t> ring;
        if (get_ring(get_ringdb_key(), td.m_key_image, ring))
        {
          MINFO("This output has a known ring, reusing (size " << ring.size() << ")");
          THROW_WALLET_EXCEPTION_IF(ring.size() > fake_outputs_count + 1, error::wallet_internal_error,
              "An output in this transaction was previously spent on another chain with ring size " +
              std::to_string(ring.size()) + ", it cannot be spent now with ring size " +
              std::to_string(fake_outputs_count + 1) + " as it is smaller: use a higher ring size");
          bool own_found = false;
          for (const auto &out: ring)
          {
            MINFO("Ring has output " << out);
            if (out < num_outs)
            {
              MINFO("Using it");
              get_outputs.push_back({amount, out});
              ++num_found;
              seen_indices.emplace(out);
              if (out == td.m_global_output_index)
              {
                MINFO("This is the real output");
                own_found = true;
              }
            }
            else
            {
              MINFO("Ignoring output " << out << ", too recent");
            }
          }
          THROW_WALLET_EXCEPTION_IF(!own_found, error::wallet_internal_error,
              "Known ring does not include the spent output: " + std::to_string(td.m_global_output_index));
        }
      }

      if (num_outs <= requested_outputs_count)
      {
        for (uint64_t i = 0; i < num_outs; i++)
          get_outputs.push_back({amount, i});
        // duplicate to make up shortfall: this will be caught after the RPC call,
        // so we can also output the amounts for which we can't reach the required
        // mixin after checking the actual unlockedness
        for (uint64_t i = num_outs; i < requested_outputs_count; ++i)
          get_outputs.push_back({amount, num_outs - 1});
      }
      else
      {
        // start with real one
        if (num_found == 0)
        {
          num_found = 1;
          seen_indices.emplace(td.m_global_output_index);
          get_outputs.push_back({amount, td.m_global_output_index});
          LOG_PRINT_L1("Selecting real output: " << td.m_global_output_index << " for " << print_money(amount));
        }

        std::unordered_map<const char*, std::set<uint64_t>> picks;

        // while we still need more mixins
        uint64_t num_usable_outs = num_outs;
        bool allow_blackballed_or_blacklisted = false;
        MDEBUG("Starting gamma picking with " << num_outs << ", num_usable_outs " << num_usable_outs
            << ", requested_outputs_count " << requested_outputs_count);
        while (num_found < requested_outputs_count)
        {
          // if we've gone through every possible output, we've gotten all we can
          if (seen_indices.size() == num_usable_outs)
          {
            // there is a first pass which rejects blackballed/listed outputs, then a second pass
            // which allows them if we don't have enough non blackballed/list outputs to reach
            // the required amount of outputs (since consensus does not care about blackballed/listed
            // outputs, we still need to reach the minimum ring size)
            if (allow_blackballed_or_blacklisted)
              break;
            MINFO("Not enough output not marked as spent, we'll allow outputs marked as spent and outputs with known destinations and amounts");
            allow_blackballed_or_blacklisted = true;
            num_usable_outs = num_outs;
          }

          // get a random output index from the DB.  If we've already seen it,
          // return to the top of the loop and try again, otherwise add it to the
          // list of output indices we've seen.

          uint64_t i;
          const char *type = "";
          if (amount == 0 && has_rct_distribution)
          {
            THROW_WALLET_EXCEPTION_IF(!gamma, error::wallet_internal_error, "No gamma picker");
            // gamma distribution
            if (num_found -1 < recent_outputs_count + pre_fork_outputs_count)
            {
              do i = gamma->pick(); while (i >= segregation_limit[amount].first);
              type = "pre-fork gamma";
            }
            else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count + post_fork_outputs_count)
            {
              do i = gamma->pick(); while (i < segregation_limit[amount].first || i >= num_outs);
              type = "post-fork gamma";
            }
            else
            {
              do i = gamma->pick(); while (i >= num_outs);
              type = "gamma";
            }
          }
          else if (num_found - 1 < recent_outputs_count) // -1 to account for the real one we seeded with
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_recent_outs) + num_outs - num_recent_outs;
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "recent";
          }
          else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count)
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*segregation_limit[amount].first);
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = " pre-fork";
          }
          else if (num_found -1 < recent_outputs_count + pre_fork_outputs_count + post_fork_outputs_count)
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_post_fork_outs) + segregation_limit[amount].first;
            // just in case rounding up to 1 occurs after calc
            if (i == num_post_fork_outs+segregation_limit[amount].first)
              --i;
            type = "post-fork";
          }
          else
          {
            // triangular distribution over [a,b) with a=0, mode c=b=up_index_limit
            uint64_t r = crypto::rand<uint64_t>() % ((uint64_t)1 << 53);
            double frac = std::sqrt((double)r / ((uint64_t)1 << 53));
            i = (uint64_t)(frac*num_outs);
            // just in case rounding up to 1 occurs after calc
            if (i == num_outs)
              --i;
            type = "triangular";
          }

          if (seen_indices.count(i))
            continue;
          if (!allow_blackballed_or_blacklisted)
          {
            if (is_output_blackballed(std::make_pair(amount, i)) ||
                std::binary_search(output_blacklist.begin(), output_blacklist.end(), i))
            {
              --num_usable_outs;
              continue;
            }
          }
          seen_indices.emplace(i);

          picks[type].insert(i);
          get_outputs.push_back({amount, i});
          ++num_found;
          MDEBUG("picked " << i << ", " << num_found << " now picked");
        }

        if (LOG_ENABLED(Debug))
        {
          for (const auto &pick: picks)
          {
            std::string outputs;
            for (const auto& out : pick.second)
              outputs += " " + std::to_string(out);
            MDEBUG("picking " << pick.first << " outputs:" << outputs);
          }
        }

        // if we had enough unusable outputs, we might fall off here and still
        // have too few outputs, so we stuff with one to keep counts good, and
        // we'll error out later
        while (num_found < requested_outputs_count)
        {
          get_outputs.push_back({amount, 0});
          ++num_found;
        }
      }

      // sort the subsection, to ensure the daemon doesn't know which output is ours
      std::sort(get_outputs.begin() + start, get_outputs.end(),
          [](const auto& a, const auto& b) { return a.index < b.index; });
    }

    if (ELPP->vRegistry()->allowed(el::Level::Debug, OXEN_DEFAULT_LOG_CATEGORY))
    {
      std::map<uint64_t, std::set<uint64_t>> outs;
      for (const auto &i: get_outputs)
        outs[i.amount].insert(i.index);
      if (LOG_ENABLED(Debug))
      {
        for (const auto &o: outs)
        {
          std::string outputs;
          for (const auto& out : o.second)
            outputs += " " + std::to_string(out);
          MDEBUG("asking for outputs with amount " << print_money(o.first) << ":" << outputs);
        }
      }
    }

    req.get_txid = false;

    // Split out requests into MAX_COUNT if we are requesting more than that; otherwise we run into
    // problems when using a public node (which only allows MAX_COUNT per request).
    std::vector<rpc::GET_OUTPUTS_BIN::outkey> got_outs;
    got_outs.reserve(get_outputs.size());
    for (auto it = get_outputs.begin(); it != get_outputs.end(); )
    {
      auto count = std::min<size_t>(std::distance(it, get_outputs.end()), rpc::GET_OUTPUTS_BIN::MAX_COUNT);
      req.outputs.clear();
      req.outputs.reserve(count);
      req.outputs.insert(req.outputs.end(), it, it + count);
      // get the keys for those
      rpc::GET_OUTPUTS_BIN::response daemon_resp{};
      bool r = invoke_http<rpc::GET_OUTPUTS_BIN>(req, daemon_resp);
      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_outs.bin");
      THROW_WALLET_EXCEPTION_IF(daemon_resp.status == rpc::STATUS_BUSY, error::daemon_busy, "get_outs.bin");
      THROW_WALLET_EXCEPTION_IF(daemon_resp.status != rpc::STATUS_OK, error::get_outs_error, get_rpc_status(daemon_resp.status));
      THROW_WALLET_EXCEPTION_IF(daemon_resp.outs.size() != req.outputs.size(), error::wallet_internal_error,
        "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
        std::to_string(daemon_resp.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));

      for (auto& out : daemon_resp.outs)
        got_outs.push_back(std::move(out));

      it += count;
    }

    std::unordered_map<uint64_t, uint64_t> scanty_outs;
    size_t base = 0;
    outs.reserve(num_selected_transfers);
    for(size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers[idx];
      size_t requested_outputs_count = base_requested_outputs_count + (td.is_rct() ? CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE : 0);
      outs.push_back(std::vector<get_outs_entry>());
      outs.back().reserve(fake_outputs_count + 1);
      const rct::key mask = td.is_rct() ? rct::commit(td.amount(), td.m_mask) : rct::zeroCommit(td.amount());

      uint64_t num_outs = 0;
      const uint64_t amount = td.is_rct() ? 0 : td.amount();
      const bool output_is_pre_fork = td.m_block_height < segregation_fork_height;
      if (is_after_segregation_fork && m_segregate_pre_fork_outputs && output_is_pre_fork)
        num_outs = segregation_limit[amount].first;
      else for (const auto &he: resp_t.histogram)
      {
        if (he.amount == amount)
        {
          num_outs = he.unlocked_instances;
          break;
        }
      }
      bool use_histogram = amount != 0 || !has_rct_distribution;
      if (!use_histogram)
        num_outs = rct_offsets[rct_offsets.size() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE];

      // make sure the real outputs we asked for are really included, along
      // with the correct key and mask: this guards against an active attack
      // where the node sends dummy data for all outputs, and we then send
      // the real one, which the node can then tell from the fake outputs,
      // as it has different data than the dummy data it had sent earlier
      bool real_out_found = false;
      for (size_t n = 0; n < requested_outputs_count; ++n)
      {
        size_t i = base + n;
        if (get_outputs[i].index == td.m_global_output_index)
          if (got_outs[i].key == var::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key)
            if (got_outs[i].mask == mask)
            {
              real_out_found = true;
              break;
            }
      }
      THROW_WALLET_EXCEPTION_IF(!real_out_found, error::wallet_internal_error,
          "Daemon response did not include the requested real output");

      // pick real out first (it will be sorted when done)
      outs.back().push_back(std::make_tuple(td.m_global_output_index, var::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key, mask));

      // then pick outs from an existing ring, if any
      if (td.m_key_image_known && !td.m_key_image_partial)
      {
        std::vector<uint64_t> ring;
        if (get_ring(get_ringdb_key(), td.m_key_image, ring))
        {
          for (uint64_t out: ring)
          {
            if (out < num_outs)
            {
              if (out != td.m_global_output_index)
              {
                bool found = false;
                for (size_t o = 0; o < requested_outputs_count; ++o)
                {
                  size_t i = base + o;
                  if (get_outputs[i].index == out)
                  {
                    LOG_PRINT_L2("Index " << i << "/" << requested_outputs_count << ": idx " << get_outputs[i].index << " (real " << td.m_global_output_index << "), unlocked " << got_outs[i].unlocked << ", key " << got_outs[i].key << " (from existing ring)");
                    tx_add_fake_output(outs, get_outputs[i].index, got_outs[i].key, got_outs[i].mask, td.m_global_output_index, got_outs[i].unlocked);
                    found = true;
                    break;
                  }
                }
                THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error, "Falied to find existing ring output in daemon out data");
              }
            }
          }
        }
      }

      // then pick others in random order till we reach the required number
      // since we use an equiprobable pick here, we don't upset the triangular distribution
      std::vector<size_t> order;
      order.resize(requested_outputs_count);
      for (size_t n = 0; n < order.size(); ++n)
        order[n] = n;
      std::shuffle(order.begin(), order.end(), crypto::random_device{});

      LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs of size " << print_money(td.is_rct() ? 0 : td.amount()));
      for (size_t o = 0; o < requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
      {
        size_t i = base + order[o];
        LOG_PRINT_L2("Index " << i << "/" << requested_outputs_count << ": idx " << get_outputs[i].index << " (real " << td.m_global_output_index << "), unlocked " << got_outs[i].unlocked << ", key " << got_outs[i].key);
        tx_add_fake_output(outs, get_outputs[i].index, got_outs[i].key, got_outs[i].mask, td.m_global_output_index, got_outs[i].unlocked);
      }
      if (outs.back().size() < fake_outputs_count + 1)
      {
        scanty_outs[td.is_rct() ? 0 : td.amount()] = outs.back().size();
      }
      else
      {
        // sort the subsection, so any spares are reset in order
        std::sort(outs.back().begin(), outs.back().end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });
      }
      base += requested_outputs_count;
    }
    THROW_WALLET_EXCEPTION_IF(!scanty_outs.empty(), error::not_enough_outs_to_mix, scanty_outs, fake_outputs_count);
  }
  else
  {
    for (size_t idx: selected_transfers)
    {
      const transfer_details &td = m_transfers[idx];
      std::vector<get_outs_entry> v;
      const rct::key mask = td.is_rct() ? rct::commit(td.amount(), td.m_mask) : rct::zeroCommit(td.amount());
      v.push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), mask));
      outs.push_back(v);
    }
  }

  // save those outs in the ringdb for reuse
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    const size_t idx = selected_transfers[i];
    THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "selected_transfers entry out of range");
    const transfer_details &td = m_transfers[idx];
    std::vector<uint64_t> ring;
    ring.reserve(outs[i].size());
    for (const auto &e: outs[i])
      ring.push_back(std::get<0>(e));
    if (!set_ring(td.m_key_image, ring, false))
      MERROR("Failed to set ring for " << td.m_key_image);
  }
}

void wallet2::transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
  std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
  uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx, const rct::RCTConfig &rct_config, const oxen_construct_tx_params &tx_params)
{
  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  uint64_t needed_money = fee;
  LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
  LOG_PRINT_L2("selected transfers: " << strjoin(selected_transfers, " "));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount && (tx_params.tx_type != txtype::oxen_name_system), error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, m_nettype);
  }

  // if this is a multisig wallet, create a list of multisig signers we can use
  std::deque<crypto::public_key> multisig_signers;
  size_t n_multisig_txes = 0;
  std::vector<std::unordered_set<crypto::public_key>> ignore_sets;
  if (m_multisig && !m_transfers.empty())
  {
    const crypto::public_key local_signer = get_multisig_signer_public_key();
    size_t n_available_signers = 1;

    // At this step we need to define set of participants available for signature,
    // i.e. those of them who exchanged with multisig info's
    for (const crypto::public_key &signer: m_multisig_signers)
    {
      if (signer == local_signer)
        continue;
      for (const auto &i: m_transfers[0].m_multisig_info)
      {
        if (i.m_signer == signer)
        {
          multisig_signers.push_back(signer);
          ++n_available_signers;
          break;
        }
      }
    }
    // n_available_signers includes the transaction creator, but multisig_signers doesn't
    MDEBUG("We can use " << n_available_signers << "/" << m_multisig_signers.size() <<  " other signers");
    THROW_WALLET_EXCEPTION_IF(n_available_signers < m_multisig_threshold, error::multisig_import_needed);
    if (n_available_signers > m_multisig_threshold)
    {
      // If there more potential signers (those who exchanged with multisig info)
      // than threshold needed some of them should be skipped since we don't know
      // who will sign tx and who won't. Hence we don't contribute their LR pairs to the signature.

      // We create as many transactions as many combinations of excluded signers may be.
      // For example, if we have 2/4 wallet and wallets are: A, B, C and D. Let A be
      // transaction creator, so we need just 1 signature from set of B, C, D.
      // Using "excluding" logic here we have to exclude 2-of-3 wallets. Combinations go as follows:
      // BC, BD, and CD. We save these sets to use later and counting the number of required txs.
      tools::Combinator<crypto::public_key> c(std::vector<crypto::public_key>(multisig_signers.begin(), multisig_signers.end()));
      auto ignore_combinations = c.combine(multisig_signers.size() + 1 - m_multisig_threshold);
      for (const auto& combination: ignore_combinations)
      {
        ignore_sets.push_back(std::unordered_set<crypto::public_key>(combination.begin(), combination.end()));
      }

      n_multisig_txes = ignore_sets.size();
    }
    else
    {
      // If we have exact count of signers just to fit in threshold we don't exclude anyone and create 1 transaction
      n_multisig_txes = 1;
    }
    MDEBUG("We will create " << n_multisig_txes << " txes");
  }

  uint64_t found_money = 0;
  uint32_t subaddr_account = 0;
  bool has_rct = false;
  for (size_t i = 0; i < selected_transfers.size(); i++)
  {
    size_t transfer_idx        = selected_transfers[i];
    transfer_details const &td = m_transfers[transfer_idx];
    has_rct                   |= td.is_rct();
    found_money               += td.amount();

    if (i == 0)
      subaddr_account = m_transfers[transfer_idx].m_subaddr_index.major;
    else
      THROW_WALLET_EXCEPTION_IF(subaddr_account != m_transfers[transfer_idx].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");
  }
  LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  if (outs.empty())
    get_outs(outs, selected_transfers, fake_outputs_count, has_rct); // may throw

  //prepare inputs
  LOG_PRINT_L2("preparing outputs");
  size_t i = 0, out_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  std::unordered_set<rct::key> used_L;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    const transfer_details& td = m_transfers[idx];
    src.amount = td.amount();
    src.rct = td.is_rct();
    //paste mixin transaction

    THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  error::wallet_internal_error, "outs.size() < out_index + 1");
    THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");

    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
    for (size_t n = 0; n < fake_outputs_count + 1; ++n)
    {
      tx_output_entry oe;
      oe.first = std::get<0>(outs[out_index][n]);
      oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
      oe.second.mask = std::get<2>(outs[out_index][n]);
      src.outputs.push_back(oe);
    }
    ++i;

    //paste real transaction to the random index
    auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
        "real output not found");

    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second.dest = rct::pk2rct(td.get_public_key());
    real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
    *it_to_replace = real_oe;
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
    src.real_output = it_to_replace - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    src.mask = td.m_mask;
    if (m_multisig)
    {
      auto ignore_set = ignore_sets.empty() ? std::unordered_set<crypto::public_key>() : ignore_sets.front();
      src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore_set, used_L, used_L);
    }
    else
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});

    {
      std::string indexes;
      for (auto& out: src.outputs) { indexes += ' '; indexes += std::to_string(out.first); }
      LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes:" << indexes);
    }

    ++out_index;
  }
  LOG_PRINT_L2("outputs prepared");

  // we still keep a copy, since we want to keep dsts free of change for user feedback purposes
  std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;
  cryptonote::tx_destination_entry change_dts                 = {};
  change_dts.amount                                           = found_money - needed_money;
  bool update_splitted_dsts                                   = true;
  if (change_dts.amount == 0)
  {
    if (splitted_dsts.size() == 1 || tx.type == txtype::oxen_name_system)
    {
      // If the change is 0, send it to a random address, to avoid confusing
      // the sender with a 0 amount output. We send a 0 amount in order to avoid
      // letting the destination be able to work out which of the inputs is the
      // real one in our rings

      LOG_PRINT_L2("generating dummy address for 0 change");
      cryptonote::account_base dummy;
      dummy.generate();
      LOG_PRINT_L2("generated dummy address for 0 change");
      change_dts.addr = dummy.get_keys().m_account_address;
    }
    else
    {
      update_splitted_dsts = false;
    }
  }
  else
  {
    change_dts.addr = get_subaddress({subaddr_account, 0});
    change_dts.is_subaddress = subaddr_account != 0;
  }

  if (update_splitted_dsts)
  {
    // NOTE: If ONS, there's already a dummy destination entry in there that
    // we placed in (for fake calculating the TX fees and parts) that we
    // repurpose for change after the fact.
    if (tx_params.tx_type == txtype::oxen_name_system)
    {
      assert(splitted_dsts.size() == 1);
      splitted_dsts.back() = change_dts;
    }
    else
    {
      splitted_dsts.push_back(change_dts);
    }
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  rct::multisig_out msout;
  LOG_PRINT_L2("constructing tx");
  auto sources_copy = sources;
  bool r = cryptonote::construct_tx_and_get_tx_key(
      m_account.get_keys(),
      m_subaddresses,
      sources,
      splitted_dsts,
      change_dts,
      extra,
      tx,
      unlock_time,
      tx_key,
      additional_tx_keys,
      rct_config,
      m_multisig ? &msout : nullptr,
      tx_params);

  LOG_PRINT_L2("constructed tx, r="<<r);
  THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, dsts, unlock_time, m_nettype);
  THROW_WALLET_EXCEPTION_IF(upper_transaction_weight_limit <= get_transaction_weight(tx), error::tx_too_big, tx, upper_transaction_weight_limit);

  // work out the permutation done on sources
  std::vector<size_t> ins_order;
  for (size_t n = 0; n < sources.size(); ++n)
  {
    for (size_t idx = 0; idx < sources_copy.size(); ++idx)
    {
      THROW_WALLET_EXCEPTION_IF((size_t)sources_copy[idx].real_output >= sources_copy[idx].outputs.size(),
          error::wallet_internal_error, "Invalid real_output");
      if (sources_copy[idx].outputs[sources_copy[idx].real_output].second.dest == sources[n].outputs[sources[n].real_output].second.dest)
        ins_order.push_back(idx);
    }
  }
  THROW_WALLET_EXCEPTION_IF(ins_order.size() != sources.size(), error::wallet_internal_error, "Failed to work out sources permutation");

  std::vector<wallet::multisig_sig> multisig_sigs;
  if (m_multisig)
  {
    auto ignore = ignore_sets.empty() ? std::unordered_set<crypto::public_key>() : ignore_sets.front();
    multisig_sigs.push_back({tx.rct_signatures, ignore, used_L, std::unordered_set<crypto::public_key>(), msout});

    if (m_multisig_threshold < m_multisig_signers.size())
    {
      const crypto::hash prefix_hash = cryptonote::get_transaction_prefix_hash(tx);

      // create the other versions, one for every other participant (the first one's already done above)
      for (size_t ignore_index = 1; ignore_index < ignore_sets.size(); ++ignore_index)
      {
        std::unordered_set<rct::key> new_used_L;
        size_t src_idx = 0;
        THROW_WALLET_EXCEPTION_IF(selected_transfers.size() != sources.size(), error::wallet_internal_error, "mismatched selected_transfers and sources sizes");
        for(size_t idx: selected_transfers)
        {
          cryptonote::tx_source_entry& src = sources_copy[src_idx];
          src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore_sets[ignore_index], used_L, new_used_L);
          ++src_idx;
        }

        LOG_PRINT_L2("Creating supplementary multisig transaction");
        cryptonote::transaction ms_tx;
        auto sources_copy_copy = sources_copy;

        bool r = cryptonote::construct_tx_with_tx_key(m_account.get_keys(),
                                                      m_subaddresses,
                                                      sources_copy_copy,
                                                      splitted_dsts,
                                                      change_dts,
                                                      extra,
                                                      ms_tx,
                                                      unlock_time,
                                                      tx_key,
                                                      additional_tx_keys,
                                                      rct_config,
                                                      &msout,
                                                      /*shuffle_outs*/ false,
                                                      tx_params);
        LOG_PRINT_L2("constructed tx, r="<<r);
        THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, m_nettype);
        THROW_WALLET_EXCEPTION_IF(upper_transaction_weight_limit <= get_transaction_weight(tx), error::tx_too_big, tx, upper_transaction_weight_limit);
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_prefix_hash(ms_tx) != prefix_hash, error::wallet_internal_error, "Multisig txes do not share prefix");
        multisig_sigs.push_back({ms_tx.rct_signatures, ignore_sets[ignore_index], new_used_L, std::unordered_set<crypto::public_key>(), msout});

        ms_tx.rct_signatures = tx.rct_signatures;
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_hash(ms_tx) != cryptonote::get_transaction_hash(tx), error::wallet_internal_error, "Multisig txes differ by more than the signatures");
      }
    }
  }

  LOG_PRINT_L2("gathering key images");
  std::ostringstream key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, txin_to_key, in, false);
    key_images << in.k_image << ' ';
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
  LOG_PRINT_L2("gathered key images");

  ptx = {};
  ptx.key_images = key_images.str();
  ptx.fee = fee;
  ptx.dust = 0;
  ptx.dust_added_to_fee = false;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  tools::apply_permutation(ins_order, ptx.selected_transfers);
  ptx.tx_key = tx_key;
  ptx.additional_tx_keys = additional_tx_keys;
  ptx.dests = dsts;
  ptx.multisig_sigs = multisig_sigs;
  ptx.construction_data.sources = sources_copy;
  ptx.construction_data.change_dts = change_dts;
  ptx.construction_data.splitted_dsts = splitted_dsts;
  ptx.construction_data.selected_transfers = ptx.selected_transfers;
  ptx.construction_data.extra = tx.extra;
  ptx.construction_data.unlock_time = unlock_time;
  ptx.construction_data.tx_type = tx_params.tx_type;
  ptx.construction_data.hf_version = tx_params.hf_version;
  ptx.construction_data.rct_config = {
    tx.rct_signatures.p.bulletproofs.empty() ? rct::RangeProofType::Borromean : rct::RangeProofType::PaddedBulletproof,
    use_fork_rules(HF_VERSION_CLSAG, 0) ? 3 : 2
  };
  ptx.construction_data.dests = dsts;
  // record which subaddress indices are being used as inputs
  ptx.construction_data.subaddr_account = subaddr_account;
  ptx.construction_data.subaddr_indices.clear();
  for (size_t idx: selected_transfers)
    ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  LOG_PRINT_L2("transfer_selected_rct done");
}

std::vector<size_t> wallet2::pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices) const
{
  std::vector<size_t> picks;
  float current_output_relatdness = 1.0f;

  LOG_PRINT_L2("pick_preferred_rct_inputs: needed_money " << print_money(needed_money));

  // try to find a rct input of enough size
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
      LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
      picks.push_back(i);
      return picks;
    }
  }

  // then try to find two outputs
  // this could be made better by picking one of the outputs to be a small one, since those
  // are less useful since often below the needed money, so if one can be used in a pair,
  // it gets rid of it for the future
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && !td.m_key_image_partial && td.is_rct() && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
      LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
      for (size_t j = i + 1; j < m_transfers.size(); ++j)
      {
        const transfer_details& td2 = m_transfers[j];
        if (td2.amount() > m_ignore_outputs_above || td2.amount() < m_ignore_outputs_below)
        {
          MDEBUG("Ignoring output " << j << " of amount " << print_money(td2.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
          continue;
        }
        if (!is_spent(td2, false) && !td2.m_frozen && !td.m_key_image_partial && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2) && td2.m_subaddr_index == td.m_subaddr_index)
        {
          // update our picks if those outputs are less related than any we
          // already found. If the same, don't update, and oldest suitable outputs
          // will be used in preference.
          float relatedness = get_output_relatedness(td, td2);
          LOG_PRINT_L2("  with input " << j << ", " << print_money(td2.amount()) << ", relatedness " << relatedness);
          if (relatedness < current_output_relatdness)
          {
            // reset the current picks with those, and return them directly
            // if they're unrelated. If they are related, we'll end up returning
            // them if we find nothing better
            picks.clear();
            picks.push_back(i);
            picks.push_back(j);
            LOG_PRINT_L0("we could use " << i << " and " << j);
            if (relatedness == 0.0f)
              return picks;
            current_output_relatdness = relatedness;
          }
        }
      }
    }
  }

  return picks;
}

bool wallet2::should_pick_a_second_output(size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const
{
  if (n_transfers > 1)
    return false;
  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return false;
  // we want at least one free rct output to avoid a corner case where
  // we'd choose a non rct output which doesn't have enough "siblings"
  // value-wise on the chain, and thus can't be mixed
  bool found = false;
  for (auto i: unused_dust_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found) for (auto i: unused_transfers_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found)
    return false;
  return true;
}

std::vector<size_t> wallet2::get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const
{
  std::vector<size_t> indices;
  for (size_t n: unused_dust_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  for (size_t n: unused_transfers_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  return indices;
}

static uint32_t get_count_above(const std::vector<wallet2::transfer_details> &transfers, const std::vector<size_t> &indices, uint64_t threshold)
{
  uint32_t count = 0;
  for (size_t idx: indices)
    if (transfers[idx].amount() >= threshold)
      ++count;
  return count;
}

bool wallet2::light_wallet_login(bool &new_address)
{
  MDEBUG("Light wallet login request");
  m_light_wallet_connected = false;
  light_rpc::LOGIN::request request{};
  light_rpc::LOGIN::response response{};
  request.address = get_account().get_public_address_str(m_nettype);
  request.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
  // Always create account if it doesn't exist.
  request.create_account = true;
  bool connected = invoke_http<light_rpc::LOGIN>(request, response);
  // MyMonero doesn't send any status message. OpenMonero does.
  m_light_wallet_connected  = connected && (response.status.empty() || response.status == "success");
  new_address = response.new_address;
  MDEBUG("Status: " << response.status);
  MDEBUG("Reason: " << response.reason);
  MDEBUG("New wallet: " << response.new_address);
  if(m_light_wallet_connected)
  {
    // Clear old data on successful login.
    // m_transfers.clear();
    // m_payments.clear();
    // m_unconfirmed_payments.clear();
  }
  return m_light_wallet_connected;
}

bool wallet2::light_wallet_import_wallet_request(light_rpc::IMPORT_WALLET_REQUEST::response &response)
{
  MDEBUG("Light wallet import wallet request");
  light_rpc::IMPORT_WALLET_REQUEST::request oreq{};
  oreq.address = get_account().get_public_address_str(m_nettype);
  oreq.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
  bool r = invoke_http<light_rpc::IMPORT_WALLET_REQUEST>(oreq, response);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "import_wallet_request");


  return true;
}

void wallet2::light_wallet_get_unspent_outs()
{
  MDEBUG("Getting unspent outs");

  light_rpc::GET_UNSPENT_OUTS::request oreq{};
  light_rpc::GET_UNSPENT_OUTS::response ores{};

  oreq.amount = "0";
  oreq.address = get_account().get_public_address_str(m_nettype);
  oreq.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
  // openMonero specific
  oreq.dust_threshold = boost::lexical_cast<std::string>(::config::DEFAULT_DUST_THRESHOLD);
  // below are required by openMonero api - but are not used.
  oreq.mixin = 0;
  oreq.use_dust = true;


  bool r = invoke_http<light_rpc::GET_UNSPENT_OUTS>(oreq, ores);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_unspent_outs");
  THROW_WALLET_EXCEPTION_IF(ores.status == "error", error::wallet_internal_error, ores.reason);

  m_light_wallet_per_kb_fee = ores.per_kb_fee;

  std::unordered_map<crypto::hash,bool> transfers_txs;
  for(const auto &t: m_transfers)
    transfers_txs.emplace(t.m_txid,t.m_spent);

  MDEBUG("FOUND " << ores.outputs.size() <<" outputs");

  // return if no outputs found
  if(ores.outputs.empty())
    return;

  // Clear old outputs
  m_transfers.clear();

  for (const auto &o: ores.outputs) {
    bool spent = false;
    bool add_transfer = true;
    crypto::key_image unspent_key_image;
    crypto::public_key tx_public_key{};
    THROW_WALLET_EXCEPTION_IF(o.tx_pub_key.size() != 64 || !oxenmq::is_hex(o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
    tools::hex_to_type(o.tx_pub_key, tx_public_key);

    for (const std::string &ski: o.spend_key_images) {
      spent = false;

      // Check if key image is ours
      THROW_WALLET_EXCEPTION_IF(ski.size() != 64 || !oxenmq::is_hex(ski), error::wallet_internal_error, "Invalid key image");
      tools::hex_to_type(ski, unspent_key_image);
      if(light_wallet_key_image_is_ours(unspent_key_image, tx_public_key, o.index)){
        MTRACE("Output " << o.public_key << " is spent. Key image: " <<  ski);
        spent = true;
        break;
      } {
        MTRACE("Unspent output found. " << o.public_key);
      }
    }

    // Check if tx already exists in m_transfers.
    crypto::hash txid;
    crypto::public_key tx_pub_key;
    crypto::public_key public_key;
    THROW_WALLET_EXCEPTION_IF(o.tx_hash.size() != 64 || !oxenmq::is_hex(o.tx_hash), error::wallet_internal_error, "Invalid tx_hash field");
    THROW_WALLET_EXCEPTION_IF(o.public_key.size() != 64 || !oxenmq::is_hex(o.public_key), error::wallet_internal_error, "Invalid public_key field");
    THROW_WALLET_EXCEPTION_IF(o.tx_pub_key.size() != 64 || !oxenmq::is_hex(o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
    tools::hex_to_type(o.tx_hash, txid);
    tools::hex_to_type(o.public_key, public_key);
    tools::hex_to_type(o.tx_pub_key, tx_pub_key);

    for(auto &t: m_transfers){
      if(t.get_public_key() == public_key) {
        t.m_spent = spent;
        add_transfer = false;
        break;
      }
    }

    if(!add_transfer)
      continue;

    m_transfers.emplace_back();
    transfer_details& td = m_transfers.back();

    td.m_block_height = o.height;
    td.m_global_output_index = o.global_index;
    td.m_txid = txid;

    // Add to extra
    add_tx_extra<tx_extra_pub_key>(td.m_tx, tx_pub_key);

    td.m_key_image = unspent_key_image;
    td.m_key_image_known = !m_watch_only && !m_multisig;
    td.m_key_image_request = false;
    td.m_key_image_partial = m_multisig;
    td.m_amount = o.amount;
    td.m_pk_index = 0;
    td.m_internal_output_index = o.index;
    td.m_spent = spent;
    td.m_frozen = false;

    tx_out txout;
    txout.target = txout_to_key(public_key);
    txout.amount = td.m_amount;

    td.m_tx.vout.resize(td.m_internal_output_index + 1);
    td.m_tx.vout[td.m_internal_output_index] = txout;

    THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "Light wallet multiple output unlock time not supported yet");

    // Add unlock time and coinbase bool got from get_address_txs api call
    std::unordered_map<crypto::hash,address_tx>::const_iterator found = m_light_wallet_address_txs.find(txid);
    THROW_WALLET_EXCEPTION_IF(found == m_light_wallet_address_txs.end(), error::wallet_internal_error, "Lightwallet: tx not found in m_light_wallet_address_txs");
    bool miner_tx = found->second.is_coinbase();
    td.m_tx.unlock_time = found->second.m_unlock_time;

    if (!o.rct.empty())
    {
      // Coinbase tx's
      if(miner_tx)
      {
        td.m_mask = rct::identity();
      }
      else
      {
        // rct txs
        // decrypt rct mask, calculate commit hash and compare against blockchain commit hash
        rct::key rct_commit;
        light_wallet_parse_rct_str(o.rct, tx_pub_key, td.m_internal_output_index, td.m_mask, rct_commit, true);
        bool valid_commit = (rct_commit == rct::commit(td.amount(), td.m_mask));
        if(!valid_commit)
        {
          MDEBUG("output index: " << o.global_index);
          MDEBUG("mask: " + tools::type_to_hex(td.m_mask));
          MDEBUG("calculated commit: " + tools::type_to_hex(rct::commit(td.amount(), td.m_mask)));
          MDEBUG("expected commit: " + tools::type_to_hex(rct_commit));
          MDEBUG("amount: " << td.amount());
        }
        THROW_WALLET_EXCEPTION_IF(!valid_commit, error::wallet_internal_error, "Lightwallet: rct commit hash mismatch!");
      }
      td.m_rct = true;
    }
    else
    {
      td.m_mask = rct::identity();
      td.m_rct = false;
    }
    if(!spent)
      set_unspent(m_transfers.size()-1);
    m_key_images[td.m_key_image] = m_transfers.size()-1;
    m_pub_keys[td.get_public_key()] = m_transfers.size()-1;
  }
}

bool wallet2::light_wallet_get_address_info(light_rpc::GET_ADDRESS_INFO::response &response)
{
  MTRACE(__FUNCTION__);

  light_rpc::GET_ADDRESS_INFO::request request{};

  request.address = get_account().get_public_address_str(m_nettype);
  request.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
  bool r = invoke_http<light_rpc::GET_ADDRESS_INFO>(request, response);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_address_info");
  // TODO: Validate result
  return true;
}

void wallet2::light_wallet_get_address_txs()
{
  MDEBUG("Refreshing light wallet");

  light_rpc::GET_ADDRESS_TXS::request ireq{};
  light_rpc::GET_ADDRESS_TXS::response ires{};

  ireq.address = get_account().get_public_address_str(m_nettype);
  ireq.view_key = tools::type_to_hex(get_account().get_keys().m_view_secret_key);
  bool r = invoke_http<light_rpc::GET_ADDRESS_TXS>(ireq, ires);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_address_txs");
  //OpenMonero sends status=success, Mymonero doesn't.
  THROW_WALLET_EXCEPTION_IF((!ires.status.empty() && ires.status != "success"), error::no_connection_to_daemon, "get_address_txs");


  // Abort if no transactions
  if(ires.transactions.empty())
    return;

  // Create searchable vectors
  std::vector<crypto::hash> payments_txs;
  for(const auto &p: m_payments)
    payments_txs.push_back(p.second.m_tx_hash);
  std::vector<crypto::hash> unconfirmed_payments_txs;
  for(const auto &up: m_unconfirmed_payments)
    unconfirmed_payments_txs.push_back(up.second.m_pd.m_tx_hash);

  // for balance calculation
  uint64_t wallet_total_sent = 0;
  // txs in pool
  std::vector<crypto::hash> pool_txs;

  for (const auto &t: ires.transactions) {
    const uint64_t total_received = t.total_received;
    uint64_t total_sent = t.total_sent;

    // Check key images - subtract fake outputs from total_sent
    for(const auto &so: t.spent_outputs)
    {
      crypto::public_key tx_public_key;
      crypto::key_image key_image;
      THROW_WALLET_EXCEPTION_IF(so.tx_pub_key.size() != 64 || !oxenmq::is_hex(so.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
      THROW_WALLET_EXCEPTION_IF(so.key_image.size() != 64 || !oxenmq::is_hex(so.key_image), error::wallet_internal_error, "Invalid key_image field");
      tools::hex_to_type(so.tx_pub_key, tx_public_key);
      tools::hex_to_type(so.key_image, key_image);

      if(!light_wallet_key_image_is_ours(key_image, tx_public_key, so.out_index)) {
        THROW_WALLET_EXCEPTION_IF(so.amount > t.total_sent, error::wallet_internal_error, "Lightwallet: total sent is negative!");
        total_sent -= so.amount;
      }
    }

    // Do not add tx if empty.
    if(total_sent == 0 && total_received == 0)
      continue;

    crypto::hash payment_id = null_hash;
    crypto::hash tx_hash;

    THROW_WALLET_EXCEPTION_IF(t.payment_id.size() != 64 || !oxenmq::is_hex(t.payment_id), error::wallet_internal_error, "Invalid payment_id field");
    THROW_WALLET_EXCEPTION_IF(t.hash.size() != 64 || !oxenmq::is_hex(t.hash), error::wallet_internal_error, "Invalid hash field");
    tools::hex_to_type(t.payment_id, payment_id);
    tools::hex_to_type(t.hash, tx_hash);

    // lightwallet specific info
    bool incoming = (total_received > total_sent);
    address_tx address_tx;
    address_tx.m_tx_hash = tx_hash;
    address_tx.m_incoming = incoming;
    address_tx.m_amount  =  incoming ? total_received - total_sent : total_sent - total_received;
    address_tx.m_fee = 0;                 // TODO
    address_tx.m_unmined_blink = false;
    address_tx.m_was_blink = false;
    address_tx.m_block_height = t.height;
    address_tx.m_unlock_time  = t.unlock_time;
    address_tx.m_timestamp = t.timestamp;
    address_tx.m_type  = t.coinbase ? wallet::pay_type::miner : wallet::pay_type::in; // TODO(oxen): Only accounts for miner, but wait, do we even care about this code? Looks like openmonero code
    address_tx.m_mempool  = t.mempool;
    m_light_wallet_address_txs.emplace(tx_hash,address_tx);

    // populate data needed for history (m_payments, m_unconfirmed_payments, m_confirmed_txs)
    // INCOMING transfers
    if(total_received > total_sent) {
      payment_details payment;
      payment.m_tx_hash = tx_hash;
      payment.m_amount       = total_received - total_sent;
      payment.m_fee          = 0;         // TODO
      payment.m_unmined_blink = false;
      payment.m_was_blink = false;
      payment.m_block_height = t.height;
      payment.m_unlock_time  = t.unlock_time;
      payment.m_timestamp = t.timestamp;
      payment.m_type = t.coinbase ? wallet::pay_type::miner : wallet::pay_type::in; // TODO(oxen): Only accounts for miner, but wait, do we even care about this code? Looks like openmonero code

      if (t.mempool) {
        if (std::find(unconfirmed_payments_txs.begin(), unconfirmed_payments_txs.end(), tx_hash) == unconfirmed_payments_txs.end()) {
          pool_txs.push_back(tx_hash);
          // assume false as we don't get that info from the light wallet server
          crypto::hash payment_id;
          THROW_WALLET_EXCEPTION_IF(!tools::hex_to_type(t.payment_id, payment_id),
              error::wallet_internal_error, "Failed to parse payment id");
          emplace_or_replace(m_unconfirmed_payments, payment_id, pool_payment_details{payment, false});
          if (0 != m_callback) {
            m_callback->on_lw_unconfirmed_money_received(t.height, payment.m_tx_hash, payment.m_amount);
          }
        }
      } else {
        if (std::find(payments_txs.begin(), payments_txs.end(), tx_hash) == payments_txs.end()) {
          m_payments.emplace(tx_hash, payment);
          if (0 != m_callback) {
            m_callback->on_lw_money_received(t.height, payment.m_tx_hash, payment.m_amount);
          }
        }
      }
    // Outgoing transfers
    } else {
      uint64_t amount_sent = total_sent - total_received;
      cryptonote::transaction dummy_tx; // not used by light wallet
      // increase wallet total sent
      wallet_total_sent += total_sent;
      if (t.mempool)
      {
        // Handled by add_unconfirmed_tx in commit_tx
        // If sent from another wallet instance we need to add it
        if(m_unconfirmed_txs.find(tx_hash) == m_unconfirmed_txs.end())
        {
          unconfirmed_transfer_details utd;
          utd.m_amount_in = amount_sent;
          utd.m_amount_out = amount_sent;
          utd.m_change = 0;
          utd.m_payment_id = payment_id;
          utd.m_timestamp = t.timestamp;
          utd.m_state = wallet2::unconfirmed_transfer_details::pending;
          m_unconfirmed_txs.emplace(tx_hash,utd);
        }
      }
      else
      {
        // Only add if new
        auto confirmed_tx = m_confirmed_txs.find(tx_hash);
        if(confirmed_tx == m_confirmed_txs.end()) {
          // tx is added to m_unconfirmed_txs - move to confirmed
          if(m_unconfirmed_txs.find(tx_hash) != m_unconfirmed_txs.end())
          {
            process_unconfirmed(tx_hash, dummy_tx, t.height);
          }
          // Tx sent by another wallet instance
          else
          {
            confirmed_transfer_details ctd;
            ctd.m_amount_in = amount_sent;
            ctd.m_amount_out = amount_sent;
            ctd.m_change = 0;
            ctd.m_payment_id = payment_id;
            ctd.m_block_height = t.height;
            ctd.m_timestamp = t.timestamp;
            m_confirmed_txs.emplace(tx_hash,ctd);
          }
          if (0 != m_callback)
          {
            m_callback->on_lw_money_spent(t.height, tx_hash, amount_sent);
          }
        }
        // If not new - check the amount and update if necessary.
        // when sending a tx to same wallet the receiving amount has to be credited
        else
        {
          if(confirmed_tx->second.m_amount_in != amount_sent || confirmed_tx->second.m_amount_out != amount_sent)
          {
            MDEBUG("Adjusting amount sent/received for tx: <" + t.hash + ">. Is tx sent to own wallet? " << print_money(amount_sent) << " != " << print_money(confirmed_tx->second.m_amount_in));
            confirmed_tx->second.m_amount_in = amount_sent;
            confirmed_tx->second.m_amount_out = amount_sent;
            confirmed_tx->second.m_change = 0;
          }
        }
      }
    }
  }
  // TODO: purge old unconfirmed_txs
  remove_obsolete_pool_txs(pool_txs);

  // Calculate wallet balance
  m_light_wallet_balance = ires.total_received-wallet_total_sent;
  // MyMonero doesn't send unlocked balance
  if(ires.total_received_unlocked > 0)
    m_light_wallet_unlocked_balance = ires.total_received_unlocked-wallet_total_sent;
  else
    m_light_wallet_unlocked_balance = m_light_wallet_balance;
}

bool wallet2::light_wallet_parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const
{
  // rct string is empty if output is non RCT
  if (rct_string.empty())
    return false;
  // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
  rct::key encrypted_mask;
  std::string rct_commit_str = rct_string.substr(0,64);
  std::string encrypted_mask_str = rct_string.substr(64,64);
  THROW_WALLET_EXCEPTION_IF(rct_commit_str.size() != 64 || !oxenmq::is_hex(rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
  THROW_WALLET_EXCEPTION_IF(encrypted_mask_str.size() != 64 || !oxenmq::is_hex(encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
  tools::hex_to_type(rct_commit_str, rct_commit);
  tools::hex_to_type(encrypted_mask_str, encrypted_mask);
  if (decrypt) {
    // Decrypt the mask
    crypto::key_derivation derivation;
    bool r = generate_key_derivation(tx_pub_key, get_account().get_keys().m_view_secret_key, derivation);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
    crypto::secret_key scalar;
    crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
    sc_sub(decrypted_mask.bytes,encrypted_mask.bytes,rct::hash_to_scalar(rct::sk2rct(scalar)).bytes);
  }
  return true;
}

bool wallet2::light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index)
{
  // Lookup key image from cache
  std::map<uint64_t, crypto::key_image> index_keyimage_map;
  std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> >::const_iterator found_pub_key = m_key_image_cache.find(tx_public_key);
  if(found_pub_key != m_key_image_cache.end()) {
    // pub key found. key image for index cached?
    index_keyimage_map = found_pub_key->second;
    std::map<uint64_t,crypto::key_image>::const_iterator index_found = index_keyimage_map.find(out_index);
    if(index_found != index_keyimage_map.end())
      return key_image == index_found->second;
  }

  // Not in cache - calculate key image
  crypto::key_image calculated_key_image;
  cryptonote::keypair in_ephemeral;

  // Subaddresses aren't supported in mymonero/openmonero yet. Roll out the original scheme:
  //   compute D = a*R
  //   compute P = Hs(D || i)*G + B
  //   compute x = Hs(D || i) + b      (and check if P==x*G)
  //   compute I = x*Hp(P)
  const account_keys& ack = get_account().get_keys();
  crypto::key_derivation derivation;
  bool r = crypto::generate_key_derivation(tx_public_key, ack.m_view_secret_key, derivation);
  CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");

  r = crypto::derive_public_key(derivation, out_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub);
  CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key (" << derivation << ", " << out_index << ", " << ack.m_account_address.m_spend_public_key << ")");

  crypto::derive_secret_key(derivation, out_index, ack.m_spend_secret_key, in_ephemeral.sec);
  crypto::public_key out_pkey_test;
  r = crypto::secret_key_to_public_key(in_ephemeral.sec, out_pkey_test);
  CHECK_AND_ASSERT_MES(r, false, "failed to secret_key_to_public_key(" << in_ephemeral.sec << ")");
  CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_pkey_test, false, "derived secret key doesn't match derived public key");

  crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, calculated_key_image);

  index_keyimage_map.emplace(out_index, calculated_key_image);
  m_key_image_cache.emplace(tx_public_key, index_keyimage_map);
  return key_image == calculated_key_image;
}

// Another implementation of transaction creation that is hopefully better
// While there is anything left to pay, it goes through random outputs and tries
// to fill the next destination/amount. If it fully fills it, it will use the
// remainder to try to fill the next one as well.
// The tx size if roughly estimated as a linear function of only inputs, and a
// new tx will be created when that size goes above a given fraction of the
// max tx size. At that point, more outputs may be added if the fee cannot be
// satisfied.
// If the next output in the next tx would go to the same destination (ie, we
// cut off at a tx boundary in the middle of paying a given destination), the
// fee will be carved out of the current input if possible, to avoid having to
// add another output just for the fee and getting change.
// This system allows for sending (almost) the entire balance, since it does
// not generate spurious change in all txes, thus decreasing the instantaneous
// usable balance.
std::vector<wallet2::pending_tx> wallet2::create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra_base, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, oxen_construct_tx_params &tx_params)
{
  //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
  std::unique_lock hwdev_lock{hwdev};
  hw::mode_resetter rst{hwdev};

  bool const is_ons_tx = (tx_params.tx_type == txtype::oxen_name_system);
  auto original_dsts = dsts;
  if (is_ons_tx)
  {
    THROW_WALLET_EXCEPTION_IF(dsts.size() != 0, error::wallet_internal_error, "oxen name system txs must not have any destinations set, has: " + std::to_string(dsts.size()));
    dsts.emplace_back(0, account_public_address{} /*address*/, false /*is_subaddress*/); // NOTE: Create a dummy dest that gets repurposed into the change output.
  }

  if(m_light_wallet) {
    // Populate m_transfers
    light_wallet_get_unspent_outs();
  }
  std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_transfers_indices_per_subaddr;
  std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_dust_indices_per_subaddr;
  uint64_t needed_money;
  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    pending_tx ptx;
    size_t weight;
    uint64_t needed_fee;
    std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

    TX() : weight(0), needed_fee(0) {}

    void add(const cryptonote::tx_destination_entry &de, uint64_t amount, unsigned int original_output_index, bool merge_destinations) {
      if (merge_destinations)
      {
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &de.addr, sizeof(de.addr)); });
        if (i == dsts.end())
        {
          dsts.push_back(de);
          i = dsts.end() - 1;
          i->amount = 0;
        }
        i->amount += amount;
      }
      else
      {
        THROW_WALLET_EXCEPTION_IF(original_output_index > dsts.size(), error::wallet_internal_error,
            std::string("original_output_index too large: ") + std::to_string(original_output_index) + " > " + std::to_string(dsts.size()));
        if (original_output_index == dsts.size())
        {
          dsts.push_back(de);
          dsts.back().amount = 0;
        }
        THROW_WALLET_EXCEPTION_IF(memcmp(&dsts[original_output_index].addr, &de.addr, sizeof(de.addr)), error::wallet_internal_error, "Mismatched destination address");
        dsts[original_output_index].amount += amount;
      }
    }
  };
  std::vector<TX> txes;
  bool adding_fee; // true if new outputs go towards fee, rather than destinations
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  const bool clsag = use_fork_rules(HF_VERSION_CLSAG, 0);
  const rct::RCTConfig rct_config{rct::RangeProofType::PaddedBulletproof, clsag ? 3 : 2};

  const auto base_fee = get_base_fees();
  const uint64_t fee_percent = get_fee_percent(priority, tx_params.tx_type);
  uint64_t fixed_fee = 0;
  const uint64_t fee_quantization_mask = get_fee_quantization_mask();

  uint64_t burn_fixed = 0, burn_percent = 0;
  // Swap these out because we don't want them present for building intermediate temporary tx
  // calculations (which we don't actually use); we'll set them again at the end before we build the
  // real transactions.
  std::swap(burn_fixed, tx_params.burn_fixed);
  std::swap(burn_percent, tx_params.burn_percent);
  bool burning = burn_fixed || burn_percent;
  THROW_WALLET_EXCEPTION_IF(burning && tx_params.hf_version < HF_VERSION_FEE_BURNING, error::wallet_internal_error, "cannot construct transaction: cannot burn amounts under the current hard fork");
  std::vector<uint8_t> extra_plus; // Copy and modified from input if modification needed
  const std::vector<uint8_t> &extra = burning ? extra_plus : extra_base;
  if (burning)
  {
    extra_plus = extra_base;
    add_burned_amount_to_tx_extra(extra_plus, 0);
    fixed_fee += burn_fixed;
    THROW_WALLET_EXCEPTION_IF(burn_percent > fee_percent, error::wallet_internal_error, "invalid burn fees: cannot burn more than the tx fee");
  }

  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  needed_money = 0;
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount && !is_ons_tx, error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, 0, m_nettype);
  }


  // throw if attempting a transaction with no money
  THROW_WALLET_EXCEPTION_IF(needed_money == 0 && !is_ons_tx, error::zero_destination);

  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddr = unlocked_balance_per_subaddress(subaddr_account, false);
  std::map<uint32_t, uint64_t> balance_per_subaddr = balance_per_subaddress(subaddr_account, false);

  if (subaddr_indices.empty()) // "index=<N1>[,<N2>,...]" wasn't specified -> use all the indices with non-zero unlocked balance
  {
    for (const auto& i : balance_per_subaddr)
      subaddr_indices.insert(i.first);
  }

  // early out if we know we can't make it anyway
  // we could also check for being within FEE_PER_KB, but if the fee calculation
  // ever changes, this might be missed, so let this go through
  const uint64_t min_outputs = tx_params.tx_type == cryptonote::txtype::oxen_name_system ? 1 : 2; // if ons, only request the change output
  {
    uint64_t min_fee = (
        base_fee.first * estimate_rct_tx_size(1, fake_outs_count, min_outputs, extra.size(), clsag) +
        base_fee.second * min_outputs
    ) * fee_percent / 100;

    uint64_t balance_subtotal = 0;
    uint64_t unlocked_balance_subtotal = 0;
    for (uint32_t index_minor : subaddr_indices)
    {
      balance_subtotal += balance_per_subaddr[index_minor];
      unlocked_balance_subtotal += unlocked_balance_per_subaddr[index_minor].first;
    }
    THROW_WALLET_EXCEPTION_IF(needed_money + min_fee + fixed_fee > balance_subtotal, error::not_enough_money,
      balance_subtotal, needed_money, 0);
    // first check overall balance is enough, then unlocked one, so we throw distinct exceptions
    THROW_WALLET_EXCEPTION_IF(needed_money + min_fee + fixed_fee > unlocked_balance_subtotal, error::not_enough_unlocked_money,
        unlocked_balance_subtotal, needed_money, 0);
  }

  for (uint32_t i : subaddr_indices)
    LOG_PRINT_L2("Candidate subaddress index for spending: " << i);

  // determine threshold for fractional amount
  const size_t tx_weight_one_ring = estimate_tx_weight(1, fake_outs_count, 2, 0, clsag);
  const size_t tx_weight_two_rings = estimate_tx_weight(2, fake_outs_count, 2, 0, clsag);
  THROW_WALLET_EXCEPTION_IF(tx_weight_one_ring > tx_weight_two_rings, error::wallet_internal_error, "Estimated tx weight with 1 input is larger than with 2 inputs!");
  const size_t tx_weight_per_ring = tx_weight_two_rings - tx_weight_one_ring;
  const uint64_t fractional_threshold = base_fee.first * fee_percent / 100 * tx_weight_per_ring;

  // gather all dust and non-dust outputs belonging to specified subaddresses
  size_t num_nondust_outputs = 0;
  size_t num_dust_outputs = 0;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && !td.m_key_image_partial && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      if (td.amount() > m_ignore_outputs_above || td.amount() < m_ignore_outputs_below)
      {
        MDEBUG("Ignoring output " << i << " of amount " << print_money(td.amount()) << " which is outside prescribed range [" << print_money(m_ignore_outputs_below) << ", " << print_money(m_ignore_outputs_above) << "]");
        continue;
      }
      const uint32_t index_minor = td.m_subaddr_index.minor;
      auto find_predicate = [&index_minor](const std::pair<uint32_t, std::vector<size_t>>& x) { return x.first == index_minor; };
      if (td.is_rct())
      {
        auto found = std::find_if(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), find_predicate);
        if (found == unused_transfers_indices_per_subaddr.end())
        {
          unused_transfers_indices_per_subaddr.push_back({index_minor, {i}});
        }
        else
        {
          found->second.push_back(i);
        }
        ++num_nondust_outputs;
      }
      else
      {
        auto found = std::find_if(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), find_predicate);
        if (found == unused_dust_indices_per_subaddr.end())
        {
          unused_dust_indices_per_subaddr.push_back({index_minor, {i}});
        }
        else
        {
          found->second.push_back(i);
        }
        ++num_dust_outputs;
      }
    }
  }

  // sort output indices
  {
    auto sort_predicate = [&unlocked_balance_per_subaddr] (const std::pair<uint32_t, std::vector<size_t>>& x, const std::pair<uint32_t, std::vector<size_t>>& y)
    {
      return unlocked_balance_per_subaddr[x.first].first > unlocked_balance_per_subaddr[y.first].first;
    };
    std::sort(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), sort_predicate);
    std::sort(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), sort_predicate);
  }

  LOG_PRINT_L2("Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs");

  if (unused_dust_indices_per_subaddr.empty() && unused_transfers_indices_per_subaddr.empty())
    return std::vector<wallet2::pending_tx>();

  // if empty, put dummy entry so that the front can be referenced later in the loop
  if (unused_dust_indices_per_subaddr.empty())
    unused_dust_indices_per_subaddr.push_back({});
  if (unused_transfers_indices_per_subaddr.empty())
    unused_transfers_indices_per_subaddr.push_back({});

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  adding_fee = false;
  needed_fee = 0;
  std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

  // for rct, since we don't see the amounts, we will try to make all transactions
  // look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
  // this prevents linking to another by provenance analysis, but two is ok if we
  // try to pick outputs not from the same block. We will get two outputs, one for
  // the destination, and one for change.
  LOG_PRINT_L2("checking preferred");
  std::vector<size_t> preferred_inputs;
  uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
  rct_outs_needed += 100; // some fudge factor since we don't know how many are locked
  {
    // this is used to build a tx that's 1 or 2 inputs, and 1 or 2 outputs, which will get us a known fee.
    uint64_t estimated_fee = estimate_fee(2, fake_outs_count, min_outputs, extra.size(), clsag, base_fee, fee_percent, fixed_fee, fee_quantization_mask);
    preferred_inputs = pick_preferred_rct_inputs(needed_money + estimated_fee, subaddr_account, subaddr_indices);
    if (!preferred_inputs.empty())
    {
      std::string s;
      for (auto i: preferred_inputs) s += boost::lexical_cast<std::string>(i) + " (" + print_money(m_transfers[i].amount()) + ") ";
      LOG_PRINT_L1("Found preferred rct inputs for rct tx: " << s);

      // bring the list of available outputs stored by the same subaddress index to the front of the list
      uint32_t index_minor = m_transfers[preferred_inputs[0]].m_subaddr_index.minor;
      for (size_t i = 1; i < unused_transfers_indices_per_subaddr.size(); ++i)
      {
        if (unused_transfers_indices_per_subaddr[i].first == index_minor)
        {
          std::swap(unused_transfers_indices_per_subaddr[0], unused_transfers_indices_per_subaddr[i]);
          break;
        }
      }
      for (size_t i = 1; i < unused_dust_indices_per_subaddr.size(); ++i)
      {
        if (unused_dust_indices_per_subaddr[i].first == index_minor)
        {
          std::swap(unused_dust_indices_per_subaddr[0], unused_dust_indices_per_subaddr[i]);
          break;
        }
      }
    }
  }
  LOG_PRINT_L2("done checking preferred");

  // while:
  // - we have something to send
  // - or we need to gather more fee
  // - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
  unsigned int original_output_index = 0;
  std::vector<size_t>* unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
  std::vector<size_t>* unused_dust_indices      = &unused_dust_indices_per_subaddr[0].second;

  hwdev.set_mode(hw::device::TRANSACTION_CREATE_FAKE);
  while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty() || should_pick_a_second_output(txes.back().selected_transfers.size(), *unused_transfers_indices, *unused_dust_indices)) {
    TX &tx = txes.back();

    LOG_PRINT_L2("Start of loop with " << unused_transfers_indices->size() << " " << unused_dust_indices->size() << ", tx.dsts.size() " << tx.dsts.size());
    LOG_PRINT_L2("unused_transfers_indices: " << strjoin(*unused_transfers_indices, " "));
    LOG_PRINT_L2("unused_dust_indices: " << strjoin(*unused_dust_indices, " "));
    LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
    LOG_PRINT_L2("adding_fee " << adding_fee);

    // if we need to spend money and don't have any left, we fail
    if (unused_dust_indices->empty() && unused_transfers_indices->empty()) {
      LOG_PRINT_L2("No more outputs to choose from");
      THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account, false), needed_money, accumulated_fee + needed_fee);
    }

    // get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
    // This could be more clever, but maybe at the cost of making probabilistic inferences easier
    size_t idx;
    if (!preferred_inputs.empty()) {
      idx = pop_back(preferred_inputs);
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else if ((dsts.empty() || (dsts[0].amount == 0 && !is_ons_tx)) && !adding_fee) {
      // NOTE: A ONS tx sets dsts[0].amount to 0, but this branch is for the
      // 2 inputs/2 outputs. We only have 1 output as ONS transactions are
      // distinguishable, so we actually want the last branch which uses unused
      // outputs in the wallet to pay off the ONS fee.

      // the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
      std::vector<size_t> indices = get_only_rct(*unused_dust_indices, *unused_transfers_indices);
      idx = pop_best_value(indices, tx.selected_transfers, true);

      // we might not want to add it if it's a large output and we don't have many left
      uint64_t min_output_value = m_min_output_value;
      uint32_t min_output_count = m_min_output_count;
      if (min_output_value == 0 && min_output_count == 0)
      {
        min_output_value = DEFAULT_MIN_OUTPUT_VALUE;
        min_output_count = DEFAULT_MIN_OUTPUT_COUNT;
      }
      if (m_transfers[idx].amount() >= min_output_value) {
        if (get_count_above(m_transfers, *unused_transfers_indices, min_output_value) < min_output_count) {
          LOG_PRINT_L2("Second output was not strictly needed, and we're running out of outputs above " << print_money(min_output_value) << ", not adding");
          break;
        }
      }

      // since we're trying to add a second output which is not strictly needed,
      // we only add it if it's unrelated enough to the first one
      float relatedness = get_output_relatedness(m_transfers[idx], m_transfers[tx.selected_transfers.front()]);
      if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD)
      {
        LOG_PRINT_L2("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
        break;
      }
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else
      idx = pop_best_value(unused_transfers_indices->empty() ? *unused_dust_indices : *unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers[idx];
    LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    if (adding_fee)
    {
      LOG_PRINT_L2("We need more fee, adding it to fee");
      available_for_fee += available_amount;
    }
    else
    {
      while (!dsts.empty() && dsts[0].amount <= available_amount && estimate_tx_weight(tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), clsag) < tx_weight_target(upper_transaction_weight_limit))
      {
        // we can fully pay that destination
        LOG_PRINT_L2("We can fully pay " << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr) <<
          " for " << print_money(dsts[0].amount));
        tx.add(dsts[0], dsts[0].amount, original_output_index, m_merge_destinations);
        available_amount -= dsts[0].amount;
        dsts[0].amount = 0;
        pop_index(dsts, 0);
        ++original_output_index;
      }

      if (available_amount > 0 && !dsts.empty() && estimate_tx_weight(tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), clsag) < tx_weight_target(upper_transaction_weight_limit)) {
        // we can partially fill that destination
        LOG_PRINT_L2("We can partially pay " << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr) <<
          " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
        tx.add(dsts[0], available_amount, original_output_index, m_merge_destinations);
        dsts[0].amount -= available_amount;
        available_amount = 0;
      }
    }

    // here, check if we need to sent tx and start a new one
    LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_weight_limit);
    bool try_tx = false;
    // if we have preferred picks, but haven't yet used all of them, continue
    if (preferred_inputs.empty())
    {
      if (adding_fee)
      {
        /* might not actually be enough if adding this output bumps size to next kB, but we need to try */
        try_tx = available_for_fee >= needed_fee;
      }
      else
      {
        const size_t estimated_rct_tx_weight = estimate_tx_weight(tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()+1, extra.size(), clsag);
        try_tx = dsts.empty() || (estimated_rct_tx_weight >= tx_weight_target(upper_transaction_weight_limit));
        THROW_WALLET_EXCEPTION_IF(try_tx && tx.dsts.empty(), error::tx_too_big, estimated_rct_tx_weight, upper_transaction_weight_limit);
      }
    }

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t num_outputs = get_num_outputs(tx.dsts, m_transfers, tx.selected_transfers, tx_params);
      needed_fee = estimate_fee(tx.selected_transfers.size(), fake_outs_count, num_outputs, extra.size(), clsag, base_fee, fee_percent, fixed_fee, fee_quantization_mask);

      uint64_t inputs = 0, outputs = needed_fee;
      for (size_t idx: tx.selected_transfers) inputs += m_transfers[idx].amount();
      for (const auto &o: tx.dsts) outputs += o.amount;

      if (inputs < outputs)
      {
        LOG_PRINT_L2("We don't have enough for the basic fee, switching to adding_fee");
        adding_fee = true;
        goto skip_tx;
      }

      LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
        tx.selected_transfers.size() << " inputs");
      transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          test_tx, test_ptx, rct_config, tx_params);
      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(test_ptx.tx, txBlob.size(), base_fee, fee_percent, fixed_fee, fee_quantization_mask);
      available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
      LOG_PRINT_L2("Made a " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
      {
        // we don't have enough for the fee, but we've only partially paid the current address,
        // so we can take the fee from the paid amount, since we'll have to make another tx anyway
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
          [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
        THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");
        if (i->amount > needed_fee)
        {
          uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
          LOG_PRINT_L2("Adjusting amount paid to " << get_account_address_as_str(m_nettype, i->is_subaddress, i->addr) << " from " <<
            print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accommodate " <<
            print_money(needed_fee) << " fee");
          dsts[0].amount += i->amount - new_paid_amount;
          i->amount = new_paid_amount;
          test_ptx.fee = needed_fee;
          available_for_fee = needed_fee;
        }
      }

      if (needed_fee > available_for_fee)
      {
        LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");

        adding_fee = true;
      }
      else
      {
        LOG_PRINT_L2("We made a tx, adjusting fee and saving it, we need " << print_money(needed_fee) << " and we have " << print_money(test_ptx.fee));
        while (needed_fee > test_ptx.fee) {
          transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
              test_tx, test_ptx, rct_config, tx_params);
          txBlob = t_serializable_object_to_blob(test_ptx.tx);
          needed_fee = calculate_fee(test_ptx.tx, txBlob.size(), base_fee, fee_percent, fixed_fee, fee_quantization_mask);
          LOG_PRINT_L2("Made an attempt at a  final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
            " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
        }

        LOG_PRINT_L2("Made a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

        tx.tx = test_tx;
        tx.ptx = test_ptx;
        tx.weight = get_transaction_weight(test_tx, txBlob.size());
        tx.outs = outs;
        tx.needed_fee = test_ptx.fee;
        accumulated_fee += test_ptx.fee;
        accumulated_change += test_ptx.change_dts.amount;
        adding_fee = false;
        if (!dsts.empty())
        {
          LOG_PRINT_L2("We have more to pay, starting another tx");
          txes.push_back(TX());
          original_output_index = 0;
        }
      }
    }

skip_tx:
    // if unused_*_indices is empty while unused_*_indices_per_subaddr has multiple elements, and if we still have something to pay,
    // pop front of unused_*_indices_per_subaddr and have unused_*_indices point to the front of unused_*_indices_per_subaddr
    if ((!dsts.empty() && dsts[0].amount > 0) || adding_fee)
    {
      if (unused_transfers_indices->empty() && unused_transfers_indices_per_subaddr.size() > 1)
      {
        unused_transfers_indices_per_subaddr.erase(unused_transfers_indices_per_subaddr.begin());
        unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
      }
      if (unused_dust_indices->empty() && unused_dust_indices_per_subaddr.size() > 1)
      {
        unused_dust_indices_per_subaddr.erase(unused_dust_indices_per_subaddr.begin());
        unused_dust_indices = &unused_dust_indices_per_subaddr[0].second;
      }
    }
  }

  if (adding_fee)
  {
    LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
    THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account, false), needed_money, accumulated_fee + needed_fee);
  }

  LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");

  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);
  for (auto &tx : txes)
  {
    // Convert burn percent into a fixed burn amount because this is the last place we can back out
    // the base fee that would apply at 100% (the actual fee here is that times the priority-based
    // fee percent)
    if (burning)
      tx_params.burn_fixed = burn_fixed + (tx.needed_fee - burn_fixed) * burn_percent / fee_percent;

    cryptonote::transaction test_tx;
    pending_tx test_ptx;
    transfer_selected_rct(  tx.dsts,                    /* NOMOD std::vector<cryptonote::tx_destination_entry> dsts,*/
                            tx.selected_transfers,      /* const std::list<size_t> selected_transfers */
                            fake_outs_count,            /* CONST size_t fake_outputs_count, */
                            tx.outs,                    /* MOD   std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, */
                            unlock_time,                /* CONST uint64_t unlock_time,  */
                            tx.needed_fee,              /* CONST uint64_t fee, */
                            extra,                      /* const std::vector<uint8_t>& extra, */
                            test_tx,                    /* OUT   cryptonote::transaction& tx, */
                            test_ptx,                   /* OUT   cryptonote::transaction& tx, */
                            rct_config,
                            tx_params);
    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.weight = get_transaction_weight(test_tx, txBlob.size());
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers[idx].amount();
    LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      " " << get_transaction_hash(tx.ptx.tx) << ": " << get_weight_string(tx.weight) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  THROW_WALLET_EXCEPTION_IF(!sanity_check(ptx_vector, original_dsts), error::wallet_internal_error, "Created transaction(s) failed sanity check");

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}

bool wallet2::sanity_check(const std::vector<wallet2::pending_tx> &ptx_vector, std::vector<cryptonote::tx_destination_entry> dsts) const
{
  MDEBUG("sanity_check: " << ptx_vector.size() << " txes, " << dsts.size() << " destinations");

  hw::device &hwdev = m_account.get_device();

  THROW_WALLET_EXCEPTION_IF(ptx_vector.empty(), error::wallet_internal_error, "No transactions");

  // check every party in there does receive at least the required amount
  std::unordered_map<account_public_address, std::pair<uint64_t, bool>> required;
  for (const auto &d: dsts)
  {
    required[d.addr].first += d.amount;
    required[d.addr].second = d.is_subaddress;
  }

  // add change
  uint64_t change = 0;
  for (const auto &ptx: ptx_vector)
  {
    for (size_t idx: ptx.selected_transfers)
      change += m_transfers[idx].amount();
    change -= ptx.fee;
  }
  for (const auto &r: required)
    change -= r.second.first;
  MDEBUG("Adding " << cryptonote::print_money(change) << " expected change");

  // for all txes that have actual change, check change is coming back to the sending wallet
  for (const pending_tx &ptx: ptx_vector)
  {
    if (ptx.change_dts.amount == 0)
      continue;
    THROW_WALLET_EXCEPTION_IF(m_subaddresses.find(ptx.change_dts.addr.m_spend_public_key) == m_subaddresses.end(),
         error::wallet_internal_error, "Change address is not ours");
    required[ptx.change_dts.addr].first += ptx.change_dts.amount;
    required[ptx.change_dts.addr].second = ptx.change_dts.is_subaddress;
  }

  for (const auto &r: required)
  {
    const account_public_address &address = r.first;
    const crypto::public_key &view_pkey = address.m_view_public_key;

    uint64_t total_received = 0;
    for (const auto &ptx: ptx_vector)
    {
      uint64_t received = 0;
      try
      {
        std::string proof = get_tx_proof(ptx.tx, ptx.tx_key, ptx.additional_tx_keys, address, r.second.second, "automatic-sanity-check");
        check_tx_proof(ptx.tx, address, r.second.second, "automatic-sanity-check", proof, received);
      }
      catch (const std::exception &e) { received = 0; }
      total_received += received;
    }

    std::stringstream ss;
    ss << "Total received by " << cryptonote::get_account_address_as_str(m_nettype, r.second.second, address) << ": "
        << cryptonote::print_money(total_received) << ", expected " << cryptonote::print_money(r.second.first);
    MDEBUG(ss.str());
    THROW_WALLET_EXCEPTION_IF(total_received < r.second.first, error::wallet_internal_error, ss.str());
  }

  return true;
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, cryptonote::txtype tx_type)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;

  THROW_WALLET_EXCEPTION_IF(unlocked_balance(subaddr_account, false) == 0, error::wallet_internal_error, "No unlocked balance in the entire wallet");

  std::map<uint32_t, std::pair<std::vector<size_t>, std::vector<size_t>>> unused_transfer_dust_indices_per_subaddr;

  // gather all dust and non-dust outputs of specified subaddress (if any) and below specified threshold (if any)
  bool fund_found = false;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!is_spent(td, false) && !td.m_frozen && !td.m_key_image_partial && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && (subaddr_indices.empty() || subaddr_indices.count(td.m_subaddr_index.minor) == 1))
    {
      fund_found = true;
      if (below == 0 || td.amount() < below)
      {
        if (td.m_tx.version <= txversion::v1)
          continue;

        if (td.is_rct())
          unused_transfer_dust_indices_per_subaddr[td.m_subaddr_index.minor].first.push_back(i);
        else
          unused_transfer_dust_indices_per_subaddr[td.m_subaddr_index.minor].second.push_back(i);
      }
    }
  }
  THROW_WALLET_EXCEPTION_IF(!fund_found, error::wallet_internal_error, "No unlocked balance in the specified subaddress(es)");
  THROW_WALLET_EXCEPTION_IF(unused_transfer_dust_indices_per_subaddr.empty(), error::wallet_internal_error, "The smallest amount found is not below the specified threshold");

  if (subaddr_indices.empty())
  {
    // in case subaddress index wasn't specified, choose non-empty subaddress randomly (with index=0 being chosen last)
    if (unused_transfer_dust_indices_per_subaddr.count(0) == 1 && unused_transfer_dust_indices_per_subaddr.size() > 1)
      unused_transfer_dust_indices_per_subaddr.erase(0);
    auto i = unused_transfer_dust_indices_per_subaddr.begin();
    std::advance(i, crypto::rand_idx(unused_transfer_dust_indices_per_subaddr.size()));
    unused_transfers_indices = i->second.first;
    unused_dust_indices = i->second.second;
    LOG_PRINT_L2("Spending from subaddress index " << i->first);
  }
  else
  {
    for (const auto& p : unused_transfer_dust_indices_per_subaddr)
    {
      unused_transfers_indices.insert(unused_transfers_indices.end(), p.second.first.begin(), p.second.first.end());
      unused_dust_indices.insert(unused_dust_indices.end(), p.second.second.begin(), p.second.second.end());
      LOG_PRINT_L2("Spending from subaddress index " << p.first);
    }
  }

  return create_transactions_from(address, is_subaddress, outputs, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra, tx_type);
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, cryptonote::txtype tx_type)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  // find output with the given key image
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (td.m_key_image_known && td.m_key_image == ki && !is_spent(td, false) && !td.m_frozen && is_transfer_unlocked(td))
    {
      if (td.is_rct())
        unused_transfers_indices.push_back(i);
      else
        unused_dust_indices.push_back(i);
      break;
    }
  }
  return create_transactions_from(address, is_subaddress, outputs, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra, tx_type);
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra_base, cryptonote::txtype tx_type)
{
  //ensure device is let in NONE mode in any case
  hw::device &hwdev = m_account.get_device();
  std::unique_lock hwdev_lock{hwdev};
  hw::mode_resetter rst{hwdev};

  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    pending_tx ptx;
    size_t weight;
    uint64_t needed_fee;
    std::vector<std::vector<get_outs_entry>> outs;

    TX() : weight(0), needed_fee(0) {}
  };
  std::vector<TX> txes;
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_weight_limit = get_upper_transaction_weight_limit();
  std::vector<std::vector<get_outs_entry>> outs;

  const bool clsag = use_fork_rules(HF_VERSION_CLSAG, 0);
  const rct::RCTConfig rct_config { rct::RangeProofType::PaddedBulletproof, clsag ? 3 : 2 };
  const auto base_fee = get_base_fees();
  const uint64_t fee_percent = get_fee_percent(priority, tx_type);
  const uint64_t fee_quantization_mask = get_fee_quantization_mask();
  uint64_t fixed_fee = 0;

  std::optional<uint8_t> hf_version = get_hard_fork_version();
  THROW_WALLET_EXCEPTION_IF(!hf_version, error::get_hard_fork_version_error, "Failed to query current hard fork version");

  oxen_construct_tx_params oxen_tx_params = tools::wallet2::construct_params(*hf_version, tx_type, priority);
  uint64_t burn_fixed = 0, burn_percent = 0;
  // Swap these out because we don't want them present for building intermediate temporary tx
  // calculations (which we don't actually use); we'll set them again at the end before we build the
  // real transactions.
  std::swap(burn_fixed, oxen_tx_params.burn_fixed);
  std::swap(burn_percent, oxen_tx_params.burn_percent);
  bool burning = burn_fixed || burn_percent;
  THROW_WALLET_EXCEPTION_IF(burning && oxen_tx_params.hf_version < HF_VERSION_FEE_BURNING, error::wallet_internal_error, "cannot construct transaction: cannot burn amounts under the current hard fork");
  std::vector<uint8_t> extra_plus; // Copy and modified from input if modification needed
  const std::vector<uint8_t> &extra = burning ? extra_plus : extra_base;
  if (burning)
  {
    extra_plus = extra_base;
    add_burned_amount_to_tx_extra(extra_plus, 0);
    fixed_fee += burn_fixed;
    THROW_WALLET_EXCEPTION_IF(burn_percent > fee_percent, error::wallet_internal_error, "invalid burn fees: cannot burn more than the tx fee");
  }

  LOG_PRINT_L2("Starting with " << unused_transfers_indices.size() << " non-dust outputs and " << unused_dust_indices.size() << " dust outputs");

  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return std::vector<wallet2::pending_tx>();

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  needed_fee = 0;

  // while we have something to send
  hwdev.set_mode(hw::device::TRANSACTION_CREATE_FAKE);
  while (!unused_dust_indices.empty() || !unused_transfers_indices.empty()) {
    TX &tx = txes.back();

    // get a random unspent output and use it to pay next chunk. We try to alternate
    // dust and non dust to ensure we never get with only dust, from which we might
    // get a tx that can't pay for itself
    uint64_t fee_dust_threshold;
    {
      const uint64_t estimated_tx_weight_with_one_extra_output = estimate_tx_weight(tx.selected_transfers.size() + 1, fake_outs_count, tx.dsts.size()+1, extra.size(), clsag);
      fee_dust_threshold = calculate_fee_from_weight(base_fee, estimated_tx_weight_with_one_extra_output, outputs, fee_percent, fixed_fee, fee_quantization_mask);
    }

    size_t idx =
      unused_transfers_indices.empty()
        ? pop_best_value(unused_dust_indices, tx.selected_transfers)
      : unused_dust_indices.empty()
        ? pop_best_value(unused_transfers_indices, tx.selected_transfers)
      : ((tx.selected_transfers.size() & 1) || accumulated_outputs > fee_dust_threshold)
        ? pop_best_value(unused_dust_indices, tx.selected_transfers)
      : pop_best_value(unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers[idx];
    LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()));

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    // here, check if we need to sent tx and start a new one
    LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_weight_limit);
    const size_t estimated_rct_tx_weight = estimate_tx_weight(tx.selected_transfers.size(), fake_outs_count, tx.dsts.size() + 2, extra.size(), clsag);
    bool try_tx = (unused_dust_indices.empty() && unused_transfers_indices.empty()) || ( estimated_rct_tx_weight >= tx_weight_target(upper_transaction_weight_limit));

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t num_outputs = get_num_outputs(tx.dsts, m_transfers, tx.selected_transfers, oxen_tx_params);
      needed_fee = estimate_fee(tx.selected_transfers.size(), fake_outs_count, num_outputs, extra.size(), clsag, base_fee, fee_percent, fixed_fee, fee_quantization_mask);

      // add N - 1 outputs for correct initial fee estimation
      for (size_t i = 0; i < ((outputs > 1) ? outputs - 1 : outputs); ++i)
        tx.dsts.push_back(tx_destination_entry(1, address, is_subaddress));

      LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " destinations and " <<
        tx.selected_transfers.size() << " outputs");
      transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          test_tx, test_ptx, rct_config, oxen_tx_params);
      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(test_ptx.tx, txBlob.size(), base_fee, fee_percent, fixed_fee, fee_quantization_mask);
      available_for_fee = test_ptx.fee + test_ptx.change_dts.amount;
      for (auto &dt: test_ptx.dests)
        available_for_fee += dt.amount;
      LOG_PRINT_L2("Made a " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      // add last output, missed for fee estimation
      if (outputs > 1)
        tx.dsts.push_back(tx_destination_entry(1, address, is_subaddress));

      THROW_WALLET_EXCEPTION_IF(needed_fee > available_for_fee, error::wallet_internal_error, "Transaction cannot pay for itself");

      do {
        LOG_PRINT_L2("We made a tx, adjusting fee and saving it");
        // distribute total transferred amount between outputs
        uint64_t amount_transferred = available_for_fee - needed_fee;
        uint64_t dt_amount = amount_transferred / outputs;
        // residue is distributed as one atomic unit per output until it reaches zero
        uint64_t residue = amount_transferred % outputs;
        for (auto &dt: tx.dsts)
        {
          uint64_t dt_residue = 0;
          if (residue > 0)
          {
            dt_residue = 1;
            residue -= 1;
          }
          dt.amount = dt_amount + dt_residue;
        }
        transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
            test_tx, test_ptx, rct_config, oxen_tx_params);
        txBlob = t_serializable_object_to_blob(test_ptx.tx);
        needed_fee = calculate_fee(test_ptx.tx, txBlob.size(), base_fee, fee_percent, fixed_fee, fee_quantization_mask);
        LOG_PRINT_L2("Made an attempt at a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
      } while (needed_fee > test_ptx.fee);

      LOG_PRINT_L2("Made a final " << get_weight_string(test_ptx.tx, txBlob.size()) << " tx, with " << print_money(test_ptx.fee) <<
        " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

      tx.tx = test_tx;
      tx.ptx = test_ptx;
      tx.weight = get_transaction_weight(test_tx, txBlob.size());
      tx.outs = outs;
      tx.needed_fee = test_ptx.fee;
      accumulated_fee += test_ptx.fee;
      accumulated_change += test_ptx.change_dts.amount;
      if (!unused_transfers_indices.empty() || !unused_dust_indices.empty())
      {
        LOG_PRINT_L2("We have more to pay, starting another tx");
        txes.push_back(TX());
      }
    }
  }

  LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");

  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);
  for (auto &tx : txes)
  {
    // Convert burn percent into a fixed burn amount because this is the last place we can back out
    // the base fee that would apply at 100% (the actual fee here is that times the priority-based
    // fee percent)
    if (burning)
      oxen_tx_params.burn_fixed = burn_fixed + tx.needed_fee * burn_percent / fee_percent;

    cryptonote::transaction test_tx;
    pending_tx test_ptx;
    transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, tx.outs, unlock_time, tx.needed_fee, extra, test_tx, test_ptx, rct_config, oxen_tx_params);
    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.weight = get_transaction_weight(test_tx, txBlob.size());
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers[idx].amount();
    LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      " " << get_transaction_hash(tx.ptx.tx) << ": " << get_weight_string(tx.weight) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  uint64_t a = 0;
  for (const TX &tx: txes)
  {
    for (size_t idx: tx.selected_transfers)
    {
      a += m_transfers[idx].amount();
    }
    a -= tx.ptx.fee;
  }
  std::vector<cryptonote::tx_destination_entry> synthetic_dsts(1, cryptonote::tx_destination_entry("", a, address, is_subaddress));
  THROW_WALLET_EXCEPTION_IF(!sanity_check(ptx_vector, synthetic_dsts), error::wallet_internal_error, "Created transaction(s) failed sanity check");

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}
//----------------------------------------------------------------------------------------------------
void wallet2::cold_tx_aux_import(const std::vector<pending_tx> & ptx, const std::vector<std::string> & tx_device_aux)
{
  CHECK_AND_ASSERT_THROW_MES(ptx.size() == tx_device_aux.size(), "TX aux has invalid size");
  for (size_t i = 0; i < ptx.size(); ++i){
    crypto::hash txid;
    txid = get_transaction_hash(ptx[i].tx);
    set_tx_device_aux(txid, tx_device_aux[i]);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::cold_sign_tx(const std::vector<pending_tx>& ptx_vector, signed_tx_set &exported_txs, std::vector<cryptonote::address_parse_info> const &dsts_info, std::vector<std::string> & tx_device_aux)
{
  auto & hwdev = get_account().get_device();
  if (!hwdev.has_tx_cold_sign()){
    throw std::invalid_argument("Device does not support cold sign protocol");
  }

  unsigned_tx_set txs;
  for (auto &tx: ptx_vector)
  {
    txs.txes.push_back(get_construction_data_with_decrypted_short_payment_id(tx, m_account.get_device()));
  }
  txs.transfers = std::make_pair(0, m_transfers);

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");

  hw::tx_aux_data aux_data;
  hw::wallet_shim wallet_shim;
  setup_shim(&wallet_shim, this);
  aux_data.tx_recipients = dsts_info;
  aux_data.bp_version = use_fork_rules(HF_VERSION_CLSAG, 0) ? 3 : 2;
  std::optional<uint8_t> hf_version = get_hard_fork_version();
  CHECK_AND_ASSERT_THROW_MES(hf_version, "Failed to query hard fork");
  aux_data.hard_fork = *hf_version;
  dev_cold->tx_sign(&wallet_shim, txs, exported_txs, aux_data);
  tx_device_aux = aux_data.tx_device_aux;

  MDEBUG("Signed tx data from hw: " << exported_txs.ptx.size() << " transactions");
  for (auto &c_ptx: exported_txs.ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(c_ptx.tx));
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::cold_key_image_sync(uint64_t &spent, uint64_t &unspent) {
  auto & hwdev = get_account().get_device();
  CHECK_AND_ASSERT_THROW_MES(hwdev.has_ki_cold_sync(), "Device does not support cold ki sync protocol");

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");

  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
  hw::wallet_shim wallet_shim;
  setup_shim(&wallet_shim, this);

  dev_cold->ki_sync(&wallet_shim, m_transfers, ski);

  // Call rpc::IS_KEY_IMAGE_SPENT only if daemon is trusted.
  uint64_t import_res = import_key_images(ski, 0, spent, unspent, is_trusted_daemon());
  m_device_last_key_image_sync = time(NULL);

  return import_res;
}
//----------------------------------------------------------------------------------------------------
void wallet2::device_show_address(uint32_t account_index, uint32_t address_index, const std::optional<crypto::hash8> &payment_id)
{
  if (!key_on_device())
  {
    return;
  }

  auto & hwdev = get_account().get_device();
  hwdev.display_address(subaddress_index{account_index, address_index}, payment_id);
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_hard_fork_info(uint8_t version, uint64_t &earliest_height) const
{
  if (!m_node_rpc_proxy.get_earliest_height(version, earliest_height))
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, __func__);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::use_fork_rules(uint8_t version, uint64_t early_blocks) const
{
  // TODO: How to get fork rule info from light wallet node?
  if(m_light_wallet)
    return true;
  uint64_t height, earliest_height{0};
  if (!m_node_rpc_proxy.get_height(height))
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, __func__);
  if (!m_node_rpc_proxy.get_earliest_height(version, earliest_height))
    THROW_WALLET_EXCEPTION(tools::error::no_connection_to_daemon, __func__);

  bool close_enough = height >= earliest_height - early_blocks; // start using the rules that many blocks beforehand
  if (early_blocks > earliest_height) // Start using rules early if early_blocks would underflow earliest_height, in prev calc
    close_enough = true;

  if (close_enough)
    LOG_PRINT_L2("Using v" << (unsigned)version << " rules");
  else
    LOG_PRINT_L2("Not using v" << (unsigned)version << " rules");
  return close_enough;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_upper_transaction_weight_limit() const
{
  if (m_upper_transaction_weight_limit > 0)
    return m_upper_transaction_weight_limit;
  return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs(const std::function<bool(const transfer_details &td)> &f) const
{
  std::vector<size_t> outputs;
  size_t n = 0;
  for (transfer_container::const_iterator i = m_transfers.begin(); i != m_transfers.end(); ++i, ++n)
  {
    if (is_spent(*i, false))
      continue;
    if (i->m_frozen)
      continue;
    if (i->m_key_image_partial)
      continue;
    if (!is_transfer_unlocked(*i))
      continue;
    if (f(*i))
      outputs.push_back(n);
  }
  return outputs;
}
//----------------------------------------------------------------------------------------------------
std::vector<uint64_t> wallet2::get_unspent_amounts_vector(bool strict) const
{
  std::set<uint64_t> set;
  for (const auto &td: m_transfers)
  {
    if (!is_spent(td, strict) && !td.m_frozen)
      set.insert(td.is_rct() ? 0 : td.amount());
  }
  std::vector<uint64_t> vector;
  vector.reserve(set.size());
  for (const auto &i: set)
  {
    vector.push_back(i);
  }
  return vector;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct)
{
  cryptonote::rpc::GET_OUTPUT_HISTOGRAM::request req_t{};
  cryptonote::rpc::GET_OUTPUT_HISTOGRAM::response resp_t{};
  if (is_trusted_daemon())
    req_t.amounts = get_unspent_amounts_vector(false);
  req_t.min_count = count;
  req_t.max_count = 0;
  req_t.unlocked = unlocked;
  req_t.recent_cutoff = 0;
  bool r = invoke_http<rpc::GET_OUTPUT_HISTOGRAM>(req_t, resp_t);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "select_available_outputs_from_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status == rpc::STATUS_BUSY, error::daemon_busy, "get_output_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status != rpc::STATUS_OK, error::get_histogram_error, resp_t.status);

  std::set<uint64_t> mixable;
  for (const auto &i: resp_t.histogram)
  {
    mixable.insert(i.amount);
  }

  return select_available_outputs([mixable, atleast, allow_rct](const transfer_details &td) {
    if (!allow_rct && td.is_rct())
      return false;
    const uint64_t amount = td.is_rct() ? 0 : td.amount();
    if (atleast) {
      if (mixable.find(amount) != mixable.end())
        return true;
    }
    else {
      if (mixable.find(amount) == mixable.end())
        return true;
    }
    return false;
  });
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_num_rct_outputs()
{
  cryptonote::rpc::GET_OUTPUT_HISTOGRAM::request req_t{};
  cryptonote::rpc::GET_OUTPUT_HISTOGRAM::response resp_t{};
  req_t.amounts.push_back(0);
  req_t.min_count = 0;
  req_t.max_count = 0;
  req_t.unlocked = true;
  req_t.recent_cutoff = 0;
  bool r = invoke_http<rpc::GET_OUTPUT_HISTOGRAM>(req_t, resp_t);
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_num_rct_outputs");
  THROW_WALLET_EXCEPTION_IF(resp_t.status == rpc::STATUS_BUSY, error::daemon_busy, "get_output_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status != rpc::STATUS_OK, error::get_histogram_error, resp_t.status);
  THROW_WALLET_EXCEPTION_IF(resp_t.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
  THROW_WALLET_EXCEPTION_IF(resp_t.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");

  return resp_t.histogram[0].total_instances;
}
//----------------------------------------------------------------------------------------------------
const wallet2::transfer_details &wallet2::get_transfer_details(size_t idx) const
{
  THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Bad transfer index");
  return m_transfers[idx];
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_unmixable_outputs()
{
  // request all outputs with not enough available mixins
  constexpr size_t min_mixin = 9;
  return select_available_outputs_from_histogram(min_mixin + 1, false, true, false);
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_mixable_outputs()
{
  // request all outputs with at least 10nstances, so we can use mixin 9 with
  constexpr size_t min_mixin = 9;
  return select_available_outputs_from_histogram(min_mixin + 1, true, true, true);
}
//----------------------------------------------------------------------------------------------------
std::vector<wallet2::pending_tx> wallet2::create_unmixable_sweep_transactions()
{
  const auto base_fee  = get_base_fees();

  // may throw
  std::vector<size_t> unmixable_outputs = select_available_unmixable_outputs();
  size_t num_dust_outputs = unmixable_outputs.size();

  if (num_dust_outputs == 0)
  {
    return std::vector<wallet2::pending_tx>();
  }

  // split in "dust" and "non dust" to make it easier to select outputs
  std::vector<size_t> unmixable_transfer_outputs, unmixable_dust_outputs;
  for (auto n: unmixable_outputs)
  {
    if (m_transfers[n].amount() < base_fee.first)
      unmixable_dust_outputs.push_back(n);
    else
      unmixable_transfer_outputs.push_back(n);
  }

  return create_transactions_from(m_account_public_address, false, 1, unmixable_transfer_outputs, unmixable_dust_outputs, 0 /*fake_outs_count */, 0 /* unlock_time */, 1 /*priority */, std::vector<uint8_t>{});
}
//----------------------------------------------------------------------------------------------------
void wallet2::discard_unmixable_outputs()
{
  // may throw
  std::vector<size_t> unmixable_outputs = select_available_unmixable_outputs();
  for (size_t idx : unmixable_outputs)
  {
    freeze(idx);
  }
}

bool wallet2::get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const
{
  additional_tx_keys.clear();
  const std::unordered_map<crypto::hash, crypto::secret_key>::const_iterator i = m_tx_keys.find(txid);
  if (i == m_tx_keys.end())
    return false;
  tx_key = i->second;
  if (tx_key == crypto::null_skey)
    return false;
  const auto j = m_additional_tx_keys.find(txid);
  if (j != m_additional_tx_keys.end())
    additional_tx_keys = j->second;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys)
{
  bool r = get_tx_key_cached(txid, tx_key, additional_tx_keys);
  if (r)
  {
    MDEBUG("tx key cached for txid: " << txid);
    return true;
  }

  auto & hwdev = get_account().get_device();

  // So far only Cold protocol devices are supported.
  if (hwdev.device_protocol() != hw::device::PROTOCOL_COLD)
  {
    return false;
  }

  const auto tx_data_it = m_tx_device.find(txid);
  if (tx_data_it == m_tx_device.end())
  {
    MDEBUG("Aux data not found for txid: " << txid);
    return false;
  }

  auto dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev);
  CHECK_AND_ASSERT_THROW_MES(dev_cold, "Device does not implement cold signing interface");
  if (!dev_cold->is_get_tx_key_supported())
  {
    MDEBUG("get_tx_key not supported by the device");
    return false;
  }

  hw::device_cold::tx_key_data_t tx_key_data;
  dev_cold->load_tx_key_data(tx_key_data, tx_data_it->second);

  // Load missing tx prefix hash
  if (tx_key_data.tx_prefix_hash.empty())
  {
    auto res = request_transaction(txid);

    cryptonote::transaction tx;
    crypto::hash tx_hash{};
    cryptonote::blobdata tx_data;
    crypto::hash tx_prefix_hash{};
    const auto& res_tx = res.txs.front();
    bool valid_hex = string_tools::parse_hexstr_to_binbuff(*res_tx.pruned_as_hex + (res_tx.prunable_as_hex ? *res_tx.prunable_as_hex : ""s), tx_data);
    THROW_WALLET_EXCEPTION_IF(!valid_hex, error::wallet_internal_error, "Failed to parse transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx, tx_hash, tx_prefix_hash),
                              error::wallet_internal_error, "Failed to validate transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error,
                              "Failed to get the right transaction from daemon");

    tx_key_data.tx_prefix_hash = std::string(tx_prefix_hash.data, 32);
  }

  std::vector<crypto::secret_key> tx_keys;
  dev_cold->get_tx_key(tx_keys, tx_key_data, m_account.get_keys().m_view_secret_key);
  if (tx_keys.empty())
  {
    MDEBUG("Empty tx keys for txid: " << txid);
    return false;
  }

  if (tx_keys[0] == crypto::null_skey)
  {
    return false;
  }

  tx_key = tx_keys[0];
  tx_keys.erase(tx_keys.begin());
  additional_tx_keys = tx_keys;
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys)
{
  // fetch tx from daemon and check if secret keys agree with corresponding public keys
  auto res = request_transaction(txid);
  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error,
      "Failed to get transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "txid mismatch");
  std::vector<tx_extra_field> tx_extra_fields;
  THROW_WALLET_EXCEPTION_IF(!parse_tx_extra(tx.extra, tx_extra_fields), error::wallet_internal_error, "Transaction extra has unsupported format");
  tx_extra_pub_key pub_key_field;
  bool found = false;
  size_t index = 0;
  while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, index++))
  {
    crypto::public_key calculated_pub_key;
    crypto::secret_key_to_public_key(tx_key, calculated_pub_key);
    if (calculated_pub_key == pub_key_field.pub_key)
    {
      found = true;
      break;
    }
  }
  THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error, "Given tx secret key doesn't agree with the tx public key in the blockchain");
  tx_extra_additional_pub_keys additional_tx_pub_keys;
  find_tx_extra_field_by_type(tx_extra_fields, additional_tx_pub_keys);
  THROW_WALLET_EXCEPTION_IF(additional_tx_keys.size() != additional_tx_pub_keys.data.size(), error::wallet_internal_error, "The number of additional tx secret keys doesn't agree with the number of additional tx public keys in the blockchain" );
  m_tx_keys.insert(std::make_pair(txid, tx_key));
  m_additional_tx_keys.insert(std::make_pair(txid, additional_tx_keys));
}

//----------------------------------------------------------------------------------------------------
std::string wallet2::get_spend_proof(const crypto::hash &txid, std::string_view message)
{
  THROW_WALLET_EXCEPTION_IF(m_watch_only, error::wallet_internal_error,
    "get_spend_proof requires spend secret key and is not available for a watch-only wallet");

  // fetch tx from daemon
  auto res = request_transaction(txid);

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error, "Failed to get tx from daemon");

  std::vector<std::vector<crypto::signature>> signatures;

  // get signature prefix hash
  std::string sig_prefix_data = tools::copy_guts(txid);
  sig_prefix_data += message;
  crypto::hash sig_prefix_hash;
  crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = std::get_if<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;

    // check if the key image belongs to us
    const auto found = m_key_images.find(in_key->k_image);
    if(found == m_key_images.end())
    {
      THROW_WALLET_EXCEPTION_IF(i > 0, error::wallet_internal_error, "subset of key images belong to us, very weird!");
      THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "This tx wasn't generated by this wallet!");
    }

    // derive the real output keypair
    const transfer_details& in_td = m_transfers[found->second];
    const txout_to_key* const in_tx_out_pkey = std::get_if<txout_to_key>(std::addressof(in_td.m_tx.vout[in_td.m_internal_output_index].target));
    THROW_WALLET_EXCEPTION_IF(in_tx_out_pkey == nullptr, error::wallet_internal_error, "Output is not txout_to_key");
    const crypto::public_key in_tx_pub_key = get_tx_pub_key_from_extra(in_td.m_tx, in_td.m_pk_index);
    const std::vector<crypto::public_key> in_additionakl_tx_pub_keys = get_additional_tx_pub_keys_from_extra(in_td.m_tx);
    keypair in_ephemeral;
    crypto::key_image in_img;
    THROW_WALLET_EXCEPTION_IF(!generate_key_image_helper(m_account.get_keys(), m_subaddresses, in_tx_out_pkey->key, in_tx_pub_key, in_additionakl_tx_pub_keys, in_td.m_internal_output_index, in_ephemeral, in_img, m_account.get_device()),
      error::wallet_internal_error, "failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(in_key->k_image != in_img, error::wallet_internal_error, "key image mismatch");

    // get output pubkeys in the ring
    const std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
    const size_t ring_size = in_key->key_offsets.size();
    THROW_WALLET_EXCEPTION_IF(absolute_offsets.size() != ring_size, error::wallet_internal_error, "absolute offsets size is wrong");
    rpc::GET_OUTPUTS_BIN::request req{};
    req.outputs.resize(ring_size);
    for (size_t j = 0; j < ring_size; ++j)
    {
      req.outputs[j].amount = in_key->amount;
      req.outputs[j].index = absolute_offsets[j];
    }
    rpc::GET_OUTPUTS_BIN::response res{};
    bool r = invoke_http<rpc::GET_OUTPUTS_BIN>(req, res);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::wallet_internal_error, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.outs.size() != ring_size, error::wallet_internal_error,
      "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
      std::to_string(res.outs.size()) + ", expected " +  std::to_string(ring_size));

    // copy pubkey pointers
    std::vector<const crypto::public_key*> p_output_keys;
    p_output_keys.reserve(res.outs.size());
    for (auto& out : res.outs)
      p_output_keys.push_back(&out.key);

    // figure out real output index and secret key
    size_t sec_index = -1;
    for (size_t j = 0; j < ring_size; ++j)
    {
      if (res.outs[j].key == in_ephemeral.pub)
      {
        sec_index = j;
        break;
      }
    }
    THROW_WALLET_EXCEPTION_IF(sec_index >= ring_size, error::wallet_internal_error, "secret index not found");

    // generate ring sig for this input
    auto& sigs = signatures.emplace_back(in_key->key_offsets.size());
    crypto::generate_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, in_ephemeral.sec, sec_index, sigs.data());
  }

  std::string sig_str{SPEND_PROOF_MAGIC};
  for (const std::vector<crypto::signature>& ring_sig : signatures)
    for (const crypto::signature& sig : ring_sig)
       sig_str += tools::base58::encode(tools::view_guts(sig));
  return sig_str;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::check_spend_proof(const crypto::hash &txid, std::string_view message, std::string_view sig_str)
{
  THROW_WALLET_EXCEPTION_IF(!tools::starts_with(sig_str, SPEND_PROOF_MAGIC),
      error::wallet_internal_error, "Signature header check error");
  sig_str.remove_prefix(SPEND_PROOF_MAGIC.size());

  // fetch tx from daemon
  auto res = request_transaction(txid);

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(res.txs[0], tx, tx_hash), error::wallet_internal_error, "failed to get tx from daemon");

  // check signature size
  size_t num_sigs = 0;
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = std::get_if<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key != nullptr)
      num_sigs += in_key->key_offsets.size();
  }
  std::vector<std::vector<crypto::signature>> signatures = { std::vector<crypto::signature>(1) };
  const size_t sig_len = tools::base58::encode(tools::view_guts(signatures[0][0])).size();
  if( sig_str.size() != num_sigs * sig_len ) {
    return false;
  }

  // decode base58
  signatures.clear();
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = std::get_if<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;
    signatures.resize(signatures.size() + 1);
    signatures.back().resize(in_key->key_offsets.size());
    for (size_t j = 0; j < in_key->key_offsets.size(); ++j)
    {
      std::string sig_decoded;
      THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(0, sig_len), sig_decoded), error::wallet_internal_error, "Signature decoding error");
      THROW_WALLET_EXCEPTION_IF(sizeof(crypto::signature) != sig_decoded.size(), error::wallet_internal_error, "Signature decoding error");
      memcpy(&signatures.back()[j], sig_decoded.data(), sizeof(crypto::signature));
      sig_str.remove_prefix(sig_len);
    }
  }

  // get signature prefix hash
  std::string sig_prefix_data = tools::copy_guts(txid);
  sig_prefix_data += message;
  crypto::hash sig_prefix_hash;
  crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

  std::vector<std::vector<crypto::signature>>::const_iterator sig_iter = signatures.cbegin();
  for(size_t i = 0; i < tx.vin.size(); ++i)
  {
    const txin_to_key* const in_key = std::get_if<txin_to_key>(std::addressof(tx.vin[i]));
    if (in_key == nullptr)
      continue;

    // get output pubkeys in the ring
    rpc::GET_OUTPUTS_BIN::request req{};
    const std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
    req.outputs.resize(absolute_offsets.size());
    for (size_t j = 0; j < absolute_offsets.size(); ++j)
    {
      req.outputs[j].amount = in_key->amount;
      req.outputs[j].index = absolute_offsets[j];
    }
    rpc::GET_OUTPUTS_BIN::response res{};
    bool r = invoke_http<rpc::GET_OUTPUTS_BIN>(req, res);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.status == rpc::STATUS_BUSY, error::daemon_busy, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.status != rpc::STATUS_OK, error::wallet_internal_error, "get_outs.bin");
    THROW_WALLET_EXCEPTION_IF(res.outs.size() != req.outputs.size(), error::wallet_internal_error,
      "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
      std::to_string(res.outs.size()) + ", expected " +  std::to_string(req.outputs.size()));

    // copy pointers
    std::vector<const crypto::public_key *> p_output_keys;
    for (const auto& out : res.outs)
      p_output_keys.push_back(&out.key);

    // check this ring
    if (!crypto::check_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, sig_iter->data()))
      return false;
    ++sig_iter;
  }
  THROW_WALLET_EXCEPTION_IF(sig_iter != signatures.cend(), error::wallet_internal_error, "Signature iterator didn't reach the end");
  return true;
}
//----------------------------------------------------------------------------------------------------

void wallet2::check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  crypto::key_derivation derivation;
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(address.m_view_public_key, tx_key, derivation), error::wallet_internal_error,
    "Failed to generate key derivation from supplied parameters");

  std::vector<crypto::key_derivation> additional_derivations;
  additional_derivations.resize(additional_tx_keys.size());
  for (size_t i = 0; i < additional_tx_keys.size(); ++i)
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(address.m_view_public_key, additional_tx_keys[i], additional_derivations[i]), error::wallet_internal_error,
      "Failed to generate key derivation from supplied parameters");

  check_tx_key_helper(txid, derivation, additional_derivations, address, received, in_pool, confirmations);
}

void wallet2::check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received) const
{
  received = 0;

  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    const cryptonote::txout_to_key* const out_key = std::get_if<cryptonote::txout_to_key>(std::addressof(tx.vout[n].target));
    if (!out_key)
      continue;

    crypto::public_key derived_out_key;
    bool r = crypto::derive_public_key(derivation, n, address.m_spend_public_key, derived_out_key);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
    bool found = out_key->key == derived_out_key;
    crypto::key_derivation found_derivation = derivation;
    if (!found && !additional_derivations.empty())
    {
      r = crypto::derive_public_key(additional_derivations[n], n, address.m_spend_public_key, derived_out_key);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to derive public key");
      found = out_key->key == derived_out_key;
      found_derivation = additional_derivations[n];
    }

    if (found)
    {
      uint64_t amount;
      if (tx.version == txversion::v1 || tx.rct_signatures.type == rct::RCTType::Null)
      {
        amount = tx.vout[n].amount;
      }
      else
      {
        crypto::secret_key scalar1;
        crypto::derivation_to_scalar(found_derivation, n, scalar1);
        rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
        rct::ecdhDecode(ecdh_info, rct::sk2rct(scalar1), tools::equals_any(tx.rct_signatures.type, rct::RCTType::Bulletproof2, rct::RCTType::CLSAG));
        const rct::key C = tx.rct_signatures.outPk[n].mask;
        rct::key Ctmp;
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.mask.bytes) != 0, error::wallet_internal_error, "Bad ECDH input mask");
        THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.amount.bytes) != 0, error::wallet_internal_error, "Bad ECDH input amount");
        rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
        if (rct::equalKeys(C, Ctmp))
          amount = rct::h2d(ecdh_info.amount);
        else
          amount = 0;
      }
      received += amount;
    }
  }
}

void wallet2::check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  auto res = request_transaction(txid);
  cryptonote::transaction tx;
  crypto::hash tx_hash;
  bool ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
  THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error,
    "Failed to get the right transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(!additional_derivations.empty() && additional_derivations.size() != tx.vout.size(), error::wallet_internal_error,
    "The size of additional derivations is wrong");

  check_tx_key_helper(tx, derivation, additional_derivations, address, received);

  in_pool = res.txs.front().in_pool;
  confirmations = 0;
  if (!in_pool)
  {
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (err.empty())
      confirmations = bc_height - res.txs.front().block_height;
  }
}

std::string wallet2::get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message)
{
    // fetch tx pubkey from the daemon
    auto res = request_transaction(txid);

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    bool ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
    THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    crypto::secret_key tx_key = crypto::null_skey;
    std::vector<crypto::secret_key> additional_tx_keys;
    const bool is_out = m_subaddresses.count(address.m_spend_public_key) == 0;
    if (is_out)
    {
      THROW_WALLET_EXCEPTION_IF(!get_tx_key(txid, tx_key, additional_tx_keys), error::wallet_internal_error, "Tx secret key wasn't found in the wallet file.");
    }

    return get_tx_proof(tx, tx_key, additional_tx_keys, address, is_subaddress, message);
}

std::string wallet2::get_tx_proof(const cryptonote::transaction &tx, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message) const
{
  hw::device &hwdev = m_account.get_device();
  rct::key  aP;
  // determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
  const bool is_out = m_subaddresses.count(address.m_spend_public_key) == 0;

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data = tools::copy_guts(txid);
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  std::vector<crypto::public_key> shared_secret;
  std::vector<crypto::signature> sig;
  std::string sig_str;
  if (is_out)
  {
    const size_t num_sigs = 1 + additional_tx_keys.size();
    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);

    hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(tx_key));
    shared_secret[0] = rct::rct2pk(aP);
    crypto::public_key tx_pub_key;
    if (is_subaddress)
    {
      hwdev.scalarmultKey(aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(tx_key));
      tx_pub_key = rct2pk(aP);
      hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], tx_key, sig[0]);
    }
    else
    {
      hwdev.secret_key_to_public_key(tx_key, tx_pub_key);
      hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[0], tx_key, sig[0]);
    }
    for (size_t i = 1; i < num_sigs; ++i)
    {
      hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
      shared_secret[i] = rct::rct2pk(aP);
      if (is_subaddress)
      {
        hwdev.scalarmultKey(aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
        tx_pub_key = rct2pk(aP);
        hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[i], additional_tx_keys[i - 1], sig[i]);
      }
      else
      {
        hwdev.secret_key_to_public_key(additional_tx_keys[i - 1], tx_pub_key);
        hwdev.generate_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[i], additional_tx_keys[i - 1], sig[i]);
      }
    }
    sig_str = OUTBOUND_PROOF_MAGIC;
  }
  else
  {
    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    const size_t num_sigs = 1 + additional_tx_pub_keys.size();
    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);

    const crypto::secret_key& a = m_account.get_keys().m_view_secret_key;
    hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
    shared_secret[0] =  rct2pk(aP);
    if (is_subaddress)
    {
      hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, address.m_spend_public_key, shared_secret[0], a, sig[0]);
    }
    else
    {
      hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, std::nullopt, shared_secret[0], a, sig[0]);
    }
    for (size_t i = 1; i < num_sigs; ++i)
    {
      hwdev.scalarmultKey(aP,rct::pk2rct(additional_tx_pub_keys[i - 1]), rct::sk2rct(a));
      shared_secret[i] = rct2pk(aP);
      if (is_subaddress)
      {
        hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], address.m_spend_public_key, shared_secret[i], a, sig[i]);
      }
      else
      {
        hwdev.generate_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i - 1], std::nullopt, shared_secret[i], a, sig[i]);
      }
    }
    sig_str = INBOUND_PROOF_MAGIC;
  }
  const size_t num_sigs = shared_secret.size();

  // check if this address actually received any funds
  crypto::key_derivation derivation;
  THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
  std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
  for (size_t i = 1; i < num_sigs; ++i)
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]), error::wallet_internal_error, "Failed to generate key derivation");
  uint64_t received;
  check_tx_key_helper(tx, derivation, additional_derivations, address, received);
  THROW_WALLET_EXCEPTION_IF(!received, error::wallet_internal_error, tr("No funds received in this tx."));

  // concatenate all signature strings
  for (size_t i = 0; i < num_sigs; ++i)
  {
    sig_str += tools::base58::encode(tools::view_guts(shared_secret[i]));
    sig_str += tools::base58::encode(tools::view_guts(sig[i]));
  }
  return sig_str;
}

bool wallet2::check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message, std::string_view sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
  // fetch tx pubkey from the daemon
  auto res = request_transaction(txid);

  cryptonote::transaction tx;
  crypto::hash tx_hash;
  bool ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
  THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");
  THROW_WALLET_EXCEPTION_IF(tx_hash != txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

  if (!check_tx_proof(tx, address, is_subaddress, message, sig_str, received))
    return false;

  in_pool = res.txs.front().in_pool;
  confirmations = 0;
  if (!in_pool)
  {
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (err.empty())
      confirmations = bc_height - res.txs.front().block_height;
  }

  return true;
}

bool wallet2::check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message, std::string_view sig_str, uint64_t &received) const
{
  bool is_out;
  if (tools::starts_with(sig_str, OUTBOUND_PROOF_MAGIC)) {
    is_out = true;
    sig_str.remove_prefix(OUTBOUND_PROOF_MAGIC.size());
  } else if (tools::starts_with(sig_str, INBOUND_PROOF_MAGIC)) {
    is_out = false;
    sig_str.remove_prefix(INBOUND_PROOF_MAGIC.size());
  } else {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "Signature header check error");
  }

  // decode base58
  std::vector<crypto::public_key> shared_secret(1);
  std::vector<crypto::signature> sig(1);
  const size_t pk_len = tools::base58::encode(tools::view_guts(shared_secret[0])).size();
  const size_t sig_len = tools::base58::encode(tools::view_guts(sig[0])).size();
  const size_t num_sigs = sig_str.size() / (pk_len + sig_len);
  THROW_WALLET_EXCEPTION_IF(sig_str.size() % (pk_len + sig_len), error::wallet_internal_error,
    "Wrong signature size");
  shared_secret.resize(num_sigs);
  sig.resize(num_sigs);
  std::string pk_decoded, sig_decoded;
  for (size_t i = 0; i < num_sigs; ++i)
  {
    pk_decoded.clear();
    sig_decoded.clear();
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(0, pk_len), pk_decoded), error::wallet_internal_error,
      "Signature decoding error");
    sig_str.remove_prefix(pk_len);
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(0, sig_len), sig_decoded), error::wallet_internal_error,
      "Signature decoding error");
    sig_str.remove_prefix(sig_len);
    THROW_WALLET_EXCEPTION_IF(sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::signature) != sig_decoded.size(), error::wallet_internal_error,
      "Signature decoding error");
    memcpy(&shared_secret[i], pk_decoded.data(), sizeof(crypto::public_key));
    memcpy(&sig[i], sig_decoded.data(), sizeof(crypto::signature));
  }

  crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
  THROW_WALLET_EXCEPTION_IF(tx_pub_key == null_pkey, error::wallet_internal_error, "Tx pubkey was not found");

  std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
  THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.size() + 1 != num_sigs, error::wallet_internal_error, "Signature size mismatch with additional tx pubkeys");

  const crypto::hash txid = cryptonote::get_transaction_hash(tx);
  std::string prefix_data = tools::copy_guts(txid);
  prefix_data += message;
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // check signature
  std::vector<int> good_signature(num_sigs, 0);
  if (is_out)
  {
    good_signature[0] = is_subaddress ?
      crypto::check_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, address.m_spend_public_key, shared_secret[0], sig[0]) :
      crypto::check_tx_proof(prefix_hash, tx_pub_key, address.m_view_public_key, std::nullopt, shared_secret[0], sig[0]);

    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      good_signature[i + 1] = is_subaddress ?
        crypto::check_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, address.m_spend_public_key, shared_secret[i + 1], sig[i + 1]) :
        crypto::check_tx_proof(prefix_hash, additional_tx_pub_keys[i], address.m_view_public_key, std::nullopt, shared_secret[i + 1], sig[i + 1]);
    }
  }
  else
  {
    good_signature[0] = is_subaddress ?
      crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, address.m_spend_public_key, shared_secret[0], sig[0]) :
      crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, std::nullopt, shared_secret[0], sig[0]);

    for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
    {
      good_signature[i + 1] = is_subaddress ?
        crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], address.m_spend_public_key, shared_secret[i + 1], sig[i + 1]) :
        crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[i], std::nullopt, shared_secret[i + 1], sig[i + 1]);
    }
  }

  if (std::any_of(good_signature.begin(), good_signature.end(), [](int i) { return i > 0; }))
  {
    // obtain key derivation by multiplying scalar 1 to the shared secret
    crypto::key_derivation derivation;
    if (good_signature[0])
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");

    std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
    for (size_t i = 1; i < num_sigs; ++i)
      if (good_signature[i])
        THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]), error::wallet_internal_error, "Failed to generate key derivation");

    check_tx_key_helper(tx, derivation, additional_derivations, address, received);
    return true;
  }
  return false;
}

std::string wallet2::get_reserve_proof(const std::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, std::string prefix_data)
{
  THROW_WALLET_EXCEPTION_IF(m_watch_only || m_multisig, error::wallet_internal_error, "Reserve proof can only be generated by a full wallet");
  THROW_WALLET_EXCEPTION_IF(balance_all(true) == 0, error::wallet_internal_error, "Zero balance");
  THROW_WALLET_EXCEPTION_IF(account_minreserve && balance(account_minreserve->first, true) < account_minreserve->second, error::wallet_internal_error,
    "Not enough balance in this account for the requested minimum reserve amount");

  // determine which outputs to include in the proof
  std::vector<size_t> selected_transfers;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[i];
    if (!is_spent(td, true) && !td.m_frozen && (!account_minreserve || account_minreserve->first == td.m_subaddr_index.major))
      selected_transfers.push_back(i);
  }

  if (account_minreserve)
  {
    THROW_WALLET_EXCEPTION_IF(account_minreserve->second == 0, error::wallet_internal_error, "Proved amount must be greater than 0");
    // minimize the number of outputs included in the proof, by only picking the N largest outputs that can cover the requested min reserve amount
    std::sort(selected_transfers.begin(), selected_transfers.end(), [&](const size_t a, const size_t b)
      { return m_transfers[a].amount() > m_transfers[b].amount(); });
    while (selected_transfers.size() >= 2 && m_transfers[selected_transfers[1]].amount() >= account_minreserve->second)
      selected_transfers.erase(selected_transfers.begin());
    size_t sz = 0;
    uint64_t total = 0;
    while (total < account_minreserve->second)
    {
      total += m_transfers[selected_transfers[sz]].amount();
      ++sz;
    }
    selected_transfers.resize(sz);
  }

  // compute signature prefix hash
  prefix_data += tools::view_guts(m_account.get_keys().m_account_address);
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    prefix_data += tools::view_guts(m_transfers[selected_transfers[i]].m_key_image);
  }
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // generate proof entries
  std::vector<reserve_proof_entry> proofs(selected_transfers.size());
  std::unordered_set<cryptonote::subaddress_index> subaddr_indices = { {0,0} };
  for (size_t i = 0; i < selected_transfers.size(); ++i)
  {
    const transfer_details &td = m_transfers[selected_transfers[i]];
    reserve_proof_entry& proof = proofs[i];
    proof.txid = td.m_txid;
    proof.index_in_tx = td.m_internal_output_index;
    proof.key_image = td.m_key_image;
    subaddr_indices.insert(td.m_subaddr_index);

    // get tx pub key
    const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    // determine which tx pub key was used for deriving the output key
    const crypto::public_key *tx_pub_key_used = &tx_pub_key;
    for (int i = 0; i < 2; ++i)
    {
      proof.shared_secret = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(*tx_pub_key_used), rct::sk2rct(m_account.get_keys().m_view_secret_key)));
      crypto::key_derivation derivation;
      THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation),
        error::wallet_internal_error, "Failed to generate key derivation");
      crypto::public_key subaddress_spendkey;
      THROW_WALLET_EXCEPTION_IF(!derive_subaddress_public_key(td.get_public_key(), derivation, proof.index_in_tx, subaddress_spendkey),
        error::wallet_internal_error, "Failed to derive subaddress public key");
      if (m_subaddresses.count(subaddress_spendkey) == 1)
        break;
      THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.empty(), error::wallet_internal_error,
        "Normal tx pub key doesn't derive the expected output, while the additional tx pub keys are empty");
      THROW_WALLET_EXCEPTION_IF(i == 1, error::wallet_internal_error,
        "Neither normal tx pub key nor additional tx pub key derive the expected output key");
      tx_pub_key_used = &additional_tx_pub_keys[proof.index_in_tx];
    }

    // generate signature for shared secret
    crypto::generate_tx_proof(prefix_hash, m_account.get_keys().m_account_address.m_view_public_key, *tx_pub_key_used, std::nullopt, proof.shared_secret, m_account.get_keys().m_view_secret_key, proof.shared_secret_sig);

    // derive ephemeral secret key
    crypto::key_image ki;
    cryptonote::keypair ephemeral;
    const bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, td.get_public_key(), tx_pub_key,  additional_tx_pub_keys, td.m_internal_output_index, ephemeral, ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(ephemeral.pub != td.get_public_key(), error::wallet_internal_error, "Derived public key doesn't agree with the stored one");

    // generate signature for key image
    crypto::generate_key_image_signature(td.m_key_image, ephemeral.pub, ephemeral.sec, proof.key_image_sig);
  }

  // collect all subaddress spend keys that received those outputs and generate their signatures
  std::unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
  for (const cryptonote::subaddress_index &index : subaddr_indices)
  {
    crypto::secret_key subaddr_spend_skey = m_account.get_keys().m_spend_secret_key;
    if (!index.is_zero())
    {
      crypto::secret_key m = m_account.get_device().get_subaddress_secret_key(m_account.get_keys().m_view_secret_key, index);
      crypto::secret_key tmp = subaddr_spend_skey;
      sc_add((unsigned char*)&subaddr_spend_skey, (unsigned char*)&m, (unsigned char*)&tmp);
    }
    crypto::public_key subaddr_spend_pkey;
    secret_key_to_public_key(subaddr_spend_skey, subaddr_spend_pkey);
    crypto::generate_signature(prefix_hash, subaddr_spend_pkey, subaddr_spend_skey, subaddr_spendkeys[subaddr_spend_pkey]);
  }

  // serialize & encode
  std::ostringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  ar << proofs << subaddr_spendkeys;
  std::string result{RESERVE_PROOF_MAGIC};
  result += tools::base58::encode(oss.str());
  return result;
}

bool wallet2::check_reserve_proof(const cryptonote::account_public_address &address, std::string_view message, std::string_view sig_str, uint64_t &total, uint64_t &spent)
{
  rpc::version_t rpc_version;
  THROW_WALLET_EXCEPTION_IF(!check_connection(&rpc_version), error::wallet_internal_error, "Failed to connect to daemon: " + get_daemon_address());
  THROW_WALLET_EXCEPTION_IF((rpc_version < rpc::version_t{1, 0}), error::wallet_internal_error, "Daemon RPC version is too old");

  THROW_WALLET_EXCEPTION_IF(tools::starts_with(sig_str, RESERVE_PROOF_MAGIC), error::wallet_internal_error,
    "Signature header check error");
  sig_str.remove_prefix(RESERVE_PROOF_MAGIC.size());

  std::string sig_decoded;
  THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str, sig_decoded), error::wallet_internal_error,
    "Signature decoding error");

  std::istringstream iss(sig_decoded);
  boost::archive::portable_binary_iarchive ar(iss);
  std::vector<reserve_proof_entry> proofs;
  std::unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
  ar >> proofs >> subaddr_spendkeys;

  THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(address.m_spend_public_key) == 0, error::wallet_internal_error,
    "The given address isn't found in the proof");

  std::vector<std::string> txids_hex;
  txids_hex.reserve(proofs.size());

  // compute signature prefix hash
  std::string prefix_data;
  prefix_data.reserve(message.size() + sizeof(cryptonote::account_public_address) + proofs.size() * sizeof(crypto::key_image));
  prefix_data.append(message);

  prefix_data += tools::view_guts(address);
  for (const auto& proof : proofs)
  {
    prefix_data += tools::view_guts(proof.key_image);
    txids_hex.push_back(tools::type_to_hex(proof.txid));
  }
  crypto::hash prefix_hash;
  crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

  // fetch txes from daemon
  auto gettx_res = request_transactions(std::move(txids_hex));

  // check spent status
  rpc::IS_KEY_IMAGE_SPENT::request kispent_req{};
  rpc::IS_KEY_IMAGE_SPENT::response kispent_res{};
  for (size_t i = 0; i < proofs.size(); ++i)
    kispent_req.key_images.push_back(tools::type_to_hex(proofs[i].key_image));
  bool ok = invoke_http<rpc::IS_KEY_IMAGE_SPENT>(kispent_req, kispent_res);
  THROW_WALLET_EXCEPTION_IF(!ok || kispent_res.spent_status.size() != proofs.size(),
    error::wallet_internal_error, "Failed to get key image spent status from daemon");

  total = spent = 0;
  for (size_t i = 0; i < proofs.size(); ++i)
  {
    const reserve_proof_entry& proof = proofs[i];
    THROW_WALLET_EXCEPTION_IF(gettx_res.txs[i].in_pool, error::wallet_internal_error, "Tx is unconfirmed");

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    ok = get_pruned_tx(gettx_res.txs[i], tx, tx_hash);
    THROW_WALLET_EXCEPTION_IF(!ok, error::wallet_internal_error, "Failed to parse transaction from daemon");

    THROW_WALLET_EXCEPTION_IF(tx_hash != proof.txid, error::wallet_internal_error, "Failed to get the right transaction from daemon");

    THROW_WALLET_EXCEPTION_IF(proof.index_in_tx >= tx.vout.size(), error::wallet_internal_error, "index_in_tx is out of bound");

    const cryptonote::txout_to_key* const out_key = std::get_if<cryptonote::txout_to_key>(std::addressof(tx.vout[proof.index_in_tx].target));
    THROW_WALLET_EXCEPTION_IF(!out_key, error::wallet_internal_error, "Output key wasn't found");

    // TODO(oxen): We should make a catch-all function that gets all the public
    // keys out into an array and iterate through all insteaad of multiple code
    // paths for additional keys and the main public key storage which can then
    // have multiple keys ..

    // But for now, the minimal fix to avoid re-architecting everything prematurely.

    // check singature for shared secret
    const bool is_miner = tx.vin.size() == 1 && std::holds_alternative<cryptonote::txin_gen>(tx.vin[0]);
    if (is_miner)
    {
      // NOTE(oxen): The service node reward is added as a duplicate TX public
      // key instead of into the additional public key, so we need to check upto
      // 2 public keys when we're checking miner transactions.

      // TODO(oxen): This might still be broken for governance rewards since it uses a deterministic key iirc.
      crypto::public_key main_keys[2] = {
          get_tx_pub_key_from_extra(tx, 0),
          get_tx_pub_key_from_extra(tx, 1),
      };

      for (crypto::public_key const &tx_pub_key : main_keys)
      {
        ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, std::nullopt, proof.shared_secret, proof.shared_secret_sig);
        if (ok) break;
      }
    }
    else
    {
      const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
      THROW_WALLET_EXCEPTION_IF(tx_pub_key == crypto::null_pkey, error::wallet_internal_error, "The tx public key isn't found");
      ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, tx_pub_key, std::nullopt, proof.shared_secret, proof.shared_secret_sig);
    }

    if (!ok)
    {
      const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
      if (additional_tx_pub_keys.size() == tx.vout.size())
        ok = crypto::check_tx_proof(prefix_hash, address.m_view_public_key, additional_tx_pub_keys[proof.index_in_tx], std::nullopt, proof.shared_secret, proof.shared_secret_sig);
    }

    if (!ok)
      return false;

    // check signature for key image
    ok = crypto::check_key_image_signature(proof.key_image, out_key->key, proof.key_image_sig);
    if (!ok)
      return false;

    // check if the address really received the fund
    crypto::key_derivation derivation;
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation), error::wallet_internal_error, "Failed to generate key derivation");
    crypto::public_key subaddr_spendkey;
    crypto::derive_subaddress_public_key(out_key->key, derivation, proof.index_in_tx, subaddr_spendkey);
    THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(subaddr_spendkey) == 0, error::wallet_internal_error,
      "The address doesn't seem to have received the fund");

    // check amount
    uint64_t amount = tx.vout[proof.index_in_tx].amount;
    if (amount == 0)
    {
      // decode rct
      crypto::secret_key shared_secret;
      crypto::derivation_to_scalar(derivation, proof.index_in_tx, shared_secret);
      rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[proof.index_in_tx];
      rct::ecdhDecode(ecdh_info, rct::sk2rct(shared_secret), tools::equals_any(tx.rct_signatures.type, rct::RCTType::Bulletproof2, rct::RCTType::CLSAG));
      amount = rct::h2d(ecdh_info.amount);
    }
    total += amount;
    if (kispent_res.spent_status[i])
      spent += amount;
  }

  // check signatures for all subaddress spend keys
  for (const auto &i : subaddr_spendkeys)
  {
    if (!crypto::check_signature(prefix_hash, i.first, i.second))
      return false;
  }
  return true;
}

const fs::path& wallet2::get_wallet_file() const
{
  return m_wallet_file;
}

const fs::path& wallet2::get_keys_file() const
{
  return m_keys_file;
}

std::string wallet2::get_daemon_address() const
{
  return m_http_client.get_base_url();
}

uint64_t wallet2::get_daemon_blockchain_height(std::string& err) const
{
  uint64_t height;

  if (!m_node_rpc_proxy.get_height(height))
  {
    err = "daemon error";
    return 0;
  }

  err.clear();
  return height;
}

uint64_t wallet2::get_daemon_blockchain_target_height(std::string& err)
{
  uint64_t target_height = 0;
  if (!m_node_rpc_proxy.get_target_height(target_height))
  {
    err = "daemon error";
    return 0;
  }
  err.clear();
  return target_height;
}

uint64_t wallet2::get_approximate_blockchain_height() const
{
  const auto& netconf = cryptonote::get_config(m_nettype);
  const time_t since_ts = time(nullptr) - netconf.HEIGHT_ESTIMATE_TIMESTAMP;
  uint64_t approx_blockchain_height = netconf.HEIGHT_ESTIMATE_HEIGHT + (since_ts > 0 ? (uint64_t)since_ts / tools::to_seconds(TARGET_BLOCK_TIME) : 0) - BLOCKS_EXPECTED_IN_DAYS(7); // subtract a week's worth of blocks to be conservative
  LOG_PRINT_L2("Calculated blockchain height: " << approx_blockchain_height);
  return approx_blockchain_height;
}

std::vector<rpc::GET_SERVICE_NODES::response::entry> wallet2::list_current_stakes()
{

  std::vector<rpc::GET_SERVICE_NODES::response::entry> service_node_states;

  auto [success, all_nodes] = this->get_all_service_nodes();
  if (!success)
  {
    return service_node_states;
  }

  cryptonote::account_public_address const primary_address = this->get_address();
  for (rpc::GET_SERVICE_NODES::response::entry const &node_info : all_nodes)
  {
    for (const auto& contributor : node_info.contributors)
    {
      address_parse_info address_info = {};
      if (!cryptonote::get_account_address_from_str(address_info, this->nettype(), contributor.address))
      {
        continue;
      }

      if (primary_address != address_info.address)
        continue;

      service_node_states.push_back(node_info);
    }
  }

  return service_node_states;
}

void wallet2::set_ons_cache_record(wallet2::ons_detail detail)
{
  ons_records_cache[detail.hashed_name] = std::move(detail);
}

void wallet2::delete_ons_cache_record(const std::string& hashed_name)
{
  ons_records_cache.erase(hashed_name);
}

std::unordered_map<std::string, wallet2::ons_detail> wallet2::get_ons_cache()
{
  return ons_records_cache;
}

void wallet2::set_tx_note(const crypto::hash &txid, const std::string &note)
{
  m_tx_notes[txid] = note;
}

std::string wallet2::get_tx_note(const crypto::hash &txid) const
{
  std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_notes.find(txid);
  if (i == m_tx_notes.end())
    return std::string();
  return i->second;
}

void wallet2::set_tx_device_aux(const crypto::hash &txid, const std::string &aux)
{
  m_tx_device[txid] = aux;
}

std::string wallet2::get_tx_device_aux(const crypto::hash &txid) const
{
  std::unordered_map<crypto::hash, std::string>::const_iterator i = m_tx_device.find(txid);
  if (i == m_tx_device.end())
    return std::string();
  return i->second;
}

void wallet2::set_attribute(const std::string &key, const std::string &value)
{
  m_attributes[key] = value;
}

bool wallet2::get_attribute(const std::string &key, std::string &value) const
{
  std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
  if (i == m_attributes.end())
    return false;
  value = i->second;
  return true;
}

void wallet2::set_description(const std::string &description)
{
  set_attribute(ATTRIBUTE_DESCRIPTION, description);
}

std::string wallet2::get_description() const
{
  std::string s;
  if (get_attribute(ATTRIBUTE_DESCRIPTION, s))
    return s;
  return "";
}

const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& wallet2::get_account_tags()
{
  // ensure consistency
  if (m_account_tags.second.size() != get_num_subaddress_accounts())
    m_account_tags.second.resize(get_num_subaddress_accounts(), "");
  for (const std::string& tag : m_account_tags.second)
  {
    if (!tag.empty() && m_account_tags.first.count(tag) == 0)
      m_account_tags.first.insert({tag, ""});
  }
  for (auto i = m_account_tags.first.begin(); i != m_account_tags.first.end(); )
  {
    if (std::find(m_account_tags.second.begin(), m_account_tags.second.end(), i->first) == m_account_tags.second.end())
      i = m_account_tags.first.erase(i);
    else
      ++i;
  }
  return m_account_tags;
}

void wallet2::set_account_tag(const std::set<uint32_t> &account_indices, const std::string& tag)
{
  for (uint32_t account_index : account_indices)
  {
    THROW_WALLET_EXCEPTION_IF(account_index >= get_num_subaddress_accounts(), error::wallet_internal_error, "Account index out of bound");
    if (m_account_tags.second[account_index] == tag)
      MDEBUG("This tag is already assigned to this account");
    else
      m_account_tags.second[account_index] = tag;
  }
  get_account_tags();
}

void wallet2::set_account_tag_description(const std::string& tag, const std::string& description)
{
  THROW_WALLET_EXCEPTION_IF(tag.empty(), error::wallet_internal_error, "Tag must not be empty");
  THROW_WALLET_EXCEPTION_IF(m_account_tags.first.count(tag) == 0, error::wallet_internal_error, "Tag is unregistered");
  m_account_tags.first[tag] = description;
}

std::string wallet2::sign(std::string_view data, cryptonote::subaddress_index index) const
{
  if (m_watch_only)
    throw std::logic_error{"Unable to sign with a watch-only wallet"};

  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  const cryptonote::account_keys &keys = m_account.get_keys();
  crypto::signature signature;
  crypto::secret_key skey = keys.m_spend_secret_key;

  crypto::public_key pkey;
  if (index.is_zero())
    pkey = keys.m_account_address.m_spend_public_key;
  else
  {
    crypto::secret_key m = m_account.get_device().get_subaddress_secret_key(keys.m_view_secret_key, index);
    sc_add((unsigned char*)&skey, (unsigned char*)&m, (unsigned char*)&skey);
    secret_key_to_public_key(skey, pkey);
  }
  crypto::generate_signature(hash, pkey, skey, signature);
  std::string result{SIG_MAGIC};
  result += tools::base58::encode(tools::view_guts(signature));
  return result;
}

bool wallet2::verify(std::string_view data, const cryptonote::account_public_address &address, std::string_view signature)
{
  if (!tools::starts_with(signature, SIG_MAGIC)) {
    LOG_PRINT_L0("Signature header check error");
    return false;
  }
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  std::string decoded;
  if (!tools::base58::decode(signature.substr(SIG_MAGIC.size()), decoded)) {
    LOG_PRINT_L0("Signature decoding error");
    return false;
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    LOG_PRINT_L0("Signature decoding error");
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, address.m_spend_public_key, s);
}

std::string wallet2::sign_multisig_participant(std::string_view data) const
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");

  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  const cryptonote::account_keys &keys = m_account.get_keys();
  crypto::signature signature;
  crypto::generate_signature(hash, get_multisig_signer_public_key(), keys.m_spend_secret_key, signature);
  std::string result{MULTISIG_SIGNATURE_MAGIC};
  result += tools::base58::encode(tools::view_guts(signature));
  return result;
}

bool wallet2::verify_with_public_key(std::string_view data, const crypto::public_key &public_key, std::string_view signature) const
{
  if (!tools::starts_with(signature, MULTISIG_SIGNATURE_MAGIC)) {
    MERROR("Signature header check error");
    return false;
  }
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  std::string decoded;
  if (!tools::base58::decode(signature.substr(MULTISIG_SIGNATURE_MAGIC.size()), decoded)) {
    MERROR("Signature decoding error");
    return false;
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    MERROR("Signature decoding error");
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, public_key, s);
}
//----------------------------------------------------------------------------------------------------
static bool try_get_tx_pub_key_using_td(const tools::wallet2::transfer_details &td, crypto::public_key &pub_key)
{
  std::vector<tx_extra_field> tx_extra_fields;
  if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
  }

  if (td.m_pk_index >= tx_extra_fields.size())
    return false;

  tx_extra_pub_key pub_key_field;
  if (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, td.m_pk_index))
  {
    pub_key = pub_key_field.pub_key;
    return true;
  }

  return false;
}

crypto::public_key wallet2::get_tx_pub_key_from_received_outs(const tools::wallet2::transfer_details &td) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
  }

  // Due to a previous bug, there might be more than one tx pubkey in extra, one being
  // the result of a previously discarded signature.
  // For speed, since scanning for outputs is a slow process, we check whether extra
  // contains more than one pubkey. If not, the first one is returned. If yes, they're
  // checked for whether they yield at least one output
  tx_extra_pub_key pub_key_field;
  THROW_WALLET_EXCEPTION_IF(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 0), error::wallet_internal_error,
      "Public key wasn't found in the transaction extra");
  const crypto::public_key tx_pub_key = pub_key_field.pub_key;
  bool two_found = find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 1);
  if (!two_found) {
    // easy case, just one found
    return tx_pub_key;
  }

  // more than one, loop and search
  const cryptonote::account_keys& keys = m_account.get_keys();
  size_t pk_index = 0;
  hw::device &hwdev = m_account.get_device();

  while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++)) {
    const crypto::public_key tx_pub_key = pub_key_field.pub_key;
    crypto::key_derivation derivation;
    bool r = hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");

    for (size_t i = 0; i < td.m_tx.vout.size(); ++i)
    {
      tx_scan_info_t tx_scan_info;
      check_acc_out_precomp(td.m_tx.vout[i], derivation, {}, i, tx_scan_info);
      if (!tx_scan_info.error && tx_scan_info.received)
        return tx_pub_key;
    }
  }

  // we found no key yielding an output, but it might be in the additional
  // tx pub keys only, which we do not need to check, so return the first one
  return tx_pub_key;
}

bool wallet2::export_key_images_to_file(const fs::path& filename, bool requested_only) const
{
  // NOTE: Exported Key Image File
  // [(magic bytes) (ciphertext..................................................................................) (hashed ciphertext signature)]
  // [              ((transfer array offset*) (spend public key) (view public key) {(key image) (signature), ...})                              ]
  // *The offset in the wallet's transfers this exported key image file contains.

  PERF_TIMER(__FUNCTION__);
  std::pair<size_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> ski = export_key_images(requested_only);
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  std::string data;
  const uint32_t offset = boost::endian::native_to_little(ski.first);
  data.reserve(sizeof(offset) + ski.second.size() * (sizeof(crypto::key_image) + sizeof(crypto::signature)) + 2 * sizeof(crypto::public_key));
  data.resize(sizeof(offset));
  std::memcpy(&data[0], &offset, sizeof(offset));
  data += tools::view_guts(keys.m_spend_public_key);
  data += tools::view_guts(keys.m_view_public_key);
  for (const auto &i: ski.second)
  {
    data += tools::view_guts(i.first);
    data += tools::view_guts(i.second);
  }

  // encrypt data, keep magic plaintext
  PERF_TIMER(export_key_images_encrypt);
  std::string ciphertext{KEY_IMAGE_EXPORT_FILE_MAGIC};
  ciphertext += encrypt_with_view_secret_key(data);
  return save_to_file(filename, ciphertext);
}

//----------------------------------------------------------------------------------------------------
std::pair<size_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> wallet2::export_key_images(bool requested_only) const
{
  PERF_TIMER(export_key_images_raw);
  std::vector<std::pair<crypto::key_image, crypto::signature>> ski;

  size_t offset = 0;

  if (requested_only)
  {
    while (offset < m_transfers.size() && !m_transfers[offset].m_key_image_request)
      ++offset;
  }

  ski.reserve(m_transfers.size() - offset);
  for (size_t n = offset; n < m_transfers.size(); ++n)
  {
    const transfer_details &td = m_transfers[n];

    // get ephemeral public key
    const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
    THROW_WALLET_EXCEPTION_IF(!std::holds_alternative<txout_to_key>(out.target), error::wallet_internal_error,
        "Output is not txout_to_key");
    const auto pkey = var::get<cryptonote::txout_to_key>(out.target).key;

    crypto::public_key tx_pub_key;
    if (!try_get_tx_pub_key_using_td(td, tx_pub_key))
    {
      // TODO(doyle): TODO(oxen): Fallback to old get tx pub key method for
      // incase for now. But we need to go find out why we can't just use
      // td.m_pk_index for everything? If we were able to decode the output
      // using that, why not use it for everthing?
      tx_pub_key = get_tx_pub_key_from_received_outs(td);
    }
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    // generate ephemeral secret key
    crypto::key_image ki;
    cryptonote::keypair in_ephemeral;
    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, ki, m_account.get_device());

    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");

    THROW_WALLET_EXCEPTION_IF(td.m_key_image_known && !td.m_key_image_partial && ki != td.m_key_image,
        error::wallet_internal_error, "key_image generated not matched with cached key image");
    THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != pkey,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

    // sign the key image with the output secret key
    auto& ki_s = ski.emplace_back();
    ki_s.first = td.m_key_image;
    crypto::generate_key_image_signature(ki_s.first, pkey, in_ephemeral.sec, ki_s.second);
  }
  return std::make_pair(offset, ski);
}

uint64_t wallet2::import_key_images_from_file(const fs::path& filename, uint64_t& spent, uint64_t& unspent)
{
  PERF_TIMER(__FUNCTION__);
  std::string data;
  bool r = load_from_file(filename, data);

  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, std::string(tr("failed to read file ")) + filename.u8string());

  if (!tools::starts_with(data, KEY_IMAGE_EXPORT_FILE_MAGIC))
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad key image export file magic in ") + filename.u8string());
  }

  try
  {
    PERF_TIMER(import_key_images_decrypt);
    data = decrypt_with_view_secret_key(std::string_view{data}.substr(KEY_IMAGE_EXPORT_FILE_MAGIC.size())).view();
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to decrypt ") + filename.u8string() + ": " + e.what());
  }

  const size_t headerlen = 4 + 2 * sizeof(crypto::public_key);
  THROW_WALLET_EXCEPTION_IF(data.size() < headerlen, error::wallet_internal_error, std::string("Bad data size from file ") + filename.u8string());

  uint32_t offset;
  std::memcpy(&offset, data.data(), sizeof(offset));
  boost::endian::little_to_native_inplace(offset);
  THROW_WALLET_EXCEPTION_IF(offset > m_transfers.size(), error::wallet_internal_error, "Offset larger than known outputs");

  // Validate embedded spend/view public keys
  {
    crypto::public_key public_spend_key, public_view_key;
    std::memcpy(&public_spend_key, &data[sizeof(offset)], sizeof(public_spend_key));
    std::memcpy(&public_view_key, &data[sizeof(offset) + sizeof(public_spend_key)], sizeof(public_view_key));

    const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
    if (public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key)
    {
      THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string( "Key images from ") + filename.u8string() + " are for a different account");
    }
  }

  const size_t record_size        = sizeof(crypto::key_image) + sizeof(crypto::signature);
  const size_t record_buffer_size = data.size() - headerlen;
  THROW_WALLET_EXCEPTION_IF(record_buffer_size % record_size, error::wallet_internal_error, std::string("Bad data size from file ") + filename.u8string());

  const size_t num_records = record_buffer_size / record_size;
  std::vector<std::pair<crypto::key_image, crypto::signature>> ski(num_records);
  for (size_t n = 0; n < num_records; ++n)
  {
    size_t const key_image_offset = n * record_size;
    size_t const signature_offset = key_image_offset + sizeof(key_image);
    std::pair<crypto::key_image, crypto::signature> &pair = ski[n];
    std::memcpy(&pair.first,  &data[headerlen + key_image_offset], sizeof(key_image));
    std::memcpy(&pair.second, &data[headerlen + signature_offset], sizeof(signature));
  }

  return import_key_images(ski, offset, spent, unspent);
}

//----------------------------------------------------------------------------------------------------
uint64_t wallet2::import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images, size_t offset, uint64_t &spent, uint64_t &unspent, bool check_spent)
{
  PERF_TIMER(import_key_images_lots);
  rpc::IS_KEY_IMAGE_SPENT::request req{};
  rpc::IS_KEY_IMAGE_SPENT::response daemon_resp{};

  THROW_WALLET_EXCEPTION_IF(offset > m_transfers.size(), error::wallet_internal_error, "Offset larger than known outputs");
  THROW_WALLET_EXCEPTION_IF(signed_key_images.size() > m_transfers.size() - offset, error::wallet_internal_error,
      "The blockchain is out of date compared to the signed key images");

  spent   = 0;
  unspent = 0;
  if (signed_key_images.empty() && offset == 0)
  {
    return 0;
  }

  req.key_images.reserve(signed_key_images.size());

  PERF_TIMER_START(import_key_images_A_validate_and_extract_key_images);
  for (size_t n = 0; n < signed_key_images.size(); ++n)
  {
    const transfer_details &td = m_transfers[n + offset];
    const crypto::key_image &key_image = signed_key_images[n].first;
    const crypto::signature &signature = signed_key_images[n].second;

    // get ephemeral public key
    const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
    THROW_WALLET_EXCEPTION_IF(!std::holds_alternative<txout_to_key>(out.target), error::wallet_internal_error,
      "Non txout_to_key output found");
    const auto& pkey = var::get<cryptonote::txout_to_key>(out.target).key;

    std::string const key_image_str = tools::type_to_hex(key_image);
    if (!td.m_key_image_known || !(key_image == td.m_key_image))
    {
      THROW_WALLET_EXCEPTION_IF(!(rct::scalarmultKey(rct::ki2rct(key_image), rct::curveOrder()) == rct::identity()),
          error::wallet_internal_error, "Key image out of validity domain: input " + std::to_string(n + offset) + "/"
          + std::to_string(signed_key_images.size()) + ", key image " + key_image_str);

      // TODO(oxen): This can fail in a worse-case scenario. We re-sort blinks
      // when they arrive out of order (i.e. blink is confirmed in mempool and
      // gets inserted into m_transfers in a different order from the order they
      // are committed to the blockchain).

      // If a watch only wallet sees a blink and the main wallet doesn't, then
      // for that block, export_key_images will fail temporarily until the
      // block is commited and the wallets sorts its transfers into a finalized
      // canonical ordering.
      THROW_WALLET_EXCEPTION_IF(!crypto::check_key_image_signature(key_image, pkey, signature),
          error::signature_check_failed, std::to_string(n + offset) + "/"
          + std::to_string(signed_key_images.size()) + ", key image " + key_image_str
          + ", signature " + tools::type_to_hex(signature) + ", pubkey " + tools::type_to_hex(pkey));
    }
    req.key_images.push_back(key_image_str);
  }
  PERF_TIMER_STOP(import_key_images_A_validate_and_extract_key_images);

  PERF_TIMER_START(import_key_images_B_update_wallet_key_images);
  for (size_t n = 0; n < signed_key_images.size(); ++n)
  {
    m_transfers[n + offset].m_key_image = signed_key_images[n].first;
    m_key_images[m_transfers[n + offset].m_key_image] = n + offset;
    m_transfers[n + offset].m_key_image_known = true;
    m_transfers[n + offset].m_key_image_request = false;
    m_transfers[n + offset].m_key_image_partial = false;
  }
  PERF_TIMER_STOP(import_key_images_B_update_wallet_key_images);

  if(check_spent)
  {
    PERF_TIMER(import_key_images_RPC);
    bool r = invoke_http<rpc::IS_KEY_IMAGE_SPENT>(req, daemon_resp);
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "is_key_image_spent");
    THROW_WALLET_EXCEPTION_IF(daemon_resp.status == rpc::STATUS_BUSY, error::daemon_busy, "is_key_image_spent");
    THROW_WALLET_EXCEPTION_IF(daemon_resp.status != rpc::STATUS_OK, error::is_key_image_spent_error, daemon_resp.status);
    THROW_WALLET_EXCEPTION_IF(daemon_resp.spent_status.size() != signed_key_images.size(), error::wallet_internal_error,
      "daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
      std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(signed_key_images.size()));
    for (size_t n = 0; n < daemon_resp.spent_status.size(); ++n)
    {
      transfer_details &td = m_transfers[n + offset];
      td.m_spent = daemon_resp.spent_status[n] != rpc::IS_KEY_IMAGE_SPENT::UNSPENT;
    }
  }
  std::unordered_set<crypto::hash> spent_txids;   // For each spent key image, search for a tx in m_transfers that uses it as input.
  std::vector<size_t> swept_transfers;            // If such a spending tx wasn't found in m_transfers, this means the spending tx
                                                  // was created by sweep_all, so we can't know the spent height and other detailed info.
  std::unordered_map<crypto::key_image, crypto::hash> spent_key_images;

  PERF_TIMER_START(import_key_images_C);
  for (const transfer_details &td: m_transfers)
  {
    for (const cryptonote::txin_v& in : td.m_tx.vin)
    {
      if (std::holds_alternative<cryptonote::txin_to_key>(in))
        spent_key_images.insert(std::make_pair(var::get<cryptonote::txin_to_key>(in).k_image, td.m_txid));
    }
  }
  PERF_TIMER_STOP(import_key_images_C);

  // accumulate outputs before the updated data
  for(size_t i = 0; i < offset; ++i)
  {
    const transfer_details &td = m_transfers[i];
    if (td.m_frozen)
      continue;
    uint64_t amount = td.amount();
    if (td.m_spent)
      spent += amount;
    else
      unspent += amount;
  }

  PERF_TIMER_START(import_key_images_D);
  for(size_t i = 0; i < signed_key_images.size(); ++i)
  {
    const transfer_details &td = m_transfers[i + offset];
    if (td.m_frozen)
      continue;
    uint64_t amount = td.amount();
    if (td.m_spent)
      spent += amount;
    else
      unspent += amount;
    LOG_PRINT_L2("Transfer " << i << ": " << print_money(amount) << " (" << td.m_global_output_index << "): "
        << (td.m_spent ? "spent" : "unspent") << " (key image " << req.key_images[i] << ")");

    if (i < daemon_resp.spent_status.size() && daemon_resp.spent_status[i] == rpc::IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN)
    {
      const std::unordered_map<crypto::key_image, crypto::hash>::const_iterator skii = spent_key_images.find(td.m_key_image);
      if (skii == spent_key_images.end())
        swept_transfers.push_back(i);
      else
        spent_txids.insert(skii->second);
    }
  }
  PERF_TIMER_STOP(import_key_images_D);

  MDEBUG("Total: " << print_money(spent) << " spent, " << print_money(unspent) << " unspent");

  if (check_spent)
  {
    // query outgoing txes
    PERF_TIMER_START(import_key_images_E);
    auto gettxs_res = request_transactions(hashes_to_hex(spent_txids.begin(), spent_txids.end()));
    PERF_TIMER_STOP(import_key_images_E);

    // process each outgoing tx
    PERF_TIMER_START(import_key_images_F);
    auto spent_txid = spent_txids.begin();
    hw::device &hwdev =  m_account.get_device();
    auto it = spent_txids.begin();
    for (const auto& e : gettxs_res.txs)
    {
      THROW_WALLET_EXCEPTION_IF(e.in_pool, error::wallet_internal_error, "spent tx isn't supposed to be in txpool");

      cryptonote::transaction spent_tx;
      crypto::hash spnet_txid_parsed;
      THROW_WALLET_EXCEPTION_IF(!get_pruned_tx(e, spent_tx, spnet_txid_parsed), error::wallet_internal_error, "Failed to get tx from daemon");
      THROW_WALLET_EXCEPTION_IF(!(spnet_txid_parsed == *it), error::wallet_internal_error, "parsed txid mismatch");
      ++it;

      // get received (change) amount
      uint64_t tx_money_got_in_outs = 0;
      const cryptonote::account_keys& keys = m_account.get_keys();
      const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(spent_tx);
      crypto::key_derivation derivation;
      bool r = hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
      const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(spent_tx);
      std::vector<crypto::key_derivation> additional_derivations;
      for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
      {
        additional_derivations.push_back({});
        r = hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back());
        THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
      }
      size_t output_index = 0;
      bool miner_tx = cryptonote::is_coinbase(spent_tx);
      for (const cryptonote::tx_out& out : spent_tx.vout)
      {
        tx_scan_info_t tx_scan_info;
        check_acc_out_precomp(out, derivation, additional_derivations, output_index, tx_scan_info);
        THROW_WALLET_EXCEPTION_IF(tx_scan_info.error, error::wallet_internal_error, "check_acc_out_precomp failed");
        if (tx_scan_info.received)
        {
          if (tx_scan_info.money_transfered == 0 && !miner_tx)
          {
            rct::key mask;
            tx_scan_info.money_transfered = tools::decodeRct(spent_tx.rct_signatures, tx_scan_info.received->derivation, output_index, mask, hwdev);
          }
          THROW_WALLET_EXCEPTION_IF(tx_money_got_in_outs >= std::numeric_limits<uint64_t>::max() - tx_scan_info.money_transfered,
              error::wallet_internal_error, "Overflow in received amounts");
          tx_money_got_in_outs += tx_scan_info.money_transfered;
        }
        ++output_index;
      }

      // get spent amount
      uint64_t tx_money_spent_in_ins = 0;
      uint32_t subaddr_account = (uint32_t)-1;
      std::set<uint32_t> subaddr_indices;
      for (const cryptonote::txin_v& in : spent_tx.vin)
      {
        if (!std::holds_alternative<cryptonote::txin_to_key>(in))
          continue;
        auto it = m_key_images.find(var::get<cryptonote::txin_to_key>(in).k_image);
        if (it != m_key_images.end())
        {
          THROW_WALLET_EXCEPTION_IF(it->second >= m_transfers.size(), error::wallet_internal_error, std::string("Key images cache contains illegal transfer offset: ") + std::to_string(it->second) + std::string(" m_transfers.size() = ") + std::to_string(m_transfers.size()));
          const transfer_details& td = m_transfers[it->second];
          uint64_t amount = var::get<cryptonote::txin_to_key>(in).amount;
          if (amount > 0)
          {
            THROW_WALLET_EXCEPTION_IF(amount != td.amount(), error::wallet_internal_error,
                std::string("Inconsistent amount in tx input: got ") + print_money(amount) +
                std::string(", expected ") + print_money(td.amount()));
          }
          amount = td.amount();
          tx_money_spent_in_ins += amount;

          LOG_PRINT_L0("Spent money: " << print_money(amount) << ", with tx: " << *spent_txid);
          set_spent(it->second, e.block_height);
          if (m_callback)
            m_callback->on_money_spent(e.block_height, *spent_txid, spent_tx, amount, spent_tx, td.m_subaddr_index);
          if (subaddr_account != (uint32_t)-1 && subaddr_account != td.m_subaddr_index.major)
            LOG_PRINT_L0("WARNING: This tx spends outputs received by different subaddress accounts, which isn't supposed to happen");
          subaddr_account = td.m_subaddr_index.major;
          subaddr_indices.insert(td.m_subaddr_index.minor);
        }
      }

      // create outgoing payment
      process_outgoing(*spent_txid, spent_tx, e.block_height, e.block_timestamp, tx_money_spent_in_ins, tx_money_got_in_outs, subaddr_account, subaddr_indices);

      // erase corresponding incoming payment
      for (auto j = m_payments.begin(); j != m_payments.end(); ++j)
      {
        if (j->second.m_tx_hash == *spent_txid)
        {
          m_payments.erase(j);
          break;
        }
      }

      ++spent_txid;
    }
    PERF_TIMER_STOP(import_key_images_F);

    PERF_TIMER_START(import_key_images_G);
    for (size_t n : swept_transfers)
    {
      const transfer_details& td = m_transfers[n];
      confirmed_transfer_details pd;
      pd.m_change    = (uint64_t)-1;                        // change is unknown
      pd.m_amount_in = pd.m_amount_out = td.amount();       // fee is unknown
      pd.m_block_height                = 0;                 // spent block height is unknown
      const crypto::hash &spent_txid   = crypto::null_hash; // spent txid is unknown
      bool stake                       = service_nodes::tx_get_staking_components(td.m_tx, nullptr /*stake*/, td.m_txid);
      pd.m_pay_type = stake ? wallet::pay_type::stake : wallet::pay_type::out;
      m_confirmed_txs.insert(std::make_pair(spent_txid, pd));
    }
    PERF_TIMER_STOP(import_key_images_G);
  }

  // this can be 0 if we do not know the height
  return m_transfers[signed_key_images.size() + offset - 1].m_block_height;
}

bool wallet2::import_key_images(std::vector<crypto::key_image> key_images, size_t offset, std::optional<std::unordered_set<size_t>> selected_transfers)
{
  if (key_images.size() + offset > m_transfers.size())
  {
    LOG_PRINT_L1("More key images returned that we know outputs for");
    return false;
  }
  for (size_t ki_idx = 0; ki_idx < key_images.size(); ++ki_idx)
  {
    const size_t transfer_idx = ki_idx + offset;
    if (selected_transfers && !selected_transfers->count(transfer_idx))
      continue;

    transfer_details &td = m_transfers[transfer_idx];
    if (td.m_key_image_known && !td.m_key_image_partial && td.m_key_image != key_images[ki_idx])
      LOG_PRINT_L0("WARNING: imported key image differs from previously known key image at index " << ki_idx << ": trusting imported one");
    td.m_key_image = key_images[ki_idx];
    m_key_images[td.m_key_image] = transfer_idx;
    td.m_key_image_known = true;
    td.m_key_image_request = false;
    td.m_key_image_partial = false;
    m_pub_keys[td.get_public_key()] = transfer_idx;
  }

  return true;
}

bool wallet2::import_key_images(signed_tx_set & signed_tx, size_t offset, bool only_selected_transfers)
{
  std::unordered_set<size_t> selected_transfers;
  if (only_selected_transfers)
    for (const pending_tx & ptx : signed_tx.ptx)
      for (const size_t s: ptx.selected_transfers)
        selected_transfers.insert(s);

  return import_key_images(signed_tx.key_images, offset, only_selected_transfers ? std::make_optional(std::move(selected_transfers)) : std::nullopt);
}

wallet2::payment_container wallet2::export_payments() const
{
  payment_container payments;
  for (auto const &p : m_payments)
  {
    payments.emplace(p);
  }
  return payments;
}
void wallet2::import_payments(const payment_container &payments)
{
  m_payments.clear();
  for (auto const &p : payments)
  {
    m_payments.emplace(p);
  }
}
void wallet2::import_payments_out(const std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>> &confirmed_payments)
{
  m_confirmed_txs.clear();
  for (auto const &p : confirmed_payments)
  {
    m_confirmed_txs.emplace(p);
  }
}

std::tuple<size_t,crypto::hash,std::vector<crypto::hash>> wallet2::export_blockchain() const
{
  std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> bc;
  std::get<0>(bc) = m_blockchain.offset();
  std::get<1>(bc) = m_blockchain.empty() ? crypto::null_hash: m_blockchain.genesis();
  for (size_t n = m_blockchain.offset(); n < m_blockchain.size(); ++n)
  {
    std::get<2>(bc).push_back(m_blockchain[n]);
  }
  return bc;
}

void wallet2::import_blockchain(const std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> &bc)
{
  m_blockchain.clear();
  if (std::get<0>(bc))
  {
    for (size_t n = std::get<0>(bc); n > 0; --n)
      m_blockchain.push_back(std::get<1>(bc));
    m_blockchain.trim(std::get<0>(bc));
  }
  for (auto const &b : std::get<2>(bc))
  {
    m_blockchain.push_back(b);
  }
  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);
  check_genesis(genesis_hash);
  m_last_block_reward = cryptonote::get_outs_money_amount(genesis.miner_tx);
}
//----------------------------------------------------------------------------------------------------
std::pair<size_t, std::vector<tools::wallet2::transfer_details>> wallet2::export_outputs(bool all) const
{
  PERF_TIMER(export_outputs);
  std::vector<tools::wallet2::transfer_details> outs;

  size_t offset = 0;
  if (!all)
    while (offset < m_transfers.size() && (m_transfers[offset].m_key_image_known && !m_transfers[offset].m_key_image_request))
      ++offset;

  outs.reserve(m_transfers.size() - offset);
  for (size_t n = offset; n < m_transfers.size(); ++n)
  {
    const transfer_details &td = m_transfers[n];

    outs.push_back(td);
  }

  return std::make_pair(offset, outs);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::export_outputs_to_str(bool all) const
{
  PERF_TIMER(export_outputs_to_str);

  std::stringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  const auto& outputs = export_outputs(all);
  ar << outputs;

  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  std::string header;
  header += tools::view_guts(keys.m_spend_public_key);
  header += tools::view_guts(keys.m_view_public_key);
  header += oss.str();
  PERF_TIMER(export_outputs_encryption);
  std::string ciphertext{OUTPUT_EXPORT_FILE_MAGIC};
  ciphertext += encrypt_with_view_secret_key(header);
  return ciphertext;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::import_outputs(const std::pair<size_t, std::vector<tools::wallet2::transfer_details>> &outputs)
{
  PERF_TIMER(import_outputs);

  THROW_WALLET_EXCEPTION_IF(outputs.first > m_transfers.size(), error::wallet_internal_error,
      "Imported outputs omit more outputs that we know of");

  const size_t offset = outputs.first;
  const size_t original_size = m_transfers.size();
  m_transfers.resize(offset + outputs.second.size());
  for (size_t i = 0; i < offset; ++i)
    m_transfers[i].m_key_image_request = false;
  for (size_t i = 0; i < outputs.second.size(); ++i)
  {
    transfer_details td = outputs.second[i];

    // skip those we've already imported, or which have different data
    if (i + offset < original_size)
    {
      // compare the data used to create the key image below
      const transfer_details &org_td = m_transfers[i + offset];
      if (!org_td.m_key_image_known)
        goto process;
#define CMPF(f) if (!(td.f == org_td.f)) goto process
      CMPF(m_txid);
      CMPF(m_key_image);
      CMPF(m_internal_output_index);
#undef CMPF
      if (!(get_transaction_prefix_hash(td.m_tx) == get_transaction_prefix_hash(org_td.m_tx)))
        goto process;

      // copy anyway, since the comparison does not include ancillary fields which may have changed
      m_transfers[i + offset] = std::move(td);
      continue;
    }

process:

    // the hot wallet wouldn't have known about key images (except if we already exported them)
    cryptonote::keypair in_ephemeral;

    THROW_WALLET_EXCEPTION_IF(td.m_tx.vout.empty(), error::wallet_internal_error, "tx with no outputs at index " + std::to_string(i + offset));
    crypto::public_key tx_pub_key;
    if (!try_get_tx_pub_key_using_td(td, tx_pub_key))
    {
      // TODO(doyle): TODO(oxen): Fallback to old get tx pub key method for
      // incase for now. But we need to go find out why we can't just use
      // td.m_pk_index for everything? If we were able to decode the output
      // using that, why not use it for everthing?
      tx_pub_key = get_tx_pub_key_from_received_outs(td);
    }
    const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

    THROW_WALLET_EXCEPTION_IF(!std::holds_alternative<cryptonote::txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target),
        error::wallet_internal_error, "Unsupported output type");
    const crypto::public_key& out_key = var::get<cryptonote::txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key;
    bool r = cryptonote::generate_key_image_helper(m_account.get_keys(), m_subaddresses, out_key, tx_pub_key, additional_tx_pub_keys, td.m_internal_output_index, in_ephemeral, td.m_key_image, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    if (should_expand(td.m_subaddr_index))
      expand_subaddresses(td.m_subaddr_index);
    td.m_key_image_known = true;
    td.m_key_image_request = true;
    td.m_key_image_partial = false;
    THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != out_key,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key at index " + std::to_string(i + offset));

    m_key_images[td.m_key_image] = i + offset;
    m_pub_keys[td.get_public_key()] = i + offset;
    m_transfers[i + offset] = std::move(td);
  }

  return m_transfers.size();
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::import_outputs_from_str(std::string data)
{
  PERF_TIMER(import_outputs_from_str);
  if (!tools::starts_with(data, OUTPUT_EXPORT_FILE_MAGIC))
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad magic from outputs"));
  }

  try
  {
    PERF_TIMER(import_outputs_decrypt);
    data = decrypt_with_view_secret_key(std::string_view{data}.substr(OUTPUT_EXPORT_FILE_MAGIC.size())).view();
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to decrypt outputs: ") + e.what());
  }

  const size_t headerlen = 2 * sizeof(crypto::public_key);
  if (data.size() < headerlen)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Bad data size for outputs"));
  }
  const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
  const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];
  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  if (public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Outputs from are for a different account"));
  }

  size_t imported_outputs = 0;
  try
  {
    std::string_view body{data};
    body.remove_prefix(headerlen);
    std::stringstream iss;
    iss << body;
    std::pair<size_t, std::vector<tools::wallet2::transfer_details>> outputs;
    try
    {
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> outputs;
    }
    catch (...)
    {
      iss.str("");
      iss << body;
      boost::archive::binary_iarchive ar(iss);
      ar >> outputs;
    }

    imported_outputs = import_outputs(outputs);
  }
  catch (const std::exception &e)
  {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, std::string("Failed to import outputs") + e.what());
  }

  return imported_outputs;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signer_public_key(const crypto::secret_key &spend_skey) const
{
  crypto::public_key pkey;
  crypto::secret_key_to_public_key(get_multisig_blinded_secret_key(spend_skey), pkey);
  return pkey;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signer_public_key() const
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
  crypto::public_key signer;
  CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(get_account().get_keys().m_spend_secret_key, signer), "Failed to generate signer public key");
  return signer;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signing_public_key(const crypto::secret_key &msk) const
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
  crypto::public_key pkey;
  CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(msk, pkey), "Failed to derive public key");
  return pkey;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signing_public_key(size_t idx) const
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
  CHECK_AND_ASSERT_THROW_MES(idx < get_account().get_multisig_keys().size(), "Multisig signing key index out of range");
  return get_multisig_signing_public_key(get_account().get_multisig_keys()[idx]);
}
//----------------------------------------------------------------------------------------------------
rct::key wallet2::get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L) const
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
  CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "idx out of range");
  for (const auto &k: m_transfers[idx].m_multisig_k)
  {
    rct::key L;
    rct::scalarmultBase(L, k);
    if (used_L.find(L) != used_L.end())
      return k;
  }
  THROW_WALLET_EXCEPTION(tools::error::multisig_export_needed);
  return rct::zero();
}
//----------------------------------------------------------------------------------------------------
rct::multisig_kLRki wallet2::get_multisig_kLRki(size_t n, const rct::key &k) const
{
  CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad m_transfers index");
  rct::multisig_kLRki kLRki;
  kLRki.k = k;
  cryptonote::generate_multisig_LR(m_transfers[n].get_public_key(), rct::rct2sk(kLRki.k), (crypto::public_key&)kLRki.L, (crypto::public_key&)kLRki.R);
  kLRki.ki = rct::ki2rct(m_transfers[n].m_key_image);
  return kLRki;
}
//----------------------------------------------------------------------------------------------------
rct::multisig_kLRki wallet2::get_multisig_composite_kLRki(size_t n, const std::unordered_set<crypto::public_key> &ignore_set, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L) const
{
  CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad transfer index");

  const transfer_details &td = m_transfers[n];
  rct::multisig_kLRki kLRki = get_multisig_kLRki(n, rct::skGen());

  // pick a L/R pair from every other participant but one
  size_t n_signers_used = 1;
  for (const auto &p: m_transfers[n].m_multisig_info)
  {
    if (ignore_set.find(p.m_signer) != ignore_set.end())
      continue;

    for (const auto &lr: p.m_LR)
    {
      if (used_L.find(lr.m_L) != used_L.end())
        continue;
      used_L.insert(lr.m_L);
      new_used_L.insert(lr.m_L);
      rct::addKeys(kLRki.L, kLRki.L, lr.m_L);
      rct::addKeys(kLRki.R, kLRki.R, lr.m_R);
      ++n_signers_used;
      break;
    }
  }
  CHECK_AND_ASSERT_THROW_MES(n_signers_used >= m_multisig_threshold, "LR not found for enough participants");

  return kLRki;
}
//----------------------------------------------------------------------------------------------------
crypto::key_image wallet2::get_multisig_composite_key_image(size_t n) const
{
  CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad output index");

  const transfer_details &td = m_transfers[n];
  crypto::public_key tx_key;
  if (!try_get_tx_pub_key_using_td(td, tx_key))
  {
    // TODO(doyle): TODO(oxen): Fallback to old get tx pub key method for
    // incase for now. But we need to go find out why we can't just use
    // td.m_pk_index for everything? If we were able to decode the output
    // using that, why not use it for everthing?
    tx_key = get_tx_pub_key_from_received_outs(td);
  }
  const std::vector<crypto::public_key> additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);
  crypto::key_image ki;
  std::vector<crypto::key_image> pkis;
  for (const auto &info: td.m_multisig_info)
    for (const auto &pki: info.m_partial_key_images)
      pkis.push_back(pki);
  bool r = cryptonote::generate_multisig_composite_key_image(get_account().get_keys(), m_subaddresses, td.get_public_key(), tx_key, additional_tx_keys, td.m_internal_output_index, pkis, ki);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
  return ki;
}
//----------------------------------------------------------------------------------------------------
cryptonote::blobdata wallet2::export_multisig()
{
  std::vector<wallet::multisig_info> info;

  const crypto::public_key signer = get_multisig_signer_public_key();

  info.resize(m_transfers.size());
  for (size_t n = 0; n < m_transfers.size(); ++n)
  {
    transfer_details &td = m_transfers[n];
    crypto::key_image ki;
    memwipe(td.m_multisig_k.data(), td.m_multisig_k.size() * sizeof(td.m_multisig_k[0]));
    info[n].m_LR.clear();
    info[n].m_partial_key_images.clear();

    for (size_t m = 0; m < get_account().get_multisig_keys().size(); ++m)
    {
      // we want to export the partial key image, not the full one, so we can't use td.m_key_image
      bool r = generate_multisig_key_image(get_account().get_keys(), m, td.get_public_key(), ki);
      CHECK_AND_ASSERT_THROW_MES(r, "Failed to generate key image");
      info[n].m_partial_key_images.push_back(ki);
    }

    // Wallet tries to create as many transactions as many signers combinations. We calculate the maximum number here as follows:
    // if we have 2/4 wallet with signers: A, B, C, D and A is a transaction creator it will need to pick up 1 signer from 3 wallets left.
    // That means counting combinations for excluding 2-of-3 wallets (k = total signers count - threshold, n = total signers count - 1).
    size_t nlr = tools::combinations_count(m_multisig_signers.size() - m_multisig_threshold, m_multisig_signers.size() - 1);
    for (size_t m = 0; m < nlr; ++m)
    {
      td.m_multisig_k.push_back(rct::skGen());
      const rct::multisig_kLRki kLRki = get_multisig_kLRki(n, td.m_multisig_k.back());
      info[n].m_LR.push_back({kLRki.L, kLRki.R});
    }

    info[n].m_signer = signer;
  }

  std::stringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  ar << info;

  const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
  std::string header;
  header += tools::view_guts(keys.m_spend_public_key);
  header += tools::view_guts(keys.m_view_public_key);
  header += tools::view_guts(signer);
  std::string ciphertext{MULTISIG_EXPORT_FILE_MAGIC};
  ciphertext += encrypt_with_view_secret_key(header + oss.str());
  return ciphertext;
}
//----------------------------------------------------------------------------------------------------
void wallet2::update_multisig_rescan_info(const std::vector<std::vector<rct::key>> &multisig_k, const std::vector<std::vector<wallet::multisig_info>> &info, size_t n)
{
  CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad index in update_multisig_info");
  CHECK_AND_ASSERT_THROW_MES(multisig_k.size() >= m_transfers.size(), "Mismatched sizes of multisig_k and info");

  MDEBUG("update_multisig_rescan_info: updating index " << n);
  transfer_details &td = m_transfers[n];
  td.m_multisig_info.clear();
  for (const auto &pi: info)
  {
    CHECK_AND_ASSERT_THROW_MES(n < pi.size(), "Bad pi size");
    td.m_multisig_info.push_back(pi[n]);
  }
  m_key_images.erase(td.m_key_image);
  td.m_key_image = get_multisig_composite_key_image(n);
  td.m_key_image_known = true;
  td.m_key_image_request = false;
  td.m_key_image_partial = false;
  td.m_multisig_k = multisig_k[n];
  m_key_images[td.m_key_image] = n;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::import_multisig(std::vector<cryptonote::blobdata> blobs)
{
  CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");

  std::vector<std::vector<wallet::multisig_info>> info;
  std::unordered_set<crypto::public_key> seen;
  for (cryptonote::blobdata &data: blobs)
  {
    THROW_WALLET_EXCEPTION_IF(!tools::starts_with(data, MULTISIG_EXPORT_FILE_MAGIC),
        error::wallet_internal_error, "Bad multisig info file magic in ");

    data = decrypt_with_view_secret_key(std::string_view{data}.substr(MULTISIG_EXPORT_FILE_MAGIC.size())).view();

    const size_t headerlen = 3 * sizeof(crypto::public_key);
    THROW_WALLET_EXCEPTION_IF(data.size() < headerlen, error::wallet_internal_error, "Bad data size");

    const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
    const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];
    const crypto::public_key &signer = *(const crypto::public_key*)&data[2*sizeof(crypto::public_key)];
    const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
    THROW_WALLET_EXCEPTION_IF(public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key,
        error::wallet_internal_error, "Multisig info is for a different account");
    if (get_multisig_signer_public_key() == signer)
    {
      MINFO("Multisig info from this wallet ignored");
      continue;
    }
    if (seen.find(signer) != seen.end())
    {
      MINFO("Duplicate multisig info ignored");
      continue;
    }
    seen.insert(signer);

    std::string_view body{data};
    body.remove_prefix(headerlen);
    std::stringstream iss;
    iss << body;
    std::vector<wallet::multisig_info> i;
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> i;
    MINFO(i.size() << " outputs found");
    info.push_back(std::move(i));
  }

  CHECK_AND_ASSERT_THROW_MES(info.size() + 1 <= m_multisig_signers.size() && info.size() + 1 >= m_multisig_threshold, "Wrong number of multisig sources");

  std::vector<std::vector<rct::key>> k;
  OXEN_DEFER {
    for (auto& kv : k)
      memwipe(kv.data(), kv.size() * sizeof(rct::key));
  };
  k.reserve(m_transfers.size());
  for (const auto &td: m_transfers)
    k.push_back(td.m_multisig_k);

  // how many outputs we're going to update
  size_t n_outputs = m_transfers.size();
  for (const auto &pi: info)
    if (pi.size() < n_outputs)
      n_outputs = pi.size();

  if (n_outputs == 0)
    return 0;

  // check signers are consistent
  for (const auto &pi: info)
  {
    CHECK_AND_ASSERT_THROW_MES(std::find(m_multisig_signers.begin(), m_multisig_signers.end(), pi[0].m_signer) != m_multisig_signers.end(),
        "Signer is not a member of this multisig wallet");
    for (size_t n = 1; n < n_outputs; ++n)
      CHECK_AND_ASSERT_THROW_MES(pi[n].m_signer == pi[0].m_signer, "Mismatched signers in imported multisig info");
  }

  // trim data we don't have info for from all participants
  for (auto &pi: info)
    pi.resize(n_outputs);

  // sort by signer
  if (!info.empty() && !info.front().empty())
  {
    std::sort(info.begin(), info.end(), [](const auto& a, const auto& b) { return a[0].m_signer < b[0].m_signer; });
  }

  // first pass to determine where to detach the blockchain
  for (size_t n = 0; n < n_outputs; ++n)
  {
    const transfer_details &td = m_transfers[n];
    if (!td.m_key_image_partial)
      continue;
    MINFO("Multisig info importing from block height " << td.m_block_height);
    detach_blockchain(td.m_block_height);
    break;
  }

  for (size_t n = 0; n < n_outputs && n < m_transfers.size(); ++n)
  {
    update_multisig_rescan_info(k, info, n);
  }

  m_multisig_rescan_k = &k;
  m_multisig_rescan_info = &info;
  try
  {

    refresh(false);
  }
  catch (...)
  {
    m_multisig_rescan_info = NULL;
    m_multisig_rescan_k = NULL;
    throw;
  }
  m_multisig_rescan_info = NULL;
  m_multisig_rescan_k = NULL;

  return n_outputs;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(std::string_view plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  std::string ciphertext;
  crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(plaintext.size() + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
  crypto::chacha20(plaintext.data(), plaintext.size(), key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, skey, signature);
  }
  return ciphertext;
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt(const epee::span<char> &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(std::string_view{plaintext.data(), plaintext.size()}, skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::encrypt_with_view_secret_key(std::string_view plaintext, bool authenticated) const
{
  return encrypt(plaintext, get_account().get_keys().m_view_secret_key, authenticated);
}
//----------------------------------------------------------------------------------------------------
epee::wipeable_string wallet2::decrypt(std::string_view ciphertext, const crypto::secret_key &skey, bool authenticated) const
{
  const size_t prefix_size = sizeof(chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
  THROW_WALLET_EXCEPTION_IF(ciphertext.size() < prefix_size,
    error::wallet_internal_error, "Unexpected ciphertext size");

  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    const crypto::signature &signature = *(const crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    THROW_WALLET_EXCEPTION_IF(!crypto::check_signature(hash, pkey, signature),
      error::wallet_internal_error, "Failed to authenticate ciphertext");
  }
  epee::wipeable_string buffer;
  buffer.resize(ciphertext.size() - prefix_size);
  crypto::chacha20(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, buffer.data());
  return buffer;
}
//----------------------------------------------------------------------------------------------------
epee::wipeable_string wallet2::decrypt_with_view_secret_key(std::string_view ciphertext, bool authenticated) const
{
  return decrypt(ciphertext, get_account().get_keys().m_view_secret_key, authenticated);
}

static constexpr auto uri_prefix = "oxen:"sv;

//----------------------------------------------------------------------------------------------------
std::string wallet2::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const
{
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("wrong address: ") + address;
    return std::string();
  }

  // we want only one payment id
  if (info.has_payment_id && !payment_id.empty())
  {
    error = "A single payment id is allowed";
    return std::string();
  }

  if (!payment_id.empty())
  {
    crypto::hash pid;
    if (!wallet2::parse_payment_id(payment_id, pid))
    {
      error = "Invalid payment id";
      return std::string();
    }
  }

  cpr::CurlHolder curl;
  cpr::Parameters params;

  if (!payment_id.empty())
    params.Add({"tx_payment_id", payment_id});

  if (amount > 0) // URI encoded amount is in decimal units, not atomic units
    params.Add({"tx_amount", cryptonote::print_money(amount)});

  if (!recipient_name.empty())
    params.Add({"recipient_name", recipient_name});

  if (!tx_description.empty())
    params.Add({"tx_description", tx_description});

  std::string uri{uri_prefix};
  uri += address;
  if (auto content = params.GetContent(curl); !content.empty()) {
    uri += '?';
    uri += std::move(content);
  }
  return uri;
}

namespace {

std::string uri_decode(std::string_view encoded)
{
  std::string decoded;
  for (auto it = encoded.begin(); it != encoded.end(); )
  {
    if (*it == '%' && encoded.end() - it >= 3 && oxenmq::is_hex(it + 1, it + 3))
    {
      decoded += oxenmq::from_hex(it + 1, it + 3);
      it += 3;
    }
    else
      decoded += *it++;
  }
  return decoded;
}

}

//----------------------------------------------------------------------------------------------------
bool wallet2::parse_uri(std::string_view uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error)
{
  if (!tools::starts_with(uri, uri_prefix))
  {
    error = "URI has wrong scheme (expected \"" ;
    error += uri_prefix;
    error += "\"): ";
    error += uri;
    return false;
  }
  uri.remove_prefix(uri_prefix.size());
  auto query_begins = uri.find('?');
  address = uri.substr(0, query_begins);

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = "URI has invalid address: "s + address;
    return false;
  }
  if (query_begins == std::string::npos || query_begins == uri.size() - 1)
  {
    return true;
  }
  uri.remove_prefix(query_begins + 1);

  std::unordered_set<std::string_view> have_arg;
  for (const auto &arg: tools::split(uri, "&"sv))
  {
    auto raw_kv = tools::split(arg, "="sv);
    if (raw_kv.size() != 2)
    {
      error = "URI has invalid parameter (expected key=val): "s;
      error += arg;
      return false;
    }
    std::string key = uri_decode(raw_kv[0]);
    if (!have_arg.insert(key).second)
    {
      error = "URI has more than one instance of " + key;
      return false;
    }
    std::string value = uri_decode(raw_kv[1]);

    if (key == "tx_amount"sv)
    {
      amount = 0;
      if (!cryptonote::parse_amount(amount, value))
      {
        error = "URI has invalid amount: " + value;
        return false;
      }
    }
    else if (key == "tx_payment_id"sv)
    {
      if (info.has_payment_id)
      {
        error = "URI cannot use both an integrated address and an explicit payment id";
        return false;
      }
      crypto::hash hash;
      if (!wallet2::parse_payment_id(value, hash))
      {
        error = "Invalid payment id: " + value;
        return false;
      }
      payment_id = std::move(value);
    }
    else if (key == "recipient_name"sv)
      recipient_name = std::move(value);
    else if (key == "tx_description"sv)
      tx_description = std::move(value);
    else
      unknown_parameters.emplace_back(arg);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day)
{
  rpc::version_t version;
  if (!check_connection(&version))
  {
    throw std::runtime_error("failed to connect to daemon: " + get_daemon_address());
  }
  if (version < rpc::version_t{1, 6})
  {
    throw std::runtime_error("this function requires RPC version 1.6 or higher");
  }
  std::tm date = { 0, 0, 0, 0, 0, 0, 0, 0 };
  date.tm_year = year - 1900;
  date.tm_mon  = month - 1;
  date.tm_mday = day;
  if (date.tm_mon < 0 || 11 < date.tm_mon || date.tm_mday < 1 || 31 < date.tm_mday)
  {
    throw std::runtime_error("month or day out of range");
  }
  uint64_t timestamp_target = std::mktime(&date);
  std::string err;
  uint64_t height_min = 0;
  uint64_t height_max = get_daemon_blockchain_height(err) - 1;
  if (!err.empty())
  {
    throw std::runtime_error("failed to get blockchain height");
  }
  while (true)
  {
    rpc::GET_BLOCKS_BY_HEIGHT::request req{};
    rpc::GET_BLOCKS_BY_HEIGHT::response res{};
    uint64_t height_mid = (height_min + height_max) / 2;
    req.heights =
    {
      height_min,
      height_mid,
      height_max
    };
    bool r = invoke_http<rpc::GET_BLOCKS_BY_HEIGHT>(req, res);
    if (!r || res.status != rpc::STATUS_OK)
    {
      std::ostringstream oss;
      oss << "failed to get blocks by heights: ";
      for (auto height : req.heights)
        oss << height << ' ';
      oss << std::endl << "reason: ";
      if (!r)
        oss << "possibly lost connection to daemon";
      else if (res.status == rpc::STATUS_BUSY)
        oss << "daemon is busy";
      else
        oss << get_rpc_status(res.status);
      throw std::runtime_error(oss.str());
    }
    cryptonote::block blk_min, blk_mid, blk_max;
    if (res.blocks.size() < 3) throw std::runtime_error("Not enough blocks returned from daemon");
    if (!parse_and_validate_block_from_blob(res.blocks[0].block, blk_min)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_min));
    if (!parse_and_validate_block_from_blob(res.blocks[1].block, blk_mid)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_mid));
    if (!parse_and_validate_block_from_blob(res.blocks[2].block, blk_max)) throw std::runtime_error("failed to parse blob at height " + std::to_string(height_max));
    uint64_t timestamp_min = blk_min.timestamp;
    uint64_t timestamp_mid = blk_mid.timestamp;
    uint64_t timestamp_max = blk_max.timestamp;
    if (!(timestamp_min <= timestamp_mid && timestamp_mid <= timestamp_max))
    {
      // the timestamps are not in the chronological order.
      // assuming they're sufficiently close to each other, simply return the smallest height
      return std::min({height_min, height_mid, height_max});
    }
    if (timestamp_target > timestamp_max)
    {
      throw std::runtime_error("specified date is in the future");
    }
    if (timestamp_target <= timestamp_min + 2 * 24 * 60 * 60)   // two days of "buffer" period
    {
      return height_min;
    }
    if (timestamp_target <= timestamp_mid)
      height_max = height_mid;
    else
      height_min = height_mid;
    if (height_max - height_min <= 2 * 24 * 30)        // don't divide the height range finer than two days
    {
      return height_min;
    }
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_synced(uint64_t grace_blocks) const
{
  uint64_t height;
  if (!m_node_rpc_proxy.get_height(height))
    return false;
  return get_blockchain_current_height() + grace_blocks >= height;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_segregation_fork_height() const
{
  if (m_nettype == MAINNET && m_segregation_height > 0)
    return m_segregation_height;
  return SEGREGATION_FORK_HEIGHT;
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_genesis(cryptonote::block& b) const {
  cryptonote::generate_genesis_block(b, m_nettype);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::contains_address(const cryptonote::account_public_address& address) const {
  size_t accounts = get_num_subaddress_accounts() + m_subaddress_lookahead_major;
  for (uint32_t i = 0; i < accounts; i++) {
    size_t subaddresses = get_num_subaddresses(i) + m_subaddress_lookahead_minor;
    for (uint32_t j = 0; j < subaddresses; j++)
      if (get_subaddress({i, j}) == address)
        return true;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::contains_key_image(const crypto::key_image& key_image) const {
  const auto &key_image_it = m_key_images.find(key_image);
  bool result = (key_image_it != m_key_images.end());
  return result;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_signature_for_request_stake_unlock(const crypto::key_image& key_image, crypto::signature& signature) const
{
  auto key_image_it = m_key_images.find(key_image);
  if (key_image_it == m_key_images.end())
    return false;

  const auto& td = m_transfers[key_image_it->second];

  // get ephemeral public key
  const auto& target = td.m_tx.vout[td.m_internal_output_index].target;
  THROW_WALLET_EXCEPTION_IF(!std::holds_alternative<txout_to_key>(target), error::wallet_internal_error, "Output is not txout_to_key");
  const auto& pkey = var::get<cryptonote::txout_to_key>(target).key;

  crypto::public_key tx_pub_key;
  if (!try_get_tx_pub_key_using_td(td, tx_pub_key))
  {
    // TODO(doyle): TODO(oxen): Fallback to old get tx pub key method for
    // incase for now. But we need to go find out why we can't just use
    // td.m_pk_index for everything? If we were able to decode the output
    // using that, why not use it for everthing?
    tx_pub_key = get_tx_pub_key_from_received_outs(td);
  }

  // generate ephemeral secret key
  auto& hwdev = m_account.get_device();
  cryptonote::keypair in_ephemeral;
  crypto::key_image ki;
  bool r = cryptonote::generate_key_image_helper(
      m_account.get_keys(),
      m_subaddresses,
      pkey,
      tx_pub_key,
      get_additional_tx_pub_keys_from_extra(td.m_tx),
      td.m_internal_output_index,
      in_ephemeral,
      ki,
      hwdev);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
  THROW_WALLET_EXCEPTION_IF(td.m_key_image_known && !td.m_key_image_partial && ki != td.m_key_image, error::wallet_internal_error, "key_image generated not matched with cached key image");
  THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != pkey, error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

  THROW_WALLET_EXCEPTION_IF(
      !hwdev.generate_unlock_signature(in_ephemeral.pub, in_ephemeral.sec, signature),
      error::wallet_internal_error, "Hardware device failed to sign the unlock request");
  return true;
}
//----------------------------------------------------------------------------------------------------
mms::multisig_wallet_state wallet2::get_multisig_wallet_state() const
{
  mms::multisig_wallet_state state;
  state.nettype = m_nettype;
  state.multisig = multisig(&state.multisig_is_ready);
  state.has_multisig_partial_key_images = has_multisig_partial_key_images();
  state.multisig_rounds_passed = m_multisig_rounds_passed;
  state.num_transfer_details = m_transfers.size();
  if (state.multisig)
  {
    THROW_WALLET_EXCEPTION_IF(!m_original_keys_available, error::wallet_internal_error, "MMS use not possible because own original Monero address not available");
    state.address = m_original_address;
    state.view_secret_key = m_original_view_secret_key;
  }
  else
  {
    state.address = m_account.get_keys().m_account_address;
    state.view_secret_key = m_account.get_keys().m_view_secret_key;
  }
  state.mms_file=m_mms_file;
  return state;
}
//----------------------------------------------------------------------------------------------------
wallet_device_callback * wallet2::get_device_callback()
{
  if (!m_device_callback){
    m_device_callback.reset(new wallet_device_callback(this));
  }
  return m_device_callback.get();
}//----------------------------------------------------------------------------------------------------
void wallet2::on_device_button_request(uint64_t code)
{
  if (nullptr != m_callback)
    m_callback->on_device_button_request(code);
}
//----------------------------------------------------------------------------------------------------
void wallet2::on_device_button_pressed()
{
  if (nullptr != m_callback)
    m_callback->on_device_button_pressed();
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> wallet2::on_device_pin_request()
{
  if (nullptr != m_callback)
    return m_callback->on_device_pin_request();
  return std::nullopt;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> wallet2::on_device_passphrase_request(bool& on_device)
{
  if (nullptr != m_callback)
    return m_callback->on_device_passphrase_request(on_device);
  else
    on_device = true;
  return std::nullopt;
}
//----------------------------------------------------------------------------------------------------
void wallet2::on_device_progress(const hw::device_progress& event)
{
  if (nullptr != m_callback)
    m_callback->on_device_progress(event);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_rpc_status(const std::string &s) const
{
  if (m_trusted_daemon)
    return s;
  return "<error>";
}
//----------------------------------------------------------------------------------------------------

bool wallet2::save_to_file(const fs::path& path_to_file, std::string_view binary, bool is_printable) const
{
  if (is_printable || m_export_format == ExportFormat::Binary)
  {
    return tools::dump_file(path_to_file, binary);
  }

#ifdef _WIN32
  FILE *fp = _wfopen(path_to_file.c_str(), L"w+");
#else
  FILE *fp = fopen(path_to_file.c_str(), "w+");
#endif
  if (!fp)
  {
    MERROR("Failed to open wallet file for writing: " << path_to_file << ": " << strerror(errno));
    return false;
  }

  // Save the result b/c we need to close the fp before returning success/failure.
  int write_result = PEM_write(fp, ASCII_OUTPUT_MAGIC.c_str(), "", reinterpret_cast<const unsigned char *>(binary.data()), binary.length());
  fclose(fp);

  return write_result != 0;
}
//----------------------------------------------------------------------------------------------------

bool wallet2::load_from_file(const fs::path& path_to_file, std::string& target_str)
{
  std::string data;
  if (!tools::slurp_file(path_to_file, data))
    return false;

  if (data.find(ASCII_OUTPUT_MAGIC) == std::string::npos)
  {
    // It's NOT our ascii dump.
    target_str = std::move(data);
    return true;
  }

  // Creating a BIO and calling PEM_read_bio instead of simpler PEM_read
  // to avoid reading the file from disk twice.
  BIO* b = BIO_new_mem_buf((const void*) data.data(), data.length());

  char *name = nullptr;
  char *header = nullptr;
  unsigned char *openssl_data = nullptr;
  long len = 0;

  // Save the result b/c we need to free the data before returning success/failure.
  bool success = PEM_read_bio(b, &name, &header, &openssl_data, &len);
  if (success)
  {
    target_str.clear();
    target_str.append((const char*) openssl_data, len);
  }

  OPENSSL_free((void *) name);
  OPENSSL_free((void *) header);
  OPENSSL_free((void *) openssl_data);
  BIO_free(b);

  return success;
}
//----------------------------------------------------------------------------------------------------
void wallet2::hash_m_transfer(const transfer_details & transfer, crypto::hash &hash) const
{
  KECCAK_CTX state;
  keccak_init(&state);
  keccak_update(&state, (const uint8_t *) transfer.m_txid.data, sizeof(transfer.m_txid.data));
  keccak_update(&state, (const uint8_t *) transfer.m_internal_output_index, sizeof(transfer.m_internal_output_index));
  keccak_update(&state, (const uint8_t *) transfer.m_global_output_index, sizeof(transfer.m_global_output_index));
  keccak_update(&state, (const uint8_t *) transfer.m_amount, sizeof(transfer.m_amount));
  keccak_finish(&state, (uint8_t *) hash.data);
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::hash_m_transfers(int64_t transfer_height, crypto::hash &hash) const
{
  CHECK_AND_ASSERT_THROW_MES(transfer_height > (int64_t)m_transfers.size(), "Hash height is greater than number of transfers");

  KECCAK_CTX state;
  crypto::hash tmp_hash{};
  uint64_t current_height = 0;

  keccak_init(&state);
  for(const transfer_details & transfer : m_transfers){
    if (transfer_height >= 0 && current_height >= (uint64_t)transfer_height){
      break;
    }

    hash_m_transfer(transfer, tmp_hash);
    keccak_update(&state, (const uint8_t *) transfer.m_block_height, sizeof(transfer.m_block_height));
    keccak_update(&state, (const uint8_t *) tmp_hash.data, sizeof(tmp_hash.data));
    current_height += 1;
  }

  keccak_finish(&state, (uint8_t *) hash.data);
  return current_height;
}

bool parse_subaddress_indices(std::string_view arg, std::set<uint32_t>& subaddr_indices, std::string *err_msg)
{
  subaddr_indices.clear();

  if (arg.substr(0, 6) != "index="sv)
    return false;
  arg.remove_prefix(6);
  auto subaddr_indices_str = tools::split(arg, ","sv);

  for (const auto& subaddr_index_str : subaddr_indices_str)
  {
    uint32_t subaddr_index;
    if(!tools::parse_int(subaddr_index_str, subaddr_index))
    {
      subaddr_indices.clear();
      if (err_msg) *err_msg = tr("failed to parse index: ") + std::string{subaddr_index_str};
      return false;
    }
    subaddr_indices.insert(subaddr_index);
  }
  return true;
}

bool parse_priority(const std::string& arg, uint32_t& priority)
{
  auto priority_pos = std::find(
    allowed_priority_strings.begin(),
    allowed_priority_strings.end(),
    arg);
  if(priority_pos != allowed_priority_strings.end()) {
    priority = std::distance(allowed_priority_strings.begin(), priority_pos);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------------------------------------
void wallet2::finish_rescan_bc_keep_key_images(uint64_t transfer_height, const crypto::hash &hash)
{
  // Compute hash of m_transfers, if differs there had to be BC reorg.
  crypto::hash new_transfers_hash{};
  hash_m_transfers((int64_t) transfer_height, new_transfers_hash);

  if (new_transfers_hash != hash)
  {
    // Soft-Reset to avoid inconsistency in case of BC reorg.
    clear_soft(false);  // keep_key_images works only with soft reset.
    THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "Transfers changed during rescan, soft or hard rescan is needed");
  }

  // Restore key images in m_transfers from m_key_images
  for(auto it = m_key_images.begin(); it != m_key_images.end(); it++)
  {
    THROW_WALLET_EXCEPTION_IF(it->second >= m_transfers.size(), error::wallet_internal_error, "Key images cache contains illegal transfer offset");
    m_transfers[it->second].m_key_image = it->first;
    m_transfers[it->second].m_key_image_known = true;
  }
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_bytes_sent() const
{
  return m_http_client.get_bytes_sent() + m_long_poll_client.get_bytes_sent();
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_bytes_received() const
{
  return m_http_client.get_bytes_received() + m_long_poll_client.get_bytes_received();
}
}
