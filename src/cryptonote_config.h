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

#include <stdexcept>
#include <string>
#include <string_view>
#include <boost/uuid/uuid.hpp>
#include <stdexcept>
#include <chrono>
#include <array>
#include <ratio>

using namespace std::literals;

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            30
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2           60*10
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10
#define CRYPTONOTE_DEFAULT_TX_MIXIN                     9

#define STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS          20
#define STAKING_PORTIONS                                UINT64_C(0xfffffffffffffffc)
#define MAX_NUMBER_OF_CONTRIBUTORS                      4
#define MIN_PORTIONS                                    (STAKING_PORTIONS / MAX_NUMBER_OF_CONTRIBUTORS)

static_assert(STAKING_PORTIONS % 12 == 0, "Use a multiple of twelve, so that it divides evenly by two, three, or four contributors.");

#define STAKING_AUTHORIZATION_EXPIRATION_WINDOW         (60*60*24*7*2)  // 2 weeks

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               11

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 // NOTE(oxen): For testing suite, //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                9

#define FEE_PER_BYTE_V12                                ((uint64_t)17200) // Higher fee in v12 (only, v13 switches back)
#define FEE_PER_BYTE_V13                                ((uint64_t)215)   // Fallback used in wallet if no fee is available from RPC
#define FEE_PER_OUTPUT_V13                              ((uint64_t)20000000) // 0.02 OXEN per tx output (in addition to the per-byte fee), starting in v13
#define FEE_PER_OUTPUT_V18                              ((uint64_t)5000000) // 0.005 OXEN per tx output (in addition to the per-byte fee), starting in v18
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000) // 10 * pow(10,12)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)400000000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT        ((uint64_t)3000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V12    ((uint64_t)240000) // Only v12 (v13 switches back)

constexpr auto TARGET_BLOCK_TIME           = 2min;
constexpr uint64_t DIFFICULTY_WINDOW       = 59;
constexpr uint64_t DIFFICULTY_BLOCKS_COUNT(bool before_hf16)
{
  // NOTE: We used to have a different setup here where,
  // DIFFICULTY_WINDOW       = 60
  // DIFFICULTY_BLOCKS_COUNT = 61
  // next_difficulty_v2's  N = DIFFICULTY_WINDOW - 1
  //
  // And we resized timestamps/difficulties to (N+1) (chopping off the latest timestamp).
  //
  // Now we re-adjust DIFFICULTY_WINDOW to 59. To preserve the old behaviour we
  // add +2. After HF16 we avoid trimming the top block and just add +1.
  //
  // Ideally, we just set DIFFICULTY_BLOCKS_COUNT to DIFFICULTY_WINDOW
  // + 1 for before and after HF16 (having one unified constant) but this
  // requires some more investigation to get it working with pre HF16 blocks and
  // alt chain code without bugs.
  uint64_t result = (before_hf16) ? DIFFICULTY_WINDOW + 2 : DIFFICULTY_WINDOW + 1;
  return result;
}

constexpr uint64_t BLOCKS_EXPECTED_IN_HOURS(int hours) { return (1h / TARGET_BLOCK_TIME) * hours; }
constexpr uint64_t BLOCKS_EXPECTED_IN_DAYS(int days)   { return BLOCKS_EXPECTED_IN_HOURS(24) * days; }
constexpr uint64_t BLOCKS_EXPECTED_IN_YEARS(int years) { return BLOCKS_EXPECTED_IN_DAYS(365) * years; }

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   TARGET_BLOCK_TIME * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     (86400*7) //seconds, one week

#define MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME          (2 * 60 * 60) // seconds, 2 hours
// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

#define CRYPTONOTE_MAX_FRAGMENTS                        20 // ~20 * NOISE_BYTES max payload size for covert/noise send


#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT_OUT               8
#define P2P_DEFAULT_CONNECTIONS_COUNT_IN                32
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       2048       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     8192       // kB/s

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

// TODO(doyle): Deprecate after checkpointing hardfork, remove notion of being
// able to sync non-fluffy blocks, keep here so we can still accept blocks
// pre-hardfork
#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define CRYPTONOTE_NAME                         "oxen"
#define CRYPTONOTE_POOLDATA_FILENAME            "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_PER_BYTE_FEE                 cryptonote::network_version_10_bulletproofs
#define HF_VERSION_SMALLER_BP                   cryptonote::network_version_11_infinite_staking
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       cryptonote::network_version_11_infinite_staking
#define HF_VERSION_INCREASE_FEE                 cryptonote::network_version_12_checkpointing
#define HF_VERSION_PER_OUTPUT_FEE               cryptonote::network_version_13_enforce_checkpoints
#define HF_VERSION_ED25519_KEY                  cryptonote::network_version_13_enforce_checkpoints
#define HF_VERSION_FEE_BURNING                  cryptonote::network_version_14_blink
#define HF_VERSION_BLINK                        cryptonote::network_version_14_blink
#define HF_VERSION_MIN_2_OUTPUTS                cryptonote::network_version_16_pulse
#define HF_VERSION_REJECT_SIGS_IN_COINBASE      cryptonote::network_version_16_pulse
#define HF_VERSION_ENFORCE_MIN_AGE              cryptonote::network_version_16_pulse
#define HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY cryptonote::network_version_16_pulse
#define HF_VERSION_PULSE cryptonote::network_version_16_pulse
#define HF_VERSION_CLSAG                        cryptonote::network_version_16_pulse
#define HF_VERSION_PROOF_BTENC                  cryptonote::network_version_18

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8

#define HASH_OF_HASHES_STEP                     256

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500 // the smaller, the more space saved
//#define CRYPTONOTE_PRUNING_DEBUG_SPOOF_SEED

// New constants are intended to go here
namespace config
{
  inline constexpr auto DNS_TIMEOUT = 20s;
  inline constexpr uint64_t DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  inline constexpr uint8_t FEE_CALCULATION_MAX_RETRIES = 10;
  inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2000000000; // 2 * pow(10, 9)
  inline constexpr uint64_t BASE_REWARD_CLAMP_THRESHOLD = 100000000; // pow(10, 8)

  // Maximum allowed stake contribution, as a fraction of the available contribution room.  This
  // should generally be slightly larger than 1.  This is used to disallow large overcontributions
  // which can happen when there are competing stakes submitted at the same time for the same
  // service node.
  using MAXIMUM_ACCEPTABLE_STAKE = std::ratio<101, 100>;

  // Used to estimate the blockchain height from a timestamp, with some grace time.  This can drift
  // slightly over time (because average block time is not typically *exactly*
  // DIFFICULTY_TARGET_V2).
  inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 582088;
  inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595359932;

  inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 114;
  inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115;
  inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 116;
  inline constexpr uint16_t P2P_DEFAULT_PORT = 22022;
  inline constexpr uint16_t RPC_DEFAULT_PORT = 22023;
  inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 22024;
  inline constexpr uint16_t QNET_DEFAULT_PORT = 22025;
  inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0x46 ,0x61, 0x72, 0x62 ,0x61, 0x75, 0x74, 0x69, 0x2a, 0x4c, 0x61, 0x75, 0x66, 0x65, 0x79
    } }; // Bender's nightmare
  inline constexpr std::string_view GENESIS_TX = "021e01ff000380808d93f5d771027c4fd4553bc9886f1f49e3f76d945bf71e8632a94e6c177b19cbc780e7e6bdb48080b4ccd4dfc60302c8b9f6461f58ef3f2107e577c7425d06af584a1c7482bf19060e84059c98b4c3808088fccdbcc32302732b53b0b0db706fcc3087074fb4b786da5ab72b2065699f9453448b0db27f892101ed71f2ce3fc70d7b2036f8a4e4b3fb75c66c12184b55a908e7d1a1d6995566cf00"sv;
  inline constexpr uint32_t GENESIS_NONCE = 1022201;

  inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = BLOCKS_EXPECTED_IN_DAYS(7);
  inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
  {
    "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67wZ73uh9AujXLQ1RKmXEyL"sv, // hardfork v7-10
    "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdycETKM1STrz"sv, // hardfork v11
  };

  inline constexpr auto UPTIME_PROOF_TOLERANCE = 5min; // How much an uptime proof timestamp can deviate from our timestamp before we refuse it
  inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 30s; // How long to wait after startup before broadcasting a proof
  inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 30s; // How frequently to check whether we need to broadcast a proof
  inline constexpr auto UPTIME_PROOF_FREQUENCY = 1h; // How often to send proofs out to the network since the last proof we successfully sent.  (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum accepted time between proofs is half of this.
  inline constexpr auto UPTIME_PROOF_VALIDITY = 2h + 5min; // The maximum time that we consider an uptime proof to be valid (i.e. after this time since the last proof we consider the SN to be down)
  inline constexpr auto REACHABLE_MAX_FAILURE_VALIDITY = 5min; // If we don't hear any SS ping/lokinet session test failures for more than this long then we start considering the SN as passing for the purpose of obligation testing until we get another test result.  This should be somewhat larger than SS/lokinet's max re-test backoff (2min).

  // Hash domain separators
  inline constexpr std::string_view HASH_KEY_BULLETPROOF_EXPONENT = "bulletproof"sv;
  inline constexpr std::string_view HASH_KEY_RINGDB = "ringdsb\0"sv;
  inline constexpr std::string_view HASH_KEY_SUBADDRESS = "SubAddr\0"sv;
  inline constexpr unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  inline constexpr unsigned char HASH_KEY_WALLET = 0x8c;
  inline constexpr unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  inline constexpr unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x58;
  inline constexpr unsigned char HASH_KEY_MEMORY = 'k';
  inline constexpr std::string_view HASH_KEY_MULTISIG = "Multisig\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_ROUND = "CLSAG_round"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_AGG_0 = "CLSAG_agg_0"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_AGG_1 = "CLSAG_agg_1"sv;

  //Batching SN Rewards
  inline constexpr uint64_t BATCHING_INTERVAL = 6;
  inline constexpr uint64_t MIN_BATCH_PAYMENT_AMOUNT = 10;
  inline constexpr uint64_t LIMIT_BATCH_OUTPUTS = 15;

  namespace testnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 339767;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595360006;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 156;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 158;
    inline constexpr uint16_t P2P_DEFAULT_PORT = 38156;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 38157;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 38158;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 38159;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0x5f, 0x3a, 0x78, 0x65, 0xe1, 0x6f, 0xca, 0xb8, 0x02, 0xa1, 0xdc, 0x17, 0x61, 0x64, 0x15, 0xbe,
      } }; // Bender's daydream
    inline constexpr std::string_view GENESIS_TX = "03011e001e01ff00018080c9db97f4fb270259b546996f69aa71abe4238995f41d780ab1abebcac9f00e808f147bdb9e3228420112573af8c309b69a1a646f41b5212ba7d9c4590bf86e04f36c486467cfef9d3d72000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 10001;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 1000;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "T6SUprTYE5rQpep9iQFxyPcKVd91DFR1fQ1Qsyqp5eYLiFc8XuYd3reRE71qDL8c3DXioUbDEpDFdaUpetnL37NS1R3rzoKxi"sv, // hardfork v7-9
      "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1cRM1SRNqbp44"sv, // hardfork v10
    };

    // Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 10min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 21min;
  }

  namespace devnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1597170000;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 3930; // ~ dV1 .. dV3
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442; // ~ dVA .. dVC
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850; // ~dVa .. dVc
    inline constexpr uint16_t P2P_DEFAULT_PORT = 38856;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 38857;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 38858;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 38859;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0xa9, 0xf7, 0x5c, 0x7d, 0x55, 0x17, 0xcb, 0x6b, 0x5b, 0xf4, 0x63, 0x79, 0x7a, 0x57, 0xab, 0xd3
      } };
    inline constexpr std::string_view GENESIS_TX = "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec1526da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 12345;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = BLOCKS_EXPECTED_IN_DAYS(7);
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv, // hardfork v7-9
      "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv, // hardfork v10
    };

    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
  }

  namespace fakechain {
    // Fakechain uptime proofs are 60x faster than mainnet, because this really only runs on a
    // hand-crafted, typically local temporary network.
    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
    inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 5s;
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 1min;
    inline constexpr auto UPTIME_PROOF_VALIDITY = 2min + 5s;
  }
}

namespace cryptonote
{
  enum network_version
  {
    network_version_7 = 7,
    network_version_8,
    network_version_9_service_nodes, // Proof Of Stake w/ Service Nodes
    network_version_10_bulletproofs, // Bulletproofs, Service Node Grace Registration Period, Batched Governance
    network_version_11_infinite_staking, // Infinite Staking, CN-Turtle
    network_version_12_checkpointing, // Checkpointing, Relaxed Deregistration, RandomXL, Oxen Storage Server
    network_version_13_enforce_checkpoints,
    network_version_14_blink,
    network_version_15_ons,
    network_version_16_pulse,
    network_version_17,
    network_version_18,
    network_version_19,

    network_version_count,
  };

  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    DEVNET,
    FAKECHAIN,
    UNDEFINED = 255
  };

  inline constexpr std::string_view network_type_str(network_type nettype)
  {
    switch(nettype)
    {
      case MAINNET: return "Mainnet"sv;
      case TESTNET: return "Testnet"sv;
      case DEVNET: return "Devnet"sv;
      case FAKECHAIN: return "Fakenet"sv;
      case UNDEFINED: return "Undefined Net"sv;
    }
    return "Unhandled Net"sv;
  }

  struct network_config
  {
    network_type NETWORK_TYPE;
    uint64_t HEIGHT_ESTIMATE_HEIGHT;
    time_t HEIGHT_ESTIMATE_TIMESTAMP;
    uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t P2P_DEFAULT_PORT;
    uint16_t RPC_DEFAULT_PORT;
    uint16_t ZMQ_RPC_DEFAULT_PORT;
    uint16_t QNET_DEFAULT_PORT;
    boost::uuids::uuid NETWORK_ID;
    std::string_view GENESIS_TX;
    uint32_t GENESIS_NONCE;
    uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    std::chrono::seconds UPTIME_PROOF_TOLERANCE;
    std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
    std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
    std::chrono::seconds UPTIME_PROOF_FREQUENCY;
    std::chrono::seconds UPTIME_PROOF_VALIDITY;

    uint64_t BATCHING_INTERVAL;
    uint64_t MIN_BATCH_PAYMENT_AMOUNT;
    uint64_t LIMIT_BATCH_OUTPUTS;

    inline constexpr std::string_view governance_wallet_address(int hard_fork_version) const {
      const auto wallet_switch =
        (NETWORK_TYPE == MAINNET || NETWORK_TYPE == FAKECHAIN)
        ? network_version_11_infinite_staking
        : network_version_10_bulletproofs;
      return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
    }
  };
  inline constexpr network_config mainnet_config{
    MAINNET,
    ::config::HEIGHT_ESTIMATE_HEIGHT,
    ::config::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::P2P_DEFAULT_PORT,
    ::config::RPC_DEFAULT_PORT,
    ::config::ZMQ_RPC_DEFAULT_PORT,
    ::config::QNET_DEFAULT_PORT,
    ::config::NETWORK_ID,
    ::config::GENESIS_TX,
    ::config::GENESIS_NONCE,
    ::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::UPTIME_PROOF_FREQUENCY,
    config::UPTIME_PROOF_VALIDITY,
    config::BATCHING_INTERVAL,
    config::MIN_BATCH_PAYMENT_AMOUNT,
    config::LIMIT_BATCH_OUTPUTS,
  };
  inline constexpr network_config testnet_config{
    TESTNET,
    ::config::testnet::HEIGHT_ESTIMATE_HEIGHT,
    ::config::testnet::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::testnet::P2P_DEFAULT_PORT,
    ::config::testnet::RPC_DEFAULT_PORT,
    ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
    ::config::testnet::QNET_DEFAULT_PORT,
    ::config::testnet::NETWORK_ID,
    ::config::testnet::GENESIS_TX,
    ::config::testnet::GENESIS_NONCE,
    ::config::testnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::testnet::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::testnet::UPTIME_PROOF_FREQUENCY,
    config::testnet::UPTIME_PROOF_VALIDITY,
    config::BATCHING_INTERVAL,
    config::MIN_BATCH_PAYMENT_AMOUNT,
    config::LIMIT_BATCH_OUTPUTS,
  };
  inline constexpr network_config devnet_config{
    DEVNET,
    ::config::devnet::HEIGHT_ESTIMATE_HEIGHT,
    ::config::devnet::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::devnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::devnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::devnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::devnet::P2P_DEFAULT_PORT,
    ::config::devnet::RPC_DEFAULT_PORT,
    ::config::devnet::ZMQ_RPC_DEFAULT_PORT,
    ::config::devnet::QNET_DEFAULT_PORT,
    ::config::devnet::NETWORK_ID,
    ::config::devnet::GENESIS_TX,
    ::config::devnet::GENESIS_NONCE,
    ::config::devnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::devnet::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::UPTIME_PROOF_STARTUP_DELAY,
    config::UPTIME_PROOF_CHECK_INTERVAL,
    config::testnet::UPTIME_PROOF_FREQUENCY,
    config::testnet::UPTIME_PROOF_VALIDITY,
    config::BATCHING_INTERVAL,
    config::MIN_BATCH_PAYMENT_AMOUNT,
    config::LIMIT_BATCH_OUTPUTS,
  };
  inline constexpr network_config fakenet_config{
    FAKECHAIN,
    ::config::HEIGHT_ESTIMATE_HEIGHT,
    ::config::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::P2P_DEFAULT_PORT,
    ::config::RPC_DEFAULT_PORT,
    ::config::ZMQ_RPC_DEFAULT_PORT,
    ::config::QNET_DEFAULT_PORT,
    ::config::NETWORK_ID,
    ::config::GENESIS_TX,
    ::config::GENESIS_NONCE,
    100, //::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::GOVERNANCE_WALLET_ADDRESS,
    config::UPTIME_PROOF_TOLERANCE,
    config::fakechain::UPTIME_PROOF_STARTUP_DELAY,
    config::fakechain::UPTIME_PROOF_CHECK_INTERVAL,
    config::fakechain::UPTIME_PROOF_FREQUENCY,
    config::fakechain::UPTIME_PROOF_VALIDITY,
    config::BATCHING_INTERVAL,
    config::MIN_BATCH_PAYMENT_AMOUNT,
    config::LIMIT_BATCH_OUTPUTS,
  };

  inline constexpr const network_config& get_config(network_type nettype)
  {
    switch (nettype)
    {
      case MAINNET: return mainnet_config;
      case TESTNET: return testnet_config;
      case DEVNET: return devnet_config;
      case FAKECHAIN: return fakenet_config;
      default: throw std::runtime_error{"Invalid network type"};
    }
  }
}
