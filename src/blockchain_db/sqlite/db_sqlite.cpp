// Copyright (c) 2021, The Oxen Project
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

#include "db_sqlite.h"

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

#include <string>
#include <iostream>
#include <cassert>

#include "cryptonote_core/blockchain.h"
#include "common/string_util.h"


#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "blockchain.db.sqlite"

namespace cryptonote
{

template <typename T> constexpr bool is_cstr = false;
template <size_t N> constexpr bool is_cstr<char[N]> = true;
template <size_t N> constexpr bool is_cstr<const char[N]> = true;
template <> constexpr bool is_cstr<char*> = true;
template <> constexpr bool is_cstr<const char*> = true;

// Simple wrapper class that can be used to bind a blob through the templated binding code below.
// E.g. `exec_query(st, 100, 42, blob_binder{data})` binds the third parameter using no-copy blob
// binding of the contained data.
struct blob_binder {
    std::string_view data;
    explicit blob_binder(std::string_view d) : data{d} {}
};

// Binds a string_view as a no-copy blob at parameter index i.
void bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob) {
    st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
}

// Called from exec_query and similar to bind statement parameters for immediate execution.  strings
// (and c strings) use no-copy binding; user_pubkey_t values use *two* sequential binding slots for
// pubkey (first) and type (second); integer values are bound by value.  You can bind a blob (by
// reference, like strings) by passing `blob_binder{data}`.
template <typename T>
void bind_oneshot(SQLite::Statement& st, int& i, const T& val) {
    if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
        st.bindNoCopy(i++, val);
    else if constexpr (std::is_same_v<T, blob_binder>)
        bind_blob_ref(st, i++, val.data);
    else
        st.bind(i++, val);
}

// Executes a query that does not expect results.  Optionally binds parameters, if provided.
// Returns the number of affected rows; throws on error or if results are returned.
template <typename... T>
int exec_query(SQLite::Statement& st, const T&... bind) {
    int i = 1;
    (bind_oneshot(st, i, bind), ...);
    return st.exec();
}

// Same as above, but prepares a literal query on the fly for use with queries that are only used
// once.
template <typename... T>
int exec_query(SQLite::Database& db, const char* query, const T&... bind) {
    SQLite::Statement st{db, query};
    return exec_query(st, bind...);
}

constexpr std::chrono::milliseconds SQLite_busy_timeout = 3s;

BlockchainSQLite::BlockchainSQLite():height(0){};


void BlockchainSQLite::create_schema() {

	SQLite::Transaction transaction{*db};

	db->exec(R"(
CREATE TABLE batch_sn_payments (
    address BLOB NOT NULL PRIMARY KEY,
    amount BIGINT NOT NULL,
    height BIGINT NOT NULL,
    UNIQUE(address)
    CHECK(amount >= 0)
);

CREATE TRIGGER batch_payments_delete_empty
AFTER UPDATE ON batch_sn_payments FOR EACH ROW WHEN NEW.amount = 0 
BEGIN
  DELETE FROM batch_sn_payments WHERE address = NEW.address;
END;
	)");

	transaction.commit();

	MINFO("Database setup complete");
} 

void BlockchainSQLite::load_database(std::optional<fs::path> file)
{
  if (db)
    throw std::runtime_error("Reloading database not supported");

  std::string fileString;
  if (file.has_value())
  {
    fileString = file->string();
    MINFO("Loading sqliteDB from file " << fileString);
  }
  else
  {
    fileString = ":memory:";
    MINFO("Loading memory-backed sqliteDB");
  }
  db = std::make_unique<SQLite::Database>(
      SQLite::Database{
      fileString, 
      SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX,
      SQLite_busy_timeout.count()
      });

  if (!db->tableExists("batch_sn_payments")) {
    create_schema();
  }
}

uint64_t BlockchainSQLite::batching_count() {
  SQLite::Statement st{*db, "SELECT count(*) FROM batch_sn_payments"};
  uint64_t count = 0;
  while (st.executeStep()) {
    count = st.getColumn(0).getInt();
  }
  return count;
}

std::optional<uint64_t> BlockchainSQLite::retrieve_amount_by_address(const std::string& address) {
  SQLite::Statement st{*db, "SELECT amount FROM batch_sn_payments WHERE address = ?"};
  st.bind(1, address);
  std::optional<uint64_t> amount = std::nullopt;
  while (st.executeStep()) {
    assert(!amount);
    amount.emplace(st.getColumn(0).getInt64());
  }
  return amount;
}

// tuple (Address, amount, height)
bool BlockchainSQLite::add_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::batch_sn_payment>& payments, uint64_t height)
{

  //Assert that all the payments are unique
  // TODO sean: unsure if this is necessary. The rewards probably don't ever need to support multiple additions to the same address. Thought it would mess with the database but it looks like its supported
  //std::sort(payments.begin(),payments.end(),[](auto i, auto j){ return tools::view_guts(i.address) < tools::view_guts(j.address); });
  //auto uniq = std::unique( payments.begin(), payments.end(), [](auto i, auto j){ return tools::view_guts(i.address) == tools::view_guts(j.address); } );
  //if(uniq != payments.end()) {
    //MWARNING("Duplicate addresses in payments list");
    //return false;
  //}

	SQLite::Transaction transaction{*db};

  SQLite::Statement insert_payment{*db,
    "INSERT INTO batch_sn_payments (address, amount, height) VALUES (?, ?, ?)"};

  SQLite::Statement update_payment{*db,
    "UPDATE batch_sn_payments SET amount = ? WHERE address = ?"};

  for (auto& payment: payments) {
    std::string address_str = cryptonote::get_account_address_as_str(nettype, 0, payment.address_info.address);
    auto prev_amount = retrieve_amount_by_address(address_str);
    if(prev_amount.has_value()){
      MDEBUG("Record found for SN reward contributor, adding " << address_str << "to database with amount " << int64_t{payment.amount});
      exec_query(update_payment, int64_t{*prev_amount} + int64_t{payment.amount}, address_str);
      update_payment.reset();
    } else {
      MDEBUG("No Record found for SN reward contributor, adding " << address_str << "to database with amount " << int64_t{payment.amount});
      exec_query(insert_payment, address_str, int64_t{payment.amount}, int64_t{height});
      insert_payment.reset();
    }
  };

  //TODO sean: revert on failure?
  transaction.commit();

  return true;
}

// tuple (Address, amount)
bool BlockchainSQLite::subtract_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::batch_sn_payment>& payments, uint64_t height)
{
	SQLite::Transaction transaction{*db};

  SQLite::Statement update_payment{*db,
    "UPDATE batch_sn_payments SET amount = ? WHERE address = ?"};

  for (auto& payment: payments) {
    std::string address_str = cryptonote::get_account_address_as_str(nettype, 0, payment.address_info.address);
    auto prev_amount = retrieve_amount_by_address(address_str);
    if(prev_amount.has_value()){
      if (payment.amount > *prev_amount)
        return false;
      //update_payment.bind(*prev_amount - payment.amount, address_str);
      exec_query(update_payment, int64_t{*prev_amount - payment.amount}, address_str);
      update_payment.reset();

    } else {
      return false;
    }
  };

  transaction.commit();

  return true;
}

std::optional<std::vector<cryptonote::batch_sn_payment>> BlockchainSQLite::get_sn_payments(cryptonote::network_type nettype, uint64_t height)
{

  const auto& conf = get_config(nettype);

  SQLite::Statement select_payments{*db,
    "SELECT address, amount FROM batch_sn_payments WHERE height <= ? AND amount > ? ORDER BY height LIMIT ?"};

  select_payments.bind(1, int64_t{height - conf.BATCHING_INTERVAL});
  select_payments.bind(2, int64_t{conf.MIN_BATCH_PAYMENT_AMOUNT});
  select_payments.bind(3, int64_t{conf.LIMIT_BATCH_OUTPUTS});

  std::vector<cryptonote::batch_sn_payment> payments;

  std::string address;
  uint64_t amount;
  while (select_payments.executeStep())
  {
    cryptonote::address_parse_info info;
    address = select_payments.getColumn(0).getString();
    amount = uint64_t{select_payments.getColumn(1).getInt64()};
    //TODO sean make this from constructor
    if (cryptonote::get_account_address_from_str(info, nettype, address))
    {
      cryptonote::batch_sn_payment pmt(info, amount, nettype);

      //TODO sean emplace back
      payments.push_back(pmt);
    }
    else
      return std::nullopt;
  }

  return payments;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::calculate_rewards(cryptonote::network_type nettype, const cryptonote::block& block, std::vector<cryptonote::batch_sn_payment> contributors)
{
  uint64_t distribution_amount = block.reward;
  uint64_t total_contributed_to_winner_sn = 0;
  std::vector<cryptonote::batch_sn_payment> payments;
  for (auto & contributor : contributors)
  {
    total_contributed_to_winner_sn += contributor.amount;
  }
  
  for (auto & contributor : contributors)
  {
    //cryptonote::batch_sn_payment something(contributor.address, (contributor.amount / total_contributed_to_winner_sn * distribution_amount));
    payments.emplace_back(contributor.address, (contributor.amount / total_contributed_to_winner_sn * distribution_amount), nettype);
  }
  return payments;
}

bool BlockchainSQLite::add_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors)
{

  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - blcok height: " << cryptonote::get_block_height(block));
  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - db height: " << height);
  assert(cryptonote::get_block_height(block) == height +1);
  //assert(cryptonote::is_valid_address(block.service_node_winner_key, nettype));

  auto hf_version = block.major_version;
  if (hf_version < cryptonote::network_version_19)
  {
    height++;
    return true;
  }

  std::vector<std::tuple<crypto::public_key, uint64_t>> batched_paid_out;

  bool search_for_governance_reward = false;
  uint64_t batched_governance_reward = 0;
  if(height_has_governance_output(nettype, hf_version, block.height)) {
    size_t num_blocks = cryptonote::get_config(nettype).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    batched_governance_reward = num_blocks * FOUNDATION_REWARD_HF17;
    search_for_governance_reward = true;

  }

  for(auto & vout : block.miner_tx.vout)
  {
    if(search_for_governance_reward && vout.amount == batched_governance_reward) {
      continue;
    }
    batched_paid_out.emplace_back(var::get<txout_to_key>(vout.target).key,vout.amount);
  }

  auto calculated_rewards = get_sn_payments(nettype, block.height);
  if (!validate_batch_payment(batched_paid_out, *calculated_rewards, block.height)) {
    return false;
  } else {
    if (!subtract_sn_payments(nettype, *calculated_rewards, block.height)) {
      return false;
    }
  }


  std::vector<cryptonote::batch_sn_payment> payments = calculate_rewards(nettype, block, contributors);

  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - height: " << height);
  height++;
  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - height: " << height);
  return add_sn_payments(nettype, payments, block.height);
}


bool BlockchainSQLite::pop_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors)
{
  assert(cryptonote::get_block_height(block) == height);
  //assert(cryptonote::is_valid_address(block.service_node_winner, nettype));

  auto hf_version = block.major_version;
  if (hf_version < cryptonote::network_version_19)
  {
    height--;
    return true;
  }

  std::vector<std::tuple<crypto::public_key, uint64_t>> batched_paid_out;

  bool search_for_governance_reward = false;
  uint64_t batched_governance_reward = 0;
  if(height_has_governance_output(nettype, hf_version, block.height)) {
    size_t num_blocks = cryptonote::get_config(nettype).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    batched_governance_reward = num_blocks * FOUNDATION_REWARD_HF17;
    search_for_governance_reward = true;
  }

  for(auto & vout : block.miner_tx.vout)
  {
    if(search_for_governance_reward && vout.amount == batched_governance_reward) 
      continue;
    batched_paid_out.emplace_back(var::get<txout_to_key>(vout.target).key,vout.amount);
  }

  auto calculated_rewards = get_sn_payments(nettype, block.height);
  if (!validate_batch_payment(batched_paid_out, *calculated_rewards, block.height)) {
    return false;
  } else {
    if (!add_sn_payments(nettype, *calculated_rewards, block.height))
      return false;
  }

  std::vector<cryptonote::batch_sn_payment> payments = calculate_rewards(nettype, block, contributors);

  height--;
  return subtract_sn_payments(nettype, payments, block.height);
}

bool BlockchainSQLite::validate_batch_sn_payment_tx(uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, std::string *reason)
{
  return true;
}

bool BlockchainSQLite::validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> batch_payment, std::vector<cryptonote::batch_sn_payment> calculated_payment, uint64_t height)
{
  keypair const txkey{hw::get_device("default")};
  size_t length_batch_payment = batch_payment.size();
  size_t length_calculated_payment = calculated_payment.size();

  if (length_batch_payment != length_calculated_payment)
  {
    MERROR("Length of batch paments does not match");
    return false;
  }

  keypair const &derivation_pair = txkey;
  for(int i=0;i<length_batch_payment;i++) {
    const auto& [pk, amount] = batch_payment[i];
    if (calculated_payment[i].amount != amount)
    {
      MERROR("Batched amounts do not match");
      return false;
    }
    //TODO sean, this loses information because we delete out the reward vout so batch_payment might no longer align with the block outputs
    keypair const deterministic_keypair = get_deterministic_keypair_from_height(height);
    crypto::public_key out_eph_public_key{};
    if (!get_deterministic_output_key(calculated_payment[i].address_info.address, deterministic_keypair, i, out_eph_public_key))
    {
      MERROR("Failed to generate output one-time public key");
      return false;
    }
    if (tools::view_guts(out_eph_public_key) != tools::view_guts(pk))
    {
      return false;
    }
  }

  return true;
}


} // namespace cryptonote
