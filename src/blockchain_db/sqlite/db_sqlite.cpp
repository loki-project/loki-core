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
#include <SQLiteCpp/VariadicBind.h>
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

BlockchainSQLite::BlockchainSQLite():height(0){};

void BlockchainSQLite::load_database(std::optional<fs::path> file)
{
  if (m_storage)
    throw std::runtime_error("Reloading database not supported");  // TODO

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

  m_storage = std::make_unique<SQLite::Database>(SQLite::Database{fileString});

  if (!m_storage->tableExists("batch_sn_payments")) {
    create_schema();
  }

}

void BlockchainSQLite::create_schema() {

	SQLite::Transaction transaction{*m_storage};

	m_storage->exec(R"(
CREATE TABLE batch_sn_payments (
    address BLOB NOT NULL PRIMARY KEY,
    amount INTEGER NOT NULL,
    height INTEGER NOT NULL,
    UNIQUE(address)
    CHECK(amount >= 0)
);

CREATE TRIGGER batch_payments_delete_empty
AFTER UPDATE ON batch_sn_payments FOR EACH ROW WHEN NEW.amount = 0 THEN DELETE FROM batch_sn_payments WHERE address = NEW.address;
	)");

	transaction.commit();

	MINFO("Database setup complete");
} 

std::optional<uint64_t> BlockchainSQLite::retrieve_amount_by_address(const std::string& address) {
  SQLite::Statement st{*m_storage, "SELECT amount FROM batch_sn_payments WHERE address = ?"};
  st.bind(1, address);
  std::optional<uint64_t> amount;
  while (st.executeStep()) {
    assert(!amount);
    amount = st.getColumn(0).getInt();
  }
  return amount;
}

// tuple (Address, amount, height)
bool BlockchainSQLite::add_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::reward_payout>& payments, uint64_t height)
{
	SQLite::Transaction transaction{*m_storage};

  SQLite::Statement insert_payment{*m_storage,
    "INSERT INTO batch_sn_payments (address, amount, height) VALUES (?, ?, ?)"};

  SQLite::Statement update_payment{*m_storage,
    "UPDATE batch_sn_payments SET amount = ? WHERE address = ?"};

  for (auto& payment: payments) {
    std::string address_str = cryptonote::get_account_address_as_str(nettype, 0, payment.address);
    auto prev_amount = retrieve_amount_by_address(address_str);
    if(prev_amount.has_value()){
      MINFO("Record found for SN reward contributor, adding to database");
      update_payment.bind(*prev_amount + payment.amount, address_str);
    } else {
      MINFO("No record found for SN reward contributor, adding to database");
      insert_payment.bind(address_str, payment.amount, height);
    }
  };
  return true;
}

// tuple (Address, amount)
bool BlockchainSQLite::subtract_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::reward_payout>& payments, uint64_t height)
{
  //for (auto& payment: payments) {
    //std::string address_str = cryptonote::get_account_address_as_str(nettype, 0, payment.address);
    //auto prev_entry = m_storage->get<cryptonote::batch_sn_payments>(address_str);
    //if (payment.amount > prev_entry.amount)
      //return false;
    //m_storage->update_all(
        //set(
          //c(&cryptonote::batch_sn_payments::amount) = (prev_entry.amount - payment.amount),
          //c(&cryptonote::batch_sn_payments::height) = height),
        //where(c(&cryptonote::batch_sn_payments::address) = prev_entry.address));

    //// TODO: sean removing sqlite orm. amount == 0 isnt working, so workaround with amount <= 0 and amount >= 0
    //m_storage->remove_all<cryptonote::batch_sn_payments>(where(c(&cryptonote::batch_sn_payments::amount) <= 0 and c(&cryptonote::batch_sn_payments::amount) >= 0));
  //};
return true;
}

std::optional<std::vector<cryptonote::reward_payout>> BlockchainSQLite::get_sn_payments(cryptonote::network_type nettype, uint64_t height)
{

//const auto& conf = get_config(nettype);

////SELECT
  ////address,
  ////amount
//auto result = m_storage->select(
    //columns(
      //&cryptonote::batch_sn_payments::address,
      //&cryptonote::batch_sn_payments::amount)
    //,
    //where(c(&cryptonote::batch_sn_payments::height) <= height - conf.BATCHING_INTERVAL and
          //c(&cryptonote::batch_sn_payments::amount) > conf.MIN_BATCH_PAYMENT_AMOUNT),
    //order_by(&cryptonote::batch_sn_payments::height),
    //limit(conf.LIMIT_BATCH_OUTPUTS));

  //std::vector<cryptonote::reward_payout> payments;

  //for(auto &payment : result) {
    ////TODO sean remove
    ////std::cout << std::get<0>(payment) << '\t' << std::get<1>(payment) << std::endl;
    //cryptonote::address_parse_info info;
    //if (cryptonote::get_account_address_from_str(info, nettype, std::get<0>(payment)))
    //{
      //cryptonote::reward_payout pmt = {cryptonote::reward_type::snode, info.address, std::get<1>(payment)};

      //payments.push_back(pmt);
    //}
    //else
      //return std::nullopt;
  //}

  //return payments;
  return std::nullopt;
}

std::vector<cryptonote::reward_payout> BlockchainSQLite::calculate_rewards(const cryptonote::block& block, std::vector<cryptonote::reward_payout> contributors)
{
  uint64_t distribution_amount = block.reward;
  uint64_t total_contributed_to_winner_sn = 0;
  std::vector<cryptonote::reward_payout> payments;
  for (auto & contributor : contributors)
  {
    total_contributed_to_winner_sn += contributor.amount;
  }
  
  for (auto & contributor : contributors)
  {
    cryptonote::reward_payout something(cryptonote::reward_type::snode, contributor.address, (contributor.amount / total_contributed_to_winner_sn * distribution_amount));
    payments.emplace_back(cryptonote::reward_type::snode, contributor.address, (contributor.amount / total_contributed_to_winner_sn * distribution_amount));
  }
  return payments;
}

bool BlockchainSQLite::add_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::reward_payout> contributors)
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


  std::vector<cryptonote::reward_payout> payments = calculate_rewards(block, contributors);

  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - height: " << height);
  height++;
  MINFO(__FILE__ << ":" << __LINE__ << " TODO sean remove this - height: " << height);
  return add_sn_payments(nettype, payments, block.height);
}


bool BlockchainSQLite::pop_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::reward_payout> contributors)
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

  std::vector<cryptonote::reward_payout> payments = calculate_rewards(block, contributors);

  height--;
  return subtract_sn_payments(nettype, payments, block.height);
}

bool BlockchainSQLite::validate_batch_sn_reward_tx(uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, std::string *reason)
{
  return true;
}

bool BlockchainSQLite::validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> batch_payment, std::vector<cryptonote::reward_payout> calculated_payment, uint64_t height)
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
    if (!get_deterministic_output_key(calculated_payment[i].address, deterministic_keypair, i, out_eph_public_key))
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
