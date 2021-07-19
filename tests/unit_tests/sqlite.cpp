// Copyright (c) 2021, The Oxen Project
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

#include <gtest/gtest.h>

#include "blockchain_db/sqlite/db_sqlite.h"


TEST(SQLITE, AddSNRewards)
{
  cryptonote::BlockchainSQLite sqliteDB;
  sqliteDB.load_database(":memory:");

  std::cout << "in memory db opened" << std::endl;

  EXPECT_TRUE(sqliteDB.batching_count() == 0);

  std::vector<cryptonote::batch_sn_payment> t1;

  cryptonote::address_parse_info wallet_address;

  cryptonote::get_account_address_from_str(wallet_address, cryptonote::network_type::TESTNET, "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1cRM1SRNqbp44");

  t1.emplace_back(wallet_address.address, 16500000000, cryptonote::network_type::TESTNET);
  t1.emplace_back(wallet_address.address, 16500000000, cryptonote::network_type::TESTNET);
  t1.emplace_back(wallet_address.address, 16500000000/2, cryptonote::network_type::TESTNET);

  bool success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 1); 
  EXPECT_TRUE(success);
  success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 2); 
  EXPECT_TRUE(success);
  success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 3); 
  EXPECT_TRUE(success);
  success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 4); 
  EXPECT_TRUE(success);
  success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 5); 
  EXPECT_TRUE(success);
  success = sqliteDB.add_sn_payments(cryptonote::network_type::TESTNET, t1, 6); 
  EXPECT_TRUE(success);

  EXPECT_TRUE(sqliteDB.batching_count() == 1);

  std::optional<std::vector<cryptonote::batch_sn_payment>> p1;
  p1 = sqliteDB.get_sn_payments(cryptonote::network_type::TESTNET, 6);
  EXPECT_TRUE(p1.has_value());
  EXPECT_TRUE((*p1).size() == 0);

  std::optional<std::vector<cryptonote::batch_sn_payment>> p2;
  p2 = sqliteDB.get_sn_payments(cryptonote::network_type::TESTNET, 7);
  EXPECT_TRUE(p2.has_value());
  EXPECT_TRUE((*p2).size() == 1);
  uint64_t expected_amount = (16500000000 * 2 + 16500000000/2) * 6;
  EXPECT_TRUE((*p2)[0].amount == expected_amount);
  //EXPECT_TRUE((*p2)[0].amount == (16500000000) * 6);

  // Subtract the amount back out and expect the database to be empty
  std::vector<cryptonote::batch_sn_payment> t2;
  t2.emplace_back(wallet_address.address, expected_amount, cryptonote::network_type::TESTNET);

  success = sqliteDB.subtract_sn_payments(cryptonote::network_type::TESTNET, t2, 7); 
  EXPECT_TRUE(success);
  EXPECT_TRUE(sqliteDB.batching_count() == 0);
}

