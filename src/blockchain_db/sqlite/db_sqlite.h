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

#pragma once

#include <string>
#include <filesystem>

#include "types.h"

#include "epee/misc_log_ex.h"
#include "../../cryptonote_basic/cryptonote_format_utils.h"
#include "../../cryptonote_core/cryptonote_tx_utils.h"
#include "common/fs.h"

#include <SQLiteCpp/SQLiteCpp.h>

namespace cryptonote
{

class BlockchainSQLite
{
public:
  BlockchainSQLite();

  void create_schema();
  void load_database(std::optional<fs::path> file);

  uint64_t batching_count();
  std::optional<uint64_t> retrieve_amount_by_address(const std::string& address);

  //add/subtract_sn_payments -> passing an array of addressesd and amount. These will be added or subtracted to the database for each address specified. If the address does not exist it will be created.
  bool add_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::batch_sn_payment>& payments, uint64_t height);
  bool subtract_sn_payments(cryptonote::network_type nettype, std::vector<cryptonote::batch_sn_payment>& payments, uint64_t height);

  //get_payments -> passing a block range will return an array of payments that should be created in a transaction on that date. Possibly allow for the returned figure to include all payments between that range. Or also an optional parameter if it is “unpaid” which should be the same in most normal cases
  std::optional<std::vector<cryptonote::batch_sn_payment>> get_sn_payments(cryptonote::network_type nettype, uint64_t height);

  std::vector<cryptonote::batch_sn_payment> calculate_rewards(cryptonote::network_type nettype, const cryptonote::block& block, std::vector<cryptonote::batch_sn_payment> contributors);

  bool add_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors);
  bool pop_block(cryptonote::network_type nettype, const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors);

  bool validate_batch_sn_payment_tx(uint8_t hf_version, uint64_t blockchain_height, cryptonote::transaction const &tx, std::string *reason);
  bool validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> batch_payment, std::vector<cryptonote::batch_sn_payment> calculated_payment, uint64_t height);
  bool is_governance_payment(cryptonote::tx_out out);

  uint64_t height;

  std::unique_ptr<SQLite::Database> db;
  std::string filename;

private:

};

}
