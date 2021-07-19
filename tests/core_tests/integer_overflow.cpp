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

#include "chaingen.h"
#include "integer_overflow.h"
#include "cryptonote_core/uptime_proof.h"

using namespace cryptonote;

namespace
{
  void split_miner_tx_outs(transaction& miner_tx, uint64_t amount_1)
  {
    uint64_t total_amount = get_outs_money_amount(miner_tx);
    uint64_t amount_2 = total_amount - amount_1;
    txout_target_v target = miner_tx.vout[0].target;

    miner_tx.vout.clear();

    tx_out out1;
    out1.amount = amount_1;
    out1.target = target;
    miner_tx.vout.push_back(out1);

    tx_out out2;
    out2.amount = amount_2;
    out2.target = target;
    miner_tx.vout.push_back(out2);
  }

  void append_tx_source_entry(std::vector<cryptonote::tx_source_entry>& sources, const transaction& tx, size_t out_idx)
  {
    cryptonote::tx_source_entry se;
    se.amount = tx.vout[out_idx].amount;
    se.push_output(0, var::get<cryptonote::txout_to_key>(tx.vout[out_idx].target).key, se.amount);
    se.real_output = 0;
    se.rct = false;
    se.real_out_tx_key = get_tx_pub_key_from_extra(tx);
    se.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(tx);
    se.real_output_in_tx_index = out_idx;

    sources.push_back(se);
  }
}

//======================================================================================================================

gen_uint_overflow_base::gen_uint_overflow_base()
  : m_last_valid_block_event_idx(static_cast<size_t>(-1))
{
  REGISTER_CALLBACK(mark_last_valid_block);
}

bool gen_uint_overflow_base::check_tx_verification_context(const cryptonote::tx_verification_context& tvc, bool tx_added, size_t event_idx, const cryptonote::transaction& /*tx*/)
{
  return m_last_valid_block_event_idx < event_idx ? !tx_added && tvc.m_verifivation_failed : tx_added && !tvc.m_verifivation_failed;
}

bool gen_uint_overflow_base::check_block_verification_context(const cryptonote::block_verification_context& bvc, size_t event_idx, const cryptonote::block& /*block*/)
{
  return m_last_valid_block_event_idx < event_idx ? bvc.m_verifivation_failed | bvc.m_marked_as_orphaned : !bvc.m_verifivation_failed;
}

bool gen_uint_overflow_base::mark_last_valid_block(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  m_last_valid_block_event_idx = ev_index - 1;
  return true;
}

//======================================================================================================================

bool gen_uint_overflow_1::generate(std::vector<test_event_entry>& events) const
{
  auto hard_forks = oxen_generate_hard_fork_table();
  oxen_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().version);
  gen.add_n_blocks(40);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base bob   = gen.add_account();
  cryptonote::account_base alice = gen.add_account();

  // Problem 1. Miner tx outputs overflow
  {
    oxen_blockchain_entry entry       = gen.create_next_block();
    if ( entry.block.major_version < cryptonote::network_version_19)
    {
      cryptonote::transaction &miner_tx = entry.block.miner_tx;
      split_miner_tx_outs(miner_tx, MONEY_SUPPLY);
      gen.add_block(entry, false /*can_be_added_to_blockchain*/, "We purposely overflow miner tx by MONEY_SUPPLY in the miner tx");
    }
  }

  // Problem 2. block_reward overflow
  {
    {
      // Create txs with fee greater than the block reward
      std::vector<cryptonote::transaction> txs;
      txs.push_back(gen.create_and_add_tx(gen.first_miner_, alice.get_keys().m_account_address, MK_COINS(1), MK_COINS(100) /*fee*/, false /*kept_by_block*/));

      oxen_blockchain_entry entry       = gen.create_next_block(txs);
      if ( entry.block.major_version < cryptonote::network_version_19)
      {
        cryptonote::transaction &miner_tx = entry.block.miner_tx;
        miner_tx.vout[0].amount           = 0; // Take partial block reward, fee > block_reward so ordinarly it would overflow. This should be disallowed
        gen.add_block(entry, false /*can_be_added_to_blockchain*/, "We should not be able to add TX because the fee is greater than the base miner reward");
      }
    }

    {
      // Set kept_by_block = true
      std::vector<cryptonote::transaction> txs;
      txs.push_back(gen.create_and_add_tx(gen.first_miner_, alice.get_keys().m_account_address, MK_COINS(1), MK_COINS(100) /*fee*/, true /*kept_by_block*/));

      oxen_blockchain_entry entry       = gen.create_next_block(txs);
      if ( entry.block.major_version < cryptonote::network_version_19)
      {
        cryptonote::transaction &miner_tx = entry.block.miner_tx;
        miner_tx.vout[0].amount           = 0; // Take partial block reward, fee > block_reward so ordinarly it would overflow. This should be disallowed
        gen.add_block(entry, false /*can_be_added_to_blockchain*/, "We should not be able to add TX because the fee is greater than the base miner reward even if kept_by_block is true");
      }
    }
  }
  return true;
}

//======================================================================================================================

bool gen_uint_overflow_2::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  GENERATE_ACCOUNT(miner_account);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  MAKE_ACCOUNT(events, bob_account);
  MAKE_ACCOUNT(events, alice_account);
  REWIND_BLOCKS(events, blk_0r, blk_0, miner_account);
  DO_CALLBACK(events, "mark_last_valid_block");

  // Problem 1. Regular tx outputs overflow
  std::vector<cryptonote::tx_source_entry> sources;
  for (size_t i = 0; i < blk_0.miner_tx.vout.size(); ++i)
  {
    if (TESTS_DEFAULT_FEE < blk_0.miner_tx.vout[i].amount)
    {
      append_tx_source_entry(sources, blk_0.miner_tx, i);
      break;
    }
  }
  if (sources.empty())
  {
    return false;
  }

  std::vector<cryptonote::tx_destination_entry> destinations;
  const account_public_address& bob_addr = bob_account.get_keys().m_account_address;
  destinations.push_back(tx_destination_entry(MONEY_SUPPLY, bob_addr, false));
  destinations.push_back(tx_destination_entry(MONEY_SUPPLY - 1, bob_addr, false));
  // sources.front().amount = destinations[0].amount + destinations[2].amount + destinations[3].amount + TESTS_DEFAULT_FEE
  destinations.push_back(tx_destination_entry(sources.front().amount - MONEY_SUPPLY - MONEY_SUPPLY + 1 - TESTS_DEFAULT_FEE, bob_addr, false));

  cryptonote::transaction tx_1;
  if (!construct_tx(miner_account.get_keys(), sources, destinations, std::nullopt, std::vector<uint8_t>(), tx_1, 0))
    return false;
  events.push_back(tx_1);

  MAKE_NEXT_BLOCK_TX1(events, blk_1, blk_0r, miner_account, tx_1);
  REWIND_BLOCKS(events, blk_1r, blk_1, miner_account);

  // Problem 2. Regular tx inputs overflow
  sources.clear();
  for (size_t i = 0; i < tx_1.vout.size(); ++i)
  {
    auto& tx_1_out = tx_1.vout[i];
    if (tx_1_out.amount < MONEY_SUPPLY - 1)
      continue;

    append_tx_source_entry(sources, tx_1, i);
  }

  destinations.clear();
  cryptonote::tx_destination_entry de;
  de.addr = alice_account.get_keys().m_account_address;
  de.amount = MONEY_SUPPLY - TESTS_DEFAULT_FEE;
  destinations.push_back(de);
  destinations.push_back(de);

  cryptonote::transaction tx_2;
  if (!construct_tx(bob_account.get_keys(), sources, destinations, std::nullopt, std::vector<uint8_t>(), tx_2, 0))
    return false;
  events.push_back(tx_2);

  MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_1r, miner_account, tx_2);

  return true;
}
