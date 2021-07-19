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
#include "chaingen_tests_list.h"
#include "common/util.h"
#include "common/command_line.h"
#include "cryptonote_core/uptime_proof.h"
#include "transaction_tests.h"

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_filter                      = { "filter", "Regular expression filter for which tests to run" };
  const command_line::arg_descriptor<bool>        arg_list_tests                  = {"list_tests", ""};
  const command_line::arg_descriptor<std::string> arg_log_level                   = {"log-level", ""};
}

int main(int argc, char* argv[])
{
  TRY_ENTRY();
  tools::on_startup();
  epee::string_tools::set_module_name_and_folder(argv[0]);

  // Bypass tx version checks for core tests:
  cryptonote::hack::test_suite_permissive_txes = true;

  //set up logging options
  mlog_configure(mlog_get_default_log_path("core_tests.log"), true);
  
  po::options_description desc_options("Allowed options");
  command_line::add_arg(desc_options, command_line::arg_help);
  command_line::add_arg(desc_options, arg_filter);
  command_line::add_arg(desc_options, arg_list_tests);
  command_line::add_arg(desc_options, arg_log_level);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << desc_options << std::endl;
    return 0;
  }

  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log_level(0);

  const std::string filter = command_line::get_arg(vm, arg_filter);

  size_t tests_count = 0;
  std::vector<std::string> failed_tests;
  bool list_tests = false;
  {
    list_tests = command_line::get_arg(vm, arg_list_tests);

    // NOTE: Loki Tests
    GENERATE_AND_PLAY(oxen_checkpointing_alt_chain_handle_alt_blocks_at_tip);
    GENERATE_AND_PLAY(oxen_checkpointing_alt_chain_more_service_node_checkpoints_less_pow_overtakes);
    GENERATE_AND_PLAY(oxen_checkpointing_alt_chain_receive_checkpoint_votes_should_reorg_back);
    GENERATE_AND_PLAY(oxen_checkpointing_alt_chain_too_old_should_be_dropped);
    GENERATE_AND_PLAY(oxen_checkpointing_alt_chain_with_increasing_service_node_checkpoints);
    GENERATE_AND_PLAY(oxen_checkpointing_service_node_checkpoint_from_votes);
    GENERATE_AND_PLAY(oxen_checkpointing_service_node_checkpoints_check_reorg_windows);
    GENERATE_AND_PLAY(oxen_core_block_reward_unpenalized_pre_pulse);
    GENERATE_AND_PLAY(oxen_core_block_reward_unpenalized_post_pulse);
    GENERATE_AND_PLAY(oxen_core_block_rewards_lrc6);
    GENERATE_AND_PLAY(oxen_core_fee_burning);
    GENERATE_AND_PLAY(oxen_core_governance_batched_reward);
    GENERATE_AND_PLAY(oxen_core_test_deregister_preferred);
    GENERATE_AND_PLAY(oxen_core_test_deregister_safety_buffer);
    GENERATE_AND_PLAY(oxen_core_test_deregister_too_old);
    GENERATE_AND_PLAY(oxen_core_test_deregister_zero_fee);
    GENERATE_AND_PLAY(oxen_core_test_deregister_on_split);
    GENERATE_AND_PLAY(oxen_core_test_state_change_ip_penalty_disallow_dupes);
    GENERATE_AND_PLAY(oxen_name_system_disallow_reserved_type);
    GENERATE_AND_PLAY(oxen_name_system_expiration);
    GENERATE_AND_PLAY(oxen_name_system_get_mappings_by_owner);
    GENERATE_AND_PLAY(oxen_name_system_get_mappings_by_owners);
    GENERATE_AND_PLAY(oxen_name_system_get_mappings);
    GENERATE_AND_PLAY(oxen_name_system_handles_duplicate_in_ons_db);
    GENERATE_AND_PLAY(oxen_name_system_handles_duplicate_in_tx_pool);
    GENERATE_AND_PLAY(oxen_name_system_invalid_tx_extra_params);
    GENERATE_AND_PLAY(oxen_name_system_large_reorg);
    GENERATE_AND_PLAY(oxen_name_system_name_renewal);
    GENERATE_AND_PLAY(oxen_name_system_name_value_max_lengths);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_after_expiry_fails);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_argon2);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_multiple_owners);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_non_existent_name_fails);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_invalid_signature);
    GENERATE_AND_PLAY(oxen_name_system_update_mapping_replay);
    GENERATE_AND_PLAY(oxen_name_system_wrong_burn);
    GENERATE_AND_PLAY(oxen_name_system_wrong_version);
    GENERATE_AND_PLAY(oxen_service_nodes_alt_quorums);
    GENERATE_AND_PLAY(oxen_service_nodes_checkpoint_quorum_size);
    GENERATE_AND_PLAY(oxen_service_nodes_gen_nodes);
    GENERATE_AND_PLAY(oxen_service_nodes_insufficient_contribution);
    GENERATE_AND_PLAY(oxen_service_nodes_test_rollback);
    GENERATE_AND_PLAY(oxen_service_nodes_test_swarms_basic);
    GENERATE_AND_PLAY(oxen_pulse_invalid_validator_bitset);
    GENERATE_AND_PLAY(oxen_pulse_invalid_signature);
    GENERATE_AND_PLAY(oxen_pulse_oob_voter_index);
    GENERATE_AND_PLAY(oxen_pulse_non_participating_validator);
    GENERATE_AND_PLAY(oxen_pulse_generate_all_rounds);
    GENERATE_AND_PLAY(oxen_pulse_out_of_order_voters);
    GENERATE_AND_PLAY(oxen_pulse_reject_miner_block);
    GENERATE_AND_PLAY(oxen_pulse_generate_blocks);
    GENERATE_AND_PLAY(oxen_pulse_fallback_to_pow_and_back);
    GENERATE_AND_PLAY(oxen_pulse_chain_split);
    GENERATE_AND_PLAY(oxen_pulse_chain_split_with_no_checkpoints);
    GENERATE_AND_PLAY(oxen_batch_sn_rewards);
    GENERATE_AND_PLAY(oxen_batch_sn_rewards_bad_amount);
    GENERATE_AND_PLAY(oxen_batch_sn_rewards_bad_address);
    GENERATE_AND_PLAY(oxen_batch_sn_rewards_pop_blocks);

    // NOTE: Monero Tests
    GENERATE_AND_PLAY(gen_simple_chain_001);
    GENERATE_AND_PLAY(gen_simple_chain_split_1);
    GENERATE_AND_PLAY(gen_chain_switch_1);
    GENERATE_AND_PLAY(gen_ring_signature_1);
    GENERATE_AND_PLAY(gen_ring_signature_2);
    GENERATE_AND_PLAY(one_block);

    // Block verification tests
    GENERATE_AND_PLAY(gen_block_big_major_version);
    GENERATE_AND_PLAY(gen_block_big_minor_version);
    GENERATE_AND_PLAY(gen_block_ts_not_checked);
    GENERATE_AND_PLAY(gen_block_ts_in_past);
    GENERATE_AND_PLAY(gen_block_ts_in_future);
    GENERATE_AND_PLAY(gen_block_invalid_prev_id);
    GENERATE_AND_PLAY(gen_block_invalid_nonce);
    GENERATE_AND_PLAY(gen_block_invalid_binary_format);
    GENERATE_AND_PLAY(gen_block_no_miner_tx);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_low);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_high);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_past);
    GENERATE_AND_PLAY(gen_block_unlock_time_is_timestamp_in_future);
    GENERATE_AND_PLAY(gen_block_height_is_low);
    GENERATE_AND_PLAY(gen_block_height_is_high);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_2_in);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_2_tx_gen_in);
    GENERATE_AND_PLAY(gen_block_miner_tx_with_txin_to_key);
    GENERATE_AND_PLAY(gen_block_miner_tx_out_is_big);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_no_out);
    GENERATE_AND_PLAY(gen_block_miner_tx_has_out_to_alice);
    GENERATE_AND_PLAY(gen_block_has_invalid_tx);
    GENERATE_AND_PLAY(gen_block_is_too_big);

    GENERATE_AND_PLAY(gen_uint_overflow_1);

    // TODO(oxen): We also want to run these tx tests on deregistration tx's
    // as well because they special case and run under very different code
    // paths from the regular tx path
    // Transaction verification tests
    GENERATE_AND_PLAY(gen_tx_unlock_time);
    GENERATE_AND_PLAY(gen_tx_input_is_not_txin_to_key);
    GENERATE_AND_PLAY(gen_tx_no_inputs_no_outputs);
    GENERATE_AND_PLAY(gen_tx_no_inputs_has_outputs);
    GENERATE_AND_PLAY(gen_tx_has_inputs_no_outputs);
    GENERATE_AND_PLAY(gen_tx_invalid_input_amount);
    GENERATE_AND_PLAY(gen_tx_input_wo_key_offsets);
    GENERATE_AND_PLAY(gen_tx_key_offset_points_to_foreign_key);
    GENERATE_AND_PLAY(gen_tx_sender_key_offset_not_exist); // TODO(oxen): Revisit this test
    GENERATE_AND_PLAY(gen_tx_key_image_not_derive_from_tx_key);
    GENERATE_AND_PLAY(gen_tx_key_image_is_invalid);
    GENERATE_AND_PLAY(gen_tx_txout_to_key_has_invalid_key);
    GENERATE_AND_PLAY(gen_tx_output_is_not_txout_to_key);
    GENERATE_AND_PLAY(gen_tx_signatures_are_invalid);

    GENERATE_AND_PLAY(gen_double_spend_in_tx);
    GENERATE_AND_PLAY(gen_double_spend_in_the_same_block);
    GENERATE_AND_PLAY(gen_double_spend_in_different_blocks);
    GENERATE_AND_PLAY(gen_double_spend_in_different_chains);
    GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_the_same_block);
    GENERATE_AND_PLAY(gen_double_spend_in_alt_chain_in_different_blocks);

    GENERATE_AND_PLAY(gen_multisig_tx_invalid_23_1__no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_45_5_23_no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_22_1__no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_33_1__no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_33_1_2_no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_33_1_3_no_threshold);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_24_1_no_signers);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_25_1_no_signers);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_48_1_no_signers);
    GENERATE_AND_PLAY(gen_multisig_tx_invalid_48_1_23_no_threshold);

    GENERATE_AND_PLAY(gen_bp_tx_valid_1_old);
    GENERATE_AND_PLAY(gen_bp_tx_invalid_1_new);
    GENERATE_AND_PLAY(gen_bp_tx_valid_2);
    GENERATE_AND_PLAY(gen_bp_tx_valid_3);
    GENERATE_AND_PLAY(gen_bp_tx_valid_16);
    GENERATE_AND_PLAY(gen_bp_txs_valid_2_and_2);
    GENERATE_AND_PLAY(gen_bp_txs_valid_2_and_3_and_2_and_4);
    GENERATE_AND_PLAY(gen_bp_tx_invalid_wrong_amount);

    GENERATE_AND_PLAY(gen_rct2_tx_clsag_malleability);

    // TODO(oxen): Tests we need to fix
#if 0
      //GENERATE_AND_PLAY(gen_ring_signature_big); // Takes up to XXX hours (if CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW == 10)

      // Transaction verification tests
      GENERATE_AND_PLAY(gen_tx_mixed_key_offset_not_exist); // TODO(oxen): See comment in the function
      GENERATE_AND_PLAY(gen_tx_output_with_zero_amount); // TODO(oxen): See comment in the function

      // Double spend

      GENERATE_AND_PLAY(gen_block_reward);
      GENERATE_AND_PLAY(gen_uint_overflow_2);

      GENERATE_AND_PLAY(gen_v2_tx_mixable_0_mixin);
      GENERATE_AND_PLAY(gen_v2_tx_mixable_low_mixin);
      GENERATE_AND_PLAY(gen_v2_tx_unmixable_only);
      GENERATE_AND_PLAY(gen_v2_tx_unmixable_one);
      GENERATE_AND_PLAY(gen_v2_tx_unmixable_two);
      GENERATE_AND_PLAY(gen_v2_tx_dust);

      GENERATE_AND_PLAY(gen_rct_tx_valid_from_pre_rct);
      GENERATE_AND_PLAY(gen_rct_tx_valid_from_rct);
      GENERATE_AND_PLAY(gen_rct_tx_valid_from_mixed);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_bad_real_dest);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_bad_real_mask);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_bad_fake_dest);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_bad_fake_mask);
      GENERATE_AND_PLAY(gen_rct_tx_rct_bad_real_dest);
      GENERATE_AND_PLAY(gen_rct_tx_rct_bad_real_mask);
      GENERATE_AND_PLAY(gen_rct_tx_rct_bad_fake_dest);
      GENERATE_AND_PLAY(gen_rct_tx_rct_bad_fake_mask);
      GENERATE_AND_PLAY(gen_rct_tx_rct_spend_with_zero_commit);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_zero_vin_amount);
      GENERATE_AND_PLAY(gen_rct_tx_rct_non_zero_vin_amount);
      GENERATE_AND_PLAY(gen_rct_tx_non_zero_vout_amount);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_duplicate_key_image);
      GENERATE_AND_PLAY(gen_rct_tx_rct_duplicate_key_image);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_wrong_key_image);
      GENERATE_AND_PLAY(gen_rct_tx_rct_wrong_key_image);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_wrong_fee);
      GENERATE_AND_PLAY(gen_rct_tx_rct_wrong_fee);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_remove_vin);
      GENERATE_AND_PLAY(gen_rct_tx_rct_remove_vin);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_add_vout);
      GENERATE_AND_PLAY(gen_rct_tx_rct_add_vout);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_increase_vin_and_fee);
      GENERATE_AND_PLAY(gen_rct_tx_pre_rct_altered_extra);
      GENERATE_AND_PLAY(gen_rct_tx_rct_altered_extra);

      // NOTE: For oxen we should re-write this which is trivial to do with
      // generating some funds and attempting to spend them immediately instead
      // of the minutia of the monero framework.
      GENERATE_AND_PLAY(gen_rct_tx_uses_output_too_early);

      GENERATE_AND_PLAY(gen_multisig_tx_valid_22_1_2);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_22_1_2_many_inputs);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_22_2_1);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_33_1_23);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_33_3_21);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_23_1_2);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_23_1_3);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_23_2_1);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_23_2_3);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_45_1_234);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_45_4_135_many_inputs);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_89_3_1245789);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_24_1_2);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_24_1_2_many_inputs);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_25_1_2);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_25_1_2_many_inputs);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_48_1_234);
      GENERATE_AND_PLAY(gen_multisig_tx_valid_48_1_234_many_inputs);
#endif

    el::Level level = (failed_tests.empty() ? el::Level::Info : el::Level::Error);
    if (!list_tests)
    {
      MLOG(level, "\nREPORT:");
      MLOG(level, "  Test run: " << tests_count);
      MLOG(level, "  Failures: " << failed_tests.size());
    }
    if (!failed_tests.empty())
    {
      MLOG(level, "FAILED TESTS:");
      for (auto &test_name : failed_tests)
      {
        MLOG(level, "  " << test_name);
      }
    }
  }

  return failed_tests.empty() ? 0 : 1;

  CATCH_ENTRY_L0("main", 1);
}
