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

#pragma once
#include "chaingen.h"

/************************************************************************/
/*                                                                      */
/************************************************************************/

struct oxen_checkpointing_alt_chain_handle_alt_blocks_at_tip                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_alt_chain_more_service_node_checkpoints_less_pow_overtakes : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_alt_chain_receive_checkpoint_votes_should_reorg_back       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_alt_chain_too_old_should_be_dropped                        : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_alt_chain_with_increasing_service_node_checkpoints         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_service_node_checkpoint_from_votes                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_checkpointing_service_node_checkpoints_check_reorg_windows               : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_block_reward_unpenalized_pre_pulse                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_block_reward_unpenalized_post_pulse                                 : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_fee_burning                                                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_governance_batched_reward                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_block_rewards_lrc6                                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_deregister_preferred                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_deregister_safety_buffer                                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_deregister_too_old                                             : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_deregister_zero_fee                                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_deregister_on_split                                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_core_test_state_change_ip_penalty_disallow_dupes                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_disallow_reserved_type                                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_expiration                                                   : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_get_mappings_by_owner                                        : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_get_mappings                                                 : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_get_mappings_by_owners                                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_handles_duplicate_in_ons_db                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_handles_duplicate_in_tx_pool                                 : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_invalid_tx_extra_params                                      : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_large_reorg                                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_name_renewal                                                 : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_name_value_max_lengths                                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_update_mapping_after_expiry_fails                            : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_update_mapping                                               : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); virtual uint8_t hf(); };
struct oxen_name_system_update_mapping_argon2                                        : public oxen_name_system_update_mapping { uint8_t hf() override; };
struct oxen_name_system_update_mapping_multiple_owners                               : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_update_mapping_non_existent_name_fails                       : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_update_mapping_invalid_signature                             : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_update_mapping_replay                                        : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_wrong_burn                                                   : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_name_system_wrong_version                                                : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_alt_quorums                                                : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_checkpoint_quorum_size                                     : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_gen_nodes                                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_insufficient_contribution                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_test_rollback                                              : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_service_nodes_test_swarms_basic                                          : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_invalid_validator_bitset                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_invalid_signature                                                  : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_oob_voter_index                                                    : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_non_participating_validator                                        : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_generate_all_rounds                                                : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_out_of_order_voters                                                : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_reject_miner_block                                                 : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_generate_blocks                                                    : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_fallback_to_pow_and_back                                           : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_chain_split                                                        : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_pulse_chain_split_with_no_checkpoints                                    : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_batch_sn_rewards                                                         : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_batch_sn_rewards_bad_amount                                              : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_batch_sn_rewards_bad_address                                             : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };
struct oxen_batch_sn_rewards_pop_blocks                                              : public test_chain_unit_base { bool generate(std::vector<test_event_entry>& events); };

