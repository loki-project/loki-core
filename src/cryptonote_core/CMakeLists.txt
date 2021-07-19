# Copyright (c) 2018, The Loki Project
# Copyright (c) 2014-2019, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

add_library(cryptonote_core
  blockchain.cpp
  cryptonote_core.cpp
  service_node_rules.cpp
  service_node_list.cpp
  service_node_voting.cpp
  service_node_quorum_cop.cpp
  service_node_swarm.cpp
  tx_blink.cpp
  oxen_name_system.cpp
  tx_pool.cpp
  tx_sanity_check.cpp
  cryptonote_tx_utils.cpp
  pulse.cpp
  uptime_proof.cpp)

target_link_libraries(cryptonote_core
  PUBLIC
    version
    common
    blockchain_db
    multisig
    ringct
    device
    checkpoints
    sqlite3
  PRIVATE
    Boost::program_options
    SQLiteCpp
    systemd
    extra)

if(PER_BLOCK_CHECKPOINT)
  target_compile_definitions(cryptonote_core PUBLIC PER_BLOCK_CHECKPOINT)
  target_link_libraries(cryptonote_core PUBLIC blocks)
endif()

