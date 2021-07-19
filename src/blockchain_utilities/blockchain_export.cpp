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

#include "bootstrap_file.h"
#include "blocksdat_file.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_objects.h"
#include "version.h"
#include "cryptonote_core/uptime_proof.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);

  uint32_t log_level = 0;
  uint64_t block_stop = 0;
  bool blocks_dat = false;

  tools::on_startup();

  auto opt_size = command_line::boost_option_sizes();

  po::options_description desc_cmd_only("Command line options", opt_size.first, opt_size.second);
  po::options_description desc_cmd_sett("Command line options and settings options", opt_size.first, opt_size.second);
  const command_line::arg_descriptor<std::string> arg_output_file = {"output-file", "Specify output file", "", true};
  const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "Stop at block number", block_stop};
  const command_line::arg_descriptor<bool> arg_blocks_dat = {"blocksdat", "Output in blocks.dat format", blocks_dat};


  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, arg_output_file);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_devnet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_block_stop);
  command_line::add_arg(desc_cmd_sett, arg_blocks_dat);

  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")\n\n";
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("oxen-blockchain-export.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());
  block_stop = command_line::get_arg(vm, arg_block_stop);

  LOG_PRINT_L0("Starting...");

  bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  bool opt_devnet = command_line::get_arg(vm, cryptonote::arg_devnet_on);
  if (opt_testnet && opt_devnet)
  {
    std::cerr << "Can't specify more than one of --testnet and --devnet" << std::endl;
    return 1;
  }
  bool opt_blocks_dat = command_line::get_arg(vm, arg_blocks_dat);

  auto config_folder = fs::u8path(command_line::get_arg(vm, cryptonote::arg_data_dir));

  fs::path output_file_path;
  if (command_line::has_arg(vm, arg_output_file))
    output_file_path = fs::u8path(command_line::get_arg(vm, arg_output_file));
  else
    output_file_path = config_folder / "export" / BLOCKCHAIN_RAW;
  LOG_PRINT_L0("Export output file: " << output_file_path.string());

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  blockchain_objects_t blockchain_objects = {};
  Blockchain *core_storage = &blockchain_objects.m_blockchain;
  BlockchainDB *db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }
  LOG_PRINT_L0("database: LMDB");

  auto filename = config_folder / db->get_db_name();

  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");
  try
  {
    db->open(filename, core_storage->nettype(), DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return 1;
  }
  r = core_storage->init(db, nullptr, nullptr, opt_testnet ? cryptonote::TESTNET : opt_devnet ? cryptonote::DEVNET : cryptonote::MAINNET);

  if (core_storage->get_blockchain_pruning_seed() && !opt_blocks_dat)
  {
    LOG_PRINT_L0("Blockchain is pruned, cannot export");
    return 1;
  }

  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
  LOG_PRINT_L0("Source blockchain storage initialized OK");
  LOG_PRINT_L0("Exporting blockchain raw data...");

  if (opt_blocks_dat)
  {
    BlocksdatFile blocksdat;
    r = blocksdat.store_blockchain_raw(core_storage, NULL, output_file_path, block_stop);
  }
  else
  {
    BootstrapFile bootstrap;
    r = bootstrap.store_blockchain_raw(core_storage, NULL, output_file_path, block_stop);
  }
  CHECK_AND_ASSERT_MES(r, 1, "Failed to export blockchain raw data");
  LOG_PRINT_L0("Blockchain raw data exported OK");
  return 0;

  CATCH_ENTRY("Export error", 1);
}
