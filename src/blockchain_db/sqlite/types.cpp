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

#include "types.h"

namespace cryptonote
{

batch_sn_payment::batch_sn_payment(std::string addr, uint64_t amt, cryptonote::network_type nettype):address(addr),amount(amt){
  cryptonote::get_account_address_from_str(address_info, nettype, address);
};
batch_sn_payment::batch_sn_payment(cryptonote::address_parse_info& addr_info, uint64_t amt, cryptonote::network_type nettype):address_info(addr_info),amount(amt){
  address = cryptonote::get_account_address_as_str(nettype, address_info.is_subaddress, address_info.address);
};
batch_sn_payment::batch_sn_payment(const cryptonote::account_public_address& addr, uint64_t amt, cryptonote::network_type nettype):amount(amt){
  address_info = cryptonote::address_parse_info{addr,0};
  address = cryptonote::get_account_address_as_str(nettype, address_info.is_subaddress, address_info.address);
};

} // namespace cryptonote
