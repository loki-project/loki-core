#include "cryptonote_basic.h"

namespace cryptonote {

void transaction_prefix::set_null() {
  version = txversion::v1;
  unlock_time = 0;
  vin.clear();
  vout.clear();
  extra.clear();
  output_unlock_times.clear();
  type = txtype::standard;
}

transaction::transaction(const transaction &t) :
  transaction_prefix(t),
  hash_valid(false),
  blob_size_valid(false),
  signatures(t.signatures),
  rct_signatures(t.rct_signatures),
  pruned(t.pruned),
  unprunable_size(t.unprunable_size.load()),
  prefix_size(t.prefix_size.load())
{
  if (t.is_hash_valid()) {
    hash = t.hash;
    set_hash_valid(true);
  }
  if (t.is_blob_size_valid()) {
    blob_size = t.blob_size;
    set_blob_size_valid(true);
  }
}

transaction& transaction::operator=(const transaction& t) {
  transaction_prefix::operator=(t);
  set_hash_valid(false);
  set_blob_size_valid(false);
  signatures = t.signatures;
  rct_signatures = t.rct_signatures;
  if (t.is_hash_valid()) {
    hash = t.hash;
    set_hash_valid(true);
  }
  if (t.is_blob_size_valid()) {
    blob_size = t.blob_size;
    set_blob_size_valid(true);
  }
  pruned = t.pruned;
  unprunable_size = t.unprunable_size.load();
  prefix_size = t.prefix_size.load();
  return *this;
}

void transaction::set_null()
{
  transaction_prefix::set_null();
  signatures.clear();
  rct_signatures = {};
  rct_signatures.type = rct::RCTType::Null;
  set_hash_valid(false);
  set_blob_size_valid(false);
  pruned = false;
  unprunable_size = 0;
  prefix_size = 0;
}

void transaction::invalidate_hashes()
{
  set_hash_valid(false);
  set_blob_size_valid(false);
}

size_t transaction::get_signature_size(const txin_v& tx_in)
{
  if (std::holds_alternative<txin_to_key>(tx_in))
    return var::get<txin_to_key>(tx_in).key_offsets.size();
  return 0;
}

block::block(const block& b) :
  block_header(b),
  miner_tx{b.miner_tx},
  tx_hashes{b.tx_hashes},
  signatures{b.signatures},
  height{b.height},
  service_node_winner_key{b.service_node_winner_key},
  reward{b.reward}
{
  copy_hash(b);
}

block::block(block&& b) :
  block_header(std::move(b)),
  miner_tx{std::move(b.miner_tx)},
  tx_hashes{std::move(b.tx_hashes)},
  signatures{std::move(b.signatures)},
  height{std::move(b.height)},
  service_node_winner_key{std::move(b.service_node_winner_key)},
  reward{std::move(b.reward)}
{
  copy_hash(b);
}

block& block::operator=(const block& b)
{
  block_header::operator=(b);
  miner_tx = b.miner_tx;
  tx_hashes = b.tx_hashes;
  signatures = b.signatures;
  height = b.height;
  service_node_winner_key = b.service_node_winner_key;
  reward = b.reward;
  copy_hash(b);
  return *this;
}
block& block::operator=(block&& b)
{
  block_header::operator=(std::move(b));
  miner_tx = std::move(b.miner_tx);
  tx_hashes = std::move(b.tx_hashes);
  signatures = std::move(b.signatures);
  height = std::move(b.height);
  service_node_winner_key = std::move(b.service_node_winner_key);
  reward = std::move(b.reward);
  copy_hash(b);
  return *this;
}

bool block::is_hash_valid() const
{
  return hash_valid.load(std::memory_order_acquire);
}
void block::set_hash_valid(bool v) const
{
  hash_valid.store(v,std::memory_order_release);
}

}
