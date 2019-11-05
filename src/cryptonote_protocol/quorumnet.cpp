// Copyright (c) 2019, The Loki Project
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

#include "quorumnet.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/service_node_voting.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/tx_blink.h"
#include "cryptonote_core/tx_pool.h"
#include "quorumnet/sn_network.h"
#include "quorumnet/conn_matrix.h"
#include "cryptonote_config.h"
#include "common/random.h"

#include <shared_mutex>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "qnet"

namespace quorumnet {

namespace {

using namespace service_nodes;
using namespace std::string_literals;
using namespace std::chrono_literals;

using blink_tx = cryptonote::blink_tx;

constexpr auto NUM_BLINK_QUORUMS = tools::enum_count<blink_tx::subquorum>;
static_assert(std::is_same<const uint8_t, decltype(NUM_BLINK_QUORUMS)>(), "unexpected underlying blink quorum count type");

using quorum_array = std::array<std::shared_ptr<const service_nodes::quorum>, NUM_BLINK_QUORUMS>;

using pending_signature = std::tuple<bool, uint8_t, int, crypto::signature>; // approval, subquorum, subquorum position, signature

struct pending_signature_hash {
    size_t operator()(const pending_signature &s) const { return std::get<uint8_t>(s) + std::hash<crypto::signature>{}(std::get<crypto::signature>(s)); }
};

using pending_signature_set = std::unordered_set<pending_signature, pending_signature_hash>;

struct SNNWrapper {
    SNNetwork snn;
    cryptonote::core &core;
    cryptonote::tx_memory_pool &pool;

    // Track submitted blink txes here; unlike the blinks stored in the mempool we store these ones
    // more liberally to track submitted blinks, even if unsigned/unacceptable, while the mempool
    // only stores approved blinks.
    std::shared_timed_mutex mutex;

    struct blink_metadata {
        std::shared_ptr<blink_tx> btxptr;
        pending_signature_set pending_sigs;
        std::string reply_pubkey;
        uint64_t reply_tag = 0;
    };
    // { height => { txhash => {blink_tx,sigs,reply}, ... }, ... }
    std::map<uint64_t, std::unordered_map<crypto::hash, blink_metadata>> blinks;

    // FIXME:
    //std::chrono::steady_clock::time_point last_blink_cleanup = std::chrono::steady_clock::now();

    template <typename... Args>
    SNNWrapper(cryptonote::core &core, cryptonote::tx_memory_pool &pool, Args &&...args) :
        snn{std::forward<Args>(args)...}, core{core}, pool{pool} {}
};

template <typename T>
std::string get_data_as_string(const T &key) {
    static_assert(std::is_trivial<T>(), "cannot safely copy non-trivial class to string");
    return {reinterpret_cast<const char *>(&key), sizeof(key)};
}

crypto::x25519_public_key x25519_from_string(const std::string &pubkey) {
    crypto::x25519_public_key x25519_pub = crypto::x25519_public_key::null();
    if (pubkey.size() == sizeof(crypto::x25519_public_key))
        std::memcpy(x25519_pub.data, pubkey.data(), pubkey.size());
    return x25519_pub;
}

std::string get_connect_string(const service_node_list &sn_list, crypto::x25519_public_key x25519_pub) {
    if (!x25519_pub) {
        MDEBUG("no connection available: pubkey is empty");
        return "";
    }
    auto pubkey = sn_list.get_pubkey_from_x25519(x25519_pub);
    if (!pubkey) {
        MDEBUG("no connection available: could not find primary pubkey from x25519 pubkey " << x25519_pub);
        return "";
    }
    auto states = sn_list.get_service_node_list_state({{pubkey}});
    if (states.empty()) {
        MDEBUG("no connection available: primary pubkey " << pubkey << " is not registered");
        return "";
    }
    const auto &proof = *states[0].info->proof;
    if (!proof.public_ip || !proof.quorumnet_port) {
        MDEBUG("no connection available: primary pubkey " << pubkey << " has no associated ip and/or port");
        return "";
    }
    return "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port);
}

constexpr el::Level easylogging_level(LogLevel level) {
    switch (level) {
        case LogLevel::fatal: return el::Level::Fatal;
        case LogLevel::error: return el::Level::Error;
        case LogLevel::warn:  return el::Level::Warning;
        case LogLevel::info:  return el::Level::Info;
        case LogLevel::debug: return el::Level::Debug;
        case LogLevel::trace: return el::Level::Trace;
    };
    return el::Level::Unknown;
};
bool snn_want_log(LogLevel level) {
    return ELPP->vRegistry()->allowed(easylogging_level(level), LOKI_DEFAULT_LOG_CATEGORY);
}
void snn_write_log(LogLevel level, const char *file, int line, std::string msg) {
    el::base::Writer(easylogging_level(level), file, line, ELPP_FUNC, el::base::DispatchAction::NormalLog).construct(LOKI_DEFAULT_LOG_CATEGORY) << msg;
}

void *new_snnwrapper(cryptonote::core &core, cryptonote::tx_memory_pool &pool, const std::string &bind) {
    auto keys = core.get_service_node_keys();
    auto peer_lookup = [&sn_list = core.get_service_node_list()](const std::string &x25519_pub) {
        return get_connect_string(sn_list, x25519_from_string(x25519_pub));
    };
    auto allow = [&sn_list = core.get_service_node_list()](const std::string &ip, const std::string &x25519_pubkey_str) {
        auto x25519_pubkey = x25519_from_string(x25519_pubkey_str);
        auto pubkey = sn_list.get_pubkey_from_x25519(x25519_pubkey);
        if (pubkey) {
            MINFO("Accepting incoming SN connection authentication from ip/x25519/pubkey: " << ip << "/" << x25519_pubkey << "/" << pubkey);
            return SNNetwork::allow::service_node;
        }

        // Public connection:
        //
        // TODO: we really only want to accept public connections here if we are in (or soon
        // to be or recently were in) a blink quorum; at other times we want to refuse a
        // non-SN connection.  We could also IP limit throttle.
        //
        // (In theory we could extend this to also only allow SN
        // connections when in or near a blink/checkpoint/obligations/pulse quorum, but that
        // would get messy fast and probably have little practical benefit).
        return SNNetwork::allow::client;
    };
    SNNWrapper *obj;
    if (!keys) {
        MINFO("Starting remote-only quorumnet instance");

        obj = new SNNWrapper(core, pool, peer_lookup, allow, snn_want_log, snn_write_log);
    } else {
        MINFO("Starting quorumnet listener on " << bind << " with x25519 pubkey " << keys->pub_x25519);
        obj = new SNNWrapper(core, pool,
            get_data_as_string(keys->pub_x25519),
            get_data_as_string(keys->key_x25519.data),
            std::vector<std::string>{{bind}},
            peer_lookup,
            allow,
            snn_want_log, snn_write_log);
    }

    obj->snn.data = obj; // Provide pointer to the instance for callbacks

    return obj;
}

void delete_snnwrapper(void *&obj) {
    auto *snn = reinterpret_cast<SNNWrapper *>(obj);
    MINFO("Shutting down quorumnet listener");
    delete snn;
    obj = nullptr;
}


template <typename E>
E get_enum(const bt_dict &d, const std::string &key) {
    E result = static_cast<E>(get_int<std::underlying_type_t<E>>(d.at(key)));
    if (result < E::_count)
        return result;
    throw std::invalid_argument("invalid enum value for field " + key);
}

/// Helper class to calculate and relay to peers of quorums.
///
/// TODO: add a wrapper that caches this so that looking up the same quorum peers within a certain
/// amount of time doesn't need to recalculate.
class peer_info {
public:
    using exclude_set = std::unordered_set<crypto::public_key>;

    /// Maps pubkeys to x25519 pubkeys and zmq connection strings
    std::unordered_map<crypto::public_key, std::pair<crypto::x25519_public_key, std::string>> remotes;
    /// Stores the x25519 string pubkeys to either zmq connection strings (for a "strong"
    /// connection) or empty strings (for an opportunistic "weak" connection).
    std::unordered_map<std::string /*x25519 pubkey*/, std::string /*conn location*/> peers;
    /// The number of strong peers, that is, the count of `peers` that has a non-empty second value.
    /// Will be the same as `peers.count()` if opportunistic connections are disabled.
    int strong_peers;
    /// The caller's positions in the given quorum(s), -1 if not found
    std::vector<int> my_position;
    /// The number of actual positions found in my_position (i.e. the number of elements of
    /// `my_position` not equal to -1).
    int my_position_count;

    /// Singleton wrapper around peer_info
    peer_info(
            SNNWrapper &snw,
            quorum_type q_type,
            std::shared_ptr<const quorum> &quorum,
            bool opportunistic = true,
            exclude_set exclude = {}
            )
        : peer_info(snw, q_type, &quorum, &quorum + 1, opportunistic, std::move(exclude)) {}

    /// Constructs peer information for the given quorums and quorum position of the caller.
    /// \param snw - the SNNWrapper reference
    /// \param q_type - the type of quorum
    /// \param qbegin, qend - the iterators to a set of pointers (or other deferenceable type) to quorums
    /// \param opportunistic - if true then the peers to relay will also attempt to relay to any
    ///     incoming peers *if* those peers are already connected when the message is relayed.
    /// \param exclude - can be specified as a set of peers that should be excluded from the peer
    ///     list.  Typically for peers that we already know have the relayed information.  This SN's
    ///     pubkey is always added to this exclude list.
    template <typename QuorumIt>
    peer_info(
            SNNWrapper &snw,
            quorum_type q_type,
            QuorumIt qbegin, QuorumIt qend,
            bool opportunistic = true,
            std::unordered_set<crypto::public_key> exclude = {}
            )
    : snn{snw.snn} {

        auto keys = snw.core.get_service_node_keys();
        assert(keys);
        const auto &my_pubkey = keys->pub;
        exclude.insert(my_pubkey);

        // Find my positions in the quorums
        my_position_count = 0;
        for (auto qit = qbegin; qit != qend; ++qit) {
            auto &v = (*qit)->validators;
            auto found = std::find(v.begin(), v.end(), my_pubkey);
            if (found == v.end())
                my_position.push_back(-1);
            else {
                my_position.push_back(std::distance(v.begin(), found));
                my_position_count++;
            }
        }

        std::unordered_set<crypto::public_key> need_remotes;
        auto qit = qbegin;
        // Figure out all the remotes we need to be able to lookup (so that we can do all lookups in
        // a single shot -- since it requires a mutex).
        for (size_t i = 0; qit != qend; ++i, ++qit) {
            const auto &v = (*qit)->validators;
            for (int j : quorum_outgoing_conns(my_position[i], v.size()))
                if (!exclude.count(v[j]))
                    need_remotes.insert(v[j]);
            if (opportunistic)
                for (int j : quorum_incoming_conns(my_position[i], v.size()))
                    if (!exclude.count(v[j]))
                        need_remotes.insert(v[j]);
        }

        // Lookup the x25519 and ZMQ connection string for all peers
        snw.core.get_service_node_list().for_each_service_node_info(need_remotes.begin(), need_remotes.end(),
            [this](const crypto::public_key &pubkey, const service_nodes::service_node_info &info) {
                if (!info.is_active()) return;
                auto &proof = *info.proof;
                if (!proof.pubkey_x25519 || !proof.quorumnet_port || !proof.public_ip) return;
                remotes.emplace(pubkey,
                    std::make_pair(proof.pubkey_x25519, "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port)));
            });

        compute_peers(qbegin, qend, opportunistic);
    }

    /// Relays a command and any number of serialized data to everyone we're supposed to relay to
    template <typename... T>
    void relay_to_peers(const std::string &cmd, const T &...data) {
        relay_to_peers_impl(cmd, std::array<send_option::serialized, sizeof...(T)>{send_option::serialized{data}...},
                std::make_index_sequence<sizeof...(T)>{});
    }

private:
    SNNetwork &snn;

    /// Looks up a pubkey in known remotes and adds it to `peers`.  If strong, it is added with an
    /// address, otherwise it is added with an empty address.  If the element already exists, it
    /// will be updated *if* it the existing entry is weak and `strong` is true, otherwise it will
    /// be left as is.  Returns true if a new entry was created or a weak entry was upgraded.
    bool add_peer(const crypto::public_key &pubkey, bool strong = true) {
        auto it = remotes.find(pubkey);
        if (it != remotes.end()) {
            std::string remote_addr = strong ? it->second.second : ""s;
            auto ins = peers.emplace(get_data_as_string(it->second.first), std::move(remote_addr));
            if (strong && !ins.second && ins.first->second.empty()) {
                ins.first->second = it->second.second;
                strong_peers++;
                return true; // Upgraded weak to strong
            }
            if (strong && ins.second)
                strong_peers++;

            return ins.second;
        }
        return false;
    }

    // Build a map of x25519 keys -> connection strings of all our quorum peers we talk to; the
    // connection string is non-empty only for *strong* peer (i.e. one we should connect to if not
    // already connected) and empty if it's an opportunistic peer (i.e. only send along if we already
    // have a connection).
    template <typename QuorumIt>
    void compute_peers(QuorumIt qbegin, QuorumIt qend, bool opportunistic) {

        // TODO: when we receive a new block, if our quorum starts soon we can tell SNNetwork to
        // pre-connect (to save the time in handshaking when we get an actual blink tx).

        strong_peers = 0;

        size_t i = 0;
        for (QuorumIt qit = qbegin; qit != qend; ++i, ++qit) {
            if (my_position[i] < 0) {
                MTRACE("Not in subquorum " << (i == 0 ? "Q" : "Q'"));
                continue;
            }

            auto &validators = (*qit)->validators;

            // Relay to all my outgoing targets within the quorum (connecting if not already connected)
            for (int j : quorum_outgoing_conns(my_position[i], validators.size())) {
                if (add_peer(validators[j]))
                    MTRACE("Relaying within subquorum " << (i == 0 ? "Q" : "Q'") << " to service node " << validators[j]);
            }

            // Opportunistically relay to all my *incoming* sources within the quorum *if* I already
            // have a connection open with them, but don't open a new connection if I don't.
            for (int j : quorum_incoming_conns(my_position[i], validators.size())) {
                if (add_peer(validators[j], false /*!strong*/))
                    MTRACE("Optional opportunistic relay within quorum " << (i == 0 ? "Q" : "Q'") << " to service node " << validators[j]);
            }

            // Now establish strong interconnections between quorums, if we have multiple subquorums
            // (i.e.  blink quorums).
            //
            // If I'm in the last half* of the first quorum then I relay to the first half (roughly) of
            // the next quorum.  i.e. nodes 5-9 in Q send to nodes 0-4 in Q'.  For odd numbers the last
            // position gets left out (e.g. for 9 members total we would have 0-3 talk to 4-7 and no one
            // talks to 8).
            //
            // (* - half here means half the size of the smaller quorum)
            //
            // We also skip this entirely if this SN is in both quorums since then we're already
            // relaying to nodes in the next quorum.  (Ideally we'd do the same if the recipient is in
            // both quorums, but that's harder to figure out and so the special case isn't worth
            // worrying about).
            QuorumIt qnext = std::next(qit);
            if (qnext != qend && my_position[i + 1] < 0) {
                auto &next_validators = (*qnext)->validators;
                int half = std::min<int>(validators.size(), next_validators.size()) / 2;
                if (my_position[i] >= half && my_position[i] < half*2) {
                    if (add_peer(validators[my_position[i] - half]))
                        MTRACE("Inter-quorum relay from Q to Q' service node " << next_validators[my_position[i] - half]);
                } else {
                    MTRACE("Not a Q -> Q' inter-quorum relay (Q position is " << my_position[i] << ")");
                }

            }

            // Exactly the same connections as above, but in reverse and weak: the first half of Q'
            // sends to the second half of Q.  Typically this will end up reusing an already open
            // connection, but if there isn't such an open connection then we establish a new one.
            if (qit != qbegin && my_position[i - 1] < 0) {
                auto &prev_validators = (*std::prev(qit))->validators;
                int half = std::min<int>(validators.size(), prev_validators.size()) / 2;
                if (my_position[i] < half) {
                    if (add_peer(prev_validators[half + my_position[i]]))
                        MTRACE("Inter-quorum relay from Q' to Q service node " << prev_validators[my_position[i] - half]);
                } else {
                    MTRACE("Not a Q' -> Q inter-quorum relay (Q' position is " << my_position[i] << ")");
                }
            }
        }
    }

    /// Relays a command and pre-serialized data to everyone we're supposed to relay to
    template<size_t N, size_t... I>
    void relay_to_peers_impl(const std::string &cmd, std::array<send_option::serialized, N> relay_data, std::index_sequence<I...>) {
        for (auto &peer : peers) {
            MTRACE("Relaying " << cmd << " to peer " << as_hex(peer.first) << (peer.second.empty() ? " (if connected)"s : " @ " + peer.second));
            if (peer.second.empty())
                snn.send(peer.first, cmd, relay_data[I]..., send_option::optional{});
            else
                snn.send(peer.first, cmd, relay_data[I]..., send_option::hint{peer.second});
        }
    }

};


bt_dict serialize_vote(const quorum_vote_t &vote) {
    bt_dict result{
        {"v", vote.version},
        {"t", static_cast<uint8_t>(vote.type)},
        {"h", vote.block_height},
        {"g", static_cast<uint8_t>(vote.group)},
        {"i", vote.index_in_group},
        {"s", get_data_as_string(vote.signature)},
    };
    if (vote.type == quorum_type::checkpointing)
        result["bh"] = std::string{vote.checkpoint.block_hash.data, sizeof(crypto::hash)};
    else {
        result["wi"] = vote.state_change.worker_index;
        result["sc"] = static_cast<std::underlying_type_t<new_state>>(vote.state_change.state);
    }
    return result;
}

quorum_vote_t deserialize_vote(const bt_value &v) {
    const auto &d = boost::get<bt_dict>(v); // throws if not a bt_dict
    quorum_vote_t vote;
    vote.version = get_int<uint8_t>(d.at("v"));
    vote.type = get_enum<quorum_type>(d, "t");
    vote.block_height = get_int<uint64_t>(d.at("h"));
    vote.group = get_enum<quorum_group>(d, "g");
    if (vote.group == quorum_group::invalid) throw std::invalid_argument("invalid vote group");
    vote.index_in_group = get_int<uint16_t>(d.at("i"));
    auto &sig = boost::get<std::string>(d.at("s"));
    if (sig.size() != sizeof(vote.signature)) throw std::invalid_argument("invalid vote signature size");
    std::memcpy(&vote.signature, sig.data(), sizeof(vote.signature));
    if (vote.type == quorum_type::checkpointing) {
        auto &bh = boost::get<std::string>(d.at("bh"));
        if (bh.size() != sizeof(vote.checkpoint.block_hash.data)) throw std::invalid_argument("invalid vote checkpoint block hash");
        std::memcpy(vote.checkpoint.block_hash.data, bh.data(), sizeof(vote.checkpoint.block_hash.data));
    } else {
        vote.state_change.worker_index = get_int<uint16_t>(d.at("wi"));
        get_enum<new_state>(d, "sc");
    }

    return vote;
}

void relay_votes(void *obj, const std::vector<service_nodes::quorum_vote_t> &votes) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(obj);

    auto my_keys_ptr = snw.core.get_service_node_keys();
    assert(my_keys_ptr);
    const auto &my_keys = *my_keys_ptr;

    // Loop twice: the first time we build up the set of remotes we need for all votes; then we look
    // up their proofs -- which requires a potentially expensive lock -- to get the x25519 pubkey
    // and port from the proof; then we do the sending in the second loop.
    std::unordered_set<crypto::public_key> need_remotes;
    int votes_relayed = 0;
    MDEBUG("Starting relay of " << votes.size() << " votes");
    for (auto &vote : votes) {
        auto quorum = snw.core.get_service_node_list().get_quorum(vote.type, vote.block_height);

        if (!quorum) {
            MWARNING("Unable to relay vote: no testing quorum vote for type " << vote.type << " @ height " << vote.block_height);
            continue;
        }

        auto &quorum_voters = quorum->validators;
        if (quorum_voters.size() < service_nodes::min_votes_for_quorum_type(vote.type)) {
            MWARNING("Invalid vote relay: " << vote.type << " quorum @ height " << vote.block_height <<
                    " does not have enough validators (" << quorum_voters.size() << ") to reach the minimum required votes ("
                    << service_nodes::min_votes_for_quorum_type(vote.type) << ")");
            continue;
        }

        peer_info pinfo{snw, vote.type, quorum};
        if (!pinfo.my_position_count) {
            MWARNING("Invalid vote relay: vote to relay does not include this service node");
            continue;
        }

        pinfo.relay_to_peers("vote", serialize_vote(vote));
        votes_relayed++;
    }
    MDEBUG("Relayed " << votes_relayed << " votes");
}

void handle_vote(SNNetwork::message &m, void *self) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(self);

    MDEBUG("Received a relayed vote from " << as_hex(m.pubkey));

    if (m.data.size() != 1) {
        MINFO("Ignoring vote: expected 1 data part, not " << m.data.size());
        return;
    }

    try {
        quorum_vote_t vote = deserialize_vote(m.data[0]);

        if (vote.block_height > snw.core.get_current_blockchain_height()) {
            MDEBUG("Ignoring vote: block height " << vote.block_height << " is too high");
            return;
        }

        cryptonote::vote_verification_context vvc = {};
        snw.core.add_service_node_vote(vote, vvc);
        if (vvc.m_verification_failed)
        {
            MWARNING("Vote verification failed; ignoring vote");
            return;
        }

        if (vvc.m_added_to_pool)
            relay_votes(self, {{vote}});
    }
    catch (const std::exception &e) {
        MWARNING("Deserialization of vote from " << as_hex(m.pubkey) << " failed: " << e.what());
    }
}

/// Gets an integer value out of a bt_dict, if present and fits (i.e. get_int<> succeeds); if not
/// present or conversion falls, returns `fallback`.
template <typename I>
std::enable_if_t<std::is_integral<I>::value, I> get_or(bt_dict &d, const std::string &key, I fallback) {
    auto it = d.find(key);
    if (it != d.end()) {
        try { return get_int<I>(it->second); }
        catch (...) {}
    }
    return fallback;
}

// Obtains the blink quorums, verifies that they are of an acceptable size, and verifies the given
// input quorum checksum matches the computed checksum for the quorums (if provided), otherwise sets
// the given output checksum (if provided) to the calculated value.  Throws std::runtime_error on
// failure.
quorum_array get_blink_quorums(uint64_t blink_height, const service_node_list &snl, const uint64_t *input_checksum, uint64_t *output_checksum = nullptr) {
    // We currently just use two quorums, Q and Q' in the whitepaper, but this code is designed to
    // work fine with more quorums (but don't use a single subquorum; that could only be secure or
    // reliable but not both).
    quorum_array result;

    uint64_t local_checksum = 0;
    for (uint8_t qi = 0; qi < NUM_BLINK_QUORUMS; qi++) {
        auto height = blink_tx::quorum_height(blink_height, static_cast<blink_tx::subquorum>(qi));
        if (!height)
            throw std::runtime_error("too early in blockchain to create a quorum");
        result[qi] = snl.get_quorum(quorum_type::blink, height);
        auto &v = result[qi]->validators;
        if (v.size() < BLINK_MIN_VOTES || v.size() > BLINK_SUBQUORUM_SIZE)
            throw std::runtime_error("not enough blink nodes to form a quorum");
        local_checksum += quorum_checksum(v, qi * BLINK_SUBQUORUM_SIZE);
    }
    MTRACE("Verified enough active blink nodes for a quorum; quorum checksum: " << local_checksum);

    if (input_checksum) {
        if (*input_checksum != local_checksum)
            throw std::runtime_error("wrong quorum checksum: expected " + std::to_string(local_checksum) + ", received " + std::to_string(*input_checksum));

        MTRACE("Blink quorum checksum matched");
    }
    if (output_checksum)
        *output_checksum = local_checksum;

    return result;
}

// Used when debugging is enabled to print known signatures.
// Prints [x x x ...] [x x x ...] for the quorums where each "x" is either "A" for an approval
// signature, "R" for a rejection signature, or "-" for no signature.
std::string debug_known_signatures(blink_tx &btx, quorum_array &blink_quorums) {
    std::ostringstream os;
    bool first = true;
    for (uint8_t qi = 0; qi < blink_quorums.size(); qi++) {
        if (qi > 0) os << ' ';
        os << '[';
        const auto q = static_cast<blink_tx::subquorum>(qi);
        const int slots = blink_quorums[qi]->validators.size();
        for (int i = 0; i < slots; i++) {
            if (i > 0) os << ' ';
            auto st = btx.get_signature_status(q, i);
            os << (st == blink_tx::signature_status::approved ? 'A' : st == blink_tx::signature_status::rejected ? 'R' : '-');
        }
        os << ']';
    }
    return os.str();
}


/// Processes blink signatures; called immediately upon receiving a signature if we know about the
/// tx; otherwise signatures are stored until we learn about the tx and then processed.
void process_blink_signatures(SNNWrapper &snw, blink_tx &btx, quorum_array &blink_quorums, uint64_t quorum_checksum, std::list<pending_signature> &&signatures,
        uint64_t reply_tag, // > 0 if we are expected to send a status update if it becomes accepted/rejected
        const std::string reply_pubkey, // who we are supposed to send the status update to
        const std::string &received_from = ""s /* x25519 of the peer that sent this, if available (to avoid trying to pointlessly relay back to them) */) {

    bool already_approved = false, already_rejected = false;
    // First check values and discard any signatures for positions we already have.
    {
        auto lock = btx.shared_lock(); // Don't take out a heavier unique lock until later when we are sure we need
        for (auto it = signatures.begin(); it != signatures.end(); ) {
            auto &pending = *it;
            auto &qi = std::get<uint8_t>(pending);
            auto &position = std::get<int>(pending);

            auto subquorum = static_cast<blink_tx::subquorum>(qi);
            auto &validators = blink_quorums[qi]->validators;

            if (position < 0 || position >= (int) validators.size()) {
                MWARNING("Invalid blink signature: subquorum position is invalid");
                it = signatures.erase(it);
                continue;
            }

            if (btx.get_signature_status(subquorum, position) != blink_tx::signature_status::none) {
                it = signatures.erase(it);
                continue;
            }
            ++it;
        }

        already_approved = btx.approved();
        already_rejected = btx.rejected();
    }
    if (signatures.empty())
        return;

    // Now check and discard any invalid signatures (we can do this without holding a lock)
    for (auto it = signatures.begin(); it != signatures.end(); ) {
        auto &pending = *it;
        auto &approval = std::get<bool>(pending);
        auto &qi = std::get<uint8_t>(pending);
        auto &position = std::get<int>(pending);
        auto &signature = std::get<crypto::signature>(pending);

        auto subquorum = static_cast<blink_tx::subquorum>(qi);
        auto &validators = blink_quorums[qi]->validators;

        if (!crypto::check_signature(btx.hash(approval), validators[position], signature)) {
            MWARNING("Invalid blink signature: signature verification failed");
            it = signatures.erase(it);
            continue;
        }
        ++it;
    }

    if (signatures.empty())
        return;

    bool now_approved = already_approved, now_rejected = already_rejected;
    {
        auto lock = btx.unique_lock();

        MTRACE("Before recording new signatures I have existing signatures: " << debug_known_signatures(btx, blink_quorums));

        // Now actually add them (and do one last check on them)
        for (auto it = signatures.begin(); it != signatures.end(); ) {
            auto &pending = *it;
            auto &approval = std::get<bool>(pending);
            auto &qi = std::get<uint8_t>(pending);
            auto &position = std::get<int>(pending);
            auto &signature = std::get<crypto::signature>(pending);

            auto subquorum = static_cast<blink_tx::subquorum>(qi);
            auto &validators = blink_quorums[qi]->validators;

            if (btx.add_prechecked_signature(subquorum, position, approval, signature)) {
                MDEBUG("Validated and stored " << (approval ? "approval" : "rejection") << " signature for tx " << btx.tx.hash << ", subquorum " << int{qi} << ", position " << position);
                ++it;
            }
            else {
                // Signature already present, which means it got added between the check above and now
                // by another thread.
                it = signatures.erase(it);
            }
        }

        if (!signatures.empty()) {
            now_approved = btx.approved();
            now_rejected = btx.rejected();
            MDEBUG("Updated signatures; now have signatures: " << debug_known_signatures(btx, blink_quorums));
        }
    }

    if (signatures.empty())
        return;

    peer_info::exclude_set relay_exclude;
    if (!received_from.empty()) {
        auto pubkey = snw.core.get_service_node_list().get_pubkey_from_x25519(x25519_from_string(received_from));
        if (pubkey)
            relay_exclude.insert(std::move(pubkey));
    }

    // We added new signatures that we didn't have before, so relay those signatures to blink peers
    peer_info pinfo{snw, quorum_type::blink, blink_quorums.begin(), blink_quorums.end(), true /*opportunistic*/,
        std::move(relay_exclude)};

    MDEBUG("Relaying " << signatures.size() << " blink signatures to " << pinfo.strong_peers << " (strong) + " <<
            (pinfo.peers.size() - pinfo.strong_peers) << " (opportunistic) blink peers");

    bt_list i_list, p_list, r_list, s_list;
    for (auto &s : signatures) {
        i_list.emplace_back(std::get<uint8_t>(s));
        p_list.emplace_back(std::get<int>(s));
        r_list.emplace_back(std::get<bool>(s));
        s_list.emplace_back(get_data_as_string(std::get<crypto::signature>(s)));
    }

    bt_dict blink_sign_data{
        {"h", btx.height},
        {"#", get_data_as_string(btx.tx.hash)},
        {"q", quorum_checksum},
        {"i", std::move(i_list)},
        {"p", std::move(p_list)},
        {"r", std::move(r_list)},
        {"s", std::move(s_list)},
    };

    pinfo.relay_to_peers("blink_sign", blink_sign_data);

    MTRACE("Done blink signature relay");

    if (reply_tag && !reply_pubkey.empty()) {
        if (now_approved && !already_approved) {
            MINFO("Blink tx is now approved; sending result back to originating node");
            snw.snn.send(reply_pubkey, "bl_good", bt_dict{{"!", reply_tag}}, send_option::optional{});
        } else if (now_rejected && !already_rejected) {
            MINFO("Blink tx is now rejected; sending result back to originating node");
            snw.snn.send(reply_pubkey, "bl_bad", bt_dict{{"!", reply_tag}}, send_option::optional{});
        }
    }
}



/// A "blink" message is used to submit a blink tx from a node to members of the blink quorum and
/// also used to relay the blink tx between quorum members.  Fields are:
///
///     "!" - Non-zero positive integer value for a connecting node; we include the tag in any
///           response if present so that the initiator can associate the response to the request.
///           If there is no tag then there will be no success/error response.  Only included in
///           node-to-SN submission but not SN-to-SN relaying (which doesn't return a response
///           message).
///
///     "h" - Blink authorization height for the transaction.  Must be within 2 of the current
///           height for the tx to be accepted.  Mandatory.
///
///     "q" - checksum of blink quorum members.  Mandatory, and must match the receiving SN's
///           locally computed checksum of blink quorum members.
///
///     "t" - the serialized transaction data.
///
///     "#" - precomputed tx hash.  This much match the actual hash of the transaction (the blink
///           submission will fail immediately if it does not).
///
void handle_blink(SNNetwork::message &m, void *self) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(self);

    // TODO: if someone sends an invalid tx (i.e. one that doesn't get to the distribution stage)
    // then put a timeout on that IP during which new submissions from them are dropped for a short
    // time.
    // If an incoming connection:
    // - We can refuse new connections from that IP in the ZAP handler
    // - We can (somewhat hackily) disconnect by getting the raw fd via the SRCFD property of the
    //   message and close it.
    // If an outgoing connection - refuse reconnections via ZAP and just close it.

    MDEBUG("Received a blink tx from " << (m.sn ? "SN " : "non-SN ") << as_hex(m.pubkey));

    assert(snw.core.get_service_node_keys());

    if (m.data.size() != 1) {
        MINFO("Rejecting blink message: expected one data entry not " << m.data.size());
        // No valid data and so no reply tag; we can't send a response
        return;
    }
    auto &data = boost::get<bt_dict>(m.data[0]);

    auto tag = get_or<uint64_t>(data, "!", 0);

    // verify that height is within-2 of current height
    auto blink_height = get_int<uint64_t>(data.at("h"));
    auto local_height = snw.core.get_current_blockchain_height();

    if (blink_height < local_height - 2) {
        MINFO("Rejecting blink tx because blink auth height is too low (" << blink_height << " vs. " << local_height << ")");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Invalid blink authorization height"}});
        return;
    } else if (blink_height > local_height + 2) {
        // TODO: if within some threshold (maybe 5-10?) we could hold it and process it once we are
        // within 2.
        MINFO("Rejecting blink tx because blink auth height is too high (" << blink_height << " vs. " << local_height << ")");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Invalid blink authorization height"}});
        return;
    }
    MTRACE("Blink tx auth height " << blink_height << " is valid (local height is " << local_height << ")");

    auto t_it = data.find("t");
    if (t_it == data.end()) {
        MINFO("Rejecting blink tx: no tx data included in request");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "No transaction included in blink request"}});
        return;
    }
    const std::string &tx_data = boost::get<std::string>(t_it->second);
    MTRACE("Blink tx data is " << tx_data.size() << " bytes");

    // "hash" is optional -- it lets us short-circuit processing the tx if we've already seen it,
    // and is added internally by SN-to-SN forwards but not the original submitter.  We don't trust
    // the hash if we haven't seen it before -- this is only used to skip propagation and
    // validation.
    crypto::hash tx_hash;
    auto &tx_hash_str = boost::get<std::string>(data.at("#"));
    if (tx_hash_str.size() == sizeof(crypto::hash)) {
        std::memcpy(tx_hash.data, tx_hash_str.data(), sizeof(crypto::hash));
        std::shared_lock<std::shared_timed_mutex> lock{snw.mutex};
        auto bit = snw.blinks.find(blink_height);
        if (bit != snw.blinks.end()) {
            auto &umap = bit->second;
            auto it = umap.find(tx_hash);
            if (it != umap.end() && it->second.btxptr) {
                MDEBUG("Already seen and forwarded this blink tx, ignoring it.");
                if (tag && !it->second.reply_tag) {
                    // Set the tag/pubkey if not set: that means we received it from a blink quorum
                    // peer before we got it from the originating node, but this is the originating
                    // node to whom we still want to reply.
                    it->second.reply_tag = tag;
                    it->second.reply_pubkey = m.pubkey;
                }

                return;
            }
        }
        MTRACE("Blink tx hash: " << as_hex(tx_hash.data));
    } else {
        MINFO("Rejecting blink tx: invalid tx hash included in request");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Invalid transaction hash"}});
        return;
    }

    auto btxptr = std::make_shared<blink_tx>(blink_height);
    auto &btx = *btxptr;

    quorum_array blink_quorums;
    uint64_t checksum = get_int<uint64_t>(data.at("q"));
    try {
        blink_quorums = get_blink_quorums(blink_height, snw.core.get_service_node_list(), &checksum);
    } catch (const std::runtime_error &e) {
        MINFO("Rejecting blink tx: " << e.what());
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Unable to retrieve blink quorum: "s + e.what()}});
        return;
    }

    peer_info pinfo{snw, quorum_type::blink, blink_quorums.begin(), blink_quorums.end(), true /*opportunistic*/,
        {snw.core.get_service_node_list().get_pubkey_from_x25519(x25519_from_string(m.pubkey))} // exclude the peer that just sent it to us
        };

    if (pinfo.my_position_count > 0)
        MTRACE("Found this SN in " << pinfo.my_position_count << " subquorums");
    else {
        MINFO("Rejecting blink tx: this service node is not a member of the blink quorum!");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Blink tx relayed to non-blink quorum member"}});
        return;
    }

    {
        crypto::hash tx_hash_actual;
        if (!cryptonote::parse_and_validate_tx_from_blob(tx_data, btx.tx, tx_hash_actual)) {
            MINFO("Rejecting blink tx: failed to parse transaction data");
            if (tag)
                m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Failed to parse transaction data"}});
            return;
        }
        MTRACE("Successfully parsed transaction data");

        if (tx_hash != tx_hash_actual) {
            MINFO("Rejecting blink tx: submitted tx hash " << tx_hash << " did not match actual tx hash " << tx_hash_actual);
            if (tag)
                m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "Invalid transaction hash"}});
            return;
        } else {
            MTRACE("Pre-computed tx hash matches actual tx hash");
        }
    }

    // Abort if we don't have at least one strong peer to send it to.  This can only happen if it's
    // a brand new SN (not just restarted!) that hasn't received uptime proofs before.
    if (!pinfo.strong_peers) {
        MWARNING("Could not find connection info for any blink quorum peers.  Aborting blink tx");
        if (tag)
            m.reply("bl_nostart", bt_dict{{"!", tag}, {"e", "No quorum peers are currently reachable"}});
        return;
    }

    // See if we've already handled this blink tx, and if not, store it.  Also check for any pending
    // signatures for this blink tx that we received or processed before we got here with this tx.
    std::list<pending_signature> signatures;
    {
        std::unique_lock<std::shared_timed_mutex> lock(snw.mutex);
        auto &bl_info = snw.blinks[blink_height][tx_hash];
        if (bl_info.btxptr) {
            MDEBUG("Already seen and forwarded this blink tx, ignoring it.");
            return;
        }
        bl_info.btxptr = btxptr;
        for (auto &sig : bl_info.pending_sigs)
            signatures.push_back(std::move(sig));
        bl_info.pending_sigs.clear();
        if (tag > 0) {
            bl_info.reply_tag = tag;
            bl_info.reply_pubkey = m.pubkey;
        }
    }
    MTRACE("Accepted new blink tx for verification");

    // The submission looks good.  We distribute it first, *before* we start verifying the actual tx
    // details, for two reasons: we want other quorum members to start verifying ASAP, and we want
    // to propagate to peers even if the things below fail on this node (because our peers might
    // succeed).  We test the bits *above*, however, because if they fail we won't agree on the
    // right quorum to send it to.
    //
    // FIXME - am I 100% sure I want to do the above?  Verifying the TX would cut off being able to
    // induce a node to broadcast a junk TX to other quorum members.


    {
        bt_dict blink_data{
            {"h", blink_height},
            {"q", checksum},
            {"t", tx_data},
            {"#", tx_hash_str},
        };
        MDEBUG("Relaying blink tx to " << pinfo.strong_peers << " strong and " << (pinfo.peers.size() - pinfo.strong_peers) << " opportunistic blink peers");
        pinfo.relay_to_peers("blink", blink_data);
    }

    // Anything past this point always results in a success or failure signature getting sent to peers

    // Check tx for validity
    bool already_in_mempool;
    cryptonote::tx_verification_context tvc = {};
    bool approved = snw.pool.add_blink(btxptr, tvc, already_in_mempool);

    MINFO("Blink TX " << tx_hash << (approved ? " approved and added to mempool" : " rejected"));
    if (!approved)
        MDEBUG("TX rejected because: " << print_tx_verification_context(tvc));

    auto hash_to_sign = btx.hash(approved);
    auto &keys = *snw.core.get_service_node_keys();
    crypto::signature sig;
    generate_signature(hash_to_sign, keys.pub, keys.key, sig);

    // Now that we have the blink tx stored we can add our signature *and* any other pending
    // signatures we are holding onto, then blast the entire thing to our peers.
    for (uint8_t qi = 0; qi < NUM_BLINK_QUORUMS; qi++) {
        if (pinfo.my_position[qi] < 0)
            continue;
        signatures.emplace_back(approved, qi, pinfo.my_position[qi], sig);
    }

    process_blink_signatures(snw, btx, blink_quorums, checksum, std::move(signatures), tag, m.pubkey);
}

template <typename T, typename CopyValue>
void copy_signature_values(std::list<pending_signature> &signatures, const bt_value &val, CopyValue copy_value) {
    auto &results = boost::get<bt_list>(val);
    if (signatures.empty())
        signatures.resize(results.size());
    else if (results.empty())
        throw std::invalid_argument("Invalid blink signature data: no signatures sent");
    else if (signatures.size() != results.size())
        throw std::invalid_argument("Invalid blink signature data: i, p, r, s lengths must be identical");
    auto it = signatures.begin();
    for (auto &r : results)
        copy_value(std::get<T>(*it++), r);
}

/// A "blink_sign" message is used to relay signatures from one quorum member to other members.
/// Fields are:
///
///     "h" - Blink authorization height of the signature.
///
///     "#" - tx hash of the transaction.
///
///     "q" - checksum of blink quorum members.  Mandatory, and must match the receiving SN's
///           locally computed checksum of blink quorum members.
///
///     "i" - list of quorum indices, i.e. 0 for the base quorum, 1 for the future quorum
///
///     "p" - list of quorum positions
///
///     "r" - list of blink signature results (0 if rejected, 1 if approved)
///
///     "s" - list of blink signatures
///
/// Each of "i", "p", "r", and "s" must be exactly the same length; each element at a position in
/// each list corresponds to the values at the same position of the other lists.
///
/// Signatures will be forwarded if new; known signatures will be ignored.
void handle_blink_signature(SNNetwork::message &m, void *self) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(self);

    MDEBUG("Received a blink tx signature from SN " << as_hex(m.pubkey));

    if (m.data.size() != 1)
        throw std::runtime_error("Rejecting blink signature: expected one data entry not " + std::to_string(m.data.size()));

    auto &data = boost::get<bt_dict>(m.data[0]);

    uint64_t blink_height = 0, checksum = 0;
    crypto::hash tx_hash;
    bool saw_checksum = false, saw_hash = false, saw_i, saw_r, saw_p, saw_s;
    std::list<pending_signature> signatures;

    for (const auto &input : data) {
        if (input.first.size() != 1)
            throw std::invalid_argument("Invalid blink signature data: invalid/unrecognized key " + input.first);

        auto &val = input.second;
        switch (input.first[0]) {
            case 'h':
                blink_height = get_int<uint64_t>(val);
                break;
            case '#': {
                auto &hash_str = boost::get<std::string>(val);
                if (hash_str.size() != sizeof(crypto::hash))
                    throw std::invalid_argument("Invalid blink signature data: invalid tx hash");
                std::memcpy(tx_hash.data, hash_str.data(), sizeof(crypto::hash));
                saw_hash = true;
                break;
            }
            case 'q':
                checksum = get_int<uint64_t>(val);
                saw_checksum = true;
                break;
            case 'i':
                copy_signature_values<uint8_t>(signatures, val, [](uint8_t &dest, const bt_value &v) {
                    dest = get_int<uint8_t>(v);
                    if (dest >= NUM_BLINK_QUORUMS)
                        throw std::invalid_argument("Invalid blink signature data: invalid quorum index " + std::to_string(dest));
                });
                saw_i = true;
                break;
            case 'r':
                copy_signature_values<bool>(signatures, val, [](bool &dest, const bt_value &v) { dest = get_int<bool>(v); });
                saw_r = true;
                break;
            case 'p':
                copy_signature_values<int>(signatures, val, [](int &dest, const bt_value &v) {
                    dest = get_int<int>(v);
                    if (dest < 0 || dest >= BLINK_SUBQUORUM_SIZE) // This is only input validation: it might actually have to be smaller depending on the actual quorum (we check later)
                        throw std::invalid_argument("Invalid blink signature data: invalid quorum position " + std::to_string(dest));
                });
                saw_p = true;
                break;
            case 's':
                copy_signature_values<crypto::signature>(signatures, val, [](crypto::signature &dest, const bt_value &v) {
                    auto &sig_str = boost::get<std::string>(v);
                    if (sig_str.size() != sizeof(crypto::signature))
                        throw std::invalid_argument("Invalid blink signature data: invalid signature");
                    std::memcpy(&dest, sig_str.data(), sizeof(crypto::signature));
                    if (!dest)
                        throw std::invalid_argument("Invalid blink signature data: invalid null signature");
                });
                saw_s = true;
                break;
            default:
                throw std::invalid_argument("Invalid blink signature data: invalid/unrecognized key " + input.first);
        }
    }

    if (!(blink_height && saw_hash && saw_checksum && saw_i && saw_r && saw_p && saw_s))
        throw std::invalid_argument("Invalid blink signature data: missing required fields");

    auto blink_quorums = get_blink_quorums(blink_height, snw.core.get_service_node_list(), &checksum); // throws if bad quorum or checksum mismatch

    uint64_t reply_tag;
    std::string reply_pubkey;
    std::shared_ptr<blink_tx> btxptr;
    {
        std::shared_lock<std::shared_timed_mutex> lock{snw.mutex};
        auto bit = snw.blinks.find(blink_height);
        if (bit != snw.blinks.end()) {
            auto it = bit->second.find(tx_hash);
            if (it != bit->second.end()) {
                btxptr = it->second.btxptr;
                reply_tag = it->second.reply_tag;
                reply_pubkey = it->second.reply_pubkey;
            }
        }
    }

    if (btxptr)
        MINFO("Found blink tx in local blink cache");
    else {
        MINFO("Blink tx not found in local blink cache; delaying signature verification");
        std::unique_lock<std::shared_timed_mutex> lock{snw.mutex};
        auto &delayed = snw.blinks[blink_height][tx_hash].pending_sigs;
        for (auto &sig : signatures)
            delayed.insert(std::move(sig));
        return;
    }

    process_blink_signatures(snw, *btxptr, blink_quorums, checksum, std::move(signatures), reply_tag, reply_pubkey, m.pubkey);
}


// tag -> {hash, promise, expiry}
using blink_response = std::pair<cryptonote::blink_result, std::string>;
struct blink_result_data {
    crypto::hash hash;
    std::promise<blink_response> promise;
    std::chrono::high_resolution_clock::time_point expiry;
    int remote_count;
    std::atomic<int> nostart_count{0};
    std::atomic<int> bad_count{0};
    std::atomic<int> good_count{0};
};
std::unordered_map<uint64_t, blink_result_data> pending_blink_results;
std::shared_timed_mutex pending_blink_result_mutex;

// Sanity check against runaway active pending blink submissions
constexpr size_t MAX_ACTIVE_PROMISES = 1000;

std::future<std::pair<cryptonote::blink_result, std::string>> send_blink(void *obj, const std::string &tx_blob) {
    std::promise<std::pair<cryptonote::blink_result, std::string>> promise;
    auto future = promise.get_future();
    cryptonote::transaction tx;
    crypto::hash tx_hash;

    uint64_t blink_tag = 0;
    blink_result_data *brd = nullptr;

    if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash)) {
        promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Could not parse transaction data"));
    } else {
        auto now = std::chrono::high_resolution_clock::now();
        bool found = false;
        std::unique_lock<std::shared_timed_mutex> lock{pending_blink_result_mutex};
        for (auto it = pending_blink_results.begin(); it != pending_blink_results.end(); ) {
            auto &brd = it->second;
            if (brd.expiry >= now) {
                try { brd.promise.set_value(std::make_pair(cryptonote::blink_result::timeout, "Blink quorum timeout")); }
                catch (const std::future_error &) { /* ignore */ }
                it = pending_blink_results.erase(it);
            } else {
                if (!found && brd.hash == tx_hash)
                    found = true;
                ++it;
            }
        }
        if (found) {
            promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Transaction was already submitted"));
        } else if (pending_blink_results.size() >= MAX_ACTIVE_PROMISES) {
            promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Node is busy, try again later"));
        } else {
            while (!brd) {
                // Choose an unused tag randomly so that the blink tag value doesn't give anything away
                blink_tag = tools::rng();
                if (blink_tag == 0 || pending_blink_results.count(blink_tag) > 0) continue;
                brd = &pending_blink_results[blink_tag];
                brd->hash = tx_hash;
                brd->promise = std::move(promise);
                brd->expiry = std::chrono::high_resolution_clock::now() + 30s;
            }
        }
    }

    if (blink_tag > 0) {
        auto &snw = *reinterpret_cast<SNNWrapper *>(obj);
        uint64_t height = snw.core.get_current_blockchain_height();
        uint64_t checksum;
        auto quorums = get_blink_quorums(height, snw.core.get_service_node_list(), nullptr, &checksum);

        // Lookup the x25519 and ZMQ connection string for all possible blink recipients so that we
        // know where to send it to, and so that we can immediately exclude SNs that aren't active
        // anymore.
        std::unordered_set<crypto::public_key> candidates;
        for (auto &q : quorums)
            candidates.insert(q->validators.begin(), q->validators.end());

        MDEBUG("Have " << candidates.size() << " blink SN candidates");

        std::vector<std::pair<std::string, std::string>> remotes; // x25519 pubkey -> connect string
        remotes.reserve(candidates.size());
        snw.core.get_service_node_list().for_each_service_node_info(candidates.begin(), candidates.end(),
            [&remotes](const crypto::public_key &pubkey, const service_nodes::service_node_info &info) {
                if (!info.is_active()) {
                    MTRACE("Not include inactive node " << pubkey);
                    return;
                }
                auto &proof = *info.proof;
                if (!proof.pubkey_x25519 || !proof.quorumnet_port || !proof.public_ip) {
                    MTRACE("Not including node " << pubkey << ": missing x25519(" << as_hex(get_data_as_string(proof.pubkey_x25519)) << "), "
                            "public_ip(" << epee::string_tools::get_ip_string_from_int32(proof.public_ip) << "), or qnet port(" << proof.quorumnet_port << ")");
                    return;
                }
                remotes.emplace_back(get_data_as_string(proof.pubkey_x25519),
                        "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port));
            });

        MDEBUG("Have " << remotes.size() << " blink SN candidates after checking active status and connection details");

        // Select 4 random (active) blink quorum SNs to send the blink to.
        std::vector<size_t> indices(remotes.size());
        std::iota(indices.begin(), indices.end(), 0);
        std::shuffle(indices.begin(), indices.end(), tools::rng);
        if (indices.size() > 4)
            indices.resize(4);
        brd->remote_count = indices.size();

        send_option::serialized data{bt_dict{
            {"!", blink_tag},
            {"#", get_data_as_string(tx_hash)},
            {"h", height},
            {"q", checksum},
            {"t", tx_blob}
        }};

        for (size_t i : indices) {
            MINFO("Relaying blink tx to " << as_hex(remotes[i].first) << " @ " << remotes[i].second);
            snw.snn.send(remotes[i].first, "blink", data, send_option::hint{remotes[i].second});
        }
    }

    return future;
}


void common_blink_response(uint64_t tag, cryptonote::blink_result res, std::string msg, bool nostart, bool bad, bool good) {
    assert(int{nostart} + int{bad} + int{good} == 1);
    bool promise_set = false;
    {
        std::shared_lock<std::shared_timed_mutex> lock{pending_blink_result_mutex};
        auto it = pending_blink_results.find(tag);
        if (it == pending_blink_results.end())
            return; // Already handled, or obsolete

        auto &pbr = it->second;
        auto &count = nostart ? pbr.nostart_count : bad ? pbr.bad_count : pbr.good_count;
        auto count_same = ++count;
        if (count_same > pbr.remote_count / 2) {
            try {
                pbr.promise.set_value(std::make_pair(res, msg));
                promise_set = true;
            }
            catch (const std::future_error &) { /* ignore */ }
        }
    }
    if (promise_set) {
        std::unique_lock<std::shared_timed_mutex> lock{pending_blink_result_mutex};
        pending_blink_results.erase(tag);
    }
}

/// bl_nostart is sent back to the submitter when the tx doesn't get far enough to be distributed
/// among the quorum because of some failure (bad height, parse failure, etc.)  It includes:
///
///     ! - the tag as included in the submission
///     e - an error message
///
/// It's possible for some nodes to accept and others to refuse, so we don't actually set the
/// promise unless we get a nostart response from a majority of the remotes.
void handle_blink_not_started(SNNetwork::message &m, void *self) {
    if (m.data.size() != 1) {
        MERROR("Bad blink not started response: expected one data entry not " << m.data.size());
        return;
    }
    auto &data = boost::get<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));
    auto &error = boost::get<std::string>(data.at("e"));

    MINFO("Received no-start blink response: " << error);

    common_blink_response(tag, cryptonote::blink_result::rejected, std::move(error), true, false, false);
}
/// bl_bad gets returned once we know enough of the blink quorum has rejected the result to make it
/// unequivocal that it has been rejected.  We require a failure response from a majority of the
/// remotes before setting the promise.
///
///     ! - the tag as included in the submission
///
void handle_blink_failure(SNNetwork::message &m, void *self) {
    if (m.data.size() != 1) {
        MERROR("Blink failure message not understood: expected one data entry not " << m.data.size());
        return;
    }
    auto &data = boost::get<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));

    // TODO - we ought to be able to signal an error message *sometimes*, e.g. if one of the remotes
    // we sent it to rejected it then that remote can reply with a message.  That gets a bit
    // complicated, though, in terms of maintaining internal state (since the bl_bad is sent on
    // signature receipt, not at rejection time), so for now we don't include it.
    //auto &error = boost::get<std::string>(data.at("e"));

    MINFO("Received blink failure response");

    common_blink_response(tag, cryptonote::blink_result::rejected, "Transaction rejected by quorum"s, false, true, false);
}

/// bl_good gets returned once we know enough of the blink quorum has accepted the result to make it
/// valid.  We require a good response from a majority of the remotes before setting the promise.
///
///     ! - the tag as included in the submission
///
void handle_blink_success(SNNetwork::message &m, void *self) {
    if (m.data.size() != 1) {
        MERROR("Blink success message not understood: expected one data entry not " << m.data.size());
        return;
    }
    auto &data = boost::get<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));

    MINFO("Received blink success response");

    common_blink_response(tag, cryptonote::blink_result::accepted, ""s, false, false, true);
}


} // end empty namespace


/// Sets the cryptonote::quorumnet_* function pointers (allowing core to avoid linking to
/// cryptonote_protocol).  Called from daemon/daemon.cpp.  Also registers quorum command callbacks.
void init_core_callbacks() {
    cryptonote::quorumnet_new = new_snnwrapper;
    cryptonote::quorumnet_delete = delete_snnwrapper;
    cryptonote::quorumnet_relay_votes = relay_votes;
    cryptonote::quorumnet_send_blink = send_blink;

    // Receives a vote
    SNNetwork::register_quorum_command("vote", handle_vote);

    // Receives a new blink tx submission from an external node, or forward from other quorum
    // members who received it from an external node.
    SNNetwork::register_public_command("blink", handle_blink);

    // Sends a message back to the blink initiator that the transaction was NOT relayed, either
    // because the height was invalid or the quorum checksum failed.  This is only sent by the entry
    // point service nodes into the quorum to let it know the tx verification has not started from
    // that node.  It does not necessarily indicate a failure unless all entry point attempts return
    // the same.
    SNNetwork::register_quorum_command("bl_nostart", handle_blink_not_started);

    // Sends a message from the entry SNs back to the initiator that the Blink tx has been rejected:
    // that is, enough signed rejections have occured that the Blink tx cannot be accepted.
    SNNetwork::register_quorum_command("bl_bad", handle_blink_failure);

    // Sends a message from the entry SNs back to the initiator that the Blink tx has been accepted
    // and validated and is being broadcast to the network.
    SNNetwork::register_quorum_command("bl_good", handle_blink_success);

    // Receives blink tx signatures or rejections between quorum members (either original or
    // forwarded).  These are propagated by the receiver if new
    SNNetwork::register_quorum_command("blink_sign", handle_blink_signature);
}

}