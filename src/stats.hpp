#pragma once

#include "acl.hpp"
#include "packet.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace pi {

struct Stats {
    uint64_t packets = 0;
    uint64_t bytes = 0;

    // ACL outcomes (IPv4 only); everything else is "not evaluated".
    uint64_t allowed = 0;
    uint64_t blocked = 0;
    uint64_t not_evaluated = 0;

    uint64_t truncated = 0;
    uint64_t bad_ip_checksum = 0;

    // Protocol distribution
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t other_ipv4 = 0;
    uint64_t arp = 0;
    uint64_t ipv6 = 0;
    uint64_t other_l2 = 0;

    std::vector<uint64_t> rule_hits;  // parallel to ACLEngine::rules()
    uint64_t default_hits = 0;

    void reset_rule_hits(size_t rule_count);
    void record(const ParsedPacket& pkt, const Verdict* verdict);
};

// Multi-line summary. `prev` is the snapshot from the previous report and is
// used for the rate line; pass interval_sec <= 0 to omit rates.
std::string format_stats(const Stats& now, const Stats& prev, double interval_sec, double uptime_sec,
                         const ACLEngine& acl);

}  // namespace pi
