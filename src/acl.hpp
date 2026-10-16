#pragma once

#include "packet.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pi {

enum class Action : uint8_t { ALLOW, DENY };

// An IPv4 prefix in host byte order. mask == 0 matches any address.
struct IPv4Prefix {
    uint32_t addr = 0;
    uint32_t mask = 0;

    bool any() const { return mask == 0; }
    bool matches(uint32_t ip) const { return (ip & mask) == addr; }
};

// Inclusive port range. The full range [0, 65535] means "ANY".
struct PortRange {
    uint16_t lo = 0;
    uint16_t hi = 65535;

    bool any() const { return lo == 0 && hi == 65535; }
    bool matches(uint16_t port) const { return port >= lo && port <= hi; }
};

struct ACLRule {
    IPv4Prefix src_ip;
    IPv4Prefix dst_ip;
    PortRange src_port;
    PortRange dst_port;
    uint8_t protocol = 0;  // IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP / ..., 0 = ANY
    Action action = Action::ALLOW;
    std::string reason;
    int line = 0;  // line number in the rules file, for diagnostics

    bool matches(const ParsedPacket& pkt) const;
};

struct Verdict {
    Action action;
    int rule_index;  // index into the rule list, or -1 for the default policy
};

class ACLEngine {
public:
    ACLEngine() = default;
    ACLEngine(std::vector<ACLRule> rules, Action default_action);

    // First-match evaluation. Only meaningful for IPv4 packets.
    Verdict evaluate(const ParsedPacket& pkt) const;

    const std::vector<ACLRule>& rules() const { return rules_; }
    Action default_action() const { return default_action_; }

private:
    std::vector<ACLRule> rules_;
    Action default_action_ = Action::ALLOW;
};

// Rules file format (CSV, '#' starts a comment, blank lines ignored):
//   ACTION,PROTOCOL,SRC_IP,SRC_PORT,DST_IP,DST_PORT[,REASON]
//   DEFAULT,ACTION
// ACTION:   ALLOW | DENY
// PROTOCOL: ANY | TCP | UDP | ICMP | <0-255>
// IP:       ANY | a.b.c.d | a.b.c.d/len
// PORT:     ANY | n | lo-hi
struct RuleLoadResult {
    std::optional<ACLEngine> engine;
    std::string error;  // set when engine is empty
};

RuleLoadResult load_rules_file(const std::string& path);
RuleLoadResult parse_rules(const std::string& text);

const char* action_name(Action a);

}  // namespace pi
