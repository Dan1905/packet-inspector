#include "acl.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace pi {
namespace {

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

std::vector<std::string> split_csv(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream ss(line);
    std::string field;
    while (std::getline(ss, field, ',')) fields.push_back(trim(field));
    if (!line.empty() && line.back() == ',') fields.emplace_back();
    return fields;
}

bool parse_uint(const std::string& s, unsigned long max, unsigned long& out) {
    if (s.empty() || s.size() > 10) return false;
    for (char c : s)
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    out = std::stoul(s);
    return out <= max;
}

bool parse_action(const std::string& s, Action& out) {
    const std::string u = upper(s);
    if (u == "ALLOW" || u == "PASS") out = Action::ALLOW;
    else if (u == "DENY" || u == "BLOCK") out = Action::DENY;
    else return false;
    return true;
}

bool parse_protocol(const std::string& s, uint8_t& out) {
    const std::string u = upper(s);
    if (u == "ANY" || u == "*") out = 0;
    else if (u == "TCP") out = IPPROTO_TCP;
    else if (u == "UDP") out = IPPROTO_UDP;
    else if (u == "ICMP") out = IPPROTO_ICMP;
    else {
        unsigned long n;
        if (!parse_uint(s, 255, n)) return false;
        out = static_cast<uint8_t>(n);
    }
    return true;
}

bool parse_prefix(const std::string& s, IPv4Prefix& out) {
    if (upper(s) == "ANY" || s == "*") {
        out = IPv4Prefix{};
        return true;
    }
    std::string addr = s;
    unsigned long len = 32;
    if (auto slash = s.find('/'); slash != std::string::npos) {
        addr = s.substr(0, slash);
        if (!parse_uint(s.substr(slash + 1), 32, len)) return false;
    }
    in_addr a{};
    if (inet_pton(AF_INET, addr.c_str(), &a) != 1) return false;
    out.mask = len == 0 ? 0 : 0xffffffffu << (32 - len);
    out.addr = ntohl(a.s_addr) & out.mask;
    return true;
}

bool parse_ports(const std::string& s, PortRange& out) {
    if (upper(s) == "ANY" || s == "*") {
        out = PortRange{};
        return true;
    }
    unsigned long lo, hi;
    if (auto dash = s.find('-'); dash != std::string::npos) {
        if (!parse_uint(trim(s.substr(0, dash)), 65535, lo) ||
            !parse_uint(trim(s.substr(dash + 1)), 65535, hi) || lo > hi)
            return false;
    } else {
        if (!parse_uint(s, 65535, lo)) return false;
        hi = lo;
    }
    out.lo = static_cast<uint16_t>(lo);
    out.hi = static_cast<uint16_t>(hi);
    return true;
}

RuleLoadResult fail(int line, const std::string& msg) {
    return {std::nullopt, "line " + std::to_string(line) + ": " + msg};
}

}  // namespace

const char* action_name(Action a) { return a == Action::ALLOW ? "ALLOW" : "DENY"; }

bool ACLRule::matches(const ParsedPacket& pkt) const {
    if (protocol != 0 && protocol != pkt.ip_proto) return false;
    if (!src_ip.matches(pkt.src_ip) || !dst_ip.matches(pkt.dst_ip)) return false;
    if (src_port.any() && dst_port.any()) return true;
    // A rule that constrains ports can only match packets that carry ports
    // (not ICMP, not non-first fragments).
    if (!pkt.has_ports) return false;
    return src_port.matches(pkt.src_port) && dst_port.matches(pkt.dst_port);
}

ACLEngine::ACLEngine(std::vector<ACLRule> rules, Action default_action)
    : rules_(std::move(rules)), default_action_(default_action) {}

Verdict ACLEngine::evaluate(const ParsedPacket& pkt) const {
    for (size_t i = 0; i < rules_.size(); ++i)
        if (rules_[i].matches(pkt)) return {rules_[i].action, static_cast<int>(i)};
    return {default_action_, -1};
}

RuleLoadResult parse_rules(const std::string& text) {
    std::vector<ACLRule> rules;
    Action default_action = Action::ALLOW;
    bool saw_default = false;

    std::istringstream in(text);
    std::string raw;
    int line_no = 0;
    while (std::getline(in, raw)) {
        ++line_no;
        if (auto hash = raw.find('#'); hash != std::string::npos) raw.erase(hash);
        const std::string line = trim(raw);
        if (line.empty()) continue;

        const auto f = split_csv(line);
        if (upper(f[0]) == "DEFAULT") {
            if (f.size() != 2 || !parse_action(f[1], default_action))
                return fail(line_no, "expected DEFAULT,ALLOW or DEFAULT,DENY");
            if (saw_default) return fail(line_no, "DEFAULT given more than once");
            saw_default = true;
            continue;
        }
        if (f.size() < 6)
            return fail(line_no, "expected ACTION,PROTOCOL,SRC_IP,SRC_PORT,DST_IP,DST_PORT[,REASON]");

        ACLRule r;
        r.line = line_no;
        if (!parse_action(f[0], r.action)) return fail(line_no, "bad action '" + f[0] + "'");
        if (!parse_protocol(f[1], r.protocol)) return fail(line_no, "bad protocol '" + f[1] + "'");
        if (!parse_prefix(f[2], r.src_ip)) return fail(line_no, "bad source IP '" + f[2] + "'");
        if (!parse_ports(f[3], r.src_port)) return fail(line_no, "bad source port '" + f[3] + "'");
        if (!parse_prefix(f[4], r.dst_ip)) return fail(line_no, "bad destination IP '" + f[4] + "'");
        if (!parse_ports(f[5], r.dst_port)) return fail(line_no, "bad destination port '" + f[5] + "'");
        // The reason is free text and may itself contain commas.
        for (size_t i = 6; i < f.size(); ++i) r.reason += (i > 6 ? "," : "") + f[i];
        rules.push_back(std::move(r));
    }
    return {ACLEngine(std::move(rules), default_action), {}};
}

RuleLoadResult load_rules_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) return {std::nullopt, "cannot open " + path};
    std::stringstream ss;
    ss << file.rdbuf();
    RuleLoadResult result = parse_rules(ss.str());
    if (!result.engine) result.error = path + ": " + result.error;
    return result;
}

}  // namespace pi
