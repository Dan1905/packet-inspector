#include "stats.hpp"

#include <cstdio>

namespace pi {
namespace {

std::string pct(uint64_t part, uint64_t whole) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%5.1f%%", whole ? 100.0 * part / whole : 0.0);
    return buf;
}

std::string human_bytes(double b) {
    static const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    int u = 0;
    while (b >= 1024 && u < 4) {
        b /= 1024;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), u ? "%.2f %s" : "%.0f %s", b, kUnits[u]);
    return buf;
}

std::string row(const char* label, uint64_t n, uint64_t whole) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "  %-13s %10llu  %s\n", label, static_cast<unsigned long long>(n),
                  pct(n, whole).c_str());
    return buf;
}

}  // namespace

void Stats::reset_rule_hits(size_t rule_count) {
    rule_hits.assign(rule_count, 0);
    default_hits = 0;
}

void Stats::record(const ParsedPacket& pkt, const Verdict* verdict) {
    ++packets;
    bytes += pkt.wire_len;
    if (pkt.truncated) ++truncated;

    switch (pkt.l3) {
        case L3Proto::IPv4:
            if (!pkt.truncated && !pkt.ip_checksum_ok) ++bad_ip_checksum;
            switch (pkt.l4) {
                case L4Proto::TCP: ++tcp; break;
                case L4Proto::UDP: ++udp; break;
                case L4Proto::ICMP: ++icmp; break;
                default: ++other_ipv4; break;
            }
            break;
        case L3Proto::ARP: ++arp; break;
        case L3Proto::IPv6: ++ipv6; break;
        default: ++other_l2; break;
    }

    if (!verdict) {
        ++not_evaluated;
        return;
    }
    if (verdict->action == Action::ALLOW) ++allowed;
    else ++blocked;
    if (verdict->rule_index < 0) ++default_hits;
    else if (static_cast<size_t>(verdict->rule_index) < rule_hits.size()) ++rule_hits[verdict->rule_index];
}

std::string format_stats(const Stats& now, const Stats& prev, double interval_sec, double uptime_sec,
                         const ACLEngine& acl) {
    std::string out;
    char buf[160];

    std::snprintf(buf, sizeof(buf), "==== Traffic stats (uptime %.0fs) ====\n", uptime_sec);
    out += buf;
    std::snprintf(buf, sizeof(buf), "  Packets: %llu   Bytes: %s\n",
                  static_cast<unsigned long long>(now.packets), human_bytes(double(now.bytes)).c_str());
    out += buf;
    if (interval_sec > 0) {
        const double pps = (now.packets - prev.packets) / interval_sec;
        const double bps = (now.bytes - prev.bytes) / interval_sec;
        std::snprintf(buf, sizeof(buf), "  Rate:    %.1f pkt/s   %s/s\n", pps, human_bytes(bps).c_str());
        out += buf;
    }

    out += " Verdicts\n";
    out += row("Allowed", now.allowed, now.packets);
    out += row("Blocked", now.blocked, now.packets);
    out += row("Not evaluated", now.not_evaluated, now.packets);

    out += " Protocols\n";
    out += row("TCP", now.tcp, now.packets);
    out += row("UDP", now.udp, now.packets);
    out += row("ICMP", now.icmp, now.packets);
    out += row("Other IPv4", now.other_ipv4, now.packets);
    out += row("ARP", now.arp, now.packets);
    out += row("IPv6", now.ipv6, now.packets);
    out += row("Other L2", now.other_l2, now.packets);

    if (now.truncated || now.bad_ip_checksum) {
        out += " Anomalies\n";
        out += row("Truncated", now.truncated, now.packets);
        out += row("Bad IP cksum", now.bad_ip_checksum, now.packets);
    }

    out += " Rule hits\n";
    for (size_t i = 0; i < acl.rules().size() && i < now.rule_hits.size(); ++i) {
        const ACLRule& r = acl.rules()[i];
        std::snprintf(buf, sizeof(buf), "  #%-3zu line %-4d %-5s %10llu  %s\n", i + 1, r.line,
                      action_name(r.action), static_cast<unsigned long long>(now.rule_hits[i]),
                      r.reason.c_str());
        out += buf;
    }
    std::snprintf(buf, sizeof(buf), "  default        %-5s %10llu\n", action_name(acl.default_action()),
                  static_cast<unsigned long long>(now.default_hits));
    out += buf;
    out += "=====================================\n";
    return out;
}

}  // namespace pi
