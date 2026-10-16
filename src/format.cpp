#include "format.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdio>

namespace pi {
namespace {

constexpr const char* kGreen = "\033[32m";
constexpr const char* kRed = "\033[1;31m";
constexpr const char* kCyan = "\033[36m";
constexpr const char* kReset = "\033[0m";

std::string tag(const char* text, const char* color, bool use_color) {
    std::string s = "[";
    s += text;
    s += "]";
    return use_color ? color + s + kReset : s;
}

const char* l4_name(const ParsedPacket& pkt) {
    switch (pkt.l4) {
        case L4Proto::TCP: return "TCP";
        case L4Proto::UDP: return "UDP";
        case L4Proto::ICMP: return "ICMP";
        default: return nullptr;
    }
}

std::string endpoint(uint32_t ip, uint16_t port, bool has_port) {
    std::string s = ip_to_string(ip);
    if (has_port) s += ":" + std::to_string(port);
    return s;
}

}  // namespace

std::string ip_to_string(uint32_t host_order_ip) {
    in_addr a{};
    a.s_addr = htonl(host_order_ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

std::string mac_to_string(const std::array<uint8_t, 6>& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
    return buf;
}

std::string tcp_flags_to_string(uint8_t flags) {
    static constexpr struct { uint8_t bit; const char* name; } kFlags[] = {
        {0x02, "SYN"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"},
        {0x10, "ACK"}, {0x20, "URG"}, {0x40, "ECE"}, {0x80, "CWR"},
    };
    std::string s;
    for (const auto& f : kFlags) {
        if (!(flags & f.bit)) continue;
        if (!s.empty()) s += ",";
        s += f.name;
    }
    return s.empty() ? "none" : s;
}

std::string icmp_type_name(uint8_t type) {
    switch (type) {
        case 0: return "Echo Reply";
        case 3: return "Destination Unreachable";
        case 5: return "Redirect";
        case 8: return "Echo Request";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        default: return "Type " + std::to_string(type);
    }
}

std::string format_packet(const ParsedPacket& pkt, const Verdict* verdict, const ACLEngine& acl,
                          const FormatOptions& opts) {
    const bool c = opts.color;
    std::string line;

    if (verdict && verdict->action == Action::DENY) {
        line = tag("BLOCK", kRed, c) + " " +
               tag(verdict->rule_index >= 0 ? "ACL Deny" : "Default Deny", kRed, c);
    } else if (verdict) {
        line = tag("PASS", kGreen, c);
    } else {
        line = tag("INFO", kCyan, c);
    }

    if (pkt.has_vlan) line += " [VLAN " + std::to_string(pkt.vlan_id) + "]";

    const std::string len = " | Len: " + std::to_string(pkt.wire_len) + " B";
    const std::string macs = mac_to_string(pkt.src_mac) + " -> " + mac_to_string(pkt.dst_mac);

    switch (pkt.l3) {
        case L3Proto::IPv4: {
            line += " [IPv4]";
            const char* l4 = l4_name(pkt);
            line += l4 ? std::string(" [") + l4 + "]" : " [Proto " + std::to_string(pkt.ip_proto) + "]";
            line += " " + endpoint(pkt.src_ip, pkt.src_port, pkt.has_ports) + " -> " +
                    endpoint(pkt.dst_ip, pkt.dst_port, pkt.has_ports);

            if (verdict && verdict->action == Action::DENY) {
                std::string reason = "default policy";
                if (verdict->rule_index >= 0) {
                    const ACLRule& rule = acl.rules()[verdict->rule_index];
                    reason = rule.reason.empty() ? "rule at line " + std::to_string(rule.line) : rule.reason;
                }
                line += " | Reason: " + reason;
            }
            if (pkt.l4 == L4Proto::TCP && pkt.has_ports)
                line += " | Flags: [" + tcp_flags_to_string(pkt.tcp_flags) + "]";
            if (pkt.l4 == L4Proto::ICMP && pkt.first_fragment && !pkt.truncated)
                line += " | " + icmp_type_name(pkt.icmp_type) + " (" + std::to_string(pkt.icmp_type) +
                        "/" + std::to_string(pkt.icmp_code) + ")";
            line += len;
            if (pkt.is_fragment) line += pkt.first_fragment ? " | Frag: first" : " | Frag: cont";
            if (!pkt.truncated && !pkt.ip_checksum_ok) line += " | BAD IP CHECKSUM";
            if (opts.verbose) {
                line += " | TTL: " + std::to_string(pkt.ttl);
                if (pkt.l4 == L4Proto::TCP && pkt.has_ports)
                    line += " | Seq: " + std::to_string(pkt.tcp_seq) + " Ack: " + std::to_string(pkt.tcp_ack);
                if (pkt.l4 == L4Proto::UDP && pkt.has_ports) line += " | UDP Len: " + std::to_string(pkt.udp_len);
                char sum[8];
                std::snprintf(sum, sizeof(sum), "0x%04x", pkt.ip_checksum);
                line += std::string(" | Cksum: ") + sum;
                line += " | MAC: " + macs;
            }
            break;
        }
        case L3Proto::ARP: {
            line += " [ARP]";
            if (pkt.arp_op == 1)
                line += " who-has " + ip_to_string(pkt.arp_target_ip) + " tell " + ip_to_string(pkt.arp_sender_ip);
            else if (pkt.arp_op == 2)
                line += " " + ip_to_string(pkt.arp_sender_ip) + " is-at " + mac_to_string(pkt.src_mac);
            else
                line += " op " + std::to_string(pkt.arp_op);
            line += len;
            if (opts.verbose) line += " | MAC: " + macs;
            break;
        }
        case L3Proto::IPv6:
            line += " [IPv6] " + macs + len;
            break;
        default: {
            char et[16];
            std::snprintf(et, sizeof(et), "0x%04x", pkt.ethertype);
            line += std::string(" [EtherType ") + et + "] " + macs + len;
            break;
        }
    }
    if (pkt.truncated) line += " | TRUNCATED";
    return line;
}

}  // namespace pi
