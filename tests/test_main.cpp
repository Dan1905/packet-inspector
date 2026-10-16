// Self-contained unit tests (no framework dependency). Run: make test

#include "../src/acl.hpp"
#include "../src/capture.hpp"
#include "../src/format.hpp"
#include "../src/parser.hpp"
#include "../src/stats.hpp"
#include "frame_builder.hpp"

#include <netinet/in.h>

#include <cstdio>
#include <functional>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            ++g_failures;                                                        \
            std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))

struct TestCase {
    const char* name;
    std::function<void()> fn;
};
std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
struct Register {
    Register(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
#define TEST(name)                                   \
    void test_##name();                              \
    Register reg_##name(#name, test_##name);         \
    void test_##name()

using namespace fb;

pi::ParsedPacket parse(const Bytes& f) { return pi::parse_frame(f.data(), f.size(), f.size()); }

constexpr uint8_t SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04, PSH = 0x08;

const uint32_t kClient = ip(10, 0, 0, 5);
const uint32_t kServer = ip(192, 168, 1, 15);

// ---------------------------------------------------------------- parser

TEST(parse_tcp) {
    auto f = ethernet(0x0800, ipv4(kServer, kClient, IPPROTO_TCP, tcp(443, 52341, SYN | ACK, 111, 222, 10)));
    auto p = parse(f);
    CHECK(p.l3 == pi::L3Proto::IPv4);
    CHECK(p.l4 == pi::L4Proto::TCP);
    CHECK_EQ(p.src_ip, kServer);
    CHECK_EQ(p.dst_ip, kClient);
    CHECK_EQ(p.src_port, 443);
    CHECK_EQ(p.dst_port, 52341);
    CHECK_EQ(p.tcp_seq, 111u);
    CHECK_EQ(p.tcp_ack, 222u);
    CHECK_EQ(p.tcp_flags, SYN | ACK);
    CHECK_EQ(p.ttl, 64);
    CHECK(p.ip_checksum_ok);
    CHECK(!p.truncated);
    CHECK(p.src_mac == kMacA);
    CHECK(p.dst_mac == kMacB);
    CHECK_EQ(p.ethertype, 0x0800);
}

TEST(parse_udp) {
    auto p = parse(ethernet(0x0800, ipv4(ip(192, 168, 1, 100), kClient, IPPROTO_UDP, udp(53, 1234, 20))));
    CHECK(p.l4 == pi::L4Proto::UDP);
    CHECK_EQ(p.src_port, 53);
    CHECK_EQ(p.dst_port, 1234);
    CHECK_EQ(p.udp_len, 28);
    CHECK(p.has_ports);
}

TEST(parse_icmp) {
    auto p = parse(ethernet(0x0800, ipv4(kClient, ip(8, 8, 8, 8), IPPROTO_ICMP, icmp(8, 0, 32))));
    CHECK(p.l4 == pi::L4Proto::ICMP);
    CHECK_EQ(p.icmp_type, 8);
    CHECK_EQ(p.icmp_code, 0);
    CHECK(!p.has_ports);
}

TEST(parse_arp) {
    auto p = parse(ethernet(0x0806, arp(1, ip(10, 0, 0, 2), ip(10, 0, 0, 1)), -1, kMacA, kBroadcast));
    CHECK(p.l3 == pi::L3Proto::ARP);
    CHECK_EQ(p.arp_op, 1);
    CHECK_EQ(p.arp_sender_ip, ip(10, 0, 0, 2));
    CHECK_EQ(p.arp_target_ip, ip(10, 0, 0, 1));
    CHECK(p.dst_mac == kBroadcast);
}

TEST(parse_vlan) {
    auto p = parse(ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_UDP, udp(5000, 53)), 42));
    CHECK(p.has_vlan);
    CHECK_EQ(p.vlan_id, 42);
    CHECK_EQ(p.ethertype, 0x0800);
    CHECK(p.l4 == pi::L4Proto::UDP);
    CHECK_EQ(p.dst_port, 53);
}

TEST(parse_ip_options) {
    IpOpts o;
    o.option_words = 2;  // IHL = 7
    auto p = parse(ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_TCP, tcp(1111, 80, SYN), o)));
    CHECK(p.ip_checksum_ok);
    CHECK_EQ(p.src_port, 1111);
    CHECK_EQ(p.dst_port, 80);
}

TEST(parse_bad_checksum) {
    IpOpts o;
    o.corrupt_checksum = true;
    auto p = parse(ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_TCP, tcp(1, 2, SYN), o)));
    CHECK(!p.ip_checksum_ok);
    CHECK(p.l4 == pi::L4Proto::TCP);  // still parsed
}

TEST(parse_fragments) {
    IpOpts first;
    first.more_fragments = true;
    auto p1 = parse(ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_UDP, udp(5000, 53, 100), first)));
    CHECK(p1.is_fragment);
    CHECK(p1.first_fragment);
    CHECK(p1.has_ports);

    IpOpts later;
    later.frag_offset_units = 14;
    auto p2 = parse(ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_UDP, Bytes(40, 'z'), later)));
    CHECK(p2.is_fragment);
    CHECK(!p2.first_fragment);
    CHECK(p2.l4 == pi::L4Proto::UDP);
    CHECK(!p2.has_ports);  // payload bytes must not be read as ports
}

TEST(parse_ipv6_and_other) {
    CHECK(parse(ethernet(0x86dd, Bytes(40, 0))).l3 == pi::L3Proto::IPv6);
    auto p = parse(ethernet(0x88cc, Bytes(20, 0)));  // LLDP
    CHECK(p.l3 == pi::L3Proto::Other);
    CHECK_EQ(p.ethertype, 0x88cc);
}

TEST(parse_truncated_everywhere) {
    // Chop a valid TCP frame at every possible length: must never crash, and
    // anything shorter than the full headers must be flagged truncated.
    Bytes full = ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_TCP, tcp(1, 2, SYN)));
    const size_t headers = 14 + 20 + 20;
    for (size_t n = 0; n < headers; ++n) {
        auto p = pi::parse_frame(full.data(), n, full.size());
        CHECK(p.truncated);
        CHECK(!p.has_ports);
    }
    CHECK(!pi::parse_frame(full.data(), headers, full.size()).truncated);

    Bytes vlan = ethernet(0x0800, Bytes{}, 7);
    CHECK(pi::parse_frame(vlan.data(), 16, vlan.size()).truncated);  // tag cut in half
}

TEST(parse_ignores_ethernet_padding) {
    // A tiny ICMP packet is padded to 60 bytes; the IP total length must bound the L4 parse.
    Bytes f = ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_ICMP, Bytes{8, 0, 0}));
    auto p = parse(f);
    CHECK(f.size() == 60);
    CHECK(p.truncated);  // 3-byte ICMP header, despite 23 bytes of padding after it
}

TEST(parse_garbage_ip_version) {
    Bytes f = ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_TCP, tcp(1, 2, SYN)));
    f[14] = 0x65;  // version 6 inside an IPv4 ethertype
    CHECK(parse(f).l3 == pi::L3Proto::Other);
}

// ---------------------------------------------------------------- ACL

pi::ACLEngine rules(const std::string& text) {
    auto r = pi::parse_rules(text);
    if (!r.engine) std::fprintf(stderr, "  rule parse error: %s\n", r.error.c_str());
    CHECK(r.engine.has_value());
    return r.engine ? *r.engine : pi::ACLEngine{};
}

pi::ParsedPacket pkt(uint8_t proto, uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport) {
    pi::ParsedPacket p;
    p.l3 = pi::L3Proto::IPv4;
    p.ip_proto = proto;
    p.src_ip = src;
    p.dst_ip = dst;
    p.has_ports = proto == IPPROTO_TCP || proto == IPPROTO_UDP;
    p.src_port = sport;
    p.dst_port = dport;
    return p;
}

TEST(acl_first_match_and_default) {
    auto acl = rules(
        "# comment line\n"
        "ALLOW, UDP, 10.0.0.53, ANY, ANY, ANY, trusted resolver\n"
        "DENY,  UDP, ANY, 53, ANY, ANY, Blocked DNS\n"
        "\n"
        "DEFAULT, DENY\n");
    CHECK_EQ(acl.rules().size(), 2u);
    CHECK(acl.default_action() == pi::Action::DENY);

    auto v = acl.evaluate(pkt(IPPROTO_UDP, ip(10, 0, 0, 53), 53, kClient, 1234));
    CHECK(v.action == pi::Action::ALLOW);
    CHECK_EQ(v.rule_index, 0);

    v = acl.evaluate(pkt(IPPROTO_UDP, ip(192, 168, 1, 100), 53, kClient, 1234));
    CHECK(v.action == pi::Action::DENY);
    CHECK_EQ(v.rule_index, 1);
    CHECK_EQ(acl.rules()[1].reason, "Blocked DNS");

    v = acl.evaluate(pkt(IPPROTO_TCP, kServer, 443, kClient, 5555));
    CHECK(v.action == pi::Action::DENY);
    CHECK_EQ(v.rule_index, -1);
}

TEST(acl_cidr) {
    auto acl = rules("DENY,ANY,10.0.0.0/8,ANY,ANY,ANY\nALLOW,ANY,0.0.0.0/0,ANY,ANY,ANY\n");
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, ip(10, 200, 3, 4), 1, kServer, 2)).action == pi::Action::DENY);
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, ip(11, 0, 0, 1), 1, kServer, 2)).action == pi::Action::ALLOW);

    // Host bits in the rule are masked off: 192.168.1.77/24 == 192.168.1.0/24.
    auto acl2 = rules("DENY,ANY,ANY,ANY,192.168.1.77/24,ANY\n");
    CHECK(acl2.evaluate(pkt(IPPROTO_UDP, kClient, 1, ip(192, 168, 1, 200), 2)).action == pi::Action::DENY);
    CHECK(acl2.evaluate(pkt(IPPROTO_UDP, kClient, 1, ip(192, 168, 2, 1), 2)).action == pi::Action::ALLOW);
}

TEST(acl_port_ranges) {
    auto acl = rules("DENY,TCP,ANY,ANY,ANY,6000-6010\n");
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, kClient, 40000, kServer, 6000)).action == pi::Action::DENY);
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, kClient, 40000, kServer, 6010)).action == pi::Action::DENY);
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, kClient, 40000, kServer, 6011)).action == pi::Action::ALLOW);
    CHECK(acl.evaluate(pkt(IPPROTO_UDP, kClient, 40000, kServer, 6005)).action == pi::Action::ALLOW);
}

TEST(acl_port_rules_skip_portless_packets) {
    auto acl = rules("DENY,ANY,ANY,ANY,ANY,53\nDENY,ICMP,ANY,ANY,ANY,ANY,no ping\n");
    auto ping = pkt(IPPROTO_ICMP, kClient, 0, kServer, 0);
    auto v = acl.evaluate(ping);
    CHECK_EQ(v.rule_index, 1);  // the port rule must not match ICMP

    auto frag = pkt(IPPROTO_UDP, kClient, 0, kServer, 0);
    frag.has_ports = false;  // non-first fragment
    CHECK_EQ(acl.evaluate(frag).rule_index, -1);
}

TEST(acl_protocol_numbers_and_aliases) {
    auto acl = rules("block,47,any,*,any,*,GRE\npass,tcp,ANY,ANY,ANY,ANY\n");
    CHECK(acl.evaluate(pkt(47, kClient, 0, kServer, 0)).action == pi::Action::DENY);
    CHECK(acl.evaluate(pkt(IPPROTO_TCP, kClient, 1, kServer, 2)).action == pi::Action::ALLOW);
}

TEST(acl_reason_with_commas) {
    auto acl = rules("DENY,UDP,ANY,ANY,ANY,123,NTP, legacy, do not use\n");
    CHECK_EQ(acl.rules()[0].reason, "NTP,legacy,do not use");
}

TEST(acl_parse_errors) {
    const char* bad[] = {
        "DROP,TCP,ANY,ANY,ANY,ANY\n",          // unknown action
        "DENY,SCTPX,ANY,ANY,ANY,ANY\n",        // unknown protocol
        "DENY,TCP,10.0.0.300,ANY,ANY,ANY\n",   // bad IP
        "DENY,TCP,10.0.0.0/33,ANY,ANY,ANY\n",  // bad prefix length
        "DENY,TCP,ANY,70000,ANY,ANY\n",        // port out of range
        "DENY,TCP,ANY,ANY,ANY,90-80\n",        // inverted range
        "DENY,TCP,ANY,ANY\n",                  // too few fields
        "DEFAULT,MAYBE\n",
        "DEFAULT,ALLOW\nDEFAULT,DENY\n",       // duplicate default
    };
    for (const char* text : bad) {
        auto r = pi::parse_rules(text);
        CHECK(!r.engine.has_value());
        CHECK(r.error.rfind("line ", 0) == 0);
    }
    CHECK(pi::parse_rules("DENY,TCP,ANY,ANY\n").error.find("line 1") == 0);
}

// ---------------------------------------------------------------- formatting & stats

TEST(format_matches_blueprint) {
    auto acl = rules("DENY,UDP,ANY,53,ANY,ANY,Blocked DNS\n");
    pi::FormatOptions fo;

    auto pass = parse(ethernet(0x0800, ipv4(kServer, kClient, IPPROTO_TCP, tcp(443, 52341, ACK, 1, 1, 1446))));
    auto v1 = acl.evaluate(pass);
    CHECK_EQ(pi::format_packet(pass, &v1, acl, fo),
             "[PASS] [IPv4] [TCP] 192.168.1.15:443 -> 10.0.0.5:52341 | Flags: [ACK] | Len: 1500 B");

    auto dns = parse(ethernet(0x0800, ipv4(ip(192, 168, 1, 100), kClient, IPPROTO_UDP, udp(53, 1234, 32))));
    auto v2 = acl.evaluate(dns);
    CHECK_EQ(pi::format_packet(dns, &v2, acl, fo),
             "[BLOCK] [ACL Deny] [IPv4] [UDP] 192.168.1.100:53 -> 10.0.0.5:1234 | Reason: Blocked DNS | Len: 74 B");

    auto a = parse(ethernet(0x0806, arp(1, ip(10, 0, 0, 2), ip(10, 0, 0, 1))));
    CHECK_EQ(pi::format_packet(a, nullptr, acl, fo), "[INFO] [ARP] who-has 10.0.0.1 tell 10.0.0.2 | Len: 60 B");
}

TEST(format_helpers) {
    CHECK_EQ(pi::tcp_flags_to_string(SYN | ACK), "SYN,ACK");
    CHECK_EQ(pi::tcp_flags_to_string(FIN | PSH | RST), "FIN,RST,PSH");
    CHECK_EQ(pi::tcp_flags_to_string(0), "none");
    CHECK_EQ(pi::ip_to_string(ip(1, 2, 3, 4)), "1.2.3.4");
    CHECK_EQ(pi::mac_to_string(kBroadcast), "ff:ff:ff:ff:ff:ff");
    CHECK_EQ(pi::icmp_type_name(0), "Echo Reply");
}

TEST(stats_counts) {
    auto acl = rules("DENY,UDP,ANY,53,ANY,ANY\n");
    pi::Stats s;
    s.reset_rule_hits(acl.rules().size());
    std::vector<Bytes> frames = {
        ethernet(0x0800, ipv4(kServer, kClient, IPPROTO_TCP, tcp(443, 1, ACK))),
        ethernet(0x0800, ipv4(kServer, kClient, IPPROTO_UDP, udp(53, 1))),
        ethernet(0x0800, ipv4(kServer, kClient, IPPROTO_ICMP, icmp(0, 0))),
        ethernet(0x0806, arp(2, kServer, kClient)),
    };
    for (const auto& f : frames) {
        auto p = parse(f);
        if (p.l3 == pi::L3Proto::IPv4) {
            auto v = acl.evaluate(p);
            s.record(p, &v);
        } else {
            s.record(p, nullptr);
        }
    }
    CHECK_EQ(s.packets, 4u);
    CHECK_EQ(s.bytes, 240u);
    CHECK_EQ(s.allowed, 2u);
    CHECK_EQ(s.blocked, 1u);
    CHECK_EQ(s.not_evaluated, 1u);
    CHECK_EQ(s.tcp, 1u);
    CHECK_EQ(s.udp, 1u);
    CHECK_EQ(s.icmp, 1u);
    CHECK_EQ(s.arp, 1u);
    CHECK_EQ(s.rule_hits[0], 1u);
    CHECK_EQ(s.default_hits, 2u);
    CHECK(pi::format_stats(s, pi::Stats{}, 0, 1, acl).find(" 25.0%") != std::string::npos);
}

// ---------------------------------------------------------------- pcap reader

TEST(pcap_roundtrip) {
    char path[] = "/tmp/pi_test_XXXXXX";
    const int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd);

    std::vector<Bytes> frames = {
        ethernet(0x0800, ipv4(kClient, kServer, IPPROTO_TCP, tcp(1, 80, SYN))),
        ethernet(0x0806, arp(1, kClient, kServer)),
    };
    CHECK(write_pcap(path, frames));

    std::string err;
    auto src = pi::open_pcap_file(path, err);
    CHECK(src != nullptr);
    if (src) {
        pi::Frame fr;
        CHECK(src->next(fr, 0) == pi::CaptureStatus::Packet);
        CHECK_EQ(fr.cap_len, frames[0].size());
        CHECK_EQ(parse(Bytes(fr.data, fr.data + fr.cap_len)).dst_port, 80);
        CHECK(src->next(fr, 0) == pi::CaptureStatus::Packet);
        CHECK(src->next(fr, 0) == pi::CaptureStatus::End);
    }
    unlink(path);

    CHECK(pi::open_pcap_file("/nonexistent/file.pcap", err) == nullptr);
    CHECK(!err.empty());
}

}  // namespace

int main() {
    for (const auto& t : registry()) {
        const int before = g_failures;
        t.fn();
        std::printf("%s %s\n", g_failures == before ? "[ OK ]" : "[FAIL]", t.name);
    }
    std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
