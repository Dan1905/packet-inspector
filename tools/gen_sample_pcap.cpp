// Writes a small pcap with a mix of traffic that exercises every parser path
// and the sample rules.csv. Usage: gen_sample_pcap OUT.pcap

#include "../tests/frame_builder.hpp"

#include <netinet/in.h>

#include <cstdio>

using namespace fb;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s OUT.pcap\n", argv[0]);
        return 2;
    }

    const uint32_t client = ip(10, 0, 0, 5);
    const uint32_t web = ip(192, 168, 1, 15);
    const uint32_t resolver = ip(10, 0, 0, 53);
    const uint32_t public_dns = ip(8, 8, 8, 8);
    const uint32_t bad = ip(203, 0, 113, 66);
    constexpr uint8_t SYN = 0x02, ACK = 0x10, PSH = 0x08, FIN = 0x01, RST = 0x04;

    IpOpts frag_first;
    frag_first.more_fragments = true;
    IpOpts frag_rest;
    frag_rest.frag_offset_units = 185;
    IpOpts bad_sum;
    bad_sum.corrupt_checksum = true;

    std::vector<Bytes> frames = {
        ethernet(0x0806, arp(1, client, ip(10, 0, 0, 1)), -1, kMacA, kBroadcast),
        ethernet(0x0806, arp(2, ip(10, 0, 0, 1), client), -1, kMacB, kMacA),
        // TCP handshake + data with a web server
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(52341, 443, SYN, 1000, 0))),
        ethernet(0x0800, ipv4(web, client, IPPROTO_TCP, tcp(443, 52341, SYN | ACK, 5000, 1001))),
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(52341, 443, ACK, 1001, 5001))),
        ethernet(0x0800, ipv4(web, client, IPPROTO_TCP, tcp(443, 52341, ACK | PSH, 5001, 1001, 1446))),
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(52341, 443, FIN | ACK, 1001, 6447))),
        // DNS: internal resolver allowed, everything else blocked
        ethernet(0x0800, ipv4(client, resolver, IPPROTO_UDP, udp(40000, 53, 30))),
        ethernet(0x0800, ipv4(resolver, client, IPPROTO_UDP, udp(53, 40000, 46))),
        ethernet(0x0800, ipv4(client, public_dns, IPPROTO_UDP, udp(40001, 53, 30))),
        ethernet(0x0800, ipv4(ip(192, 168, 1, 100), client, IPPROTO_UDP, udp(53, 1234, 32))),
        // Telnet and IRC attempts
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(40002, 23, SYN))),
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(40003, 6667, SYN))),
        ethernet(0x0800, ipv4(web, client, IPPROTO_TCP, tcp(6667, 40003, RST | ACK))),
        // Traffic from a known-bad network
        ethernet(0x0800, ipv4(bad, client, IPPROTO_TCP, tcp(4444, 22, SYN))),
        // ICMP: outbound ping and its reply allowed, ping into the server subnet blocked
        ethernet(0x0800, ipv4(client, public_dns, IPPROTO_ICMP, icmp(8, 0, 56))),
        ethernet(0x0800, ipv4(public_dns, client, IPPROTO_ICMP, icmp(0, 0, 56))),
        ethernet(0x0800, ipv4(public_dns, web, IPPROTO_ICMP, icmp(8, 0, 56))),
        // VLAN-tagged NTP, a fragmented datagram, a corrupt header, IPv6, LLDP
        ethernet(0x0800, ipv4(client, ip(10, 0, 0, 123), IPPROTO_UDP, udp(123, 123, 48)), 20),
        ethernet(0x0800, ipv4(client, web, IPPROTO_UDP, udp(5000, 9999, 1472), frag_first)),
        ethernet(0x0800, ipv4(client, web, IPPROTO_UDP, Bytes(528, 'f'), frag_rest)),
        ethernet(0x0800, ipv4(client, web, IPPROTO_TCP, tcp(40004, 80, SYN), bad_sum)),
        ethernet(0x86dd, Bytes(40, 0)),
        ethernet(0x88cc, Bytes(30, 0)),
    };

    if (!write_pcap(argv[1], frames)) {
        std::perror(argv[1]);
        return 1;
    }
    std::printf("wrote %zu frames to %s\n", frames.size(), argv[1]);
    return 0;
}
