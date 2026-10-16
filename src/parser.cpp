#include "parser.hpp"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstring>

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif
#ifndef ETHERTYPE_QINQ
#define ETHERTYPE_QINQ 0x88a8
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

namespace pi {
namespace {

// Copies a header struct out of the buffer if enough bytes remain.
template <typename T>
bool read_struct(const uint8_t* data, size_t len, size_t off, T& out) {
    if (off > len || len - off < sizeof(T)) return false;
    std::memcpy(&out, data + off, sizeof(T));
    return true;
}

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

uint32_t be32(const uint8_t* p) {
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
}

constexpr size_t kArpEthIpv4Len = 28;
constexpr size_t kVlanTagLen = 4;
constexpr size_t kUdpHeaderLen = 8;
constexpr size_t kIcmpHeaderLen = 8;

void parse_arp(const uint8_t* data, size_t len, size_t off, ParsedPacket& pkt) {
    pkt.l3 = L3Proto::ARP;
    if (len - off < kArpEthIpv4Len) {
        pkt.truncated = true;
        return;
    }
    const uint8_t* arp = data + off;
    // Only Ethernet (htype 1) / IPv4 (ptype 0x0800) ARP has addresses at these offsets.
    if (be16(arp) != 1 || be16(arp + 2) != ETHERTYPE_IP || arp[4] != 6 || arp[5] != 4) return;
    pkt.arp_op = be16(arp + 6);
    pkt.arp_sender_ip = be32(arp + 14);
    pkt.arp_target_ip = be32(arp + 24);
}

void parse_l4(const uint8_t* data, size_t len, size_t off, ParsedPacket& pkt) {
    switch (pkt.ip_proto) {
        case IPPROTO_TCP: {
            pkt.l4 = L4Proto::TCP;
            struct tcphdr tcp;
            if (!read_struct(data, len, off, tcp)) {
                pkt.truncated = true;
                return;
            }
            pkt.has_ports = true;
            pkt.src_port = ntohs(tcp.th_sport);
            pkt.dst_port = ntohs(tcp.th_dport);
            pkt.tcp_seq = ntohl(tcp.th_seq);
            pkt.tcp_ack = ntohl(tcp.th_ack);
            pkt.tcp_flags = tcp.th_flags;
            break;
        }
        case IPPROTO_UDP: {
            pkt.l4 = L4Proto::UDP;
            struct udphdr udp;
            static_assert(sizeof(udp) == kUdpHeaderLen, "unexpected udphdr size");
            if (!read_struct(data, len, off, udp)) {
                pkt.truncated = true;
                return;
            }
            pkt.has_ports = true;
            pkt.src_port = ntohs(udp.uh_sport);
            pkt.dst_port = ntohs(udp.uh_dport);
            pkt.udp_len = ntohs(udp.uh_ulen);
            break;
        }
        case IPPROTO_ICMP: {
            pkt.l4 = L4Proto::ICMP;
            // struct icmp differs in size between platforms; type and code are
            // always the first two bytes of the 8-byte fixed header.
            if (off > len || len - off < kIcmpHeaderLen) {
                pkt.truncated = true;
                return;
            }
            pkt.icmp_type = data[off];
            pkt.icmp_code = data[off + 1];
            break;
        }
        default:
            pkt.l4 = L4Proto::Other;
            break;
    }
}

void parse_ipv4(const uint8_t* data, size_t len, size_t off, ParsedPacket& pkt) {
    pkt.l3 = L3Proto::IPv4;
    struct ip iph;
    if (!read_struct(data, len, off, iph)) {
        pkt.truncated = true;
        return;
    }
    const size_t ihl = static_cast<size_t>(iph.ip_hl) * 4;
    if (iph.ip_v != 4 || ihl < sizeof(struct ip)) {
        pkt.l3 = L3Proto::Other;  // not a sane IPv4 header
        return;
    }

    pkt.src_ip = ntohl(iph.ip_src.s_addr);
    pkt.dst_ip = ntohl(iph.ip_dst.s_addr);
    pkt.ip_proto = iph.ip_p;
    pkt.ttl = iph.ip_ttl;
    pkt.ip_total_len = ntohs(iph.ip_len);
    pkt.ip_checksum = ntohs(iph.ip_sum);

    const uint16_t frag = ntohs(iph.ip_off);
    pkt.is_fragment = (frag & IP_MF) || (frag & IP_OFFMASK);
    pkt.first_fragment = (frag & IP_OFFMASK) == 0;

    if (len - off < ihl) {  // options run past the captured bytes
        pkt.truncated = true;
        return;
    }
    pkt.ip_checksum_ok = internet_checksum(data + off, ihl) == 0;

    // The IP total length bounds the payload; anything after it is Ethernet padding.
    size_t ip_end = len;
    if (pkt.ip_total_len >= ihl && off + pkt.ip_total_len < len) ip_end = off + pkt.ip_total_len;

    if (!pkt.first_fragment) {
        // Later fragments carry payload only; record the protocol but no ports.
        switch (pkt.ip_proto) {
            case IPPROTO_TCP: pkt.l4 = L4Proto::TCP; break;
            case IPPROTO_UDP: pkt.l4 = L4Proto::UDP; break;
            case IPPROTO_ICMP: pkt.l4 = L4Proto::ICMP; break;
            default: pkt.l4 = L4Proto::Other; break;
        }
        return;
    }
    parse_l4(data, ip_end, off + ihl, pkt);
}

}  // namespace

uint16_t internet_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) sum += be16(data + i);
    if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

ParsedPacket parse_frame(const uint8_t* data, size_t cap_len, size_t wire_len) {
    ParsedPacket pkt;
    pkt.cap_len = cap_len;
    pkt.wire_len = wire_len;

    struct ether_header eth;
    if (!read_struct(data, cap_len, 0, eth)) {
        pkt.truncated = true;
        return pkt;
    }
    std::memcpy(pkt.dst_mac.data(), eth.ether_dhost, 6);
    std::memcpy(pkt.src_mac.data(), eth.ether_shost, 6);

    size_t off = sizeof(eth);
    uint16_t type = ntohs(eth.ether_type);

    // Strip any number of 802.1Q / 802.1ad tags, keeping the outermost VLAN ID.
    while (type == ETHERTYPE_VLAN || type == ETHERTYPE_QINQ) {
        if (cap_len - off < kVlanTagLen) {
            pkt.truncated = true;
            pkt.ethertype = type;
            return pkt;
        }
        if (!pkt.has_vlan) pkt.vlan_id = be16(data + off) & 0x0fff;
        pkt.has_vlan = true;
        type = be16(data + off + 2);
        off += kVlanTagLen;
    }
    pkt.ethertype = type;

    switch (type) {
        case ETHERTYPE_IP: parse_ipv4(data, cap_len, off, pkt); break;
        case ETHERTYPE_ARP: parse_arp(data, cap_len, off, pkt); break;
        case ETHERTYPE_IPV6: pkt.l3 = L3Proto::IPv6; break;
        default: pkt.l3 = L3Proto::Other; break;
    }
    return pkt;
}

}  // namespace pi
