#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace pi {

enum class L3Proto : uint8_t { None, IPv4, ARP, IPv6, Other };
enum class L4Proto : uint8_t { None, TCP, UDP, ICMP, Other };

// Everything the parser extracts from one frame. All multi-byte numeric
// fields are stored in host byte order.
struct ParsedPacket {
    size_t wire_len = 0;      // original frame length on the wire
    size_t cap_len = 0;       // bytes actually available to the parser
    bool truncated = false;   // a header claimed more bytes than were captured

    // Layer 2
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ethertype = 0;   // after stripping any 802.1Q tags
    bool has_vlan = false;
    uint16_t vlan_id = 0;

    // Layer 3
    L3Proto l3 = L3Proto::None;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t ip_proto = 0;
    uint8_t ttl = 0;
    uint16_t ip_total_len = 0;
    uint16_t ip_checksum = 0;
    bool ip_checksum_ok = false;
    bool is_fragment = false;     // MF set or offset != 0
    bool first_fragment = true;   // offset == 0 (only these carry an L4 header)

    // ARP
    uint16_t arp_op = 0;
    uint32_t arp_sender_ip = 0;
    uint32_t arp_target_ip = 0;

    // Layer 4
    L4Proto l4 = L4Proto::None;
    bool has_ports = false;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;
    uint16_t udp_len = 0;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
};

}  // namespace pi
