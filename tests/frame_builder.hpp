#pragma once

// Helpers for constructing synthetic Ethernet frames and pcap files.
// Shared by the unit tests and tools/gen_sample_pcap.

#include "../src/parser.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace fb {

using Bytes = std::vector<uint8_t>;
using Mac = std::array<uint8_t, 6>;

inline void put16(Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v));
}
inline void put32(Bytes& b, uint32_t v) {
    put16(b, static_cast<uint16_t>(v >> 16));
    put16(b, static_cast<uint16_t>(v));
}
inline void append(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }

inline uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t{a} << 24) | (uint32_t{b} << 16) | (uint32_t{c} << 8) | d;
}

constexpr Mac kMacA{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a};
constexpr Mac kMacB{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};
constexpr Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// vlan < 0 means untagged.
inline Bytes ethernet(uint16_t ethertype, const Bytes& payload, int vlan = -1, Mac src = kMacA,
                      Mac dst = kMacB) {
    Bytes b(dst.begin(), dst.end());
    b.insert(b.end(), src.begin(), src.end());
    if (vlan >= 0) {
        put16(b, 0x8100);
        put16(b, static_cast<uint16_t>(vlan & 0x0fff));
    }
    put16(b, ethertype);
    append(b, payload);
    while (b.size() < 60) b.push_back(0);  // minimum Ethernet frame (without FCS)
    return b;
}

struct IpOpts {
    uint8_t ttl = 64;
    uint16_t frag_offset_units = 0;  // in 8-byte units
    bool more_fragments = false;
    int option_words = 0;            // extra 32-bit words of IP options (NOPs)
    bool corrupt_checksum = false;
};

inline Bytes ipv4(uint32_t src, uint32_t dst, uint8_t proto, const Bytes& payload, IpOpts o = {}) {
    const size_t ihl = 5 + o.option_words;
    Bytes b;
    b.push_back(static_cast<uint8_t>(0x40 | ihl));
    b.push_back(0);
    put16(b, static_cast<uint16_t>(ihl * 4 + payload.size()));
    put16(b, 0x1234);  // id
    put16(b, static_cast<uint16_t>((o.more_fragments ? 0x2000 : 0) | o.frag_offset_units));
    b.push_back(o.ttl);
    b.push_back(proto);
    put16(b, 0);  // checksum placeholder
    put32(b, src);
    put32(b, dst);
    for (int i = 0; i < o.option_words * 4; ++i) b.push_back(1);  // NOP options
    uint16_t sum = pi::internet_checksum(b.data(), b.size());
    if (o.corrupt_checksum) sum ^= 0xffff;
    b[10] = static_cast<uint8_t>(sum >> 8);
    b[11] = static_cast<uint8_t>(sum);
    append(b, payload);
    return b;
}

inline Bytes tcp(uint16_t sport, uint16_t dport, uint8_t flags, uint32_t seq = 1000, uint32_t ack = 0,
                 size_t payload_len = 0) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    put32(b, seq);
    put32(b, ack);
    b.push_back(5 << 4);  // data offset
    b.push_back(flags);
    put16(b, 65535);      // window
    put16(b, 0);          // checksum (not verified by the inspector)
    put16(b, 0);          // urgent
    b.resize(b.size() + payload_len, 'x');
    return b;
}

inline Bytes udp(uint16_t sport, uint16_t dport, size_t payload_len = 0) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    put16(b, static_cast<uint16_t>(8 + payload_len));
    put16(b, 0);
    b.resize(b.size() + payload_len, 'u');
    return b;
}

inline Bytes icmp(uint8_t type, uint8_t code, size_t payload_len = 0) {
    Bytes b{type, code, 0, 0, 0, 1, 0, 1};  // checksum, id, seq
    b.resize(b.size() + payload_len, 'i');
    return b;
}

inline Bytes arp(uint16_t op, uint32_t sender_ip, uint32_t target_ip, Mac sender_mac = kMacA) {
    Bytes b;
    put16(b, 1);       // Ethernet
    put16(b, 0x0800);  // IPv4
    b.push_back(6);
    b.push_back(4);
    put16(b, op);
    b.insert(b.end(), sender_mac.begin(), sender_mac.end());
    put32(b, sender_ip);
    for (int i = 0; i < 6; ++i) b.push_back(0);
    put32(b, target_ip);
    return b;
}

// Writes a classic microsecond pcap file with Ethernet link type.
inline bool write_pcap(const std::string& path, const std::vector<Bytes>& frames) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    auto w32 = [&](uint32_t v) { std::fwrite(&v, 4, 1, f); };  // native byte order is valid pcap
    auto w16 = [&](uint16_t v) { std::fwrite(&v, 2, 1, f); };
    w32(0xa1b2c3d4);
    w16(2);
    w16(4);
    w32(0);
    w32(0);
    w32(65535);
    w32(1);
    uint32_t ts = 1700000000;
    for (const Bytes& fr : frames) {
        w32(ts++);
        w32(0);
        w32(static_cast<uint32_t>(fr.size()));
        w32(static_cast<uint32_t>(fr.size()));
        std::fwrite(fr.data(), 1, fr.size(), f);
    }
    return std::fclose(f) == 0;
}

}  // namespace fb
