#pragma once

#include "acl.hpp"
#include "packet.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace pi {

struct FormatOptions {
    bool color = false;
    bool verbose = false;  // add MACs, TTL, seq/ack, checksum
};

std::string ip_to_string(uint32_t host_order_ip);
std::string mac_to_string(const std::array<uint8_t, 6>& mac);
std::string tcp_flags_to_string(uint8_t flags);  // e.g. "SYN,ACK"
std::string icmp_type_name(uint8_t type);

// One log line for a packet. `verdict` is null for packets the ACL does not
// evaluate (anything that is not IPv4).
std::string format_packet(const ParsedPacket& pkt, const Verdict* verdict, const ACLEngine& acl,
                          const FormatOptions& opts);

}  // namespace pi
