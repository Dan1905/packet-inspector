#pragma once

#include "packet.hpp"

namespace pi {

// Parses an Ethernet frame (Ethernet -> [802.1Q] -> IPv4/ARP -> TCP/UDP/ICMP).
// Never reads outside [data, data + cap_len). Headers are copied out with
// memcpy rather than reinterpret_cast so unaligned frames are safe.
ParsedPacket parse_frame(const uint8_t* data, size_t cap_len, size_t wire_len);

// RFC 1071 one's-complement checksum. Returns 0 when a buffer that already
// contains its checksum field is valid.
uint16_t internet_checksum(const uint8_t* data, size_t len);

}  // namespace pi
