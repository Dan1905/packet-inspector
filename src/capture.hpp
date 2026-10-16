#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace pi {

struct Frame {
    const uint8_t* data = nullptr;  // valid until the next call to next()
    size_t cap_len = 0;             // bytes in data
    size_t wire_len = 0;            // original length (may exceed cap_len)
};

enum class CaptureStatus { Packet, Timeout, Interrupted, End, Error };

// A source of raw Ethernet frames: a live interface or a capture file.
class CaptureSource {
public:
    virtual ~CaptureSource() = default;

    // Waits up to timeout_ms (negative = forever) for the next frame.
    virtual CaptureStatus next(Frame& out, int timeout_ms) = 0;
    virtual std::string describe() const = 0;
    // Frames the kernel dropped because we did not read fast enough (live only).
    virtual uint64_t kernel_drops() { return 0; }
    const std::string& error() const { return error_; }

protected:
    std::string error_;
};

// Classic libpcap file (.pcap, not .pcapng) with Ethernet link type.
std::unique_ptr<CaptureSource> open_pcap_file(const std::string& path, std::string& error);

// Live capture via AF_PACKET raw socket. Linux only; returns null elsewhere.
std::unique_ptr<CaptureSource> open_live(const std::string& iface, bool promiscuous, std::string& error);

}  // namespace pi
