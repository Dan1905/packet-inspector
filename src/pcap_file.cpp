#include "capture.hpp"

#include <cstring>
#include <fstream>
#include <vector>

namespace pi {
namespace {

constexpr uint32_t kMagicMicro = 0xa1b2c3d4;
constexpr uint32_t kMagicNano = 0xa1b23c4d;
constexpr uint32_t kLinkTypeEthernet = 1;
constexpr uint32_t kMaxRecordLen = 256 * 1024;

uint32_t bswap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24);
}

class PcapFileSource : public CaptureSource {
public:
    bool open(const std::string& path) {
        path_ = path;
        in_.open(path, std::ios::binary);
        if (!in_) {
            error_ = "cannot open " + path;
            return false;
        }
        uint8_t hdr[24];
        if (!in_.read(reinterpret_cast<char*>(hdr), sizeof(hdr))) {
            error_ = path + ": too short for a pcap header";
            return false;
        }
        uint32_t magic;
        std::memcpy(&magic, hdr, 4);
        if (magic == kMagicMicro || magic == kMagicNano) {
            swapped_ = false;
        } else if (bswap32(magic) == kMagicMicro || bswap32(magic) == kMagicNano) {
            swapped_ = true;
        } else if (magic == 0x0a0d0d0a) {
            error_ = path + ": pcapng is not supported; convert with: editcap -F pcap in.pcapng out.pcap";
            return false;
        } else {
            error_ = path + ": not a pcap file";
            return false;
        }
        const uint32_t linktype = u32(hdr + 20) & 0x0fffffff;  // upper bits hold FCS info
        if (linktype != kLinkTypeEthernet) {
            error_ = path + ": link type " + std::to_string(linktype) + " is not Ethernet";
            return false;
        }
        return true;
    }

    CaptureStatus next(Frame& out, int /*timeout_ms*/) override {
        uint8_t rec[16];
        if (!in_.read(reinterpret_cast<char*>(rec), sizeof(rec))) return CaptureStatus::End;
        const uint32_t incl = u32(rec + 8);
        const uint32_t orig = u32(rec + 12);
        if (incl > kMaxRecordLen) {
            error_ = path_ + ": corrupt record length " + std::to_string(incl);
            return CaptureStatus::Error;
        }
        buf_.resize(incl);
        if (incl && !in_.read(reinterpret_cast<char*>(buf_.data()), incl)) return CaptureStatus::End;
        out.data = buf_.data();
        out.cap_len = incl;
        out.wire_len = orig < incl ? incl : orig;
        return CaptureStatus::Packet;
    }

    std::string describe() const override { return "file " + path_; }

private:
    uint32_t u32(const uint8_t* p) const {
        uint32_t v;
        std::memcpy(&v, p, 4);
        return swapped_ ? bswap32(v) : v;
    }

    std::string path_;
    std::ifstream in_;
    bool swapped_ = false;
    std::vector<uint8_t> buf_;
};

}  // namespace

std::unique_ptr<CaptureSource> open_pcap_file(const std::string& path, std::string& error) {
    auto src = std::make_unique<PcapFileSource>();
    if (!src->open(path)) {
        error = src->error();
        return nullptr;
    }
    return src;
}

}  // namespace pi
