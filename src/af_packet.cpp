#include "capture.hpp"

#ifdef __linux__

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

namespace pi {
namespace {

constexpr size_t kBufferSize = 65536;
constexpr int kSocketRcvBuf = 8 * 1024 * 1024;

std::string errno_str(const std::string& what) { return what + ": " + std::strerror(errno); }

class AfPacketSource : public CaptureSource {
public:
    ~AfPacketSource() override {
        if (fd_ >= 0) close(fd_);  // also drops any promiscuous membership
    }

    bool open(const std::string& iface, bool promiscuous) {
        iface_ = iface;
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0) {
            error_ = errno_str("socket(AF_PACKET)");
            if (errno == EPERM) error_ += " (run as root or grant CAP_NET_RAW)";
            return false;
        }

        const unsigned ifindex = if_nametoindex(iface.c_str());
        if (ifindex == 0) {
            error_ = "no such interface: " + iface;
            return false;
        }

        // Only Ethernet-framed devices are supported (loopback uses a fake Ethernet header).
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd_, SIOCGIFHWADDR, &ifr) < 0) {
            error_ = errno_str("SIOCGIFHWADDR " + iface);
            return false;
        }
        const int hwtype = ifr.ifr_hwaddr.sa_family;
        if (hwtype != ARPHRD_ETHER && hwtype != ARPHRD_LOOPBACK) {
            error_ = iface + " is not an Ethernet device (ARPHRD " + std::to_string(hwtype) + ")";
            return false;
        }
        loopback_ = hwtype == ARPHRD_LOOPBACK;

        sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = static_cast<int>(ifindex);
        if (bind(fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0) {
            error_ = errno_str("bind " + iface);
            return false;
        }

        if (promiscuous) {
            packet_mreq mr{};
            mr.mr_ifindex = static_cast<int>(ifindex);
            mr.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
                error_ = errno_str("PACKET_MR_PROMISC");
                return false;
            }
        }

        // A larger socket buffer absorbs bursts; failure here is not fatal.
        setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &kSocketRcvBuf, sizeof(kSocketRcvBuf));
        return true;
    }

    CaptureStatus next(Frame& out, int timeout_ms) override {
        for (;;) {
            pollfd pfd{fd_, POLLIN, 0};
            const int ready = poll(&pfd, 1, timeout_ms);
            if (ready == 0) return CaptureStatus::Timeout;
            if (ready < 0) {
                if (errno == EINTR) return CaptureStatus::Interrupted;
                error_ = errno_str("poll");
                return CaptureStatus::Error;
            }

            sockaddr_ll from{};
            socklen_t from_len = sizeof(from);
            // MSG_TRUNC makes recvfrom return the real frame length even when it
            // does not fit in the buffer.
            const ssize_t n = recvfrom(fd_, buffer_, sizeof(buffer_), MSG_TRUNC,
                                       reinterpret_cast<sockaddr*>(&from), &from_len);
            if (n < 0) {
                if (errno == EINTR) return CaptureStatus::Interrupted;
                if (errno == EAGAIN) continue;
                error_ = errno_str("recvfrom");
                return CaptureStatus::Error;
            }
            // On loopback every packet is seen twice (outgoing, then incoming); keep one copy.
            if (loopback_ && from.sll_pkttype == PACKET_OUTGOING) continue;

            out.data = buffer_;
            out.wire_len = static_cast<size_t>(n);
            out.cap_len = out.wire_len < sizeof(buffer_) ? out.wire_len : sizeof(buffer_);
            return CaptureStatus::Packet;
        }
    }

    uint64_t kernel_drops() override {
        tpacket_stats st{};
        socklen_t len = sizeof(st);
        // The kernel resets these counters on every read, so accumulate.
        if (getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0) drops_ += st.tp_drops;
        return drops_;
    }

    std::string describe() const override { return "interface " + iface_; }

private:
    int fd_ = -1;
    std::string iface_;
    bool loopback_ = false;
    uint64_t drops_ = 0;
    alignas(8) uint8_t buffer_[kBufferSize];
};

}  // namespace

std::unique_ptr<CaptureSource> open_live(const std::string& iface, bool promiscuous, std::string& error) {
    auto src = std::make_unique<AfPacketSource>();
    if (!src->open(iface, promiscuous)) {
        error = src->error();
        return nullptr;
    }
    return src;
}

}  // namespace pi

#else  // !__linux__

namespace pi {

std::unique_ptr<CaptureSource> open_live(const std::string&, bool, std::string& error) {
    error = "live capture uses AF_PACKET and is only available on Linux; "
            "use -r FILE.pcap here, or run inside the Docker image (see README)";
    return nullptr;
}

}  // namespace pi

#endif
