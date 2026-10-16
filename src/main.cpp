#include "acl.hpp"
#include "capture.hpp"
#include "format.hpp"
#include "parser.hpp"
#include "stats.hpp"

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

volatile sig_atomic_t g_stop = 0;
volatile sig_atomic_t g_reload = 0;

void on_signal(int sig) {
    if (sig == SIGHUP) g_reload = 1;
    else g_stop = 1;
}

void install_signals() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART: we want poll() to return EINTR
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);
}

enum class LogMode { All, Blocked, None };

struct Options {
    std::string iface;
    std::string pcap_path;
    std::string rules_path;
    uint64_t count = 0;  // 0 = unlimited
    int stats_interval = 5;
    LogMode log = LogMode::All;
    bool promisc = false;
    bool verbose = false;
    int color = -1;  // -1 = auto
};

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "Usage: %s (-i IFACE | -r FILE.pcap) [options]\n"
                 "\n"
                 "Passive packet inspector: parses Ethernet/IPv4/ARP/TCP/UDP/ICMP and evaluates\n"
                 "each IPv4 packet against an ordered ACL. Verdicts are logged, not enforced.\n"
                 "\n"
                 "  -i, --interface IFACE   capture live on IFACE via AF_PACKET (Linux, needs CAP_NET_RAW)\n"
                 "  -r, --read FILE         replay a classic .pcap file\n"
                 "  -c, --rules FILE        ACL rules CSV (default: no rules, default ALLOW)\n"
                 "  -n, --count N           stop after N packets\n"
                 "  -s, --stats-interval S  print stats every S seconds during live capture (0 = off, default 5)\n"
                 "  -l, --log MODE          all | blocked | none (default all)\n"
                 "  -p, --promisc           put the interface in promiscuous mode\n"
                 "  -v, --verbose           include MACs, TTL, seq/ack, checksum in log lines\n"
                 "      --color/--no-color  force ANSI colours on/off (default: auto)\n"
                 "  -h, --help              show this help\n"
                 "\n"
                 "Send SIGHUP to reload the rules file without restarting.\n",
                 argv0);
}

bool parse_args(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: %s needs a value\n", name);
                return nullptr;
            }
            return argv[++i];
        };
        const char* v = nullptr;
        if (a == "-h" || a == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else if (a == "-i" || a == "--interface") {
            if (!(v = value("--interface"))) return false;
            o.iface = v;
        } else if (a == "-r" || a == "--read") {
            if (!(v = value("--read"))) return false;
            o.pcap_path = v;
        } else if (a == "-c" || a == "--rules") {
            if (!(v = value("--rules"))) return false;
            o.rules_path = v;
        } else if (a == "-n" || a == "--count") {
            if (!(v = value("--count"))) return false;
            o.count = std::strtoull(v, nullptr, 10);
        } else if (a == "-s" || a == "--stats-interval") {
            if (!(v = value("--stats-interval"))) return false;
            o.stats_interval = std::atoi(v);
        } else if (a == "-l" || a == "--log") {
            if (!(v = value("--log"))) return false;
            const std::string m = v;
            if (m == "all") o.log = LogMode::All;
            else if (m == "blocked") o.log = LogMode::Blocked;
            else if (m == "none") o.log = LogMode::None;
            else {
                std::fprintf(stderr, "error: --log must be all, blocked or none\n");
                return false;
            }
        } else if (a == "-p" || a == "--promisc") {
            o.promisc = true;
        } else if (a == "-v" || a == "--verbose") {
            o.verbose = true;
        } else if (a == "--color") {
            o.color = 1;
        } else if (a == "--no-color") {
            o.color = 0;
        } else {
            std::fprintf(stderr, "error: unknown argument '%s'\n", a.c_str());
            return false;
        }
    }
    if (o.iface.empty() == o.pcap_path.empty()) {
        std::fprintf(stderr, "error: give exactly one of -i IFACE or -r FILE\n");
        return false;
    }
    return true;
}

double seconds_since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    pi::ACLEngine acl;
    if (!opt.rules_path.empty()) {
        auto loaded = pi::load_rules_file(opt.rules_path);
        if (!loaded.engine) {
            std::fprintf(stderr, "error: %s\n", loaded.error.c_str());
            return 1;
        }
        acl = std::move(*loaded.engine);
    }

    const bool live = !opt.iface.empty();
    std::string err;
    auto source = live ? pi::open_live(opt.iface, opt.promisc, err) : pi::open_pcap_file(opt.pcap_path, err);
    if (!source) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }

    install_signals();

    pi::FormatOptions fmt;
    fmt.color = opt.color < 0 ? isatty(STDOUT_FILENO) : opt.color == 1;
    fmt.verbose = opt.verbose;

    std::fprintf(stderr, "packet-inspector: reading %s | %zu rule(s), default %s | passive mode: "
                         "verdicts are logged, not enforced\n",
                 source->describe().c_str(), acl.rules().size(), pi::action_name(acl.default_action()));

    pi::Stats stats, last_report;
    stats.reset_rule_hits(acl.rules().size());
    const auto start = std::chrono::steady_clock::now();
    auto last_report_time = start;
    const bool periodic = live && opt.stats_interval > 0;
    int exit_code = 0;

    while (!g_stop) {
        if (g_reload) {
            g_reload = 0;
            if (opt.rules_path.empty()) {
                std::fprintf(stderr, "packet-inspector: SIGHUP ignored, no rules file given\n");
            } else if (auto loaded = pi::load_rules_file(opt.rules_path); loaded.engine) {
                acl = std::move(*loaded.engine);
                stats.reset_rule_hits(acl.rules().size());
                last_report.reset_rule_hits(acl.rules().size());
                std::fprintf(stderr, "packet-inspector: reloaded %zu rule(s), default %s\n", acl.rules().size(),
                             pi::action_name(acl.default_action()));
            } else {
                std::fprintf(stderr, "packet-inspector: reload failed, keeping old rules: %s\n",
                             loaded.error.c_str());
            }
        }

        int timeout_ms = -1;
        if (periodic) {
            const double remaining = opt.stats_interval - seconds_since(last_report_time);
            timeout_ms = remaining > 0 ? static_cast<int>(remaining * 1000) + 1 : 0;
        }

        pi::Frame frame;
        const pi::CaptureStatus st = source->next(frame, timeout_ms);
        if (st == pi::CaptureStatus::End) break;
        if (st == pi::CaptureStatus::Error) {
            std::fprintf(stderr, "error: %s\n", source->error().c_str());
            exit_code = 1;
            break;
        }

        if (st == pi::CaptureStatus::Packet) {
            const pi::ParsedPacket pkt = pi::parse_frame(frame.data, frame.cap_len, frame.wire_len);

            // The ACL only speaks IPv4 5-tuples; other traffic is counted but not judged.
            pi::Verdict verdict{};
            const bool evaluated = pkt.l3 == pi::L3Proto::IPv4;
            if (evaluated) verdict = acl.evaluate(pkt);
            stats.record(pkt, evaluated ? &verdict : nullptr);

            const bool blocked = evaluated && verdict.action == pi::Action::DENY;
            if (opt.log == LogMode::All || (opt.log == LogMode::Blocked && blocked)) {
                const std::string line = pi::format_packet(pkt, evaluated ? &verdict : nullptr, acl, fmt);
                std::fputs(line.c_str(), stdout);
                std::fputc('\n', stdout);
            }
            if (opt.count && stats.packets >= opt.count) break;
        }

        if (periodic && seconds_since(last_report_time) >= opt.stats_interval) {
            const double interval = seconds_since(last_report_time);
            std::fputs(pi::format_stats(stats, last_report, interval, seconds_since(start), acl).c_str(), stdout);
            std::fflush(stdout);
            last_report = stats;
            last_report_time = std::chrono::steady_clock::now();
        }
    }

    std::fputs("\n", stdout);
    std::fputs(pi::format_stats(stats, last_report, 0, seconds_since(start), acl).c_str(), stdout);
    if (live) std::printf("  Kernel drops: %llu\n", static_cast<unsigned long long>(source->kernel_drops()));
    std::fflush(stdout);
    return exit_code;
}
