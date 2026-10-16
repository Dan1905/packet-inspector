# packet-inspector

A passive network packet inspector and ACL engine in C++17. It captures raw Ethernet
frames, parses Ethernet / 802.1Q / IPv4 / ARP / TCP / UDP / ICMP headers, evaluates each
IPv4 packet against an ordered, first-match ACL, and reports live traffic stats.

> **Passive mode.** Capture uses an `AF_PACKET` socket, which receives *copies* of
> frames. `[BLOCK]` is a verdict that gets logged and counted. The packet is still
> delivered. Real enforcement would need NFQUEUE, XDP/eBPF or nftables.

```
 Interface ──► CaptureSource ──► parse_frame() ──► ACLEngine::evaluate() ──┬─► log line
 (AF_PACKET     (live or .pcap)   (bounds-checked,   (first match, CIDR,     └─► Stats
  or pcap file)                    memcpy headers)    port ranges, default)
```

## Build and test

You need a C++17 compiler and `make`. There are no third-party dependencies.

```bash
make            # builds build/packet-inspector, build/run-tests, build/gen-sample-pcap
make test       # unit tests: parser, ACL, formatting, stats, pcap reader
make demo       # replays generated sample traffic through rules.csv
```

The parser, ACL engine and pcap replay are portable, so they also build and run on
macOS. Live capture is Linux-only.

## Live capture (Linux / Docker)

```bash
sudo ./build/packet-inspector -i eth0 -c rules.csv          # or grant CAP_NET_RAW
```

On macOS, use the Docker image, which captures the container's own `eth0`:

```bash
docker build -t packet-inspector .
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --name pi packet-inspector
# in a second terminal, generate traffic:
docker exec pi ping -c 3 1.1.1.1
docker exec pi dig @8.8.8.8 example.com     # hits "Blocked DNS"
docker exec pi curl -sI https://example.com
```

## Usage

```
packet-inspector (-i IFACE | -r FILE.pcap) [options]
  -i, --interface IFACE   live capture via AF_PACKET (Linux, needs CAP_NET_RAW)
  -r, --read FILE         replay a classic .pcap file (not pcapng)
  -c, --rules FILE        ACL rules CSV (default: no rules, default ALLOW)
  -n, --count N           stop after N packets
  -s, --stats-interval S  stats every S seconds during live capture (0 = off, default 5)
  -l, --log MODE          all | blocked | none
  -p, --promisc           promiscuous mode
  -v, --verbose           add MACs, TTL, seq/ack, IP checksum
      --color/--no-color  force ANSI colours (default: auto)
```

To reload the rules without restarting, send `kill -HUP <pid>`. If the new file is
invalid, the old rules stay in effect.

Example output:

```
[PASS] [IPv4] [TCP] 192.168.1.15:443 -> 10.0.0.5:52341 | Flags: [PSH,ACK] | Len: 1500 B
[BLOCK] [ACL Deny] [IPv4] [UDP] 192.168.1.100:53 -> 10.0.0.5:1234 | Reason: Blocked DNS | Len: 74 B
[PASS] [VLAN 20] [IPv4] [UDP] 10.0.0.5:123 -> 10.0.0.123:123 | Len: 94 B
[INFO] [ARP] who-has 10.0.0.1 tell 10.0.0.5 | Len: 60 B
```

Packets that aren't IPv4 (ARP, IPv6, LLDP and so on) are logged as `[INFO]` and counted.
They are never judged by the ACL.

## Rules file

```
# ACTION, PROTOCOL, SRC_IP, SRC_PORT, DST_IP, DST_PORT, REASON
DENY,  UDP,  ANY,            53,  ANY, ANY,       Blocked DNS
DENY,  TCP,  ANY,            ANY, ANY, 6660-6669, IRC
DENY,  ANY,  203.0.113.0/24, ANY, ANY, ANY,       Known-bad network
DEFAULT, ALLOW
```

| Field    | Values                                         |
|----------|------------------------------------------------|
| ACTION   | `ALLOW` / `DENY` (aliases `PASS` / `BLOCK`)    |
| PROTOCOL | `ANY`, `TCP`, `UDP`, `ICMP`, or a number 0–255 |
| IP       | `ANY`, `a.b.c.d`, `a.b.c.d/len`                |
| PORT     | `ANY`, `n`, `lo-hi`                            |
| REASON   | optional free text, shown on BLOCK lines       |

- Rules are evaluated top to bottom and the first match wins. `DEFAULT` sets the
  fallback action.
- A rule that constrains ports never matches packets without ports (ICMP, or a later
  IP fragment).
- Rules are **stateless**, so replies need their own rule. For example, a DNS
  server's answers come *from* port 53. See `rules.csv`.

## Layout

| File | Purpose |
|------|---------|
| `src/parser.*`    | Bounds-checked L2–L4 parser, IPv4 header checksum |
| `src/acl.*`       | Rule types, CSV loader, first-match engine |
| `src/stats.*`     | Counters, protocol distribution, rule hits, report |
| `src/format.*`    | Log-line formatting |
| `src/capture.hpp` | `CaptureSource` interface |
| `src/af_packet.cpp` | Linux raw-socket backend (poll, `MSG_TRUNC`, kernel drop stats, loopback de-dup) |
| `src/pcap_file.cpp` | Classic pcap reader (both byte orders, µs/ns) |
| `tests/`          | Unit tests and the synthetic frame builder |
| `tools/gen_sample_pcap.cpp` | Writes the demo capture |

## Notes on the parser

- Headers are copied out with `memcpy` into the BSD-style system structs (`struct ip`,
  `tcphdr`'s `th_*`, `udphdr`'s `uh_*`). These exist on both glibc and macOS, unlike
  `struct iphdr`. Copying avoids unaligned access and strict-aliasing UB.
- The IPv4 header length comes from `ihl * 4`, so options are handled. The IP total
  length bounds the L4 parse, so Ethernet padding is never read as protocol data.
- Only the first fragment's L4 header is parsed. Later fragments carry no ports.
- The IPv4 header checksum is verified. TCP/UDP checksums are not, because NIC
  offload makes them unreliable on captured outgoing packets.
