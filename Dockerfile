# Linux environment for live AF_PACKET capture (macOS has no AF_PACKET).
#
#   docker build -t packet-inspector .
#   docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --name pi packet-inspector \
#       ./build/packet-inspector -i eth0 -c rules.csv
#
# Then generate traffic from a second terminal:
#   docker exec pi ping -c 3 1.1.1.1
#   docker exec pi dig @8.8.8.8 example.com

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        g++ make ca-certificates curl dnsutils iproute2 iputils-ping netcat-openbsd tcpdump \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN make clean && make -j"$(nproc)" && make test

CMD ["./build/packet-inspector", "-i", "eth0", "-c", "rules.csv"]
