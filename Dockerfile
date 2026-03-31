FROM ubuntu:25.10 AS builder

RUN apt update && apt install -y build-essential libpcap-dev git && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN make -j"$(nproc)" && make install


FROM ubuntu:25.10

LABEL org.opencontainers.image.title="masscan"
LABEL org.opencontainers.image.source="https://github.com/robertdavidgraham/masscan"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.description="TCP port scanner"

RUN apt update && apt install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

WORKDIR /scan

COPY --from=builder /build/bin/masscan /usr/local/bin/masscan

ENTRYPOINT ["/usr/local/bin/masscan"]

