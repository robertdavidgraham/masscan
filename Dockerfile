FROM alpine:latest AS build

RUN apk add --no-cache build-base libpcap-dev linux-headers

WORKDIR /build
COPY . .

RUN mkdir bin && make -j$(nproc) && make install

FROM alpine:latest

# OCI annotations
LABEL org.opencontainers.image.title="masscan" \
      org.opencontainers.image.authors="masscan Community" \
      org.opencontainers.image.description="TCP port scanner" \
      org.opencontainers.image.source="https://github.com/robertdavidgraham/masscan" \
      org.opencontainers.image.documentation="https://man.archlinux.org/man/extra/masscan/masscan.8.en"

RUN apk add --no-cache libpcap

# docker run --rm -v $(pwd):/scan -it masscan:latest -p 53 8.8.8.8 -oX scan.xml
WORKDIR /scan
COPY --from=build /build/bin/masscan /usr/local/bin/masscan

ENTRYPOINT ["/usr/local/bin/masscan"]
