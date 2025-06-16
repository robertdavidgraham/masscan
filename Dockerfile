FROM debian:jessie
MAINTAINER George Lewis <schvin@schvin.net>

RUN mkdir /s
RUN apt-get update -y && apt-get install -y git gcc make libpcap-dev

RUN groupadd s-scan
RUN useradd s-scan -g s-scan -d /home/s-scan
RUN mkdir /home/s-scan
RUN chown -R s-scan:s-scan /home/s-scan
ENV HOME /home/s-scan
USER s-scan
WORKDIR /home/s-scan

RUN git clone https://github.com/robertdavidgraham/masscan
WORKDIR /home/s-scan/masscan
RUN make

ENTRYPOINT ["/usr/bin/sudo", "bin/masscan"]
CMD ["--help"]
