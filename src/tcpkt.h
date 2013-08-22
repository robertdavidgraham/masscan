#ifndef TCP_PACKET_H
#define TCP_PACKET_H

/**
 * @return
 *      1 on failure
 *      0 on success
 */
int tcpkt_selftest();

enum TemplateProtocol {
    Proto_Unknown,
    Proto_TCP,
    Proto_UDP,
    Proto_ICMP,
    Proto_IPv4,
    Proto_ARP,
};

struct TcpPacket
{
    unsigned length;
    unsigned offset_ip;
    unsigned offset_tcp;
    unsigned offset_app;

    unsigned char *packet;

    unsigned checksum_ip;
    unsigned checksum_tcp;

    unsigned ip_id;

    enum TemplateProtocol proto;
};

void
tcp_init_packet(struct TcpPacket *pkt,
    unsigned ip_source,
    unsigned char *mac_souce,
    unsigned char *mac_dest);

void tcp_set_target(struct TcpPacket *pkt, unsigned ip, unsigned port, unsigned seqno);

void tcpkt_trace(struct TcpPacket *pkt, unsigned ip, unsigned port, double timestamp_start);

unsigned tcpkt_get_source_port(struct TcpPacket *pkt);
unsigned tcpkt_get_source_ip(struct TcpPacket *pkt);

void tcpkt_set_source_port(struct TcpPacket *pkt, unsigned port);
void tcpkt_set_ttl(struct TcpPacket *pkt, unsigned ttl);

#endif
