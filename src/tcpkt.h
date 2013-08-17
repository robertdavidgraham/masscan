#ifndef TCP_PACKET_H
#define TCP_PACKET_H

/**
 * @return
 *      1 on failure
 *      0 on success
 */
int tcpkt_selftest();

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
};

void
tcp_init_packet(struct TcpPacket *pkt,
    unsigned ip_source,
    unsigned char *mac_souce,
    unsigned char *mac_dest);

void
tcp_set_target(struct TcpPacket *pkt, unsigned ip, unsigned port);

unsigned
tcpkt_get_source_port(struct TcpPacket *pkt);

void
tcpkt_set_source_port(struct TcpPacket *pkt, unsigned port);

#endif
