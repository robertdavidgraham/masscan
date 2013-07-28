/*

    Construct a TCP packet based upon a template.

*/
#include "tcpkt.h"

#include <string.h>
#include <stdlib.h>

static unsigned char packet_template[] = 
	"\0\1\2\3\4\5"	/* Ethernet: destination */
	"\6\7\x8\x9\xa\xb"	/* Ethernet: source */
	"\x08\x00"		/* Etenrent type: IPv4 */
	"\x45"			/* IP type */
	"\x00"
	"\x00\x28"		/* total length = 40 bytes */
	"\x00\x00"		/* identification */
	"\x00\x00"		/* fragmentation flags */
	"\xFF\x06"		/* TTL=255, proto=TCP */
	"\xFF\xFF"		/* checksum */
	"\0\0\0\0"		/* source address */
	"\0\0\0\0"		/* destination address */
		
	"\xfe\xdc"		/* source port */
	"\0\0"			/* destination port */
	"\0\0\0\0"		/* sequence number */
	"\0\0\0\0"		/* ack number */
	"\x50"			/* header length */
	"\x02"			/* SYN */
	"\x0\x0"		/* window */
	"\xFF\xFF"		/* checksum */
	"\x00\x00"		/* urgent pointer */
;

unsigned
ip_checksum(struct TcpPacket *pkt)
{
	unsigned xsum = 0;
	unsigned i;

	xsum = 0;
	for (i=pkt->offset_ip; i<pkt->offset_tcp; i += 2) {
		xsum += pkt->packet[i]<<8 | pkt->packet[i+1];
	}
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = (xsum & 0xFFFF) + (xsum >> 16);

	return xsum;
}
unsigned
tcp_checksum(struct TcpPacket *pkt)
{
	const unsigned char *px = pkt->packet;
	unsigned xsum = 0;
	unsigned i;

	xsum = 6;
	xsum += pkt->offset_app - pkt->offset_tcp;
	xsum += px[pkt->offset_ip + 12] << 8 | px[pkt->offset_ip + 13];
	xsum += px[pkt->offset_ip + 14] << 8 | px[pkt->offset_ip + 15];
	xsum += px[pkt->offset_ip + 16] << 8 | px[pkt->offset_ip + 17];
	xsum += px[pkt->offset_ip + 18] << 8 | px[pkt->offset_ip + 19];
	for (i=pkt->offset_tcp; i<pkt->offset_app; i += 2) {
		xsum += pkt->packet[i]<<8 | pkt->packet[i+1];
	}
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = (xsum & 0xFFFF) + (xsum >> 16);

	return xsum;
}

void
tcp_set_target(struct TcpPacket *pkt, unsigned ip, unsigned port)
{
	unsigned char *px = pkt->packet;
	unsigned offset_ip = pkt->offset_ip;
	unsigned offset_tcp = pkt->offset_tcp;
	unsigned xsum;

	xsum = (ip >> 16) + (ip & 0xFFFF);
	xsum = (xsum >> 16) + (xsum & 0xFFFF);
	xsum = ~xsum;

	
	px[offset_ip+4] = (unsigned char)(xsum >> 8);
	px[offset_ip+5] = (unsigned char)(xsum & 0xFF);

	
	px[offset_ip+16] = (unsigned char)((ip >> 24) & 0xFF);
	px[offset_ip+17] = (unsigned char)((ip >> 16) & 0xFF);
	px[offset_ip+18] = (unsigned char)((ip >>  8) & 0xFF);
	px[offset_ip+19] = (unsigned char)((ip >>  0) & 0xFF);

	xsum = ip + port;
	xsum = ~xsum;
	
	px[offset_tcp+ 2] = (unsigned char)(port >> 8);
	px[offset_tcp+ 3] = (unsigned char)(port & 0xFF);
	px[offset_tcp+ 4] = (unsigned char)(xsum >> 24);
	px[offset_tcp+ 5] = (unsigned char)(xsum >> 16);
	px[offset_tcp+ 6] = (unsigned char)(xsum >>  8);
	px[offset_tcp+ 7] = (unsigned char)(xsum >>  0);
}

void
tcp_init_packet(struct TcpPacket *pkt,
    unsigned ip,
    unsigned char *mac_source,
    unsigned char *mac_dest)
{
	unsigned i;
	unsigned xsum;
	unsigned char *px;

	memset(pkt, 0, sizeof(*pkt));

	pkt->length = 54;  /* minimum size is 64 bytes */
	pkt->packet = (unsigned char *)malloc(pkt->length);
	px = pkt->packet;

	memcpy(pkt->packet, packet_template, pkt->length);
    if (memcmp(mac_dest, "\0\0\0\0\0\0", 6) != 0)
        memcpy(px+0, mac_dest, 6);
    if (memcmp(mac_source, "\0\0\0\0\0\0", 6) != 0)
        memcpy(px+6, mac_source, 6);

	pkt->offset_ip = 14;
	pkt->offset_tcp = 34;
	pkt->offset_app = 54;

    /* set the source address */
    if (ip) {
  	    px[pkt->offset_ip+12] = (unsigned char)((ip >> 24) & 0xFF);
	    px[pkt->offset_ip+13] = (unsigned char)((ip >> 16) & 0xFF);
	    px[pkt->offset_ip+14] = (unsigned char)((ip >>  8) & 0xFF);
	    px[pkt->offset_ip+15] = (unsigned char)((ip >>  0) & 0xFF);
    }

	/* Set the initial IP header checksum */
	xsum = 0;
	for (i=pkt->offset_ip; i<pkt->offset_tcp; i += 2) {
		xsum += pkt->packet[i]<<8 | pkt->packet[i+1];
	}
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = 0xFFFF - xsum;
	px[pkt->offset_ip+10] = (unsigned char)(xsum >> 8);
	px[pkt->offset_ip+11] = (unsigned char)(xsum & 0xFF);
	pkt->checksum_ip = xsum;

	/* Set the initial TCP header checksum */
	xsum = 6;
	xsum += pkt->offset_app - pkt->offset_tcp;
	xsum += px[pkt->offset_ip + 12] << 8 | px[pkt->offset_ip + 13];
	xsum += px[pkt->offset_ip + 14] << 8 | px[pkt->offset_ip + 15];
	xsum += px[pkt->offset_ip + 16] << 8 | px[pkt->offset_ip + 17];
	xsum += px[pkt->offset_ip + 18] << 8 | px[pkt->offset_ip + 19];
	for (i=pkt->offset_tcp; i<pkt->offset_app; i += 2) {
		xsum += px[i] << 8 | px[i+1];
	}
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = (xsum & 0xFFFF) + (xsum >> 16);
	xsum = 0xFFFF - xsum;
	px[pkt->offset_tcp+16] = (unsigned char)(xsum >> 8);
	px[pkt->offset_tcp+17] = (unsigned char)(xsum & 0xFF);
	pkt->checksum_tcp = xsum;

}

/***************************************************************************
 ***************************************************************************/
int
tcpkt_selftest()
{
    return 0;
}
