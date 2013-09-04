/*

    Construct a TCP packet based upon a template.

    The (eventual) idea of this module is to make this scanner extensible
    by providing an arbitrary packet template. Thus, the of this module
    is to take an existing packet template, parse it, then make
    appropriate changes.
*/
#include "tcpkt.h"
#include "proto-preprocess.h"
#include "string_s.h"
#include "pixie-timer.h"
#include "proto-preprocess.h"
#include "logger.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static unsigned char packet_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x28"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x06"      /* TTL=255, proto=TCP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\xfe\xdc"      /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* sequence number */
    "\0\0\0\0"      /* ack number */
    "\x50"          /* header length */
    "\x02"          /* SYN */
    "\x0\x0"        /* window */
    "\xFF\xFF"      /* checksum */
    "\x00\x00"      /* urgent pointer */
;

unsigned
ip_checksum(struct TcpPacket *tmpl)
{
    unsigned xsum = 0;
    unsigned i;

    xsum = 0;
    for (i=tmpl->offset_ip; i<tmpl->offset_tcp; i += 2) {
        xsum += tmpl->packet[i]<<8 | tmpl->packet[i+1];
    }
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_checksum(struct TcpPacket *tmpl)
{
    const unsigned char *px = tmpl->packet;
    unsigned xsum = 0;
    unsigned i;

    /* pseudo checksum */
    xsum = 6;
    xsum += tmpl->offset_app - tmpl->offset_tcp;
    xsum += px[tmpl->offset_ip + 12] << 8 | px[tmpl->offset_ip + 13];
    xsum += px[tmpl->offset_ip + 14] << 8 | px[tmpl->offset_ip + 15];
    xsum += px[tmpl->offset_ip + 16] << 8 | px[tmpl->offset_ip + 17];
    xsum += px[tmpl->offset_ip + 18] << 8 | px[tmpl->offset_ip + 19];

    /* tcp checksum */
    for (i=tmpl->offset_tcp; i<tmpl->offset_app; i += 2) {
        xsum += tmpl->packet[i]<<8 | tmpl->packet[i+1];
    }
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return xsum;
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcp_checksum2(const unsigned char *px, unsigned offset_ip,
    unsigned offset_tcp, size_t tcp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    /* pseudo checksum */
    xsum = 6;
    xsum += tcp_length;
    xsum += px[offset_ip + 12] << 8 | px[offset_ip + 13];
    xsum += px[offset_ip + 14] << 8 | px[offset_ip + 15];
    xsum += px[offset_ip + 16] << 8 | px[offset_ip + 17];
    xsum += px[offset_ip + 18] << 8 | px[offset_ip + 19];

    /* tcp checksum */
    for (i=0; i<tcp_length; i += 2) {
        xsum += px[offset_tcp + i]<<8 | px[offset_tcp + i + 1];
    }

    xsum -= (tcp_length & 1) * px[offset_tcp + i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}

/***************************************************************************
 ***************************************************************************/
size_t
tcp_create_packet(struct TcpPacket *tmpl, 
        unsigned ip, unsigned port,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length)
{
    unsigned ip_id = ip ^ port ^ seqno;
    unsigned offset_ip = tmpl->offset_ip;
    unsigned offset_tcp = tmpl->offset_tcp;
    unsigned offset_payload = offset_tcp + ((tmpl->packet[offset_tcp+12]&0xF0)>>2);
    size_t new_length = offset_payload + payload_length;
    uint64_t xsum;
    size_t ip_len = (offset_payload - offset_ip) + payload_length;
    unsigned old_len;
    
    if (new_length > px_length) {
        fprintf(stderr, "tcp: err generating packet: too much payload\n");
        return 0;
    }

    memcpy(px + 0,              tmpl->packet,   tmpl->length);
    memcpy(px + offset_payload, payload,        payload_length);
    old_len = px[offset_ip+2]<<8 | px[offset_ip+3];
    
    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    px[offset_ip+2] = (unsigned char)(ip_len>> 8);
    px[offset_ip+3] = (unsigned char)(ip_len & 0xFF);
    px[offset_ip+4] = (unsigned char)(ip_id >> 8);
    px[offset_ip+5] = (unsigned char)(ip_id & 0xFF);
    px[offset_ip+16] = (unsigned char)((ip >> 24) & 0xFF);
    px[offset_ip+17] = (unsigned char)((ip >> 16) & 0xFF);
    px[offset_ip+18] = (unsigned char)((ip >>  8) & 0xFF);
    px[offset_ip+19] = (unsigned char)((ip >>  0) & 0xFF);

    xsum = tmpl->checksum_ip;
    xsum += (ip_id&0xFFFF);
    xsum += ip;
    xsum += ip_len - old_len;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    px[offset_ip+10] = (unsigned char)(xsum >> 8);
    px[offset_ip+11] = (unsigned char)(xsum & 0xFF);

    /*
     * now do the same for TCP
     */
    px[offset_tcp+ 2] = (unsigned char)(port >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp+ 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp+ 6] = (unsigned char)(seqno >>  8);
    px[offset_tcp+ 7] = (unsigned char)(seqno >>  0);
    
    px[offset_tcp+ 8] = (unsigned char)(ackno >> 24);
    px[offset_tcp+ 9] = (unsigned char)(ackno >> 16);
    px[offset_tcp+10] = (unsigned char)(ackno >>  8);
    px[offset_tcp+11] = (unsigned char)(ackno >>  0);

    px[offset_tcp+13] = (unsigned char)flags;
    
    px[offset_tcp+14] = (unsigned char)(1200>>8);
    px[offset_tcp+15] = (unsigned char)(1200 & 0xFF);

    px[offset_tcp+16] = (unsigned char)(0 >>  8);
    px[offset_tcp+17] = (unsigned char)(0 >>  0);

    xsum = tcp_checksum2(px, tmpl->offset_ip, tmpl->offset_tcp, new_length - tmpl->offset_tcp);
    xsum = ~xsum;

    px[offset_tcp+16] = (unsigned char)(xsum >>  8);
    px[offset_tcp+17] = (unsigned char)(xsum >>  0);

    if (new_length < 60) {
        memset(px+new_length, 0, 60-new_length);
        new_length = 60;
    }
    return new_length;
}

/***************************************************************************
 * Here we take a packet template, parse it, then make it easier to work
 * with.
 ***************************************************************************/
void
tcp_set_target(struct TcpPacket *tmpl, unsigned ip, unsigned port, unsigned seqno)
{
    unsigned char *px = tmpl->packet;
    unsigned offset_ip = tmpl->offset_ip;
    unsigned offset_tcp = tmpl->offset_tcp;
    uint64_t xsum;
    unsigned ip_id = ip ^ port ^ seqno;


    /*
     * Fill in the empty fields in the IP header and then re-calculate
     * the checksum.
     */
    px[offset_ip+4] = (unsigned char)(ip_id >> 8);
    px[offset_ip+5] = (unsigned char)(ip_id & 0xFF);
    px[offset_ip+16] = (unsigned char)((ip >> 24) & 0xFF);
    px[offset_ip+17] = (unsigned char)((ip >> 16) & 0xFF);
    px[offset_ip+18] = (unsigned char)((ip >>  8) & 0xFF);
    px[offset_ip+19] = (unsigned char)((ip >>  0) & 0xFF);

    xsum = tmpl->checksum_ip;
    xsum += (ip_id&0xFFFF);
    xsum += ip;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    px[offset_ip+10] = (unsigned char)(xsum >> 8);
    px[offset_ip+11] = (unsigned char)(xsum & 0xFF);

    /*
     * now do the same for TCP
     */
    px[offset_tcp+ 2] = (unsigned char)(port >> 8);
    px[offset_tcp+ 3] = (unsigned char)(port & 0xFF);
    px[offset_tcp+ 4] = (unsigned char)(seqno >> 24);
    px[offset_tcp+ 5] = (unsigned char)(seqno >> 16);
    px[offset_tcp+ 6] = (unsigned char)(seqno >>  8);
    px[offset_tcp+ 7] = (unsigned char)(seqno >>  0);

    xsum = (uint64_t)tmpl->checksum_tcp
            + (uint64_t)ip
            + (uint64_t)port
            + (uint64_t)seqno;
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = (xsum >> 16) + (xsum & 0xFFFF);
    xsum = ~xsum;

    px[offset_tcp+16] = (unsigned char)(xsum >>  8);
    px[offset_tcp+17] = (unsigned char)(xsum >>  0);
}


/***************************************************************************
 * Here we take a packet template, parse it, then make it easier to work
 * with.
 ***************************************************************************/
void
tcp_init_packet(struct TcpPacket *tmpl,
    unsigned ip,
    unsigned char *mac_source,
    unsigned char *mac_dest)
{
    unsigned char *px;
    struct PreprocessedInfo parsed;
    unsigned x;

    /*
     * Create the new template structure:
     * - zero it out
     * - make copy of the old packet to serve as new template
     */
    memset(tmpl, 0, sizeof(*tmpl));
    tmpl->length = sizeof(packet_template) - 1;
    assert(tmpl->length == 54);
    tmpl->packet = (unsigned char *)malloc(tmpl->length);
    memcpy(tmpl->packet, packet_template, tmpl->length);
    px = tmpl->packet;

    /*
     * Parse the existing packet template. We support TCP, UDP, ICMP,
     * and ARP packets.
     */
    x = preprocess_frame(px, tmpl->length, 1 /*enet*/, &parsed);
    if (!x || parsed.found == FOUND_NOTHING) {
        LOG(0, "ERROR: bad packet template\n");
        exit(1);
    }
    tmpl->offset_ip = parsed.ip_offset;
    tmpl->offset_tcp = parsed.transport_offset;
    tmpl->offset_app = parsed.app_offset;
    tmpl->length = parsed.ip_offset + parsed.ip_length;

    /*
     * Overwrite the MAC and IP addresses
     */
    memcpy(px+0, mac_dest, 6);
    memcpy(px+6, mac_source, 6);
    ((unsigned char*)parsed.ip_src)[0] = (unsigned char)(ip>>24);
    ((unsigned char*)parsed.ip_src)[1] = (unsigned char)(ip>>16);
    ((unsigned char*)parsed.ip_src)[2] = (unsigned char)(ip>> 8);
    ((unsigned char*)parsed.ip_src)[3] = (unsigned char)(ip>> 0);

    /*
     * ARP
     *
     * If this is an ARP template (for doing arpscans), then just set our
     * configured source IP and MAC addresses.
     */
    if (parsed.found == FOUND_ARP) {
        memcpy((char*)parsed.ip_src - 6, mac_source, 6);
        tmpl->proto = Proto_ARP;
        return;
    }

    /*
     * IPv4
     *
     * We need to zero out the fields that'll be overwritten
     * later.
     */
    memset(px + tmpl->offset_ip + 4, 0, 2);  /* IP ID field */
    memset(px + tmpl->offset_ip + 10, 0, 2); /* checksum */
    memset(px + tmpl->offset_ip + 16, 0, 4); /* destination IP address */
    tmpl->checksum_ip = ip_checksum(tmpl);
    tmpl->proto = Proto_IPv4;

    /*
     * Higher layer protocols: zero out dest/checksum fields
     */
    switch (parsed.ip_protocol) {
    case 1: /* ICMP */
        tmpl->proto = Proto_ICMP;
        break;
    case 6: /* TCP */
        /* zero out fields that'll be overwritten */
        memset(px + tmpl->offset_tcp + 2, 0, 6); /* destination port and seqno */
        memset(px + tmpl->offset_tcp + 16, 0, 2); /* checksum */
        tmpl->checksum_tcp = tcp_checksum(tmpl);
        tmpl->proto = Proto_TCP;
        break;
    case 17: /* UDP */
        memset(px + tmpl->offset_tcp + 6, 0, 2); /* checksum */
        tmpl->checksum_tcp = tcp_checksum(tmpl);
        tmpl->proto = Proto_UDP;
        break;
    }
}

/***************************************************************************
 ***************************************************************************/
unsigned
tcpkt_get_source_ip(struct TcpPacket *tmpl)
{
    const unsigned char *px = tmpl->packet;
    unsigned offset = tmpl->offset_ip;

    return px[offset+12]<<24 | px[offset+13]<<16
        | px[offset+14]<<8 | px[offset+15]<<0;
}

/***************************************************************************
 * Retrieve the source-port of the packet. We parse this from the packet
 * because while the source-port can be configured separately, we usually
 * get a raw packet template.
 ***************************************************************************/
unsigned
tcpkt_get_source_port(struct TcpPacket *tmpl)
{
    const unsigned char *px = tmpl->packet;
    unsigned offset = tmpl->offset_tcp;

    return px[offset+0]<<8 | px[offset+1]<<0;
}

/***************************************************************************
 * Overwrites the source-port field in the packet template.
 ***************************************************************************/
void
tcpkt_set_source_port(struct TcpPacket *tmpl, unsigned port)
{
    unsigned char *px = tmpl->packet;
    unsigned offset = tmpl->offset_tcp;

    px[offset+0] = (unsigned char)(port>>8);
    px[offset+1] = (unsigned char)(port>>0);
    tmpl->checksum_tcp = tcp_checksum(tmpl);
}

/***************************************************************************
 * Overwrites the TTL of the packet
 ***************************************************************************/
void
tcpkt_set_ttl(struct TcpPacket *tmpl, unsigned ttl)
{
    unsigned char *px = tmpl->packet;
    unsigned offset = tmpl->offset_ip;

    px[offset+8] = (unsigned char)(ttl);
    tmpl->checksum_ip = tcp_checksum(tmpl);
}


/***************************************************************************
 ***************************************************************************/
int
tcpkt_selftest()
{
    return 0;
}


/***************************************************************************
 * Print packet info, when using nmap-style --packet-trace option
 ***************************************************************************/
void
tcpkt_trace(struct TcpPacket *pkt_template, unsigned ip, unsigned port, double timestamp_start)
{
    char from[32];
    char to[32];
    unsigned src_ip = tcpkt_get_source_ip(pkt_template);
    unsigned src_port = tcpkt_get_source_port(pkt_template);
    double timestamp = 1.0 * pixie_gettime() / 1000000.0;

    sprintf_s(from, sizeof(from), "%u.%u.%u.%u:%u",
        (src_ip>>24)&0xFF, (src_ip>>16)&0xFF,
        (src_ip>>8)&0xFF, (src_ip>>0)&0xFF,
        src_port);

    sprintf_s(to, sizeof(to), "%u.%u.%u.%u:%u",
        (ip>>24)&0xFF, (ip>>16)&0xFF,
        (ip>>8)&0xFF, (ip>>0)&0xFF,
        port);

    fprintf(stderr, "SENT (%5.4f) TCP %-21s > %-21s SYN\n",
        timestamp - timestamp_start, from, to);
}
