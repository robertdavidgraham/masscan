/*

    Construct a TCP packet based upon a template.

    The (eventual) idea of this module is to make this scanner extensible
    by providing an arbitrary packet template. Thus, the of this module
    is to take an existing packet template, parse it, then make
    appropriate changes.
*/
#include "templ-pkt.h"
#include "proto-preprocess.h"
#include "string_s.h"
#include "pixie-timer.h"
#include "proto-preprocess.h"
#include "logger.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

static unsigned char default_tcp_template[] =
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

static unsigned char default_udp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x1c"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x11"      /* TTL=255, proto=UDP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\xfe\xdc"      /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* checksum */
    "\0\0\0\0"      /* length */
;

static unsigned char default_sctp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x1c"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x11"      /* TTL=255, proto=UDP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\xfe\xdc"      /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* checksum */
    "\0\0\0\0"      /* length */
;


static unsigned char default_icmp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x1c"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x11"      /* TTL=255, proto=UDP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\xfe\xdc"      /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* checksum */
    "\0\0\0\0"      /* length */
;

static unsigned char default_arp_template[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Etenrent type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x1c"      /* total length = 40 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x11"      /* TTL=255, proto=UDP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\xfe\xdc"      /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* checksum */
    "\0\0\0\0"      /* length */
;

/***************************************************************************
 ***************************************************************************/
static unsigned
ip_checksum(struct TemplatePacket *tmpl)
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
static unsigned
tcp_checksum(struct TemplatePacket *tmpl)
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
tcp_create_packet(
        struct TemplatePacket *tmpl, 
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
template_set_target(
    struct TemplateSet *tmplset, 
    unsigned ip, unsigned port, 
    unsigned seqno)
{
    unsigned char *px;
    unsigned offset_ip;
    unsigned offset_tcp;
    uint64_t xsum;
    unsigned ip_id;
    struct TemplatePacket *tmpl = NULL;

    /*
     * Find out which packet template to use. This is because we can
     * simultaneously scan for both TCP and UDP (and others). We've
     * just overloaded the "port" field to signal which protocol we
     * are using
     */
    if (port < 65536)
        tmpl = &tmplset->pkts[Proto_TCP];
    else if (port < 65536*2) {
        tmpl = &tmplset->pkts[Proto_UDP];
        port &= 0xFFFF;
    } else if (port < 65536*3) {
        tmpl = &tmplset->pkts[Proto_SCTP];
        port &= 0xFFFF;
    } else if (port == 65536*3) {
        tmpl = &tmplset->pkts[Proto_ICMP];
        port = 1;
    } else if (port == 65536*3+1) {
        tmpl = &tmplset->pkts[Proto_ARP];
        port = 1;
    } else if (port == 65536*3+2) {
        tmpl = &tmplset->pkts[Proto_IP];
        port = 1;
    }

    /* Create some shorter local variables to work with */
    px = tmpl->packet;
    offset_ip = tmpl->offset_ip;
    offset_tcp = tmpl->offset_tcp;
    ip_id = ip ^ port ^ seqno;

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
     * If this port has a payload to go with it, then copy
     * over that special payload. This is used heavily in
     * UDP
     */
    if (tmpl->payloads && tmpl->payloads[port]) {
        xsum = tmpl->payloads[port]->checksum;
        memcpy(&px[tmpl->offset_app],
               tmpl->payloads[port]->buf,
               tmpl->payloads[port]->length);
    } else
        xsum = 0;

    /*
     * Now do the checksum for the higher layer protocols
     */
    switch (tmpl->proto) {
    case Proto_TCP:
        px[offset_tcp+ 2] = (unsigned char)(port >> 8);
        px[offset_tcp+ 3] = (unsigned char)(port & 0xFF);
        px[offset_tcp+ 4] = (unsigned char)(seqno >> 24);
        px[offset_tcp+ 5] = (unsigned char)(seqno >> 16);
        px[offset_tcp+ 6] = (unsigned char)(seqno >>  8);
        px[offset_tcp+ 7] = (unsigned char)(seqno >>  0);

        xsum += (uint64_t)tmpl->checksum_tcp
                + (uint64_t)ip
                + (uint64_t)port
                + (uint64_t)seqno;
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = ~xsum;

        px[offset_tcp+16] = (unsigned char)(xsum >>  8);
        px[offset_tcp+17] = (unsigned char)(xsum >>  0);
        break;
    case Proto_UDP:
        px[offset_tcp+ 2] = (unsigned char)(port >> 8);
        px[offset_tcp+ 3] = (unsigned char)(port & 0xFF);
        xsum += (uint64_t)tmpl->checksum_tcp
                + (uint64_t)ip
                + (uint64_t)port
                + (uint64_t)seqno;
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = (xsum >> 16) + (xsum & 0xFFFF);
        xsum = ~xsum;
        px[offset_tcp+4] = (unsigned char)(xsum >>  8);
        px[offset_tcp+5] = (unsigned char)(xsum >>  0);
        break;
    case Proto_SCTP:
        break;
    case Proto_ICMP:
        break;
    case Proto_ARP:
        /* don't do any checksumming */
        break;
    case Proto_IP:
        /*TODO: this is just a place holder */
        break;
    }

    tmplset->px = tmpl->packet;
    tmplset->length = tmpl->length;
}


/***************************************************************************
 * Here we take a packet template, parse it, then make it easier to work
 * with.
 ***************************************************************************/
static void
_template_init(
    struct TemplatePacket *tmpl,
    unsigned ip,
    const unsigned char *mac_source,
    const unsigned char *mac_dest,
    const void *packet_bytes,
    size_t packet_size
    )
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
    tmpl->length = (unsigned)packet_size;
    
    tmpl->packet = (unsigned char *)malloc(tmpl->length);
    memcpy(tmpl->packet, packet_bytes, tmpl->length);
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
    tmpl->proto = Proto_IP;

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
void
template_packet_init(
    struct TemplateSet *templset,
    unsigned source_ip,
    const unsigned char *source_mac,
    const unsigned char *router_mac)
{
    /* [TCP] */
    _template_init( &templset->pkts[Proto_TCP],
                    source_ip, source_mac, router_mac,
                    default_tcp_template,
                    sizeof(default_tcp_template)-1
                    );
    /* [UDP] */
    _template_init( &templset->pkts[Proto_UDP],
                    source_ip, source_mac, router_mac,
                    default_udp_template,
                    sizeof(default_udp_template)-1
                    );

    /* [SCTP] */
    _template_init( &templset->pkts[Proto_SCTP],
                    source_ip, source_mac, router_mac,
                    default_sctp_template,
                    sizeof(default_sctp_template)-1
                    );
    /* [ICMP] */
    _template_init( &templset->pkts[Proto_ICMP],
                    source_ip, source_mac, router_mac,
                    default_icmp_template,
                    sizeof(default_icmp_template)-1
                    );

    /* [ARP] */
    _template_init( &templset->pkts[Proto_ICMP],
                    source_ip, source_mac, router_mac,
                    default_icmp_template,
                    sizeof(default_sctp_template)-1
                    );
}

/***************************************************************************
 ***************************************************************************/
unsigned
template_get_source_ip(struct TemplateSet *tmplset)
{
    struct TemplatePacket *tmpl = &tmplset->pkts[Proto_TCP];
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
template_get_source_port(struct TemplateSet *tmplset)
{
    struct TemplatePacket *tmpl = &tmplset->pkts[Proto_TCP];
    const unsigned char *px = tmpl->packet;
    unsigned offset = tmpl->offset_tcp;

    return px[offset+0]<<8 | px[offset+1]<<0;
}

/***************************************************************************
 * Overwrites the source-port field in the packet template.
 ***************************************************************************/
void
template_set_source_port(struct TemplateSet *tmplset, unsigned port)
{
    int i;

    for (i=0; i<2; i++) {
        struct TemplatePacket *tmpl = &tmplset->pkts[i];
        unsigned char *px = tmpl->packet;
        unsigned offset = tmpl->offset_tcp;

        px[offset+0] = (unsigned char)(port>>8);
        px[offset+1] = (unsigned char)(port>>0);
        tmpl->checksum_tcp = tcp_checksum(tmpl);
    }

}

/***************************************************************************
 * Overwrites the TTL of the packet
 ***************************************************************************/
void
template_set_ttl(struct TemplateSet *tmplset, unsigned ttl)
{
    int i;

    for (i=0; i<8; i++) {
        struct TemplatePacket *tmpl = &tmplset->pkts[i];
        unsigned char *px = tmpl->packet;
        unsigned offset = tmpl->offset_ip;

        px[offset+8] = (unsigned char)(ttl);
        tmpl->checksum_ip = tcp_checksum(tmpl);
    }
}


/***************************************************************************
 * Print packet info, when using nmap-style --packet-trace option
 ***************************************************************************/
void
template_packet_trace(struct TemplateSet *pkt_template, 
    unsigned ip, unsigned port, double timestamp_start)
{
    char from[32];
    char to[32];
    unsigned src_ip = template_get_source_ip(pkt_template);
    unsigned src_port = template_get_source_port(pkt_template);
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

/***************************************************************************
 ***************************************************************************/
int
template_selftest()
{
    struct TemplateSet tmplset[1];
    int failures = 0;

    template_packet_init(
            tmplset,
            0x12345678,
            (const unsigned char*)"\x00\x11\x22\x33\x44\x55",
            (const unsigned char*)"\x66\x55\x44\x33\x22\x11"
            );
    failures += tmplset->pkts[Proto_TCP].proto  != Proto_TCP;
    failures += tmplset->pkts[Proto_UDP].proto  != Proto_UDP;
    failures += tmplset->pkts[Proto_SCTP].proto != Proto_SCTP;
    failures += tmplset->pkts[Proto_ICMP].proto != Proto_ICMP;
    failures += tmplset->pkts[Proto_ARP].proto  != Proto_ARP;

    if (failures)
        fprintf(stderr, "template: failed\n");
    return failures;
}

