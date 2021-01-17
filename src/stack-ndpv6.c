#include "stack-ndpv6.h"
#include "proto-preprocess.h"
#include "stack-src.h"
#include "util-checksum.h"
#include "rawsock-adapter.h"
#include "rawsock.h"
#include <string.h>



static inline void _append(unsigned char *buf, size_t *r_offset, size_t max, unsigned x)
{
    if (*r_offset >= max)
        return;
    buf[(*r_offset)++] = (unsigned char)x;
}
static inline void _append_bytes(unsigned char *buf, size_t *r_offset, size_t max, const void *v_bytes, size_t len)
{
    const unsigned char *bytes = (const unsigned char *)v_bytes;
    if (*r_offset + len >= max)
        return;
    memcpy(buf + *r_offset, bytes, len);
    *r_offset += len;
}

static inline void
_append_short(unsigned char *buf, size_t *offset, size_t max, unsigned num)
{
    if (2 > max - *offset) {
        *offset = max;
        return;
    }
    buf[(*offset)++] = (unsigned char)(num>>8);
    buf[(*offset)++] = (unsigned char)(num & 0xFF);
}

static inline unsigned
_read_byte(const unsigned char *buf, size_t *offset, size_t max)
{
    if (*offset < max) {
        return buf[(*offset)++];
    } else
        return (unsigned)~0;
}
static inline unsigned
_read_short(const unsigned char *buf, size_t *offset, size_t max)
{
    if (*offset + 1  < max) {
        unsigned result;
        result = buf[(*offset)++] << 8;
        result |= buf[(*offset)++];
        return result;
    } else
        return (unsigned)~0;
}

static inline unsigned
_read_number(const unsigned char *buf, size_t *offset, size_t max)
{
    if (*offset + 1  < max) {
        unsigned result;
        result = buf[(*offset)++] << 24;
        result |= buf[(*offset)++] << 16;
        result |= buf[(*offset)++] << 8;
        result |= buf[(*offset)++];
        return result;
    } else
        return (unsigned)~0;
}


/**
 * Handle the IPv6 Neighbor Solicitation request.
 * This happens after we've transmitted a packet, a response is on
 * it's way back, and the router needs to give us the response
 * packet. The router sends us a soliticiation, like an ARP request, 
 * to which we must respond.
 */
int
stack_ndpv6_incoming_request(struct stack_t *stack, struct PreprocessedInfo *parsed,  const unsigned char *px, size_t length)
{
    struct PacketBuffer *response = 0;
    size_t offset;
    size_t remaining;
    ipaddress target_ip;
    const unsigned char *target_ip_buf;
    const unsigned char *target_mac_buf = stack->mac_address;
    unsigned xsum;
    unsigned char *buf2;
    static const size_t max = sizeof(response->px);
    size_t offset_ip = parsed->ip_offset;
    size_t offset_ip_src = offset_ip + 8; /* offset in packet to the source IPv6 address */
    size_t offset_ip_dst = offset_ip + 24;
    size_t offset_icmpv6 = parsed->transport_offset;
    
    /* Verify it's a "Neighbor Solitication" opcode */
    if (parsed->opcode != 135)
        return -1;

    /* Make sure there's at least a full header */
    offset = parsed->transport_offset;
    remaining = length - offset;
    if (remaining < 24)
        return -1;

    /* Make sure it's looking for our own address */
    target_ip_buf = px + offset + 8;
    target_ip.version = 6;
    target_ip.ipv6 = ipv6address_from_bytes(target_ip_buf);
    if (!is_my_ip(stack->src, target_ip))
        return -1;

    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    response = stack_get_packetbuffer(stack);
    if (response == NULL)
        return -1; 


    /* Use the request packet as a template for the response */
    memcpy(response->px, px, length);
    buf2 = response->px;
    
    /* Set the destination MAC address and destination IPv6 adress*/
    memcpy(buf2 + 0, px + 6, 6);
    memcpy(buf2 + offset_ip_dst, px + offset_ip_src, 16);

    /* Set the source MAC address and source IPv6 address */
    memcpy(buf2 + offset_ip_src, target_ip_buf, 16);
    memcpy(buf2 + 6, target_mac_buf, 6);
    
    /* Format the response */
    _append(buf2, &offset, max, 136); /* type */
    _append(buf2, &offset, max, 0); /* code */
    _append(buf2, &offset, max, 0); /*checksum[hi] */
    _append(buf2, &offset, max, 0); /*checksum[lo] */
    _append(buf2, &offset, max, 0x60); /* flags*/ 
    _append(buf2, &offset, max, 0);
    _append(buf2, &offset, max, 0);
    _append(buf2, &offset, max, 0);
    _append_bytes(buf2, &offset, max, target_ip_buf, 16);
    _append(buf2, &offset, max, 2);
    _append(buf2, &offset, max, 1);
    _append_bytes(buf2, &offset, max, target_mac_buf, 6);

    xsum = checksum_ipv6(   buf2 + offset_ip_src, 
                            buf2 + offset_ip_dst, 
                            58,  
                            offset - offset_icmpv6, 
                            buf2 +offset_icmpv6);
    buf2[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf2[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);

    /* Transmit the packet-buffer */
    response->length = offset;
    stack_transmit_packetbuffer(stack, response);
    return 0;
}



static int 
_extract_router_advertisement(
    const unsigned char *buf, 
    size_t length,
    struct PreprocessedInfo *parsed, 
    ipv6address *router_ip, 
    unsigned char *router_mac)
{
    unsigned flags;
    size_t offset;

    if (parsed->ip_version != 6)
        return 1;
    
    if (parsed->ip_protocol != 58)
        return 1;
    offset = parsed->transport_offset;
    
    /* type = Router Advertisment */
    if (_read_byte(buf, &offset, length) != 134)
        return 1;

    /* code = 0 */
    if (_read_byte(buf, &offset, length) != 0)
        return 1;

    /* checksum */
    _read_short(buf, &offset, length);

    /* hop limit */
    _read_byte(buf, &offset, length);

    /* flags */
    flags = _read_byte(buf, &offset, length);

    /* router life time */
    _read_short(buf, &offset, length);

    /* reachable time */
    _read_number(buf, &offset, length);

    /* retrans timer */
    _read_number(buf, &offset, length);

    while (offset + 8 <= length) {
        unsigned type = buf[offset + 0];
        size_t len2 = buf[offset + 1] * 8;
        size_t off2 = 0;
        const unsigned char *buf2 = buf + offset;

        switch (type) {
        case 1:
            if (len2 == 8) {
                memcpy(router_mac, buf2 + 2, 6);
                return 0;
            }
            break;
        }

        offset += len2;
    }

    memcpy(router_mac, parsed->mac_src, 6);
    return 0;
}

/****************************************************************************
 ****************************************************************************/
int
stack_ndpv6_resolve(struct Adapter *adapter, 
    const unsigned char *my_mac_address, 
    unsigned char *router_mac)
{
    unsigned char buf[128];
    size_t max = sizeof(buf);
    size_t offset = 0;
    unsigned i;
    time_t start;
    unsigned is_arp_notice_given = 0;
    int is_delay_reported = 0;
    size_t offset_ip;
    size_t offset_ip_src;
    size_t offset_ip_dst;
    size_t offset_icmpv6;
    unsigned xsum;
    struct PreprocessedInfo parsed = {0};

    /*
     * [KLUDGE]
     *  If this is a VPN connection, then there is no answer
     */
    if (stack_if_datalink(adapter) == 12) {
        memcpy(router_mac, "\0\0\0\0\0\2", 6);
        return 0; /* success */
    }

    
    /*
     * Ethernet header
     */
    _append_bytes(buf, &offset, max, "\x33\x33\x00\x00\x00\x02", 6);
    _append_bytes(buf, &offset, max, my_mac_address, 6);
    
    if (adapter->is_vlan) {
        _append_short(buf, &offset, max, 0x8100);
        _append_short(buf, &offset, max, adapter->vlan_id);
    }
    _append_short(buf, &offset, max, 0x86dd);

    /*
     * Create IPv6 header
     */
    offset_ip = offset;
    _append(buf, &offset, max, 0x60); /* version = 6 */
    _append(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0); /* length = 0 */
    _append(buf, &offset, max, 58); /* proto = ICMPv6 */
    _append(buf, &offset, max, 255); /*hop limit = 255 */

    /* Link local source address based on MAC address */
    offset_ip_src = offset;
    _append_short(buf, &offset, max, 0xfe80);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_bytes(buf, &offset, max, my_mac_address, 3);
    buf[offset-3] |= 2;
    _append_short(buf, &offset, max, 0xfffe);
    _append_bytes(buf, &offset, max, my_mac_address+3, 3);

    /* All-routers link local address */
    offset_ip_dst = offset;
    _append_short(buf, &offset, max, 0xff02);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 2);
    
    /* ICMPv6 Router Solicitation */
    offset_icmpv6 = offset;
    _append(buf, &offset, max, 133); /* type = Router Solicitation */
    _append(buf, &offset, max, 0);
    _append_short(buf, &offset, max, 0); /* checksum = 0 (for the moment) */
    _append_short(buf, &offset, max, 0); /* reserved */
    _append_short(buf, &offset, max, 0); /* reserved */
    _append(buf, &offset, max, 1); /* option = source link layer address */
    _append(buf, &offset, max, 1); /* length = 2 + 6 / 8*/
    _append_bytes(buf, &offset, max, my_mac_address, 6);
    
    buf[offset_ip + 4] = (unsigned char)( (offset - offset_icmpv6) >> 8);
    buf[offset_ip + 5] = (unsigned char)( (offset - offset_icmpv6) & 0xFF);
    xsum = checksum_ipv6(   buf + offset_ip_src, 
                            buf + offset_ip_dst, 
                            58,  
                            offset - offset_icmpv6, 
                            buf + offset_icmpv6);
    buf[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);
    rawsock_send_packet(adapter, buf, (unsigned)offset, 1);

    /*
     * Send a shorter version
     */
    offset -= 8;
    buf[offset_ip + 4] = (unsigned char)( (offset - offset_icmpv6) >> 8);
    buf[offset_ip + 5] = (unsigned char)( (offset - offset_icmpv6) & 0xFF);
    xsum = checksum_ipv6(   buf + offset_ip_src, 
                            buf + offset_ip_dst, 
                            58,  
                            offset - offset_icmpv6, 
                            buf + offset_icmpv6);
    buf[offset_icmpv6 + 2] = (unsigned char)(xsum >> 8);
    buf[offset_icmpv6 + 3] = (unsigned char)(xsum >> 0);
    rawsock_send_packet(adapter, buf, (unsigned)offset, 1);
    

    start = time(0);
    i = 0;
    for (;;) {
        unsigned length2;
        unsigned secs;
        unsigned usecs;
        const unsigned char *buf2;
        int err;
        ipv6address router_ip;

        /* Resend every so often */
        if (time(0) != start) {
            start = time(0);
            rawsock_send_packet(adapter, buf, (unsigned)offset, 1);
            if (i++ >= 10)
                break; /* timeout */

            /* It's taking too long, so notify the user */
            if (!is_delay_reported) {
                fprintf(stderr, "[ ] resolving IPv6 router MAC address (may take some time)...\n");
                is_delay_reported = 1;
            }
        }

        /* If we aren't getting a response back to our ARP, then print a
         * status message */
        if (time(0) > start+1 && !is_arp_notice_given) {
            fprintf(stderr, "[ ] resolving local IPv6 router\n");
            is_arp_notice_given = 1;
        }

        err =  rawsock_recv_packet(
                    adapter,
                    &length2,
                    &secs,
                    &usecs,
                    &buf2);

        if (err != 0)
            continue;

        /*
         * Parse the packet
         */
        err = preprocess_frame(buf2, length2, 1, &parsed);
        if (err != 1)
            continue;
        if (parsed.found != FOUND_NDPv6)
            continue;
        err = _extract_router_advertisement(buf2, length2, &parsed, &router_ip, router_mac);
        if (err)
            continue;
        return 0;
    }

    return 1;
}
