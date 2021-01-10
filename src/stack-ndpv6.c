#include "stack-ndpv6.h"
#include "proto-preprocess.h"
#include "stack-src.h"
#include "util-checksum.h"
#include <string.h>



static inline void _append(unsigned char *buf, size_t *r_offset, size_t max, unsigned x)
{
    if (*r_offset >= max)
        return;
    buf[(*r_offset)++] = (unsigned char)x;
}
static inline void _append_bytes(unsigned char *buf, size_t *r_offset, size_t max, const unsigned char *bytes, size_t len)
{
    if (*r_offset + len >= max)
        return;
    memcpy(buf + *r_offset, bytes, len);
    *r_offset += len;
}

/**
 * Handle the IPv6 Neighbor Solicitation request.
 * This happens after we've transmitted a packet, a response is on
 * it's way back, and the router needs to give us the response
 * packet. The router sends us a soliticiation, like an ARP request, 
 * to which we must respond.
 */
int
stack_handle_neighbor_solicitation(struct stack_t *stack, struct PreprocessedInfo *parsed,  const unsigned char *px, size_t length)
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

int
stack_handle_ndpv6_neighbor_notification(
            ipaddress ip_me, ipaddress ip_them,
            const unsigned char *buf, size_t length,
            const unsigned char *mac_them,
            struct stack_t *stack)
{
    return 0;
}
