/*
    handle ARP

    Usage #1:
        At startup, we make a synchronous request for the local router.
        We'll wait several seconds for a response, but abort the program
        if we don't receive a response.

    Usage #2:
        While running, we'll need to respond to ARPs. That's because we
        may be bypassing the stack of the local machine with a "spoofed"
        IP address. Every so often, the local router may drop it's route
        entry and re-request our address.
*/
#include "rawsock.h"
#include "proto-arp.h"
#include "string_s.h"
#include "logger.h"
#include "pixie-timer.h"
#include "packet-queue.h"

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

/**
 * A structure representing the information parsed from an incoming
 * ARP packet. Note: unlike normal programming style, this isn't
 * overlayed on the incoming ARP header, but instead each field
 * is parsed one-by-one and converted into this internal structure.
 */
struct ARP_IncomingRequest
{
    unsigned is_valid;
    unsigned opcode;
    unsigned hardware_type;
    unsigned protocol_type;
    unsigned hardware_length;
    unsigned protocol_length;
    unsigned ip_src;
    unsigned ip_dst;
    const unsigned char *mac_src;
    const unsigned char *mac_dst;
};

/****************************************************************************
 ****************************************************************************/
static void
proto_arp_parse(struct ARP_IncomingRequest *arp,
                const unsigned char px[], unsigned offset, unsigned max)
{

    /*
     * parse the header
     */
    VERIFY_REMAINING(8);
    arp->is_valid = 0; /* not valid yet */

    arp->hardware_type = px[offset]<<8 | px[offset+1];
    arp->protocol_type = px[offset+2]<<8 | px[offset+3];
    arp->hardware_length = px[offset+4];
    arp->protocol_length = px[offset+5];
    arp->opcode = px[offset+6]<<8 | px[offset+7];
    offset += 8;

    /* We only support IPv4 and Ethernet addresses */
    if (arp->protocol_length != 4 && arp->hardware_length != 6)
        return;
    if (arp->protocol_type != 0x0800)
        return;
    if (arp->hardware_type != 1 && arp->hardware_type != 6)
        return;

    /*
     * parse the addresses
     */
    VERIFY_REMAINING(2 * arp->hardware_length + 2 * arp->protocol_length);
    arp->mac_src = px+offset;
    offset += arp->hardware_length;

    arp->ip_src = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
    offset += arp->protocol_length;

    arp->mac_dst = px+offset;
    offset += arp->hardware_length;

    arp->ip_dst = px[offset+0]<<24 | px[offset+1]<<16 | px[offset+2]<<8 | px[offset+3];
    //offset += arp->protocol_length;

    arp->is_valid = 1;
}

#include "rawsock-adapter.h"

/****************************************************************************
 * Resolve the IP address into a MAC address. Do this synchronously, meaning,
 * we'll stop and wait for the response. This is done at program startup,
 * but not during then normal asynchronous operation during the scan.
 ****************************************************************************/
int
arp_resolve_sync(struct Adapter *adapter,
    unsigned my_ipv4, const unsigned char *my_mac_address,
    unsigned your_ipv4, unsigned char *your_mac_address)
{
    unsigned char xarp_packet[64];
    unsigned char *arp_packet = &xarp_packet[0];
    unsigned i;
    time_t start;
    unsigned is_arp_notice_given = 0;
    struct ARP_IncomingRequest response;
    int is_delay_reported = 0;

    /*
     * [KLUDGE]
     *  If this is a VPN connection with raw IPv4, then we don't do any
     *  ARPing, just return immediately. In other words, there's nothing
     *  here to ARP
     */
    if (rawsock_datalink(adapter) == 12) {
        memcpy(your_mac_address, "\0\0\0\0\0\2", 6);
        return 0; /* success */
    }

    memset(&response, 0, sizeof(response));

    /* zero out bytes in packet to avoid leaking stuff in the padding
     * (ARP is 42 byte packet, Ethernet is 60 byte minimum) */
    memset(arp_packet, 0, sizeof(xarp_packet));

    /*
     * Create the request packet
     */
    memcpy(arp_packet +  0, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
    memcpy(arp_packet +  6, my_mac_address, 6);
    
    if (adapter->is_vlan) {
        memcpy(arp_packet + 12, "\x81\x00", 2);
        arp_packet[14] = (unsigned char)(adapter->vlan_id>>8);
        arp_packet[15] = (unsigned char)(adapter->vlan_id&0xFF);
        arp_packet += 4;
    }
    
    memcpy(arp_packet + 12, "\x08\x06", 2);

    
    memcpy(arp_packet + 14,
            "\x00\x01" /* hardware = Ethernet */
            "\x08\x00" /* protocol = IPv4 */
            "\x06\x04" /* MAC length = 6, IPv4 length = 4 */
            "\x00\x01" /* opcode = request */
            , 8);

    memcpy(arp_packet + 22, my_mac_address, 6);
    arp_packet[28] = (unsigned char)(my_ipv4 >> 24);
    arp_packet[29] = (unsigned char)(my_ipv4 >> 16);
    arp_packet[30] = (unsigned char)(my_ipv4 >>  8);
    arp_packet[31] = (unsigned char)(my_ipv4 >>  0);

    memcpy(arp_packet + 32, "\x00\x00\x00\x00\x00\x00", 6);
    arp_packet[38] = (unsigned char)(your_ipv4 >> 24);
    arp_packet[39] = (unsigned char)(your_ipv4 >> 16);
    arp_packet[40] = (unsigned char)(your_ipv4 >>  8);
    arp_packet[41] = (unsigned char)(your_ipv4 >>  0);


    /* Kludge: handle VLNA header if it exists. This is probably
     * the wrong way to handle this. */
    if (adapter->is_vlan)
        arp_packet -= 4;
    
    /*
     * Now loop for a few seconds looking for the response
     */
    rawsock_send_packet(adapter, arp_packet, 60, 1);
    start = time(0);
    i = 0;
    for (;;) {
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;

        if (time(0) != start) {
            start = time(0);
            rawsock_send_packet(adapter, arp_packet, 60, 1);
            if (i++ >= 10)
                break; /* timeout */

            /* It's taking too long, so notify the user */
            if (!is_delay_reported) {
                LOG(0, "...arping router MAC address...\n");
                is_delay_reported = 1;
            }
        }

        /* If we aren't getting a response back to our ARP, then print a
         * status message */
        if (time(0) > start+1 && !is_arp_notice_given) {
            fprintf(stderr, "ARPing local router %u.%u.%u.%u\n",
                (unsigned char)(your_ipv4>>24),
                (unsigned char)(your_ipv4>>16),
                (unsigned char)(your_ipv4>> 8),
                (unsigned char)(your_ipv4>> 0)
                );
            is_arp_notice_given = 1;
        }

        err =  rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;

        if (adapter->is_vlan && px[17] != 6)
            continue;
        if (!adapter->is_vlan && px[13] != 6)
            continue;


        /*
         * Parse the response as an ARP packet
         */
        if (adapter->is_vlan)
            proto_arp_parse(&response, px, 18, length);
        else
            proto_arp_parse(&response, px, 14, length);

        /* Is this an ARP packet? */
        if (!response.is_valid) {
            LOG(2, "arp: etype=0x%04x, not ARP\n", px[12]*256 + px[13]);
            continue;
        }

        /* Is this an ARP "reply"? */
        if (response.opcode != 2) {
            LOG(2, "arp: opcode=%u, not reply(2)\n", response.opcode);
            continue;
        }

        /* Is this response directed at us? */
        if (response.ip_dst != my_ipv4) {
            LOG(2, "arp: dst=%08x, not my ip 0x%08x\n", response.ip_dst, my_ipv4);
            continue;
        }
        if (memcmp(response.mac_dst, my_mac_address, 6) != 0)
            continue;

        /* Is this the droid we are looking for? */
        if (response.ip_src != your_ipv4) {
            LOG(2, "arp: target=%08x, not desired 0x%08x\n", response.ip_src, your_ipv4);
            continue;
        }

        /*
         * GOT IT!
         *  we've got a valid response, so save the results and
         *  return.
         */
        memcpy(your_mac_address, response.mac_src, 6);
        return 0;
    }

    return 1;
}

/****************************************************************************
 ****************************************************************************/
int
arp_response(
    unsigned my_ip, const unsigned char *my_mac,
    const unsigned char *px, unsigned length,
    PACKET_QUEUE *packet_buffers,
    PACKET_QUEUE *transmit_queue)
{
    struct PacketBuffer *response = 0;
    struct ARP_IncomingRequest request;
    int err;

    memset(&request, 0, sizeof(request));


    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    for (err=1; err; ) {
        err = rte_ring_sc_dequeue(packet_buffers, (void**)&response);
        if (err != 0) {
            //LOG(0, "packet buffers empty (should be impossible)\n");
            pixie_usleep(100);
        }
    }
    if (response == NULL)
        return -1; /* just to supress warnings */

    /* ARP packets are too short, so increase the packet size to
     * the Ethernet minimum */
    response->length = 60;

    /* Fill the padded area with zeroes to avoid leaking data */
    memset(response->px, 0, response->length);

    /*
     * Parse the response as an ARP packet
     */
    proto_arp_parse(&request, px, 14, length);

    /* Is this an ARP packet? */
    if (!request.is_valid) {
        LOG(2, "arp: etype=0x%04x, not ARP\n", px[12]*256 + px[13]);
        return -1;
    }

    /* Is this an ARP "request"? */
    if (request.opcode != 1) {
        LOG(2, "arp: opcode=%u, not request(1)\n", request.opcode);
        return -1;
    }

    /* Is this response directed at us? */
    if (request.ip_dst != my_ip) {
        LOG(2, "arp: dst=%08x, not my ip 0x%08x\n", request.ip_dst, my_ip);
        return -1;
    }

    /*
     * Create the response packet
     */
    memcpy(response->px +  0, request.mac_src, 6);
    memcpy(response->px +  6, my_mac, 6);
    memcpy(response->px + 12, "\x08\x06", 2);

    memcpy(response->px + 14,
            "\x00\x01" /* hardware = Ethernet */
            "\x08\x00" /* protocol = IPv4 */
            "\x06\x04" /* MAC length = 6, IPv4 length = 4 */
            "\x00\x02" /* opcode = reply(2) */
            , 8);

    memcpy(response->px + 22, my_mac, 6);
    response->px[28] = (unsigned char)(my_ip >> 24);
    response->px[29] = (unsigned char)(my_ip >> 16);
    response->px[30] = (unsigned char)(my_ip >>  8);
    response->px[31] = (unsigned char)(my_ip >>  0);

    memcpy(response->px + 32, request.mac_src, 6);
    response->px[38] = (unsigned char)(request.ip_src >> 24);
    response->px[39] = (unsigned char)(request.ip_src >> 16);
    response->px[40] = (unsigned char)(request.ip_src >>  8);
    response->px[41] = (unsigned char)(request.ip_src >>  0);


    /*
     * Now queue the packet up for transmission
     */
    for (err=1; err; ) {
        err = rte_ring_sp_enqueue(transmit_queue, response);
        if (err) {
            LOG(0, "transmit queue full (should be impossible)\n");
            pixie_usleep(10000000);
        }
    }

    return 0;
}
