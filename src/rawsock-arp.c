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
#include "string_s.h"
#include "logger.h"

#define VERIFY_REMAINING(n) if (offset+(n) > max) return;

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
void
proto_arp_parse(struct ARP_IncomingRequest *arp, const unsigned char px[], unsigned offset, unsigned max)
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
	offset += arp->protocol_length;

    arp->is_valid = 1;
}


/****************************************************************************
 ****************************************************************************/
int arp_resolve_sync(struct Adapter *adapter, 
    unsigned my_ipv4, const unsigned char *my_mac_address,
    unsigned your_ipv4, unsigned char *your_mac_address)
{
    unsigned char arp_packet[64];
    unsigned i;
    time_t start;
    struct ARP_IncomingRequest response;

    memset(&response, 0, sizeof(response));

    /* zero out bytes in packet to avoid leaking stuff in the padding
     * (ARP is 42 byte packet, Ethernet is 60 byte minimum) */
    memset(arp_packet, 0, sizeof(arp_packet));

    /*
     * Create the request packet
     */
    memcpy(arp_packet +  0, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
    memcpy(arp_packet +  6, my_mac_address, 6);
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


    /*
     * Now loop for a few seconds looking for the response
     */
    rawsock_send_packet(adapter, arp_packet, 60);
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
            rawsock_send_packet(adapter, arp_packet, 60);
            if (i++ >= 10)
                break; /* timeout */
        }

        err =  rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;

        if (px[13] != 6)
            continue;


        /*
         * Parse the response as an ARP packet
         */
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
int arp_response(struct Adapter *adapter, unsigned my_ip, const unsigned char *my_mac,
    const unsigned char *px, unsigned length)
{
    unsigned char arp_packet[64];
    struct ARP_IncomingRequest request;

    memset(&request, 0, sizeof(request));

    /* zero out bytes in packet to avoid leaking stuff */
    memset(arp_packet, 0, sizeof(arp_packet));


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
    memcpy(arp_packet +  0, request.mac_src, 6);
    memcpy(arp_packet +  6, my_mac, 6);
    memcpy(arp_packet + 12, "\x08\x06", 2);

    memcpy(arp_packet + 14, 
            "\x00\x01" /* hardware = Ethernet */
            "\x08\x00" /* protocol = IPv4 */
            "\x06\x04" /* MAC length = 6, IPv4 length = 4 */
            "\x00\x02" /* opcode = reply(2) */
            , 8);

    memcpy(arp_packet + 22, my_mac, 6);
    arp_packet[28] = (unsigned char)(my_ip >> 24);
    arp_packet[29] = (unsigned char)(my_ip >> 16);
    arp_packet[30] = (unsigned char)(my_ip >>  8);
    arp_packet[31] = (unsigned char)(my_ip >>  0);
    
    memcpy(arp_packet + 32, request.mac_src, 6);
    arp_packet[38] = (unsigned char)(request.ip_src >> 24);
    arp_packet[39] = (unsigned char)(request.ip_src >> 16);
    arp_packet[40] = (unsigned char)(request.ip_src >>  8);
    arp_packet[41] = (unsigned char)(request.ip_src >>  0);


    /*
     * Now transmit the packet
     */
    rawsock_send_packet(adapter, arp_packet, 60);

    return 0;
}
