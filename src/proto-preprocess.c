/* Copyright: (c) 2009-2010 by Robert David Graham
** License: This code is private to the author, and you do not
** have a license to run it, or own a copy, unless given
** a license personally by the author. This is
** explained in the LICENSE file at the root of the project.
**/
/****************************************************************************

        PREPROCESS PACKETS

  This function parses the entire TCP/IP stack looking for IP addresses and
  ports. The intent is that this is the minimal parsing necessary to find
  address/port information. While it does basic checking (to confirm length
  information, for example), it does not do more extensive checking (like
  whether the checksum is correct).

 ****************************************************************************/
#include "proto-preprocess.h"
#include <stdio.h>
#include <assert.h>

#define ex32be(px)  (   *((unsigned char*)(px)+0)<<24 \
                    |   *((unsigned char*)(px)+1)<<16 \
                    |   *((unsigned char*)(px)+2)<< 8 \
                    |   *((unsigned char*)(px)+3)<< 0 )
#define ex32le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 \
                    |   *((unsigned char*)(px)+3)<<24 )
#define ex16be(px)  (   *((unsigned char*)(px)+0)<< 8 \
                    |   *((unsigned char*)(px)+1)<< 0 )
#define ex16le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 )

#define ex24be(px)  (   *((unsigned char*)(px)+0)<<16 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<< 0 )
#define ex24le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 )

#define ex64be(px)  ( (((uint64_t)ex32be(px))<<32L) + ((uint64_t)ex32be((px)+4)) )
#define ex64le(px)  ( ((uint64_t)ex32be(px)) + (((uint64_t)ex32be((px)+4))<<32L) )

/**
 *  Call this frequently while parsing through the headers to make sure that
 *  we don't go past the end of a packet. Remember that 1 byte past the
 *  end can cause a crash.
 **/
#define VERIFY_REMAINING(n,f) if (offset+(n) > length) return 0; else {info->found_offset=offset; info->found=f;}


/****************************************************************************
 ****************************************************************************/
unsigned
preprocess_frame(const unsigned char *px, unsigned length, unsigned link_type,
                 struct PreprocessedInfo *info)
{
    unsigned offset = 0;
    unsigned ethertype = 0;

    info->transport_offset = 0;
    info->found = FOUND_NOTHING;
    info->found_offset = 0;

    if (link_type != 1)
        goto parse_linktype;

parse_ethernet:
    VERIFY_REMAINING(14, FOUND_ETHERNET);

    info->mac_dst = px+offset+0;
    info->mac_src = px+offset+6;
    ethertype = ex16be(px+offset+12);
    offset += 14;
    if (ethertype < 2000)
        goto parse_llc;
    if (ethertype != 0x0800)
        goto parse_ethertype;

parse_ipv4:
    {
        unsigned header_length;
        unsigned flags;
        unsigned fragment_offset;
        unsigned total_length;

        info->ip_offset = offset;
        VERIFY_REMAINING(20, FOUND_IPV4);

        /* Check version */
        if ((px[offset]>>4) != 4)
            return 0; /* not IPv4 or corrupt */

        /* Check header length */
        header_length = (px[offset] & 0x0F) * 4;
        VERIFY_REMAINING(header_length, FOUND_IPV4);

        /*TODO: verify checksum */

        /* Check for fragmentation */
        flags = px[offset+6]&0xE0;
        fragment_offset = (ex16be(px+offset+6) & 0x3FFF) << 3;
        if (fragment_offset != 0 || (flags & 0x20))
            return 0; /* fragmented */

        /* Check for total-length */
        total_length = ex16be(px+offset+2);
        VERIFY_REMAINING(total_length, FOUND_IPV4);
        if (total_length < header_length)
            return 0; /* weird corruption */
        length = offset + total_length; /* reduce the max length */


        /* Save off pseudo header for checksum calculation */
        info->ip_version = (px[offset]>>4)&0xF;
        info->ip_src = px+offset+12;
        info->ip_dst = px+offset+16;
        info->ip_ttl = px[offset+8];
        info->ip_protocol = px[offset+9];
        info->ip_length = total_length;
        if (info->ip_version != 4)
            return 0;

        /* next protocol */
        offset += header_length;
        info->transport_offset = offset;
        switch (info->ip_protocol) {
        case   1: goto parse_icmp;
        case   6: goto parse_tcp;
        case  17: goto parse_udp;
        case 132: goto parse_sctp;
        default: return 0; /* todo: should add more protocols, like ICMP */
        }
    }

parse_tcp:
    {
        unsigned tcp_length;
        VERIFY_REMAINING(20, FOUND_TCP);
        tcp_length = px[offset + 12]>>2;
        VERIFY_REMAINING(tcp_length, FOUND_TCP);
        info->port_src = ex16be(px+offset+0);
        info->port_dst = ex16be(px+offset+2);
        info->app_offset = offset + tcp_length;
        info->app_length = length - info->app_offset;
        info->transport_length = length - info->transport_offset;
        assert(info->app_length < 2000);

        return 1;
    }

parse_udp:
    {
        VERIFY_REMAINING(8, FOUND_UDP);

        info->port_src = ex16be(px+offset+0);
        info->port_dst = ex16be(px+offset+2);
        offset += 8;
        info->app_offset = offset;
        info->app_length = length - info->app_offset;
        assert(info->app_length < 2000);

        if (info->port_dst == 53 || info->port_src == 53) {
            goto parse_dns;
        }
        return 1;
    }

parse_icmp:
    {
        VERIFY_REMAINING(4, FOUND_ICMP);
        info->port_src = px[offset+0];
        info->port_dst = px[offset+1];
        return 1;
    }

parse_sctp:
    {
        VERIFY_REMAINING(12, FOUND_SCTP);
        info->port_src = ex16be(px+offset+0);
        info->port_dst = ex16be(px+offset+2);
        info->app_offset = offset + 12;
        info->app_length = length - info->app_offset;
        assert(info->app_length < 2000);
        return 1;
    }

parse_dns:
    {
        VERIFY_REMAINING(8, FOUND_DNS);
        return 1;
    }

parse_ipv6:
    {
        unsigned payload_length;

        VERIFY_REMAINING(40, FOUND_IPV6);

        /* Check version */
        if ((px[offset]>>4) != 6)
            return 0; /* not IPv4 or corrupt */

        /* Payload length */
        payload_length = ex16be(px+offset+4);
        VERIFY_REMAINING(40+payload_length, FOUND_IPV6);
        if (length > offset + 40 + payload_length)
            length = offset + 40 + payload_length;

        /* Save off pseudo header for checksum calculation */
        info->ip_version = (px[offset]>>4)&0xF;
        info->ip_src = px+offset+8;
        info->ip_dst = px+offset+8+16;
        info->ip_protocol = px[offset+6];

        /* next protocol */
        offset += 40;

parse_ipv6_next:
        switch (info->ip_protocol) {
        case 0: goto parse_ipv6_hop_by_hop;
        case 6: goto parse_tcp;
        case 17: goto parse_udp;
        case 58: goto parse_icmpv6;
        case 0x2c: /* IPv6 fragmetn */
            return 0;
        default:
            //printf("***** test me ******\n");
            return 0; /* todo: should add more protocols, like ICMP */
        }
    }

parse_ipv6_hop_by_hop:
    {
        unsigned len;

        VERIFY_REMAINING(8, FOUND_IPV6_HOP);
        info->ip_protocol = px[offset];
        len = px[offset+1] + 8;

        VERIFY_REMAINING(len, FOUND_IPV6_HOP);
        offset += len;
    }
    goto parse_ipv6_next;

parse_icmpv6:
    return 1;

parse_vlan8021q:
    VERIFY_REMAINING(4, FOUND_8021Q);
    ethertype = ex16be(px+offset+2);
    offset += 4;
    goto parse_ethertype;

parse_vlanmpls:
    /* MULTILEVEL:
     * Regress: wireshark/mpls-twolevel.cap(9)
     * There can be multiple layers of MPLS tags. This is marked by a
     * flag in the header whether the current header is the "final"
     * header in the stack*/
    while (offset + 4 < length && !(px[offset+2] & 1))
        offset += 4;

    VERIFY_REMAINING(4, FOUND_MPLS);
    offset += 4;

    if (px[offset-4+2]&1) {
        goto parse_ipv4;
    } else
        return 0;



wifi_data:
    {
        unsigned flag;
        VERIFY_REMAINING(24, FOUND_WIFI_DATA);

        flag = px[offset];

        switch (px[offset+1]&0x03) {
        case 0:
        case 2:
            info->mac_dst = px+offset+4;
            info->mac_bss = px+offset+10;
            info->mac_src = px+offset+16;
            break;
        case 1:
            info->mac_bss = px+offset+4;
            info->mac_src = px+offset+10;
            info->mac_dst = px+offset+16;
            break;
        case 3:
            info->mac_bss = (const unsigned char*)"\0\0\0\0\0\0";
            info->mac_dst = px+offset+16;
            info->mac_src = px+offset+24;
            offset += 6;
            break;
        }


        if ((px[offset+1]&0x04) != 0 || (px[offset+22]&0xF) != 0)
            return 0;

        offset += 24;
        if (flag == 0x88) {
            offset += 2;
        }

        goto parse_llc;
    }

parse_wifi:
    VERIFY_REMAINING(2, FOUND_WIFI);
    switch (px[offset]) {
    case 0x08:
    case 0x88: /* QoS data */
        if (px[1] & 0x40)
            return 0;
        goto wifi_data;
        break;
    default:
        return 0;
    }

parse_radiotap_header:
    /* Radiotap headers for WiFi. http://www.radiotap.org/
     *
     *   struct ieee80211_radiotap_header {
     *           u_int8_t        it_version;     // set to 0
     *           u_int8_t        it_pad;
     *           u_int16_t       it_len;         // entire length
     *           u_int32_t       it_present;     // fields present
     *   };
     */
    {
        unsigned header_length;
        unsigned features;

        VERIFY_REMAINING(8, FOUND_RADIOTAP);
        if (px[offset] != 0)
            return 0;
        header_length = ex16le(px+offset+2);
        features = ex32le(px+offset+4);

        VERIFY_REMAINING(header_length, FOUND_RADIOTAP);

        /* If FCS is present at the end of the packet, then change
         * the length to remove it */
        if (features & 0x4000) {
            unsigned fcs_header = ex32le(px+offset+header_length-4);
            unsigned fcs_frame = ex32le(px+length-4);
            if (fcs_header == fcs_frame)
                length -= 4;
            VERIFY_REMAINING(header_length, FOUND_RADIOTAP);
        }
        offset += header_length;
        goto parse_wifi;
    }


parse_prism_header:
    /* DLT_PRISM_HEADER */
    /* This was original created to handle Prism II cards, but now we see this
     * from other cards as well, such as the 'madwifi' drivers using Atheros
     * chipsets.
     *
     * This starts with a "TLV" format, a 4-byte little-endian tag, followed by
     * a 4-byte little-endian length. This TLV should contain the entire Prism
     * header, after which we'll find the real header. Therefore, we should just
     * be able to parse the 'length', and skip that many bytes. I'm told it's more
     * complicated than that, but it seems to work right now, so I'm keeping it
     * this way.
     */
    {
        unsigned header_length;
        VERIFY_REMAINING(8, FOUND_PRISM);

        if (ex32le(px+offset+0) != 0x00000044)
            return 0;
        header_length = ex32le(px+offset+4);
        if (header_length > 0xFFFFF)
            return 0;
        VERIFY_REMAINING(header_length, FOUND_PRISM);
        offset += header_length;
        goto parse_wifi;
    }

parse_llc:
    {
        unsigned oui;

        VERIFY_REMAINING(3, FOUND_LLC);

        switch (ex24be(px+offset)) {
        case 0x0000aa: offset += 2; goto parse_llc;
        default: return 0;
        case 0xaaaa03: break;
        }

        offset +=3 ;

        VERIFY_REMAINING(5, FOUND_LLC);

        oui = ex24be(px+offset);
        ethertype = ex16be(px+offset+3);
        offset += 5;

        switch (oui){
        case 0x000000: goto parse_ethertype;
        default: return 0;
        }

    }

parse_ethertype:
    switch (ethertype) {
    case 0x0800: goto parse_ipv4;
    case 0x0806: goto parse_arp;
    case 0x86dd: goto parse_ipv6;
    case 0x8100: goto parse_vlan8021q;
    case 0x8847: goto parse_vlanmpls;
    default: return 0;
    }

parse_linktype:
    /*
     * The "link-type" is the same as specified in "libpcap" headers
     */
    switch (link_type) {
    case 1:     goto parse_ethernet;
    case 12:    goto parse_ipv4;
    case 0x69:  goto parse_wifi;
    case 119:   goto parse_prism_header;
    case 127:   goto parse_radiotap_header;
    default:    return 0;
    }

    /*
     +--------+--------+--------+--------+
     |   hardware type |   protocol type |
     +--------+--------+--------+--------+
     | h-len  |  p-len |      opcode     |
     +--------+--------+--------+--------+
    */

parse_arp:
    info->ip_version = 256;
    info->ip_offset = offset;
    {
        //unsigned hardware_type;
        //unsigned protocol_type;
        unsigned hardware_length;
        unsigned protocol_length;
        unsigned opcode;

        VERIFY_REMAINING(8, FOUND_ARP);
        //hardware_type = px[offset]<<8 | px[offset+1];
        //protocol_type = px[offset+2]<<8 | px[offset+3];
        hardware_length = px[offset+4];
        protocol_length = px[offset+5];
        opcode = px[offset+6]<<8 | px[offset+7];
        offset += 8;

        VERIFY_REMAINING(2*hardware_length + 2*protocol_length, FOUND_ARP);

        info->ip_src = px + offset + hardware_length;
        info->ip_dst = px + offset + 2*hardware_length + protocol_length;
        info->ip_protocol = opcode;
        info->found_offset = info->ip_offset;
        return 1;
    }

}
