#ifndef MASSIP_PORT_H
#define MASSIP_PORT_H

/*
 * Ports are 16-bit numbers ([0..65535], but different
 * transports (TCP, UDP, SCTP) are distinct port ranges. Thus, we
 * instead of three 64k ranges we could instead treat this internally
 * as a 192k port range. We can expand this range to include other
 * things we scan for, such as ICMP pings or ARP requests.
 */
enum {
    Templ_TCP = 0,
    Templ_TCP_last = 65535,
    Templ_UDP = 65536,
    Templ_UDP_last = 65536 + 65535,
    Templ_SCTP = 65536*2,
    Templ_SCTP_last = 65536*2 + 65535,
    Templ_ICMP_echo = 65536*3+0,
    Templ_ICMP_timestamp = 65536*3+1,
    Templ_ARP = 65536*3+2,
    Templ_Oproto_first = 65536*3 + 256,
    Templ_Oproto_last = 65536*3 + 256 + 255,
    Templ_VulnCheck = 65536*4,
    
};

#endif
