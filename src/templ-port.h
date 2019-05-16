#ifndef TEMPL_PORT_H
#define TEMPL_PORT_H

/*
 * Due to the asynchronous scanning architecture, we have to combine TCP
 * and UDP ports (plus other scans) in a combined range. Thus, we make
 * the weird decision to put UDP ports in the range 64k to 128k, and
 * so on. We should probably make this less bizaree in the future.
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
