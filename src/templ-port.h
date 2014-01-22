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
    Templ_UDP = 65536,
    Templ_SCTP = 65536*2,
    Templ_ICMP_echo = 65536*3+0,
    Templ_ICMP_timestamp = 65536*3+1,
    Templ_ARP = 65536*3+2,
    Templ_Script = 65536*4,
};

#endif
