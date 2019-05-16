/* Copyright: (c) 2009-2010 by Robert David Graham */
#ifndef PREPROCESS_H
#define PREPROCESS_H

enum {
    FOUND_NOTHING=0,
    FOUND_ETHERNET,
    FOUND_IPV4,
    FOUND_IPV6,
    FOUND_ICMP,
    FOUND_TCP,
    FOUND_UDP,
    FOUND_SCTP,
    FOUND_DNS,
    FOUND_IPV6_HOP,
    FOUND_8021Q,
    FOUND_MPLS,
    FOUND_WIFI_DATA,
    FOUND_WIFI,
    FOUND_RADIOTAP,
    FOUND_PRISM,
    FOUND_LLC,
    FOUND_ARP,
    FOUND_SLL, /* Linux SLL */
    FOUND_OPROTO, /* some other IP protocol */
};
struct PreprocessedInfo {
    const unsigned char *mac_src;
    const unsigned char *mac_dst;
    const unsigned char *mac_bss;
    unsigned ip_offset;     /* 14 for normal Ethernet */
    unsigned ip_version;    /* 4 or 6 */
    unsigned ip_protocol;   /* 6 for TCP, 11 for UDP */
    unsigned ip_length;     /* length of total packet */
    unsigned ip_ttl;
    const unsigned char *ip_src;
    const unsigned char *ip_dst;
    unsigned transport_offset;  /* 34 for normal Ethernet */
    unsigned transport_length;
    unsigned port_src;
    unsigned port_dst;

    unsigned app_offset; /* start of TCP payload */
    unsigned app_length; /* length of TCP payload */

    int found;
    int found_offset;
};

/**
 * @return 1 if useful stuff found, 0 otherwise
 */
unsigned
preprocess_frame(const unsigned char *px, unsigned length, unsigned link_type, struct PreprocessedInfo *info);

#endif
