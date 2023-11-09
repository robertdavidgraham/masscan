/* ISAKMP protocol support */

#include "proto-isakmp.h"
#include "proto-banout.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "massip-port.h"
#include "output.h"

unsigned
isakmp_parse(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            )
{
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    unsigned cookie;
    unsigned resp_cookie;
    unsigned char i;

    /* All memcached responses will be at least 8 bytes */
    if (length < 16)
        return 0;

    /* Grab IP addresses */
    ip_them = parsed->src_ip;
    ip_me = parsed->dst_ip;

    cookie = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);

    resp_cookie = 0;
    for(i = 0; i < 8; i++)
        resp_cookie |= px[8 + i] << (56 - 8 * i);

    if (resp_cookie != cookie)
        output_report_banner(out, timestamp, ip_them, 17, port_them,
                             PROTO_ERROR, parsed->ip_ttl,
                             (unsigned char *) "IP-MISSMATCH", 12);

    output_report_banner(out, timestamp, ip_them, 17, port_them, PROTO_NONE,
                         parsed->ip_ttl, px, length);

    return 0;
}

unsigned
isakmp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    /*
    The frame header starts with an 8 bytes init cookie, which is just
    fine for us
    */

    unsigned char i;

    if (length < 8)
        return 0;

    for(i = 0; i < 8; i++)
        px[i] = (unsigned char)(seqno >> (56 - 8 * i));

    return 0;
}
