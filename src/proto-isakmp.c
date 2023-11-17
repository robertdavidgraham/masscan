/* ISAKMP protocol support 
 
 1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Initiator                            !
!                            Cookie                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Responder                            !
!                            Cookie                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Message ID                           !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                            Length                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


 */

#include "proto-isakmp.h"
#include "proto-banout.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "massip-port.h"
#include "output.h"

static const unsigned char
sample_response[] = 
    "\x00\x00\x00\x00\xc1\x18\x84\xda\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01`\x00\x00\x01D\x00"
    "\x00\x00\x01\x00\x00\x00\x01\x00\x00\x018\x01\x01\x00\x0d\x03\x00"
    "\x00\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00"
    "\x01\x80\x04\x00\x02\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00"
    "\x00\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x01"
    "\x80\x04\x00\x02\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00"
    "\x00\x01\x00\x00\x80\x01\x00\x07\x80\x02\x00\x04\x80\x03\x00\x01"
    "\x80\x04\x00\x0e\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00\x14"
    "\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x02"
    "\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
    "\x80\x03\x00\x03\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05"
    "\x80\x02\x00\x02\x80\x03\x00\x04\x03\x00\x00\x14\x00\x01\x00\x00"
    "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x08\x03\x00\x00\x14"
    "\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdd"
    "\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
    "\x80\x03\xfa\xdf\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05"
    "\x80\x02\x00\x02\x80\x03\xfd\xe9\x03\x00\x00\x14\x00\x01\x00\x00"
    "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xeb\x03\x00\x00\x14"
    "\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xed"
    "\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
    "\x80\x03\xfd\xef\x00\x00\x00\x08\x00\x01\x00\x00";

static unsigned
isakmp_parse_banner(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
             ) {
    size_t offset = 0;
    
    /* TODO: parse ISAKMP values */
    return 0;
}

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
    uint64_t cookie;
    uint64_t resp_cookie;
    
    /* All responses will be at least 8 bytes */
    if (length < 16)
        return 0;
    
    /* Grab IP addresses */
    ip_them = parsed->src_ip;
    ip_me = parsed->dst_ip;
    
    /* Calculate the expected SYN-cookie */
    cookie = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);
    
    /* Extract the SYN-cookie from the response*/
    resp_cookie = (uint64_t)px[0] << 56ull;
    resp_cookie |= (uint64_t)px[1] << 48ull;
    resp_cookie |= (uint64_t)px[2] << 40ull;
    resp_cookie |= (uint64_t)px[3] << 32ull;
    resp_cookie |= (uint64_t)px[4] << 24ull;
    resp_cookie |= (uint64_t)px[5] << 16ull;
    resp_cookie |= (uint64_t)px[6] << 8ull;
    resp_cookie |= (uint64_t)px[7] << 0ull;

    if (resp_cookie != cookie) {
        /* If they aren't equal, then this is some other protocol.
         * TODO: we should use a heuristic on these bytes to
         * discover what the protocol probably is */
        /*output_report_banner(out, timestamp, ip_them, 17, port_them,
                             PROTO_ERROR, parsed->ip_ttl,
                             (unsigned char *) "IP-MISSMATCH", 12);*/
        return 0;
    } else {
        /* We've found our protocol, so report the banner 
         * TODO: we should parse this better. */
        output_report_banner(out, timestamp, ip_them, 17, port_them, PROTO_ISAKMP,
                             parsed->ip_ttl, px, length);
        return 1;
    }

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


