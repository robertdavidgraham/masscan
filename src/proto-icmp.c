#include "proto-icmp.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan.h"

int
parse_port_unreachable(const unsigned char *px, unsigned length,
        unsigned *r_ip_me, unsigned *r_ip_them,
        unsigned *r_port_me, unsigned *r_port_them)
{
    if (length < 24)
        return -1;
    *r_ip_me = px[12]<<24 | px[13]<<16 | px[14]<<8 | px[15];
    *r_ip_them = px[16]<<24 | px[17]<<16 | px[18]<<8 | px[19];
    
    px += (px[0]&0xF)<<2;
    length -= (px[0]&0xF)<<2;

    if (length < 4)
        return -1;

    *r_port_me = px[0]<<8 | px[1];
    *r_port_them = px[2]<<8 | px[3];

    return 0;
}

void handle_icmp(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed)
{
    unsigned type = parsed->port_src;
    unsigned code = parsed->port_dst;
    unsigned seqno_me;
    unsigned ip_me;
    unsigned ip_them;

    ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
            | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;
    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;

    seqno_me = px[parsed->transport_offset+4]<<24
                | px[parsed->transport_offset+5]<<16
                | px[parsed->transport_offset+6]<<8
                | px[parsed->transport_offset+7]<<0;

    switch (type) {
    case 0: /* ICMP echo reply */
        if (syn_hash(ip_them, 65536*3+0) != seqno_me)
            return; /* not my response */

        /*
         * Report "open" or "existence" of host
         */
        output_report_status(
                            out,
                            Port_IcmpEchoResponse,
                            ip_them,
                            0,
                            0,
                            0);
        break;
    case 3: /* destination unreachable */
        switch (code) {
        case 0: /* net unreachable */
        case 1: /* host unreachable */
        case 2: /* protocol unreachable */
            break;
        case 3: /* port unreachable */
            if (length - parsed->transport_offset > 8) {
                unsigned ip_me2, ip_them2, port_me2, port_them2;
                int err;
                
                err = parse_port_unreachable(
                    px + parsed->transport_offset + 8,
                    length - parsed->transport_offset + 8,
                    &ip_me2, &ip_them2, &port_me2, &port_them2);

                if (err)
                    return;

                if (ip_me2 != ip_me)
                    return;

                if (port_me2 != out->masscan->adapter_port)
                    return;

                output_report_status(
                                    out,
                                    Port_UdpClosed,
                                    ip_them2,
                                    port_them2,
                                    0,
                                    px[parsed->ip_offset + 8]);

            }

        }
        break;
    default:
        printf(".");
    }
}

