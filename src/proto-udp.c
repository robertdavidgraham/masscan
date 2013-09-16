#include "proto-udp.h"
#include "proto-dns.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan.h"
#include "unusedparm.h"



void handle_udp(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed)
{
    unsigned ip_them;
    unsigned port_them = parsed->port_src;

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;

    output_report_status(
                        out,
                        Port_UdpClosed,
                        ip_them,
                        port_them,
                        0,
                        0);

    switch (port_them) {
    case 53:
        handle_dns(out, px, length, parsed);
        break;
    }

}
