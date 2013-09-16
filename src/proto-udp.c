#include "proto-udp.h"
#include "proto-dns.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan.h"
#include "unusedparm.h"

static int
matches_me(struct Output *out, unsigned ip, unsigned port)
{
    unsigned i;

    for (i=0; i<8; i++) {
        if (ip == out->nics[i].ip_me && port == out->nics[i].port_me)
            return 1;
    }
    return 0;
}


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
