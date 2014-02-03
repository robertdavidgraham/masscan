#include "proto-udp.h"
#include "proto-dns.h"
#include "proto-netbios.h"
#include "proto-snmp.h"
#include "proto-ntp.h"
#include "proto-zeroaccess.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan-status.h"
#include "unusedparm.h"



/****************************************************************************
 ****************************************************************************/
void 
handle_udp(struct Output *out, time_t timestamp,
        const unsigned char *px, unsigned length, 
        struct PreprocessedInfo *parsed, uint64_t entropy)
{
    unsigned ip_them;
    unsigned port_them = parsed->port_src;
    unsigned status = 0;

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;



    switch (port_them) {
        case 53:
            status = handle_dns(out, timestamp, px, length, parsed, entropy);
            break;
        case 123:
            status = ntp_handle_response(out, timestamp, px, length, parsed, entropy);
            break;
        case 137:
            status = handle_nbtstat(out, timestamp, px, length, parsed, entropy);
            break;
        case 161:
            status = handle_snmp(out, timestamp, px, length, parsed, entropy);
            break;
        case 16464:
        case 16465:
        case 16470:
        case 16471:
            status = handle_zeroaccess(out, timestamp, px, length, parsed, entropy);
            break;
            
    }

    if (status == 0)
        output_report_status(
                        out,
                        timestamp,
                        PortStatus_Open,
                        ip_them,
                        17, /* ip proto = udp */
                        port_them,
                        0,
                        0);

}
