#include "proto-udp.h"
#include "proto-coap.h"
#include "proto-dns.h"
#include "proto-isakmp.h"
#include "proto-netbios.h"
#include "proto-snmp.h"
#include "proto-memcached.h"
#include "proto-ntp.h"
#include "proto-zeroaccess.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "util-logger.h"
#include "output.h"
#include "masscan-status.h"
#include "unusedparm.h"


/****************************************************************************
 * When the "--banner" command-line option is selected, this will
 * will take up to 64 bytes of a response and display it. Other UDP
 * protocol parsers may also default to this function when they detect
 * a response is not the protocol they expect. For example, if a response
 * to port 161 obviously isn't ASN.1 formatted, the SNMP parser will
 * call this function instead. In such cases, the protocool identifier will
 * be [unknown] rather than [snmp].
 ****************************************************************************/
unsigned
default_udp_parse(struct Output *out, time_t timestamp,
           const unsigned char *px, unsigned length,
           struct PreprocessedInfo *parsed,
           uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;
    
    UNUSEDPARM(entropy);


    if (length > 64)
        length = 64;
    
    output_report_banner(
                         out, timestamp,
                         ip_them, 17, port_them,
                         PROTO_NONE,
                         parsed->ip_ttl,
                         NULL, 0,
                         px, length);

    return 0;
}

/****************************************************************************
 ****************************************************************************/
void 
handle_udp(struct Output *out, time_t timestamp,
        const unsigned char *px, unsigned length, 
        struct PreprocessedInfo *parsed, uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;
    unsigned status = 0;

    /* Report "open" status regardless  */
    output_report_status(
                             out,
                             timestamp,
                             PortStatus_Open,
                             ip_them,
                             17, /* ip proto = udp */
                             port_them,
                             0,
                             parsed->ip_ttl,
                             parsed->mac_src);


    switch (port_them) {
        case 53: /* DNS - Domain Name System (amplifier) */
            status = handle_dns(out, timestamp, px, length, parsed, entropy);
            break;
        case 123: /* NTP - Network Time Protocol (amplifier) */
            status = ntp_handle_response(out, timestamp, px, length, parsed, entropy);
            break;
        case 137: /* NetBIOS (amplifier) */
            status = handle_nbtstat(out, timestamp, px, length, parsed, entropy);
            break;
        case 161: /* SNMP - Simple Network Managment Protocol (amplifier) */
            status = handle_snmp(out, timestamp, px, length, parsed, entropy);
            break;
        case 500: /* ISAKMP - IPsec key negotiation */
            status = isakmp_parse(out, timestamp,
                                px + parsed->app_offset, parsed->app_length, parsed, entropy);
            break;
        case 5683:
            status = coap_handle_response(out, timestamp, 
                                px + parsed->app_offset, parsed->app_length, parsed, entropy);
            break;
        case 11211: /* memcached (amplifier) */
            px += parsed->app_offset;
            length = parsed->app_length;
            status = memcached_udp_parse(out, timestamp, px, length, parsed, entropy);
            break;
        case 16464:
        case 16465:
        case 16470:
        case 16471:
            status = handle_zeroaccess(out, timestamp, px, length, parsed, entropy);
            break;
        default:
            px += parsed->app_offset;
            length = parsed->app_length;
            status = default_udp_parse(out, timestamp, px, length, parsed, entropy);
            break;
    }

    
    /* Report banner if some parser didn't already do so.
     * Also report raw dump if `--rawudp` specified on the
     * command-line, even if a protocol above already created a more detailed
     * banner. */
    if (status == 0 || out->is_banner_rawudp) {
            output_report_banner(
                    out,
                    timestamp,
                    ip_them,
                    17, /* ip proto = udp */
                    port_them,
                    PROTO_NONE,
                    parsed->ip_ttl,
                    NULL, 0,
                    px + parsed->app_offset,
                    parsed->app_length);
    }
}
