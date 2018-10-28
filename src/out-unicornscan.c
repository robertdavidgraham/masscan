#include "output.h"
#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "unusedparm.h"
#include "out-tcp-services.h"





static void
unicornscan_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    fprintf(fp, "#masscan\n");
}


static void
unicornscan_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    fprintf(fp, "# end\n");
}

static void
unicornscan_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(reason);
    UNUSEDPARM(out);
    UNUSEDPARM(timestamp);

    if (ip_proto == 6) {
      fprintf(fp,"TCP %s\t%16s[%5d]\t\tfrom %u.%u.%u.%u  ttl %-3d\n",
              status_string(status),
              tcp_service_name(port),
              port,
              (ip>>24)&0xFF,
              (ip>>16)&0xFF,
              (ip>> 8)&0xFF,
              (ip>> 0)&0xFF,
              ttl);
    } else {
        /* unicornscan is TCP only, so just use grepable format for other protocols */
        fprintf(fp, "Host: %u.%u.%u.%u ()",
                (unsigned char)(ip>>24),
                (unsigned char)(ip>>16),
                (unsigned char)(ip>> 8),
                (unsigned char)(ip>> 0)
                );
        fprintf(fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n",
                port,
                status_string(status),      //"open", "closed"
                name_from_ip_proto(ip_proto),  //"tcp", "udp", "sctp"
                "", //owner
                "", //service
                "", //SunRPC info
                "" //Version info
                );
    }
}


/*************************************** *************************************
 ****************************************************************************/
static void
unicornscan_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{ /* SYN only - no banner */
    UNUSEDPARM(out);
    UNUSEDPARM(ttl);
    UNUSEDPARM(port);
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(proto);
    UNUSEDPARM(px);
    UNUSEDPARM(length);

    return;
} 
 


/****************************************************************************
 ****************************************************************************/
const struct OutputType unicornscan_output = {
    "uni",
    0,
    unicornscan_out_open,
    unicornscan_out_close,
    unicornscan_out_status,
    unicornscan_out_banner
};



