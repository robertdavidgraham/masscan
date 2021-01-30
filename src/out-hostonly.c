#include "output.h"
#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "unusedparm.h"
#include "out-tcp-services.h"





static void
hostonly_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(fp);
    UNUSEDPARM(out);
}


static void
hostonly_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(fp);
    UNUSEDPARM(out);
}

static void
hostonly_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, ipaddress ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    ipaddress_formatted_t fmt = ipaddress_fmt(ip);
    UNUSEDPARM(reason);
    UNUSEDPARM(out);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ttl);
    UNUSEDPARM(port);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(status);
    fprintf(fp, "%s\n", fmt.string);
}


/*************************************** *************************************
 ****************************************************************************/
static void
hostonly_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        ipaddress ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{ /* SYN only - no banner */
    ipaddress_formatted_t fmt = ipaddress_fmt(ip);
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
    fprintf(fp, "%s\n", fmt.string);

    return;
} 
 


/****************************************************************************
 ****************************************************************************/
const struct OutputType hostonly_output = {
    "hostonly",
    0,
    hostonly_out_open,
    hostonly_out_close,
    hostonly_out_status,
    hostonly_out_banner
};



