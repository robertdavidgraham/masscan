#include "output.h"
#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "unusedparm.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void
ipport_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    /* No header */
}

/****************************************************************************
 ****************************************************************************/
static void
ipport_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    /* No footer */
}

/****************************************************************************
 ****************************************************************************/
static void
ipport_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, ipaddress ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    ipaddress_formatted_t fmt = ipaddress_fmt(ip);
    UNUSEDPARM(ttl);
    UNUSEDPARM(reason);
    UNUSEDPARM(out);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ip_proto);

    /* Only output open ports */
    if (status == PortStatus_Open) {
        fprintf(fp, "%s:%u\n", fmt.string, port);
    }
}

/****************************************************************************
 ****************************************************************************/
static void
ipport_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        ipaddress ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    /* For IP:PORT format, we don't output banners */
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(proto);
    UNUSEDPARM(ttl);
    UNUSEDPARM(px);
    UNUSEDPARM(length);
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType ipport_output = {
    "ipport",
    0,
    ipport_out_open,
    ipport_out_close,
    ipport_out_status,
    ipport_out_banner
};