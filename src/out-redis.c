#include "output.h"
#include "masscan.h"

/****************************************************************************
 ****************************************************************************/
static void
null_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

/****************************************************************************
 ****************************************************************************/
static void
null_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

/****************************************************************************
 ****************************************************************************/
static void
null_out_status(struct Output *out, FILE *fp, 
    int status, unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(status);
    UNUSEDPARM(ip);
    UNUSEDPARM(port);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

}

/****************************************************************************
 ****************************************************************************/
static void
null_out_banner(struct Output *out, FILE *fp, unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, const unsigned char *px, unsigned length)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(proto);
    UNUSEDPARM(px);
    UNUSEDPARM(length);

}


/****************************************************************************
 ****************************************************************************/
const struct OutputType redis_output = {
    "redis",
    0,
    null_out_open,
    null_out_close,
    null_out_status,
    null_out_banner
};



