#include "output.h"
#include "masscan.h"


/****************************************************************************
 * This function doesn't really "open" the file. Instead, the purpose of
 * this function is to initialize the file by printing header information.
 ****************************************************************************/
static void
null_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

/****************************************************************************
 * This function doesn't really "close" the file. Instead, it's purpose
 * is to print trailing information to the file. This is pretty much only
 * a concern for XML files that need stuff appeneded to the end.
 ****************************************************************************/
static void
null_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

/****************************************************************************
 * Prints out the status of a port, which is almost always just "open"
 * or "closed".
 ****************************************************************************/
static void
null_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(status);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(ip);
    UNUSEDPARM(port);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

}

/****************************************************************************
 * Prints out "banner" information for a port. This is done when there is
 * a protocol defined for a port, and we do some interaction to find out
 * more information about which protocol is running on a port, it's version,
 * and other useful information.
 ****************************************************************************/
static void
null_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    UNUSEDPARM(ttl);
    UNUSEDPARM(timestamp);
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
 * This is the only structure exposed to the rest of the system. Everything
 * else in the file is defined 'static' or 'private'.
 ****************************************************************************/
const struct OutputType null_output = {
    "null",
    0,
    null_out_open,
    null_out_close,
    null_out_status,
    null_out_banner
};
