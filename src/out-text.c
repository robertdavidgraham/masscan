#include "output.h"
#include "masscan.h"
#include "masscan-app.h"
#include "unusedparm.h"

#include <ctype.h>

/****************************************************************************
 ****************************************************************************/
static void
text_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    fprintf(fp, "#masscan\n");
}

/****************************************************************************
 ****************************************************************************/
static void
text_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    fprintf(fp, "# end\n");
}

/****************************************************************************
 ****************************************************************************/
static void
text_out_status(struct Output *out, FILE *fp, 
    int status, unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(ttl);
    UNUSEDPARM(reason);
    UNUSEDPARM(out);
    

    fprintf(fp, "%s tcp %u %u.%u.%u.%u %u\n",
        status_string(status),
        port,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        (unsigned)global_now
        );
}


/*************************************** *************************************
 ****************************************************************************/
static void
text_out_banner(struct Output *out, FILE *fp, unsigned ip, unsigned ip_proto, unsigned port, 
        enum ApplicationProtocol proto, const unsigned char *px, unsigned length)
{
    char banner_buffer[4096];
    char ip_proto_sz[64];

    switch (ip_proto) {
    case 1: strcpy_s(ip_proto_sz, sizeof(ip_proto_sz), "icmp"); break;
    case 6: strcpy_s(ip_proto_sz, sizeof(ip_proto_sz), "tcp"); break;
    case 17: strcpy_s(ip_proto_sz, sizeof(ip_proto_sz), "udp"); break;
    default: sprintf_s(ip_proto_sz, sizeof(ip_proto_sz), "(%u)", ip_proto); break;
    }

    UNUSEDPARM(out);

    fprintf(fp, "%s %s %u %u.%u.%u.%u %u %s %s\n",
        "banner",
        ip_proto_sz,
        port,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        (unsigned)global_now,
        masscan_app_to_string(proto),
        normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
        );
}


/****************************************************************************
 ****************************************************************************/
const struct OutputType text_output = {
    "txt",
    0,
    text_out_open,
    text_out_close,
    text_out_status,
    text_out_banner
};



