#include "output.h"
#include "masscan.h"


/****************************************************************************
 ****************************************************************************/
static void
xml_out_open(struct Output *out, FILE *fp)
{
    const struct Masscan *masscan = out->masscan;
    
    fprintf(fp, "<?xml version=\"1.0\"?>\r\n");
    fprintf(fp, "<!-- masscan v1.0 scan -->\r\n");
    if (masscan->nmap.stylesheet[0]) {
        fprintf(fp, "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\r\n",
            masscan->nmap.stylesheet);
    }
    fprintf(fp, "<nmaprun scanner=\"%s\" start=\"%u\" version=\"%s\"  xmloutputversion=\"%s\">\r\n",
        "masscan",
        (unsigned)time(0),
        "1.0-BETA",
        "1.03" /* xml output version I copied from their site */
        );
    fprintf(fp, "<scaninfo type=\"%s\" protocol=\"%s\" />\r\n",
        "syn", "tcp" );
}


/****************************************************************************
 ****************************************************************************/
static void
xml_out_close(struct Output *out, FILE *fp)
{
    char buffer[256];
    time_t now = time(0);
    struct tm tm;

    localtime_s(&tm, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(fp,
        "<runstats>\r\n"
            "<finished time=\"%u\" timestr=\"%s\" elapsed=\"%u\" />\r\n"
            "<hosts up=\"%llu\" down=\"%llu\" total=\"%llu\" />\r\n"
        "</runstats>\r\n"
        "</nmaprun>\r\n",
    (unsigned)now,                    /* time */
    buffer,                 /* timestr */
    (unsigned)(now - out->last_rotate), /* elapsed */
    out->open_count,
    out->closed_count,
    out->open_count + out->closed_count
    );
    
}

/****************************************************************************
 ****************************************************************************/
static void
xml_out_status(struct Output *out, FILE *fp, int status, 
               unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    char reason_buffer[128];
    UNUSEDPARM(out);
    fprintf(fp, "<host endtime=\"%u\">"
                    "<address addr=\"%u.%u.%u.%u\" addrtype=\"ipv4\"/>"
                    "<ports>"
                    "<port protocol=\"tcp\" portid=\"%u\">"
                    "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%u\"/>"
                    "</port>"
                    "</ports>"
                "</host>"
                "\r\n",
        (unsigned)global_now,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        port,
        status_string(status),
        reason_string(reason, reason_buffer, sizeof(reason_buffer)),
        ttl
        );
}

/****************************************************************************
 ****************************************************************************/
static void
xml_out_banner(struct Output *out, FILE *fp, unsigned ip, unsigned port,
        unsigned proto, const unsigned char *px, unsigned length)
{
    char banner_buffer[1024];

    UNUSEDPARM(out);

    fprintf(fp, "<host endtime=\"%u\">"
                    "<address addr=\"%u.%u.%u.%u\" addrtype=\"ipv4\"/>"
                    "<ports>"
                    "<port protocol=\"tcp\" portid=\"%u\">"
                    "<service name=\"%s\">"
                    "<banner>%s</banner>"
                    "</service>"
                    "</port>"
                    "</ports>"
                "</host>"
                "\r\n",
        (unsigned)global_now,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        port,
        proto_string(proto),
        normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
        );
}

/****************************************************************************
 ****************************************************************************/
const struct OutputType xml_output = {
    "xml",
    0,
    xml_out_open,
    xml_out_close,
    xml_out_status,
    xml_out_banner
};

