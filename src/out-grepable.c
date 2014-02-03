#include "output.h"
#include "masscan.h"
#include "masscan-version.h"
#include "masscan-status.h"
#include "templ-port.h"
#include "string_s.h"


/****************************************************************************
 ****************************************************************************/
static unsigned
count_type(const struct RangeList *ports, int type)
{
    unsigned min_port = type;
    unsigned max_port = type + 65535;
    unsigned i;
    unsigned result = 0;

    for (i=0; i<ports->count; ports++) {
        struct Range r = ports->list[i];
        if (r.begin > max_port)
            continue;
        if (r.end < min_port)
            continue;

        if (r.begin < min_port)
            r.begin = min_port;
        if (r.end > max_port)
            r.end = max_port;


        result += r.end - r.begin + 1;
    }

    return result;
}

/****************************************************************************
 ****************************************************************************/
static void
print_port_list(const struct RangeList *ports, int type, FILE *fp)
{
    unsigned min_port = type;
    unsigned max_port = type + 65535;
    unsigned i;

    for (i=0; i<ports->count; ports++) {
        struct Range r = ports->list[i];
        if (r.begin > max_port)
            continue;
        if (r.end < min_port)
            continue;

        if (r.begin < min_port)
            r.begin = min_port;
        if (r.end > max_port)
            r.end = max_port;

        fprintf(fp, "%u-%u%s", r.begin, r.end, (i+1<ports->count)?",":"");
    }
}

/****************************************************************************
 * This function doesn't really "open" the file. Instead, the purpose of
 * this function is to initialize the file by printing header information.
 ****************************************************************************/
static void
grepable_out_open(struct Output *out, FILE *fp)
{
    char timestamp[64];
    struct tm tm;
    unsigned count;

    gmtime_s(&tm, &out->when_scan_started);

    //Tue Jan 21 20:23:22 2014
    //%a %b %d %H:%M:%S %Y
    strftime(timestamp, sizeof(timestamp), "%c", &tm);

    fprintf(fp, "# Masscan " MASSCAN_VERSION " scan initiated %s\n", 
                timestamp);

    count = count_type(&out->masscan->ports, Templ_TCP);
    fprintf(fp, "# Ports scanned: TCP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_TCP, fp);

    count = count_type(&out->masscan->ports, Templ_UDP);
    fprintf(fp, ") UDP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_UDP, fp);

    count = count_type(&out->masscan->ports, Templ_SCTP);
    fprintf(fp, ") SCTP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_SCTP, fp);

    fprintf(fp, ") PROTOCOLS(0;)\n");
}

/****************************************************************************
 * This function doesn't really "close" the file. Instead, it's purpose
 * is to print trailing information to the file. This is pretty much only
 * a concern for XML files that need stuff appeneded to the end.
 ****************************************************************************/
static void
grepable_out_close(struct Output *out, FILE *fp)
{
    time_t now = time(0);
    char timestamp[64];
    struct tm tm;

    UNUSEDPARM(out);

    gmtime_s(&tm, &now);

    //Tue Jan 21 20:23:22 2014
    //%a %b %d %H:%M:%S %Y
    strftime(timestamp, sizeof(timestamp), "%c", &tm);

    fprintf(fp, "# Masscan done at %s\n", 
                timestamp);
}

/****************************************************************************
 * Prints out the status of a port, which is almost always just "open"
 * or "closed".
 ****************************************************************************/
static void
grepable_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

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

/****************************************************************************
 * Prints out "banner" information for a port. This is done when there is
 * a protocol defined for a port, and we do some interaction to find out
 * more information about which protocol is running on a port, it's version,
 * and other useful information.
 ****************************************************************************/
static void
grepable_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    char banner_buffer[4096];

    UNUSEDPARM(ttl);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(ip_proto);
    
    fprintf(fp, "Host: %u.%u.%u.%u ()",
                    (unsigned char)(ip>>24),
                    (unsigned char)(ip>>16),
                    (unsigned char)(ip>> 8),
                    (unsigned char)(ip>> 0)
                    );
    fprintf(fp, "\tPort: %u", port);

    fprintf(fp, "\tService: %s", masscan_app_to_string(proto));

    normalize_string(px, length, banner_buffer, sizeof(banner_buffer));

    fprintf(fp, "\tBanner: %s\n", banner_buffer);

}



/****************************************************************************
 * This is the only structure exposed to the rest of the system. Everything
 * else in the file is defined 'static' or 'private'.
 ****************************************************************************/
const struct OutputType grepable_output = {
    "grepable",
    0,
    grepable_out_open,
    grepable_out_close,
    grepable_out_status,
    grepable_out_banner
};
