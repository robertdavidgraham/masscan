#include "output.h"
#include "masscan.h"
#include "masscan-version.h"
#include "masscan-status.h"
#include "out-tcp-services.h"
#include "massip-port.h"
#include "util-safefunc.h"


/****************************************************************************
 ****************************************************************************/
static unsigned
count_type(const struct RangeList *ports, int start_type, int end_type)
{
    unsigned min_port = start_type;
    unsigned max_port = end_type;
    unsigned i;
    unsigned result = 0;

    for (i=0; i<ports->count; i++) {
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

    for (i=0; i<ports->count; i++) {
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

extern const char *debug_recv_status;

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

    
    safe_gmtime(&tm, &out->when_scan_started);

    //Tue Jan 21 20:23:22 2014
    //%a %b %d %H:%M:%S %Y
    strftime(timestamp, sizeof(timestamp), "%c", &tm);

    fprintf(fp, "# Masscan " MASSCAN_VERSION " scan initiated %s\n", 
                timestamp);

    count = count_type(&out->masscan->targets.ports, Templ_TCP, Templ_TCP_last);
    fprintf(fp, "# Ports scanned: TCP(%u;", count);
    if (count)
        print_port_list(&out->masscan->targets.ports, Templ_TCP, fp);

    count = count_type(&out->masscan->targets.ports, Templ_UDP, Templ_UDP_last);
    fprintf(fp, ") UDP(%u;", count);
    if (count)
        print_port_list(&out->masscan->targets.ports, Templ_UDP, fp);
    
    
    count = count_type(&out->masscan->targets.ports, Templ_SCTP, Templ_SCTP_last);
    fprintf(fp, ") SCTP(%u;", count);
    if (count)
        print_port_list(&out->masscan->targets.ports, Templ_SCTP, fp);

    count = count_type(&out->masscan->targets.ports, Templ_Oproto_first, Templ_Oproto_last);
    fprintf(fp, ") PROTOCOLS(%u;", count);
    if (count)
        print_port_list(&out->masscan->targets.ports, Templ_Oproto_first, fp);
    
    fprintf(fp, ")\n");
}

/****************************************************************************
 * This function doesn't really "close" the file. Instead, it's purpose
 * is to print trailing information to the file. This is pretty much only
 * a concern for XML files that need stuff appended to the end.
 ****************************************************************************/
static void
grepable_out_close(struct Output *out, FILE *fp)
{
    time_t now = time(0);
    char timestamp[64];
    struct tm tm;

    UNUSEDPARM(out);

    safe_gmtime(&tm, &now);

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
    int status, ipaddress ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    const char *service;
    ipaddress_formatted_t fmt;
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

    if (ip_proto == 6)
        service = tcp_service_name(port);
    else if (ip_proto == 17)
        service = udp_service_name(port);
    else
        service = oproto_service_name(ip_proto);
    
    fprintf(fp, "Timestamp: %llu", (unsigned long long)timestamp);

    fmt = ipaddress_fmt(ip);
    fprintf(fp, "\tHost: %s ()", fmt.string);
    fprintf(fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n",
                port,
                status_string(status),      //"open", "closed"
                name_from_ip_proto(ip_proto),  //"tcp", "udp", "sctp"
                "", //owner
                service, //service
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
        ipaddress ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *probe, unsigned probe_length,
        const unsigned char *px, unsigned length)
{
    char banner_buffer[MAX_BANNER_LENGTH];
    char probe_buffer[MAX_PROBE_LENGTH];
    ipaddress_formatted_t fmt;

    UNUSEDPARM(ttl);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(ip_proto);
    
    fmt = ipaddress_fmt(ip);
    fprintf(fp, "Host: %s ()", fmt.string);
    fprintf(fp, "\tPort: %u", port);

    fprintf(fp, "\tService: %s", masscan_app_to_string(proto));

    if (out->masscan->is_output_probes) {
        normalize_string(probe, probe_length, probe_buffer, sizeof(probe_buffer));

        fprintf(fp, "\tProbe: %s\n", probe_buffer);
    }

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
