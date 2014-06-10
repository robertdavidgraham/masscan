/*
    Read in the configuration for MASSCAN.

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

    Most of the code in this module is for 'nmap' options we don't support.
    That's because we support some 'nmap' options, and I wanted to give
    more feedback for some of them why they don't work as expected, such
    as reminding people that this is an asynchronous scanner.

*/
#include "masscan.h"
#include "masscan-version.h"
#include "ranges.h"
#include "string_s.h"
#include "logger.h"
#include "proto-banner1.h"
#include "templ-payloads.h"
#include "templ-port.h"
#include "crypto-base64.h"
#include "script.h"
#include "masscan-app.h"

#include <ctype.h>
#include <limits.h>

/***************************************************************************
 ***************************************************************************/
/*static struct Range top_ports_tcp[] = {
    {80, 80},{23, 23}, {443,443},{21,22},{25,25},{3389,3389},{110,110},
    {445,445},
};
static struct Range top_ports_udp[] = {
    {161, 161}, {631, 631}, {137,138},{123,123},{1434},{445,445},{135,135},
    {67,67},
};
static struct Range top_ports_sctp[] = {
    {7, 7},{9, 9},{20,22},{80,80},{179,179},{443,443},{1167,1167},
};*/

/***************************************************************************
 ***************************************************************************/
void
masscan_usage(void)
{
    printf("usage:\n");
    printf("masscan -p80,8000-8100 10.0.0.0/8 --rate=10000\n");
    printf(" scan some web ports on 10.x.x.x at 10kpps\n");
    printf("masscan --nmap\n");
    printf(" list those options that are compatible with nmap\n");
    printf("masscan -p80 10.0.0.0/8 --banners -oB <filename>\n");
    printf(" save results of scan in binary format to <filename>\n");
    printf("masscan --open --banners --readscan <filename> -oX <savefile>\n");
    printf(" read binary scan results in <filename> and save them as xml in <savefile>\n");
    exit(1);
}

/***************************************************************************
 ***************************************************************************/
static void
print_version()
{
    const char *cpu = "unknown";
    const char *compiler = "unknown";
    const char *compiler_version = "unknown";
    const char *os = "unknown";
    printf("\n");
    printf("Masscan version %s ( %s )\n", 
        MASSCAN_VERSION,
        "https://github.com/robertdavidgraham/masscan"
        );
    printf("Compiled on: %s %s\n", __DATE__, __TIME__);

#if defined(_MSC_VER)
    #if defined(_M_AMD64) || defined(_M_X64)
        cpu = "x86";
    #elif defined(_M_IX86)
        cpu = "x86";
    #elif defined (_M_ARM_FP)
        cpu = "arm";
    #endif

    {
        int msc_ver = _MSC_VER;

        compiler = "VisualStudio";

        if (msc_ver < 1500)
            compiler_version = "pre2008";
        else if (msc_ver == 1500)
            compiler_version = "2008";
        else if (msc_ver == 1600)
            compiler_version = "2010";
        else if (msc_ver == 1700)
            compiler_version = "2012";
        else if (msc_ver == 1800)
            compiler_version = "2013";
        else
            compiler_version = "post-2013";
    }


#elif defined(__GNUC__)
    compiler = "gcc";
    compiler_version = __VERSION__;

#if defined(i386) || defined(__i386) || defined(__i386__)
    cpu = "x86";
#endif

#if defined(__corei7) || defined(__corei7__)
    cpu = "x86-Corei7";
#endif

#endif

#if defined(WIN32)
    os = "Windows";
#elif defined(__linux__)
    os = "Linux";
#elif defined(__APPLE__)
    os = "Apple";
#elif defined(__MACH__)
    os = "MACH";
#elif defined(__FreeBSD__)
    os = "FreeBSD";
#elif defined(unix) || defined(__unix) || defined(__unix__)
    os = "Unix";
#endif

    printf("Compiler: %s %s\n", compiler, compiler_version);
    printf("OS: %s\n", os);
    printf("CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void*))*8);

#if defined(GIT)
    printf("GIT version: %s\n", GIT);
#endif
}

/***************************************************************************
 ***************************************************************************/
static void
print_nmap_help(void)
{
    printf("Masscan (https://github.com/robertdavidgraham/masscan)\n"
"Usage: masscan [Options] -p{Target-Ports} {Target-IP-Ranges}\n"
"TARGET SPECIFICATION:\n"
"  Can pass only IPv4 address, CIDR networks, or ranges (non-nmap style)\n"
"  Ex: 10.0.0.0/8, 192.168.0.1, 10.0.0.1-10.0.0.254\n"
"  -iL <inputfilename>: Input from list of hosts/networks\n"
"  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
"  --excludefile <exclude_file>: Exclude list from file\n"
"  --randomize-hosts: Randomize order of hosts (default)\n"
"HOST DISCOVERY:\n"
"  -Pn: Treat all hosts as online (default)\n"
"  -n: Never do DNS resolution (default)\n"
"SCAN TECHNIQUES:\n"
"  -sS: TCP SYN (always on, default)\n"
"SERVICE/VERSION DETECTION:\n"
"  --banners: get the banners of the listening service if available. The\n"
"    default timeout for waiting to recieve data is 30 seconds.\n"
"PORT SPECIFICATION AND SCAN ORDER:\n"
"  -p <port ranges>: Only scan specified ports\n"
"    Ex: -p22; -p1-65535; -p 111,137,80,139,8080\n"
"TIMING AND PERFORMANCE:\n"
"  --max-rate <number>: Send packets no faster than <number> per second\n"
"  --connection-timeout <number>: time in seconds a TCP connection will\n"
"    timeout while waiting for banner data from a port.\n"
"FIREWALL/IDS EVASION AND SPOOFING:\n"
"  -S/--source-ip <IP_Address>: Spoof source address\n"
"  -e <iface>: Use specified interface\n"
"  -g/--source-port <portnum>: Use given port number\n"
"  --ttl <val>: Set IP time-to-live field\n"
"  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address\n"
"OUTPUT:\n"
"  --output-format <format>: Sets output to binary/list/json/grepable/xml\n"
"  --output-file <file>: Write scan results to file. If --output-format is\n"
"     not given default is xml\n"
"  -oL/-oJ/-oG/-oB/-oX <file>: Output scan in List/JSON/Grepable/Binary/XML format,\n"
"     respectively, to the given filename. Shortcut for\n"
"     --output-format <format> --output-file <file>\n"
"  -v: Increase verbosity level (use -vv or more for greater effect)\n"
"  -d: Increase debugging level (use -dd or more for greater effect)\n"
"  --open: Only show open (or possibly open) ports\n"
"  --packet-trace: Show all packets sent and received\n"
"  --iflist: Print host interfaces and routes (for debugging)\n"
"  --append-output: Append to rather than clobber specified output files\n"
"  --resume <filename>: Resume an aborted scan\n"
"MISC:\n"
"  --send-eth: Send using raw ethernet frames (default)\n"
"  -V: Print version number\n"
"  -h: Print this help summary page.\n"
"EXAMPLES:\n"
"  masscan -v -sS 192.168.0.0/16 10.0.0.0/8 -p 80\n"
"  masscan 23.0.0.0/0 -p80 --banners -output-format binary --output-filename internet.scan\n"
"  masscan --open --banners --readscan internet.scan -oG internet_scan.grepable\n"
"SEE (https://github.com/robertdavidgraham/masscan) FOR MORE HELP\n"
"\n");
}

/***************************************************************************
 ***************************************************************************/
static unsigned
count_cidr_bits(struct Range range)
{
    unsigned i;

    for (i=0; i<32; i++) {
        unsigned mask = 0xFFFFFFFF >> i;

        if ((range.begin & ~mask) == (range.end & ~mask)) {
            if ((range.begin & mask) == 0 && (range.end & mask) == mask)
                return i;
        }
    }

    return 0;
}


/***************************************************************************
 * Echoes the configuration for one nic
 ***************************************************************************/
static void
masscan_echo_nic(struct Masscan *masscan, FILE *fp, unsigned i)
{
    char zzz[64];

    /* If we have only one adapter, then don't print the array indexes.
     * Otherwise, we need to print the array indexes to distinguish
     * the NICs from each other */
    if (masscan->nic_count <= 1)
        zzz[0] = '\0';
    else
        sprintf_s(zzz, sizeof(zzz), "[%u]", i);

    fprintf(fp, "adapter%s = %s\n", zzz, masscan->nic[i].ifname);
    if (masscan->nic[i].src.ip.first == masscan->nic[i].src.ip.last)
        fprintf(fp, "adapter-ip%s = %u.%u.%u.%u\n", zzz,
            (masscan->nic[i].src.ip.first>>24)&0xFF,
            (masscan->nic[i].src.ip.first>>16)&0xFF,
            (masscan->nic[i].src.ip.first>> 8)&0xFF,
            (masscan->nic[i].src.ip.first>> 0)&0xFF
            );
    else
        fprintf(fp, "adapter-ip%s = %u.%u.%u.%u-%u.%u.%u.%u\n", zzz,
            (masscan->nic[i].src.ip.first>>24)&0xFF,
            (masscan->nic[i].src.ip.first>>16)&0xFF,
            (masscan->nic[i].src.ip.first>> 8)&0xFF,
            (masscan->nic[i].src.ip.first>> 0)&0xFF,
            (masscan->nic[i].src.ip.last>>24)&0xFF,
            (masscan->nic[i].src.ip.last>>16)&0xFF,
            (masscan->nic[i].src.ip.last>> 8)&0xFF,
            (masscan->nic[i].src.ip.last>> 0)&0xFF
            );

    fprintf(fp, "adapter-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", zzz,
            masscan->nic[i].my_mac[0],
            masscan->nic[i].my_mac[1],
            masscan->nic[i].my_mac[2],
            masscan->nic[i].my_mac[3],
            masscan->nic[i].my_mac[4],
            masscan->nic[i].my_mac[5]);
    if (masscan->nic[i].router_ip) {
        fprintf(fp, "router-ip%s = %u.%u.%u.%u\n", zzz,
            (masscan->nic[i].router_ip>>24)&0xFF,
            (masscan->nic[i].router_ip>>16)&0xFF,
            (masscan->nic[i].router_ip>> 8)&0xFF,
            (masscan->nic[i].router_ip>> 0)&0xFF
            );
    } else
    fprintf(fp, "router-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", zzz,
            masscan->nic[i].router_mac[0],
            masscan->nic[i].router_mac[1],
            masscan->nic[i].router_mac[2],
            masscan->nic[i].router_mac[3],
            masscan->nic[i].router_mac[4],
            masscan->nic[i].router_mac[5]);

}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all setable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
static void
masscan_echo(struct Masscan *masscan, FILE *fp)
{
    unsigned i;

    fprintf(fp, "rate = %10.2f\n", masscan->max_rate);
    fprintf(fp, "randomize-hosts = true\n");
    fprintf(fp, "seed = %" PRIu64 "\n", masscan->seed);
    fprintf(fp, "shard = %u/%u\n", masscan->shard.one, masscan->shard.of);
    if (masscan->is_banners)
        fprintf(fp, "banners = true\n");

    fprintf(fp, "# ADAPTER SETTINGS\n");
    if (masscan->nic_count == 0)
        masscan_echo_nic(masscan, fp, 0);
    else {
        for (i=0; i<masscan->nic_count; i++)
            masscan_echo_nic(masscan, fp, i);
    }


    /*
     * Output information
     */
    fprintf(fp, "# OUTPUT/REPORTING SETTINGS\n");
    switch (masscan->output.format) {
    case Output_Interactive:fprintf(fp, "output-format = interactive\n"); break;
    case Output_List:       fprintf(fp, "output-format = list\n"); break;
    case Output_XML:        fprintf(fp, "output-format = xml\n"); break;
    case Output_Binary:     fprintf(fp, "output-format = binary\n"); break;
    case Output_Grepable:   fprintf(fp, "output-format = grepable\n"); break;
    case Output_JSON:       fprintf(fp, "output-format = json\n"); break;
    case Output_Certs:      fprintf(fp, "output-format = certs\n"); break;
    case Output_None:       fprintf(fp, "output-format = none\n"); break;
    case Output_Redis:
        fprintf(fp, "output-format = redis\n");
        fprintf(fp, "redis = %u.%u.%u.%u:%u\n",
            (unsigned char)(masscan->redis.ip>>24),
            (unsigned char)(masscan->redis.ip>>16),
            (unsigned char)(masscan->redis.ip>> 8),
            (unsigned char)(masscan->redis.ip>> 0),
            masscan->redis.port);
        break;

    default:
        fprintf(fp, "output-format = unknown(%u)\n", masscan->output.format);
        break;
    }
    fprintf(fp, "show = %s,%s,%s\n",
            masscan->output.is_show_open?"open":"",
            masscan->output.is_show_closed?"closed":"",
            masscan->output.is_show_host?"host":""
            );
    if (!masscan->output.is_show_open)
        fprintf(fp, "noshow = open\n");
    fprintf(fp, "output-filename = %s\n", masscan->output.filename);
    if (masscan->output.is_append)
        fprintf(fp, "output-append = true\n");
    fprintf(fp, "rotate = %u\n", masscan->output.rotate.timeout);
    fprintf(fp, "rotate-dir = %s\n", masscan->output.rotate.directory);
    fprintf(fp, "rotate-offset = %u\n", masscan->output.rotate.offset);
    fprintf(fp, "rotate-filesize = %" PRIu64 "\n", masscan->output.rotate.filesize);
    fprintf(fp, "pcap = %s\n", masscan->pcap_filename);

    /*
     * Targets
     */
    fprintf(fp, "# TARGET SELECTION (IP, PORTS, EXCLUDES)\n");
    fprintf(fp, "ports = ");
    for (i=0; i<masscan->ports.count; i++) {
        struct Range range = masscan->ports.list[i];
        if (range.begin == range.end)
            fprintf(fp, "%u", range.begin);
        else
            fprintf(fp, "%u-%u", range.begin, range.end);
        if (i+1 < masscan->ports.count)
            fprintf(fp, ",");
    }
    fprintf(fp, "\n");
    for (i=0; i<masscan->targets.count; i++) {
        struct Range range = masscan->targets.list[i];
        fprintf(fp, "range = ");
        fprintf(fp, "%u.%u.%u.%u",
            (range.begin>>24)&0xFF,
            (range.begin>>16)&0xFF,
            (range.begin>> 8)&0xFF,
            (range.begin>> 0)&0xFF
            );
        if (range.begin != range.end) {
            unsigned cidr_bits = count_cidr_bits(range);

            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else
            fprintf(fp, "-%u.%u.%u.%u",
                (range.end>>24)&0xFF,
                (range.end>>16)&0xFF,
                (range.end>> 8)&0xFF,
                (range.end>> 0)&0xFF
                );
        }
        fprintf(fp, "\n");
    }

    fprintf(fp, "\n");
    if (masscan->http_user_agent)
        fprintf(    fp,
                "http-user-agent = %.*s\n",
                masscan->http_user_agent_length,
                masscan->http_user_agent);

    for (i=0; i<sizeof(masscan->http_headers)/sizeof(masscan->http_headers[0]); i++) {
        if (masscan->http_headers[i].header_name == 0)
            continue;
        fprintf(    fp,
                    "http-header[%s] = %.*s\n",
                    masscan->http_headers[i].header_name,
                    masscan->http_headers[i].header_value_length,
                masscan->http_headers[i].header_value);
    }


    fprintf(fp, "%scapture = cert\n", masscan->is_capture_cert?"":"no");
    fprintf(fp, "%scapture = html\n", masscan->is_capture_html?"":"no");
    fprintf(fp, "%scapture = heartbleed\n", masscan->is_capture_heartbleed?"":"no");

    /*
     *  TCP payloads
     */
    fprintf(fp, "\n");
    fprintf(fp, "min-packet = %u\n", masscan->min_packet_size);

    {
        struct TcpCfgPayloads *pay;
        for (pay = masscan->tcp_payloads; pay; pay = pay->next) {
            fprintf(fp, "hello-string[%u] = %s\n",
                pay->port, pay->payload_base64);
        }
    }
}

/***************************************************************************
 ***************************************************************************/
void
masscan_save_state(struct Masscan *masscan)
{
    char filename[512];
    FILE *fp;
    int err;


    strcpy_s(filename, sizeof(filename), "paused.conf");
    fprintf(stderr, "                                   "
                    "                                   \r");
    fprintf(stderr, "saving resume file to: %s\n", filename);

    err = fopen_s(&fp, filename, "wt");
    if (err) {
        perror(filename);
        return;
    }

    fprintf(fp, "\n# resume information\n");
    fprintf(fp, "resume-index = %" PRIu64 "\n", masscan->resume.index);

    masscan_echo(masscan, fp);

    fclose(fp);
}


/*****************************************************************************
 * Read in ranges from a file
 *
 * There can be multiple ranges on a line, delimited by spaces. In fact,
 * millions of ranges can be on a line: there is limit to the line length.
 * That makes reading the file a little bit squirrelly. From one perspective
 * this parser doesn't treat the new-line '\n' any different than other
 * space. But, from another perspective, it has to, because things like
 * comments are terminated by a newline. Also, it has to count the number
 * of lines correctly to print error messages.
 *****************************************************************************/
static void
ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    errno_t err;
    unsigned line_number = 0;


    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        exit(1); /* HARD EXIT: because if it's an exclusion file, we don't
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            line_number += (c == '\n');
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (c == '\n') {
                    break;
                }
            }
            /* Loop back to the begining state at the start of a line */
            continue;
        }

        if (c == '\n') {
            continue;
        }

        /*
         * Read in a single entry
         */
        if (!feof(fp)) {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;


            /* Grab all bytes until the next space or comma */
            address[0] = (char)c;
            i = 1;
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (isspace(c&0xFF) || c == ',') {
                    break;
                }
                if (i+1 >= sizeof(address)) {
                    LOG(0, "%s:%u:%u: bad address spec: \"%.*s\"\n",
                            filename, line_number, offset, i, address);
                    exit(1);
                } else
                    address[i] = (char)c;
                i++;
            }
            address[i] = '\0';

            /* parse the address range */
            range = range_parse_ipv4(address, &offset, (unsigned)i);
            if (range.begin == 0xFFFFFFFF && range.end == 0) {
                LOG(0, "%s:%u:%u: bad range spec: \"%.*s\"\n",
                        filename, line_number, offset, i, address);
                exit(1);
            } else {
                rangelist_add_range(ranges, range.begin, range.end);
            }
        }

    }

    fclose(fp);
}

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
static int
parse_mac_address(const char *text, unsigned char *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static uint64_t
parseInt(const char *str)
{
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
static uint64_t
parseTime(const char *value)
{
    uint64_t num = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 's':
        num *= 1;
        break;
    case 'm':
        num *= 60;
        break;
    case 'h':
        num *= 60*60;
        break;
    case 'd':
        num *= 24*60*60;
        break;
    case 'w':
        num *= 24*60*60*7;
        break;
    default:
        fprintf(stderr, "--rotate-offset: unknown character\n");
        exit(1);
    }
    if (num >= 24*60*60) {
        fprintf(stderr, "--rotate-offset: value is greater than 1 day\n");
        exit(1);
    }
    if (is_negative)
        num = 24*60*60 - num;

    return num;
}

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga", 
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
static uint64_t
parseSize(const char *value)
{
    uint64_t num = 0;

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 'k': /* kilobyte */
        num *= 1024ULL;
        break;
    case 'm': /* megabyte */
        num *= 1024ULL * 1024ULL;
        break;
    case 'g': /* gigabyte */
        num *= 1024ULL * 1024ULL * 1024ULL;
        break;
    case 't': /* terabyte, 'cause we roll that way */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'p': /* petabyte, 'cause we are awesome */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'e': /* exabyte, now that's just silly */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    default:
        fprintf(stderr, "--rotate-size: unknown character\n");
        exit(1);
    }
    return num;
}


/***************************************************************************
 ***************************************************************************/
static int
is_power_of_two(uint64_t x)
{
    while ((x&1) == 0)
        x >>= 1;
    return x == 1;
}


/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

static int
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
        if (--rhs_length == 0)
            return 1;
    }
}

static unsigned
INDEX_OF(const char *str, char c)
{
    unsigned i;
    for (i=0; str[i] && str[i] != c; i++)
        ;
    return i;
}

static unsigned
ARRAY(const char *rhs)
{
    const char *p = strchr(rhs, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)parseInt(p);
}

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --parm,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
static void
masscan_set_parameter(struct Masscan *masscan,
                      const char *name, const char *value)
{
    unsigned index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }

    if (EQUALS("conf", name) || EQUALS("config", name)) {
        masscan_read_config_file(masscan, value);
    } else if (EQUALS("adapter", name) || EQUALS("if", name) || EQUALS("interface", name)) {
        if (masscan->nic[index].ifname[0]) {
            fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", masscan->nic[index].ifname);
        }
        if (masscan->nic_count < index + 1)
            masscan->nic_count = index + 1;
        sprintf_s(  masscan->nic[index].ifname,
                    sizeof(masscan->nic[index].ifname),
                    "%s",
                    value);

    }
    else if (EQUALS("adapter-ip", name) || EQUALS("source-ip", name)
             || EQUALS("source-address", name) || EQUALS("spoof-ip", name)
             || EQUALS("spoof-address", name) || EQUALS("src-ip", name)) {
        /* Send packets FROM this IP address */
        struct Range range;

        range = range_parse_ipv4(value, 0, 0);

        /* Check for bad format */
        if (range.begin > range.end) {
            LOG(0, "FAIL: bad source IPv4 address: %s=%s\n",
                    name, value);
            LOG(0, "hint   addresses look like \"19.168.1.23\"\n");
            exit(1);
        }

        /* If more than one IP address given, make the range is
            * an even power of two (1, 2, 4, 8, 16, ...) */
        if (!is_power_of_two((uint64_t)range.end - range.begin + 1)) {
            LOG(0, "FAIL: range must be even power of two: %s=%s\n",
                    name, value);
            exit(1);
        }

        masscan->nic[index].src.ip.first = range.begin;
        masscan->nic[index].src.ip.last = range.end;
        masscan->nic[index].src.ip.range = (uint64_t)range.end - range.begin + 1;
    } else if (EQUALS("adapter-port", name) || EQUALS("source-port", name)
               || EQUALS("src-port", name)) {
        /* Send packets FROM this port number */
        unsigned is_error = 0;
        struct RangeList ports;
        memset(&ports, 0, sizeof(ports));

        rangelist_parse_ports(&ports, value, &is_error);

        /* Check if there was an error in parsing */
        if (is_error) {
            LOG(0, "FAIL: bad source port specification: %s\n",
                    name);
            exit(1);
        }

        /* Only allow one range of ports */
        if (ports.count != 1) {
            LOG(0, "FAIL: only one source port range may be specified: %s\n",
                    name);
            exit(1);
        }

        /* verify range is even power of 2 (1, 2, 4, 8, 16, ...) */
        if (!is_power_of_two(ports.list[0].end - ports.list[0].begin + 1)) {
            LOG(0, "FAIL: source port range must be even power of two: %s=%s\n",
                    name, value);
            exit(1);
        }

        masscan->nic[index].src.port.first = ports.list[0].begin;
        masscan->nic[index].src.port.last = ports.list[0].end;
        masscan->nic[index].src.port.range = ports.list[0].end - ports.list[0].begin + 1;
    } else if (EQUALS("adapter-mac", name) || EQUALS("spoof-mac", name)
               || EQUALS("source-mac", name) || EQUALS("src-mac", name)) {
        /* Send packets FROM this MAC address */
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        /* Check for duplicates */
        if (memcmp(masscan->nic[index].my_mac, mac, 6) == 0)
            return;

        /* Warn if we are overwriting a Mac address */
        if (masscan->nic[index].my_mac_count != 0) {
            LOG(0, "WARNING: overwriting MAC address\n");
        }

        memcpy(masscan->nic[index].my_mac, mac, 6);
        masscan->nic[index].my_mac_count = 1;
    }
    else if (EQUALS("router-mac", name) || EQUALS("router", name)
             || EQUALS("dest-mac", name) || EQUALS("destination-mac", name)
             || EQUALS("dst-mac", name) || EQUALS("target-mac", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(masscan->nic[index].router_mac, mac, 6);
    }
    else if (EQUALS("router-ip", name)) {
        /* Send packets FROM this IP address */
        struct Range range;

        range = range_parse_ipv4(value, 0, 0);

        /* Check for bad format */
        if (range.begin != range.end) {
            LOG(0, "FAIL: bad source IPv4 address: %s=%s\n",
                    name, value);
            LOG(0, "hint   addresses look like \"19.168.1.23\"\n");
            exit(1);
        }

        masscan->nic[index].router_ip = range.begin;
    }
    else if (EQUALS("rate", name) || EQUALS("max-rate", name) ) {
        double rate = 0.0;
        double point = 10.0;
        unsigned i;

        for (i=0; value[i] && value[i] != '.'; i++) {
            char c = value[i];
            if (c < '0' || '9' < c) {
                fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n", name, value);
                return;
            }
            rate = rate * 10.0 + (c - '0');
        }

        if (value[i] == '.') {
            i++;
            while (value[i]) {
                char c = value[i];
                if (c < '0' || '9' < c) {
                    fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n",
                            name, value);
                    return;
                }
                rate += (c - '0')/point;
                point /= 10.0;
                value++;
            }
        }

        masscan->max_rate = rate;

    }
    else if (EQUALS("ports", name) || EQUALS("port", name)
             || EQUALS("dst-port", name) || EQUALS("dest-port", name)
             || EQUALS("destination-port", name)
             || EQUALS("target-port", name)) {
        unsigned is_error = 0;
        rangelist_parse_ports(&masscan->ports, value, &is_error);
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (EQUALS("banner-types", name) || EQUALS("banner-type", name)
             || EQUALS("banner-apps", name) || EQUALS("banner-app", name)
           ) {
        enum ApplicationProtocol app;
        
        app = masscan_string_to_app(value);
        
        if (app)
            rangelist_add_range(&masscan->banner_types, app, app);
        else {
            LOG(0, "FAIL: bad banner app: %s\n", value);
            fprintf(stderr, "err\n");
            exit(1);
        }
    }
    else if (EQUALS("exclude-ports", name) || EQUALS("exclude-port", name)) {
        unsigned is_error = 0;
        rangelist_parse_ports(&masscan->exclude_port, value, &is_error);
        if (is_error) {
            LOG(0, "FAIL: bad exclude port: %s\n", value);
            exit(1);
        }
    } else if (EQUALS("arp", name) || EQUALS("arpscan", name)) {
        /* Add ICMP ping request */
        struct Range range;
        range.begin = Templ_ARP;
        range.end = Templ_ARP;
        rangelist_add_range(&masscan->ports, range.begin, range.end);
        masscan_set_parameter(masscan, "router-mac", "ff-ff-ff-ff-ff-ff");
        masscan->is_arp = 1; /* needs additional flag */
        LOG(5, "--arpscan\n");
    } else if (EQUALS("bpf", name)) {
        size_t len = strlen(value) + 1;
        if (masscan->bpf_filter)
            free(masscan->bpf_filter);
        masscan->bpf_filter = (char*)malloc(len);
        memcpy(masscan->bpf_filter, value, len);
    } else if (EQUALS("capture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 1;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 1;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 1;
        else {
            fprintf(stderr, "FAIL: %s: unknown capture type\n", value);
            exit(1);
        }
    } else if (EQUALS("nocapture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 0;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 0;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 0;
        else {
            fprintf(stderr, "FAIL: %s: unknown capture type\n", value);
            exit(1);
        }
    } else if (EQUALS("ping", name) || EQUALS("ping-sweep", name)) {
        /* Add ICMP ping request */
        struct Range range;
        range.begin = Templ_ICMP_echo;
        range.end = Templ_ICMP_echo;
        rangelist_add_range(&masscan->ports, range.begin, range.end);
        LOG(5, "--ping\n");
    } else if (EQUALS("range", name) || EQUALS("ranges", name)
               || EQUALS("ip", name) || EQUALS("ipv4", name)
               || EQUALS("dst-ip", name) || EQUALS("dest-ip", name)
               || EQUALS("destination-ip", name)
               || EQUALS("target-ip", name)) {
        const char *ranges = value;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(ranges);

        for (;;) {
            struct Range range;

            range = range_parse_ipv4(ranges, &offset, max_offset);
            if (range.end < range.begin) {
                fprintf(stderr, "ERROR: bad IP address/range: %s\n", ranges);
                break;
            }

            rangelist_add_range(&masscan->targets, range.begin, range.end);

            if (offset >= max_offset || ranges[offset] != ',')
                break;
            else
                offset++; /* skip comma */
        }
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (
                EQUALS("exclude", name) ||
                EQUALS("exclude-range", name) ||
                EQUALS("exclude-ranges", name) ||
                EQUALS("exclude-ip", name) ||
                EQUALS("exclude-ipv4", name)
                ) {
        const char *ranges = value;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(ranges);

        for (;;) {
            struct Range range;

            range = range_parse_ipv4(ranges, &offset, max_offset);
            if (range.begin == 0 && range.end == 0) {
                fprintf(stderr, "CONF: bad range spec: %s\n", ranges);
                exit(1);
            }

            rangelist_add_range(&masscan->exclude_ip, range.begin, range.end);

            if (offset >= max_offset || ranges[offset] != ',')
                break;
            else
                offset++; /* skip comma */
        }
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    } else if (EQUALS("append-output", name) || EQUALS("output-append", name)) {
        if (EQUALS("overwrite", name))
            masscan->output.is_append = 0;
        else
            masscan->output.is_append = 1;
    } else if (EQUALS("badsum", name)) {
        masscan->nmap.badsum = 1;
    } else if (EQUALS("banner1", name)) {
        banner1_test(value);
        exit(1);
    } else if (EQUALS("banners", name) || EQUALS("banner", name)) {
        masscan->is_banners = 1;
    } else if (EQUALS("nobanners", name) || EQUALS("nobanner", name)) {
        masscan->is_banners = 0;
    } else if (EQUALS("blackrock-rounds", name)) {
        masscan->blackrock_rounds = (unsigned)parseInt(value);
    } else if (EQUALS("connection-timeout", name) || EQUALS("tcp-timeout", name)) {
        /* The timeout for "banners" TCP connections */
        masscan->tcp_connection_timeout = (unsigned)parseInt(value);
    } else if (EQUALS("datadir", name)) {
        strcpy_s(masscan->nmap.datadir, sizeof(masscan->nmap.datadir), value);
    } else if (EQUALS("data-length", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 1514 - 14 - 40) {
            fprintf(stderr, "error: %s=<n>: expected number less than 1500\n", name);
        } else {
            masscan->nmap.data_length = x;
        }
    } else if (EQUALS("debug", name)) {
        if (EQUALS("if", value)) {
            masscan->op = Operation_DebugIF;
        }
    } else if (EQUALS("dns-servers", name)) {
        fprintf(stderr, "nmap(%s): unsupported: DNS lookups too synchronous\n",
                name);
        exit(1);
    } else if (EQUALS("echo", name)) {
        masscan_echo(masscan, stdout);
        exit(1);
    } else if (EQUALS("excludefile", name)) {
        unsigned count1 = masscan->exclude_ip.count;
        unsigned count2;
        LOG(1, "EXCLUDING: %s\n", value);
        ranges_from_file(&masscan->exclude_ip, value);
        count2 = masscan->exclude_ip.count;
        if (count2 - count1)
        fprintf(stderr, "%s: excluding %u ranges from file\n",
                value, count2 - count1);
    } else if (EQUALS("heartbleed", name)) {
        masscan->is_heartbleed = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "no-capture", "heartbleed");
        masscan_set_parameter(masscan, "banners", "true");
    } else if (EQUALS("hello-file", name)) {
        /* When connecting via TCP, send this file */
        FILE *fp;
        int x;
        char buf[16384];
        char buf2[16384];
        size_t bytes_read;
        size_t bytes_encoded;
        char foo[64];

        x = fopen_s(&fp, value, "rb");
        if (x != 0) {
            LOG(0, "[FAILED] could not read hello file\n");
            perror(value);
            exit(1);
        }

        bytes_read = fread(buf, 1, sizeof(buf), fp);
        if (bytes_read == 0) {
            LOG(0, "[FAILED] could not read hello file\n");
            perror(value);
            fclose(fp);
            exit(1);
        }
        fclose(fp);

        bytes_encoded = base64_encode(buf2, sizeof(buf2)-1, buf, bytes_read);
        buf2[bytes_encoded] = '\0';

        sprintf_s(foo, sizeof(foo), "hello-string[%u]", (unsigned)index);

        masscan_set_parameter(masscan, foo, buf2);
    } else if (EQUALS("hello-string", name)) {
        char *value2;
        struct TcpCfgPayloads *pay;

        value2 = (char*)malloc(strlen(value)+1);
        memcpy(value2, value, strlen(value)+1);

        pay = (struct TcpCfgPayloads *)malloc(sizeof(*pay));
        
        pay->payload_base64 = value2;
        pay->port = index;
        pay->next = masscan->tcp_payloads;
        masscan->tcp_payloads = pay;
    } else if (EQUALS("host-timeout", name)) {
        fprintf(stderr, "nmap(%s): unsupported: this is an asynchronous tool, so no timeouts\n", name);
        exit(1);
    } else if (EQUALS("http-user-agent", name)) {
        if (masscan->http_user_agent)
            free(masscan->http_user_agent);
        masscan->http_user_agent_length = (unsigned)strlen(value);
        masscan->http_user_agent = (unsigned char *)malloc(masscan->http_user_agent_length+1);
        memcpy( masscan->http_user_agent,
                value,
                masscan->http_user_agent_length+1
                );
    } else if (memcmp("http-header", name, 11) == 0) {
        unsigned j;
        unsigned name_length;
        char *newname;
        unsigned value_length = (unsigned)strlen(value);
        unsigned char *newvalue;

        /* allocate new value */
        newvalue = (unsigned char*)malloc(value_length+1);
        memcpy(newvalue, value, value_length+1);
        newvalue[value_length] = '\0';

        /* allocate a new name */
        name += 11;
        while (ispunct(*name))
            name++;
        name_length = (unsigned)strlen(name);
        while (name_length && ispunct(name[name_length-1]))
            name_length--;
        newname = (char*)malloc(name_length+1);
        memcpy(newname, name, name_length+1);
        newname[name_length] = '\0';


        for (j=0; j < sizeof(masscan->http_headers)/sizeof(masscan->http_headers[0]); j++) {
            if (masscan->http_headers[j].header_name == 0) {
                masscan->http_headers[j].header_name = newname;
                masscan->http_headers[j].header_value = newvalue;
                masscan->http_headers[j].header_value_length = value_length;
                return;
            }
        }

    } else if (EQUALS("iflist", name)) {
        masscan->op = Operation_List_Adapters;
    } else if (EQUALS("includefile", name)) {
        ranges_from_file(&masscan->targets, value);
    } else if (EQUALS("infinite", name)) {
        masscan->is_infinite = 1;
    } else if (EQUALS("interactive", name)) {
        masscan->output.is_interactive = 1;
    } else if (EQUALS("nointeractive", name)) {
        masscan->output.is_interactive = 0;
    } else if (EQUALS("ip-options", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
    } else if (EQUALS("log-errors", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
    } else if (EQUALS("min-packet", name) || EQUALS("min-pkt", name)) {
        masscan->min_packet_size = (unsigned)parseInt(value);
    } else if (EQUALS("max-retries", name)) {
        masscan_set_parameter(masscan, "retries", value);
    } else if (EQUALS("max-rate", name)) {
        masscan_set_parameter(masscan, "rate", value);
    } else if (EQUALS("min-hostgroup", name) || EQUALS("max-hostgroup", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we randomize all the groups!\n", name);
        exit(1);
    } else if (EQUALS("min-parallelism", name) || EQUALS("max-parallelism", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we all the parallel!\n", name);
        exit(1);
    } else if (EQUALS("min-rtt-timeout", name) || EQUALS("max-rtt-timeout", name) || EQUALS("initial-rtt-timeout", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we are asychronous, so no timeouts, no RTT tracking!\n", name);
        exit(1);
    } else if (EQUALS("min-rate", name)) {
        fprintf(stderr, "nmap(%s): unsupported, we go as fast as --max-rate allows\n", name);
        /* no exit here, since it's just info */
    } else if (EQUALS("mtu", name)) {
        fprintf(stderr, "nmap(%s): fragmentation not yet supported\n", name);
        exit(1);
    } else if (EQUALS("nmap", name)) {
        print_nmap_help();
        exit(1);
    } else if (EQUALS("pcap-payloads", name) || EQUALS("pcap-payload", name)) {
        if (masscan->payloads == NULL)
            masscan->payloads = payloads_create();
        payloads_read_pcap(value, masscan->payloads);
    } else if (EQUALS("nmap-payloads", name) || EQUALS("nmap-payload", name)) {
        FILE *fp;
        int err;
        err = fopen_s(&fp, value, "rt");
        if (err || fp == NULL) {
            perror(value);
        } else {
            if (masscan->payloads == NULL)
                masscan->payloads = payloads_create();
            payloads_read_file(fp, value, masscan->payloads);
            fclose(fp);
        }
    } else if (EQUALS("offline", name)) {
        /* Run in "offline" mode where it thinks it's sending packets, but
         * it's not */
        masscan->is_offline = 1;
    } else if (EQUALS("open", name) || EQUALS("open-only", name)) {
        masscan->output.is_show_open = 1;
        masscan->output.is_show_closed = 0;
        masscan->output.is_show_host = 0;
    } else if (EQUALS("output-status", name) || EQUALS("show", name)) {
        for (;;) {
            const char *val2 = value;
            unsigned val2_len = INDEX_OF(val2, ',');
            if (val2_len == 0)
                break;
            if (EQUALSx("open", val2, val2_len))
                masscan->output.is_show_open = 1;
            else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
                masscan->output.is_show_closed = 1;
            else if (EQUALSx("open", val2, val2_len))
                masscan->output.is_show_host = 1;
            else {
                LOG(0, "FAIL: unknown 'show' spec: %.*s\n", val2_len, val2);
                exit(1);
            }
            value += val2_len;
            while (*value == ',')
                value++;
        }
    } else if (EQUALS("noshow", name)) {
        for (;;) {
            const char *val2 = value;
            unsigned val2_len = INDEX_OF(val2, ',');
            if (val2_len == 0)
                break;
            if (EQUALSx("open", val2, val2_len))
                masscan->output.is_show_open = 0;
            else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
                masscan->output.is_show_closed = 0;
            else if (EQUALSx("open", val2, val2_len))
                masscan->output.is_show_host = 0;
            else {
                LOG(0, "FAIL: unknown 'show' spec: %.*s\n", val2_len, val2);
                exit(1);
            }
            value += val2_len;
            while (*value == ',')
                value++;
        }
    } else if (EQUALS("osscan-limit", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("osscan-guess", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("output-format", name)) {
        enum OutputFormat x = 0;
        if (EQUALS("interactive", value))
            masscan->output.format = Output_Interactive;
        else if (EQUALS("list", value))         x = Output_List;
        else if (EQUALS("xml", value))          x = Output_XML;
        else if (EQUALS("binary", value))       x = Output_Binary;
        else if (EQUALS("greppable", value))    x = Output_Grepable;
        else if (EQUALS("grepable", value))     x = Output_Grepable;
        else if (EQUALS("json", value))         x = Output_JSON;
        else if (EQUALS("certs", value))        x = Output_Certs;
        else if (EQUALS("none", value))         x = Output_None;
        else if (EQUALS("redis", value))        x = Output_Redis;
        else {
            LOG(0, "FAIL: unknown output-format: %s\n", value);
            LOG(0, "  hint: 'binary', 'xml', 'grepable', ...\n");
            exit(1);
        }
        masscan->output.format = x;
    } else if (EQUALS("output-filename", name) || EQUALS("output-file", name)) {
        if (masscan->output.format == 0)
            masscan->output.format = Output_XML;
        strcpy_s(masscan->output.filename,
                 sizeof(masscan->output.filename), 
                 value);
    } else if (EQUALS("pcap", name)) {
        strcpy_s(masscan->pcap_filename, sizeof(masscan->pcap_filename), value);
    } else if (EQUALS("packet-trace", name) || EQUALS("trace-packet", name)) {
        masscan->nmap.packet_trace = 1;
    } else if (EQUALS("privileged", name) || EQUALS("unprivileged", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("pfring", name)) {
        masscan->is_pfring = 1;
    } else if (EQUALS("port-ratio", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("randomize-hosts", name)) {
        /* already do that */
        ;
    } else if (EQUALS("readrange", name) || EQUALS("readranges", name)) {
        masscan->op = Operation_ReadRange;
    } else if (EQUALS("reason", name)) {
        masscan->output.is_reason = 1;
    } else if (EQUALS("redis", name)) {
        struct Range range;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(value);
        unsigned port = 6379;

        range = range_parse_ipv4(value, &offset, max_offset);
        if ((range.begin == 0 && range.end == 0) || range.begin != range.end) {
            LOG(0, "FAIL:  bad redis IP address: %s\n", value);
            exit(1);
        }
        if (offset < max_offset) {
            while (offset < max_offset && isspace(value[offset]))
                offset++;
            if (offset+1 < max_offset && value[offset] == ';' && isdigit(value[offset+1]&0xFF)) {
                port = strtoul(value+offset+1, 0, 0);
                if (port > 65535 || port == 0) {
                    LOG(0, "FAIL: bad redis port: %s\n", value+offset+1);
                    exit(1);
                }
            }
        }

        masscan->redis.ip = range.begin;
        masscan->redis.port = port;
        masscan->output.format = Output_Redis;
        strcpy_s(masscan->output.filename, 
                 sizeof(masscan->output.filename), 
                 "<redis>");
    } else if (EQUALS("release-memory", name)) {
        fprintf(stderr, "nmap(%s): this is our default option\n", name);
    } else if (EQUALS("resume", name)) {
        masscan_read_config_file(masscan, value);
        masscan_set_parameter(masscan, "output-append", "true");
    } else if (EQUALS("resume-index", name)) {
        masscan->resume.index = parseInt(value);
    } else if (EQUALS("resume-count", name)) {
        masscan->resume.count = parseInt(value);
    } else if (EQUALS("retries", name) || EQUALS("retry", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 1000) {
            fprintf(stderr, "error: retries=<n>: expected number less than 1000\n");
        } else {
            masscan->retries = x;
        }
    } else if (EQUALS("rotate-output", name) || EQUALS("rotate", name) 
        || EQUALS("ouput-rotate", name) || EQUALS("rotate-time", name) ) {
        masscan->output.rotate.timeout = (unsigned)parseTime(value);
    } else if (EQUALS("rotate-offset", name) || EQUALS("ouput-rotate-offset", name)) {
        masscan->output.rotate.offset = (unsigned)parseTime(value);
    } else if (EQUALS("rotate-size", name) || EQUALS("rotate-filesize", name)) {
        masscan->output.rotate.filesize = parseSize(value);
    } else if (EQUALS("rotate-dir", name) || EQUALS("rotate-directory", name) || EQUALS("ouput-rotate-dir", name)) {
        char *p;
        strcpy_s(   masscan->output.rotate.directory,
                    sizeof(masscan->output.rotate.directory),
                    value);

        /* strip trailing slashes */
        p = masscan->output.rotate.directory;
        while (*p && (p[strlen(p)-1] == '/' || p[strlen(p)-1] == '/'))
            p[strlen(p)-1] = '\0';
    } else if (EQUALS("script", name)) {
        if (!script_lookup(value)) {
            fprintf(stderr, "FAIL: script '%s' does not exist\n", value);
            fprintf(stderr, "  hint: most nmap scripts aren't supported\n");
            fprintf(stderr, "  hint: use '--script list' to list available scripts\n");
            exit(1);
        }
        if (masscan->script.name != NULL) {
            if (strcmp(masscan->script.name, value) == 0)
                return; /* ok */
            else {
                fprintf(stderr, "FAIL: only one script supported at a time\n");
                fprintf(stderr, "  hint: '%s' is existing script, '%s' is new script\n",
                        masscan->script.name, value);
                exit(1);
            }
        }
        
        masscan->script.name = script_lookup(value)->name;
    } else if (EQUALS("scan-delay", name) || EQUALS("max-scan-delay", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we do timing VASTLY differently!\n", name);
        exit(1);
    } else if (EQUALS("scanflags", name)) {
        fprintf(stderr, "nmap(%s): TCP scan flags not yet supported\n", name);
        exit(1);
    } else if (EQUALS("seed", name)) {
        if (EQUALS("time", value))
            masscan->seed = time(0);
        else
            masscan->seed = parseInt(value);
    } else if (EQUALS("sendq", name) || EQUALS("sendqueue", name)) {
        masscan->is_sendq = 1;
    } else if (EQUALS("send-eth", name)) {
        fprintf(stderr, "nmap(%s): unnecessary, we always do --send-eth\n", name);
    } else if (EQUALS("send-ip", name)) {
        fprintf(stderr, "nmap(%s): unsupported, we only do --send-eth\n", name);
        exit(1);
    } else if (EQUALS("selftest", name) || EQUALS("self-test", name) || EQUALS("regress", name)) {
        masscan->op = Operation_Selftest;
        return;
    } else if (EQUALS("benchmark", name)) {
        masscan->op = Operation_Benchmark;
        return;
    } else if (EQUALS("source-port", name) || EQUALS("sourceport", name)) {
        masscan_set_parameter(masscan, "adapter-port", value);
    } else if (EQUALS("shard", name) || EQUALS("shards", name)) {
        unsigned one = 0;
        unsigned of = 0;

        while (isdigit(*value))
            one = one*10 + (*(value++)) - '0';
        while (ispunct(*value))
            value++;
        while (isdigit(*value))
            of = of*10 + (*(value++)) - '0';

        if (one < 1) {
            LOG(0, "FAIL: shard index can't be zero\n");
            LOG(0, "hint   it goes like 1/4 2/4 3/4 4/4\n");
            exit(1);
        }
        if (one > of) {
            LOG(0, "FAIL: shard spec is wrong\n");
            LOG(0, "hint   it goes like 1/4 2/4 3/4 4/4\n");
            exit(1);
        }

        masscan->shard.one = one;
        masscan->shard.of = of;

    } else if (EQUALS("no-stylesheet", name)) {
        masscan->output.stylesheet[0] = '\0';
    } else if (EQUALS("stylesheet", name)) {
        strcpy_s(masscan->output.stylesheet, 
                 sizeof(masscan->output.stylesheet), 
                 value);
    } else if (EQUALS("system-dns", name)) {
        fprintf(stderr, "nmap(%s): DNS lookups will never be supported by this code\n", name);
        exit(1);
    } else if (EQUALS("top-ports", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("traceroute", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("test", name)) {
        if (EQUALS("csv", value))
            masscan->is_test_csv = 1;
    } else if (EQUALS("notest", name)) {
        if (EQUALS("csv", value))
            masscan->is_test_csv = 0;
    } else if (EQUALS("ttl", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 256) {
            fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        } else {
            masscan->nmap.ttl = x;
        }
    } else if (EQUALS("version", name)) {
        print_version();
        exit(1);
    } else if (EQUALS("version-intensity", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-light", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-all", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-trace", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("wait", name)) {
        if (EQUALS("forever", value))
            masscan->wait =  INT_MAX;
        else
            masscan->wait = (unsigned)parseInt(value);
    } else if (EQUALS("webxml", name)) {
        masscan_set_parameter(masscan, "stylesheet", "http://nmap.org/svn/docs/nmap.xsl");
    } else {
        fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
    }
}

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
static int
is_singleton(const char *name)
{
    static const char *singletons[] = {
        "echo", "selftest", "self-test", "regress",
        "benchmark",
        "system-dns", "traceroute", "version",
        "version-light",
        "version-all", "version-trace",
        "osscan-limit", "osscan-guess",
        "badsum", "reason", "open", "open-only",
        "packet-trace", "release-memory",
        "log-errors", "append-output", "webxml", "no-stylesheet",
        "no-stylesheet", "heartbleed",
        "send-eth", "send-ip", "iflist", "randomize-hosts",
        "nmap", "trace-packet", "pfring", "sendq",
        "banners", "banner", "nobanners", "nobanner",
        "offline", "ping", "ping-sweep",
        "arp",  "infinite", "interactive",
        "read-range", "read-ranges", "readrange", "read-ranges",
        0};
    size_t i;

    for (i=0; singletons[i]; i++) {
        if (EQUALS(singletons[i], name))
            return 1;
    }
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void
masscan_help()
{
    printf(
"MASSCAN is a fast port scanner. The primary input parameters are the\n"
"IP addresses/ranges you want to scan, and the port numbers. An example\n"
"is the following, which scans the 10.x.x.x network for web servers:\n"
" masscan 10.0.0.0/8 -p80\n"
"The program auto-detects network interface/adapter settings. If this\n"
"fails, you'll have to set these manually. The following is an\n"
"example of all the parameters that are needed:\n"
" --adapter-ip 192.168.10.123\n"
" --adapter-mac 00-11-22-33-44-55\n"
" --router-mac 66-55-44-33-22-11\n"
"Parameters can be set either via the command-line or config-file. The\n"
"names are the same for both. Thus, the above adapter settings would\n"
"appear as follows in a configuration file:\n"
" adapter-ip = 192.168.10.123\n"
" adapter-mac = 00-11-22-33-44-55\n"
" router-mac = 66-55-44-33-22-11\n"
"All single-dash parameters have a spelled out double-dash equivalent,\n"
"so '-p80' is the same as '--ports 80' (or 'ports = 80' in config file).\n"
"To use the config file, type:\n"
" masscan -c <filename>\n"
"To generate a config-file from the current settings, use the --echo\n"
"option. This stops the program from actually running, and just echoes\n"
"the current configuration instead. This is a useful way to generate\n"
"your first config file, or see a list of parameters you didn't know\n"
"about. I suggest you try it now:\n"
" masscan -p1234 --echo\n");
    exit(1);
}

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
masscan_command_line(struct Masscan *masscan, int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {

        /*
         * --name=value
         * --name:value
         * -- name value
         */
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strcmp(argv[i], "--help") == 0) {
                masscan_help();
            } else if (EQUALS("readscan", argv[i]+2)) {
                /* Read in a binary file instead of scanning the network*/
                masscan->op = Operation_ReadScan;
                
                /* Default to reading banners */
                masscan->is_banners = 1;

                /* This option may be followed by many filenames, therefore,
                 * skip forward in the argument list until the next
                 * argument */
                while (i+1 < argc && argv[i+1][0] != '-')
                    i++;
                continue;
            } else {
                char name2[64];
                char *name = argv[i] + 2;
                unsigned name_length;
                const char *value;

                value = strchr(&argv[i][2], '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value == NULL) {
                    if (is_singleton(name))
                        value = "";
                    else
                        value = argv[++i];
                    name_length = (unsigned)strlen(name);
                } else {
                    name_length = (unsigned)(value - name);
                    value++;
                }

                if (i >= argc) {
                    fprintf(stderr, "%.*s: empty parameter\n", name_length, name);
                    break;
                }

                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, name);
                    name_length = sizeof(name2) - 1;
                }

                memcpy(name2, name, name_length);
                name2[name_length] = '\0';

                masscan_set_parameter(masscan, name2, value);
            }
            continue;
        }

        /* For for a single-dash parameter */
        if (argv[i][0] == '-') {
            const char *arg;

            switch (argv[i][1]) {
            case '6':
                fprintf(stderr, "nmap(%s): unsupported: maybe one day\n", argv[i]);
                exit(1);
            case 'A':
                fprintf(stderr, "nmap(%s): unsupported: this tool only does SYN scan\n", argv[i]);
                exit(1);
            case 'b':
                fprintf(stderr, "nmap(%s): FTP bounce scans will never be supported\n", argv[i]);
                exit(1);
            case 'c':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_read_config_file(masscan, arg);
                break;
            case 'd': /* just do same as verbosity level */
                {
                    int v;
                    for (v=1; argv[i][v] == 'd'; v++) {
                        LOG_add_level(1);
                    }
                }
                break;
            case 'e':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter", arg);
                break;
            case 'f':
                fprintf(stderr, "nmap(%s): fragmentation not yet supported\n", argv[i]);
                exit(1);
            case 'F':
                fprintf(stderr, "nmap(%s): unsupported, no slow/fast mode\n", argv[i]);
                exit(1);
            case 'g':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter-port", arg);
                break;
            case 'h':
            case '?':
                masscan_usage();
                break;
            case 'i':
                if (argv[i][3] == '\0' && !isdigit(argv[i][2]&0xFF)) {
                    /* This looks like an nmap option*/
                    switch (argv[i][2]) {
                    case 'L':
                        masscan_set_parameter(masscan, "includefile", argv[++i]);
                        break;
                    case 'R':
                        /* -iR in nmap makes it randomize addresses completely. Thus,
                         * it's nearest equivalent is scanning the entire Internet range */
                        masscan_set_parameter(masscan, "include", "0.0.0.0/0");
                        break;
                    default:
                        fprintf(stderr, "nmap(%s): unsupported option\n", argv[i]);
                        exit(1);
                    }

                } else {
                    if (argv[i][2])
                        arg = argv[i]+2;
                    else
                        arg = argv[++i];

                    masscan_set_parameter(masscan, "adapter", arg);
                }
                break;
            case 'n':
                /* This looks like an nmap option*/
                /* Do nothing: this code never does DNS lookups anyway */
                break;
            case 'o': /* nmap output format */
                switch (argv[i][2]) {
                case 'A':
                    masscan->output.format = Output_All;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'B':
                    masscan->output.format = Output_Binary;
                    break;
                case 'J':
                    masscan->output.format = Output_JSON;
                    break;
                case 'N':
                    masscan->output.format = Output_Nmap;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'X':
                    masscan->output.format = Output_XML;
                    break;
                case 'R':
                    masscan->output.format = Output_Redis;
                    if (i+1 < argc && argv[i+1][0] != '-')
                        masscan_set_parameter(masscan, "redis", argv[i+1]);
                    break;
                case 'S':
                    masscan->output.format = Output_ScriptKiddie;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'G':
                    masscan->output.format = Output_Grepable;
                    break;
                case 'L':
                    masscan_set_parameter(masscan, "output-format", "list");
                    break;
                default:
                    fprintf(stderr, "nmap(%s): unknown output format\n", argv[i]);
                    exit(1);
                }

                ++i;
                if (i >= argc || (argv[i][0] == '-' && argv[i][1] != '\0')) {
                    fprintf(stderr, "missing output filename\n");
                    exit(1);
                }

                masscan_set_parameter(masscan, "output-filename", argv[i]);
                break;
            case 'O':
                fprintf(stderr, "nmap(%s): unsupported, OS detection is too complex\n", argv[i]);
                exit(1);
                break;
            case 'p':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "ports", arg);
                break;
            case 'P':
                switch (argv[i][2]) {
                case 'n':
                    /* we already do this */
                    break;
                default:
                    fprintf(stderr, "nmap(%s): unsupported option, maybe in future\n", argv[i]);
                    exit(1);
                }
                break;
            case 'r':
                /* This looks like an nmap option*/
                fprintf(stderr, "nmap(%s): wat? randomization is our raison d'etre!! rethink prease\n", argv[i]);
                exit(1);
                break;
            case 'R':
                /* This looks like an nmap option*/
                fprintf(stderr, "nmap(%s): unsupported. This code will never do DNS lookups.\n", argv[i]);
                exit(1);
                break;
            case 's': /* NMAP: scan type */
                if (argv[i][3] == '\0' && !isdigit(argv[i][2]&0xFF)) {
                    unsigned j;

                    for (j=2; argv[i][j]; j++)
                    switch (argv[i][j]) {
                    case 'A':
                        fprintf(stderr, "nmap(%s): ACK scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'C':
                        fprintf(stderr, "nmap(%s): unsupported\n", argv[i]);
                        exit(1);
                    case 'F':
                        fprintf(stderr, "nmap(%s): FIN scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'I':
                        fprintf(stderr, "nmap(%s): Zombie scans will never be supported\n", argv[i]);
                        exit(1);
                    case 'L': /* List Scan - simply list targets to scan */
                        masscan->op = Operation_ListScan;
                        break;
                    case 'M':
                        fprintf(stderr, "nmap(%s): Maimon scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'n': /* Ping Scan - disable port scan */
                        fprintf(stderr, "nmap(%s): ping-sweeps not yet supported\n", argv[i]);
                        exit(1);
                    case 'N':
                        fprintf(stderr, "nmap(%s): NULL scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'O':
                        fprintf(stderr, "nmap(%s): IP proto scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'S': /* TCP SYN scan - THIS IS WHAT WE DO! */
                        break;
                    case 'T': /* TCP connect scan */
                        fprintf(stderr, "nmap(%s): connect() is too synchronous for cool kids\n", argv[i]);
                        fprintf(stderr, "WARNING: doing SYN scan anyway\n");
                        break;
                    case 'U': /* UDP scan */
                        break;
                    case 'V':
                        fprintf(stderr, "nmap(%s): unlikely this will be supported\n", argv[i]);
                        exit(1);
                    case 'W':
                        fprintf(stderr, "nmap(%s): Windows scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'X':
                        fprintf(stderr, "nmap(%s): Xmas scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'Y':
                        break;
                    case 'Z':
                        fprintf(stderr, "nmap(%s): SCTP scan not yet supported\n", argv[i]);
                        exit(1);
                    default:
                        fprintf(stderr, "nmap(%s): unsupported option\n", argv[i]);
                        exit(1);
                    }

                } else {
                    fprintf(stderr, "%s: unknown parameter\n", argv[i]);
                    exit(1);
                }
                break;
            case 'S':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter-ip", arg);
                break;
            case 'v':
                {
                    int v;
                    for (v=1; argv[i][v] == 'v'; v++)
                        LOG_add_level(1);
                }
                break;
            case 'V': /* print version and exit */
                masscan_set_parameter(masscan, "version", "");
                break;
            case 'W':
                masscan->op = Operation_List_Adapters;
                return;
            case 'T':
                fprintf(stderr, "nmap(%s): unsupported, we do timing WAY different than nmap\n", argv[i]);
                exit(1);
                return;
            default:
                LOG(0, "FAIL: unknown option: -%s\n", argv[i]);
                LOG(0, " [hint] try \"--help\"\n");
                LOG(0, " [hint] ...or, to list nmap-compatible options, try \"--nmap\"\n");
                exit(1);
            }
            continue;
        }

        if (!isdigit(argv[i][0])) {
            fprintf(stderr, "FAIL: unknown command-line parameter \"%s\"\n", argv[i]);
            fprintf(stderr, " [hint] did you want \"--%s\"?\n", argv[i]);
            exit(1);
        }

        /* If parameter doesn't start with '-', assume it's an
         * IPv4 range
         */
        masscan_set_parameter(masscan, "range", argv[i]);
    }
}

/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void
trim(char *line, size_t sizeof_line)
{
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
}

/***************************************************************************
 ***************************************************************************/
void
masscan_read_config_file(struct Masscan *masscan, const char *filename)
{
    FILE *fp;
    errno_t err;
    char line[65536];

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line, sizeof(line));

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name, sizeof(line));
        trim(value, sizeof(line));

        masscan_set_parameter(masscan, name, value);
    }

    fclose(fp);
}



/***************************************************************************
 ***************************************************************************/
int masscan_conf_contains(const char *x, int argc, char **argv)
{
    int i;

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], x) == 0)
            return 1;
    }

    return 0;
}


/***************************************************************************
 ***************************************************************************/
int
mainconf_selftest()
{
    char test[] = " test 1 ";

    trim(test, sizeof(test));
    if (strcmp(test, "test 1") != 0)
        return 1; /* failure */

    {
        struct Range range;

        range.begin = 16;
        range.end = 32-1;
        if (count_cidr_bits(range) != 28)
            return 1;

        range.begin = 1;
        range.end = 13;
        if (count_cidr_bits(range) != 0)
            return 1;


    }

    /* */
    {
        int argc = 6;
        char *argv[] = { "foo", "bar", "-ddd", "--readscan", "xxx", "--something" };
    
        if (masscan_conf_contains("--nothing", argc, argv))
            return 1;

        if (!masscan_conf_contains("--readscan", argc, argv))
            return 1;
    }

    return 0;
}

