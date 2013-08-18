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
#include "ranges.h"
#include "string_s.h"

#include <ctype.h>


extern int verbosity; /* logger.c */

/***************************************************************************
 ***************************************************************************/
void masscan_usage(void)
{
    printf("usage:\n");
    printf("masscan --echo\n");
    printf(" view default configuration\n");
    printf("masscan -c mass.conf -p80,8000-8100 10.0.0.0/8 --rate=10000\n");
    printf(" scan some web ports on 10.x.x.x at 10kpps\n");
	exit(1);
}

/***************************************************************************
 ***************************************************************************/
static void
parse_port_list(struct RangeList *ports, const char *string)
{
	char *p = (char*)string;

	while (*p) {
		unsigned port;
		unsigned end;

		while (*p && isspace(*p & 0xFF))
			p++;
		if (*p == 0)
			break;

		port = strtoul(p, &p, 0);
		end = port;
		if (*p == '-') {
			p++;
			end = strtoul(p, &p, 0);
		}
		if (*p == ',')
			p++;

		if (port > 0xFFFF || end > 0xFFFF || end < port) {
			fprintf(stderr, "CONF: bad ports: %u-%u\n", port, end);
			break;
		} else {
			rangelist_add_range(ports, port, end);
		}
	}
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all setable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void
masscan_echo(struct Masscan *masscan)
{
    unsigned i;

    printf("rate = %10.2f\n", masscan->max_rate);
    printf("adapter = %s\n", masscan->ifname);
    printf("adapter-ip = %u.%u.%u.%u\n", 
        (masscan->adapter_ip>>24)&0xFF,
        (masscan->adapter_ip>>16)&0xFF,
        (masscan->adapter_ip>> 8)&0xFF,
        (masscan->adapter_ip>> 0)&0xFF
        );
    printf("adapter.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            masscan->adapter_mac[0],
            masscan->adapter_mac[1],
            masscan->adapter_mac[2],
            masscan->adapter_mac[3],
            masscan->adapter_mac[4],
            masscan->adapter_mac[5]);
    printf("router.mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
            masscan->router_mac[0],
            masscan->router_mac[1],
            masscan->router_mac[2],
            masscan->router_mac[3],
            masscan->router_mac[4],
            masscan->router_mac[5]);

    /*
     * PORTS
     */
    printf("ports = ");
    for (i=0; i<masscan->ports.count; i++) {
        struct Range range = masscan->ports.list[i];
        if (range.begin == range.end)
            printf("%u", range.begin);
        else
            printf("%u-%u", range.begin, range.end);
        if (i+1 < masscan->ports.count)
            printf(",");
    }
    if (masscan->ports.count == 0)
        printf("65536,70000-80000");
    printf("\n");

    /*
     * RANGES
     */
    for (i=0; i<masscan->targets.count; i++) {
        struct Range range = masscan->targets.list[i];
        printf("range = ");
        printf("%u.%u.%u.%u", 
            (range.begin>>24)&0xFF,
            (range.begin>>16)&0xFF,
            (range.begin>> 8)&0xFF,
            (range.begin>> 0)&0xFF
            );
        if (range.begin != range.end) {
            printf("-%u.%u.%u.%u", 
                (range.end>>24)&0xFF,
                (range.end>>16)&0xFF,
                (range.end>> 8)&0xFF,
                (range.end>> 0)&0xFF
                );
        }
        printf("\n");
    }

    if (masscan->targets.count == 0) {
        printf("range = 0.0.0.0-0.0.0.0\n");
        printf("range = 0.0.0.0/32\n");
    }

    /*
     * EXCLUDE
     */
    for (i=0; i<masscan->exclude_ip.count; i++) {
        struct Range range = masscan->exclude_ip.list[i];
        printf("exclude = ");
        printf("%u.%u.%u.%u", 
            (range.begin>>24)&0xFF,
            (range.begin>>16)&0xFF,
            (range.begin>> 8)&0xFF,
            (range.begin>> 0)&0xFF
            );
        if (range.begin != range.end) {
            printf("-%u.%u.%u.%u", 
                (range.end>>24)&0xFF,
                (range.end>>16)&0xFF,
                (range.end>> 8)&0xFF,
                (range.end>> 0)&0xFF
                );
        }
        printf("\n");
    }

    if (masscan->targets.count == 0) {
        printf("exclude = 255.255.255.255-255.255.255.255\n");
        printf("exclude = 255.255.255.255/32\n");
    }

}

/***************************************************************************
 ***************************************************************************/
void ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    errno_t err;


    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        exit(1); /* HARD EXIT: because if it's an exclusion file, we don't 
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    /* for all lines */
    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                if (c == '\n')
                    break;
            }
            continue;
        }

        /*
         * Read all space delimited entries
         */
        while (!feof(fp) && c != '\n') {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;

            /* fetch next address range */
            i = 0;
            while (!feof(fp)) {
                c = getc(fp);
                if (isspace(c&0xFF))
                    break;
                if (i+1 < sizeof(address))
                    address[i] = (char)c;
            }
            address[i] = '\0';

            /* parse the address range */
			range = range_parse_ipv4(address, &offset, (unsigned)i);
			if (range.begin == 0 && range.end == 0) {
				fprintf(stderr, "bad range spec: %s\n", address);
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
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
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
 * Called either from the "command-line" parser when it sees a --parm,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
void
masscan_set_parameter(struct Masscan *masscan, const char *name, const char *value)
{
#define EQUALS(lhs, rhs) (strcmp(lhs, rhs)==0)

    if (EQUALS("conf", name) || EQUALS("config", name)) {
        masscan_read_config_file(masscan, value);
    } else if (EQUALS("adapter", name) || EQUALS("if", name) || EQUALS("interface", name)) {
        if (masscan->ifname[0]) {
            fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", masscan->ifname);
        }
		sprintf_s(masscan->ifname, sizeof(masscan->ifname), "%s", value);
    }
    else if (EQUALS("adapter-ip", name) || EQUALS("adapter.ip", name) || EQUALS("adapterip", name)) {
			struct Range range;

			range = range_parse_ipv4(value, 0, 0);
			if (range.begin == 0 && range.end == 0) {
				fprintf(stderr, "CONF: bad IPv4 address: %s=%s\n", name, value);
                return;
			}

            masscan->adapter_ip = range.begin;
    } else if (EQUALS("adapter-port", name) || EQUALS("adapterport", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x > 65535) {
            fprintf(stderr, "error: %s=<n>: expected number less than 1000\n", name);
        } else {
            masscan->adapter_port = x;
        }
    } else if (EQUALS("adapter-mac", name) || EQUALS("adapter.mac", name) || EQUALS("adaptermac", name) || EQUALS("spoof-mac", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(masscan->adapter_mac, mac, 6);
    }
    else if (EQUALS("router-mac", name) || EQUALS("router.mac", name) || EQUALS("routermac", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(masscan->router_mac, mac, 6);
    }
    else if (EQUALS("rate", name) || EQUALS("maxrate", name) || EQUALS("max.rate", name) ) {
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
                    fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n", name, value);
                    return;
                }
                rate += (c - '0')/point;
                point /= 10.0;
                value++;
            }
        }

        masscan->max_rate = rate;
        
    }
    else if (EQUALS("ports", name) || EQUALS("port", name)) {
    	parse_port_list(&masscan->ports, value);
		masscan->op = Operation_Scan;
    }
    else if (
            EQUALS("exclude-ports", name) || EQUALS("exclude-port", name) ||
            EQUALS("exclude.ports", name) || EQUALS("exclude.port", name) ||
            EQUALS("excludeports", name) || EQUALS("excludeport", name)
        ) {
    	parse_port_list(&masscan->exclude_port, value);
    }
    else if (EQUALS("range", name) || EQUALS("ranges", name) || EQUALS("ip", name) || EQUALS("ipv4", name)) {
        const char *ranges = value;
        unsigned offset = 0;
		unsigned max_offset = (unsigned)strlen(ranges);

		for (;;) {
			struct Range range;

			range = range_parse_ipv4(ranges, &offset, max_offset);
			if (range.begin == 0 && range.end == 0) {
				fprintf(stderr, "CONF: bad range spec: %s\n", ranges);
				break;
			}

			rangelist_add_range(&masscan->targets, range.begin, range.end);

			if (offset >= max_offset || ranges[offset] != ',')
				break;
			else
				offset++; /* skip comma */
		}
      	masscan->op = Operation_Scan;
    }
    else if (   
                EQUALS("exclude", name) || 
                EQUALS("exclude-range", name) || 
                EQUALS("excluderange", name) || 
                EQUALS("exclude-ranges", name) || 
                EQUALS("excluderanges", name) || 
                EQUALS("exclude-ip", name) || 
                EQUALS("excludeip", name) || 
                EQUALS("exclude-ipv4", name) ||
                EQUALS("excludeipv4", name)
                ) {
        const char *ranges = value;
        unsigned offset = 0;
		unsigned max_offset = (unsigned)strlen(ranges);

		for (;;) {
			struct Range range;

			range = range_parse_ipv4(ranges, &offset, max_offset);
			if (range.begin == 0 && range.end == 0) {
				fprintf(stderr, "CONF: bad range spec: %s\n", ranges);
				break;
			}

			rangelist_add_range(&masscan->exclude_ip, range.begin, range.end);

			if (offset >= max_offset || ranges[offset] != ',')
				break;
			else
				offset++; /* skip comma */
		}
      	masscan->op = Operation_Scan;
    } else if (EQUALS("append-output", name)) {
        masscan->nmap.append = 1;
    } else if (EQUALS("badsum", name)) {
        masscan->nmap.badsum = 1;
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
        fprintf(stderr, "nmap(%s): DNS lookups will never be supported by this code\n", name);
        exit(1);
    } else if (EQUALS("echo", name)) {
        masscan_echo(masscan);
        exit(1);
    } else if (EQUALS("excludefile", name) || EQUALS("exclude-file", name) || EQUALS("exclude.file", name)) {
        ranges_from_file(&masscan->exclude_ip, value);
    } else if (EQUALS("host-timeout", name)) {
        fprintf(stderr, "nmap(%s): unsupported: this is an asynchronous tool, so no timeouts\n", name);
        exit(1);
    } else if (EQUALS("iflist", name)) {
		masscan->op = Operation_List_Adapters;
    } else if (EQUALS("includefile", name) || EQUALS("include-file", name) || EQUALS("include.file", name)) {
        ranges_from_file(&masscan->targets, value);
    } else if (EQUALS("ip-options", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
    } else if (EQUALS("log-errors", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
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
    } else if (EQUALS("open", name)) {
        /* This is the default behavior */
    } else if (EQUALS("osscan-limit", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("osscan-guess", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("packet-trace", name)) {
        masscan->nmap.packet_trace = 1;
    } else if (EQUALS("privileged", name) || EQUALS("unprivileged", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("port-ratio", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("randomize-hosts", name)) {
        /* already do that */
        ;
    } else if (EQUALS("reason", name)) {
        masscan->nmap.reason = 1;
    } else if (EQUALS("release-memory", name)) {
        fprintf(stderr, "nmap(%s): this is our default option\n", name);
    } else if (EQUALS("resume", name)) {
        fprintf(stderr, "nmap(%s): unsupported now, but we'll fix that soon!\n", name);
        exit(1);
    } else if (EQUALS("retries", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 1000) {
            fprintf(stderr, "error: retries=<n>: expected number less than 1000\n");
        } else {
            masscan->retries = x;
        }
    } else if (EQUALS("script", name)) {
        fprintf(stderr, "nmap(%s): unsupported, it's too complex for this simple scanner\n", name);
        exit(1);
    } else if (EQUALS("scan-delay", name) || EQUALS("max-scan-delay", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we do timing VASTLY differently!\n", name);
        exit(1);
    } else if (EQUALS("scanflags", name)) {
        fprintf(stderr, "nmap(%s): TCP scan flags not yet supported\n", name);
        exit(1);
    } else if (EQUALS("send-eth", name)) {
        fprintf(stderr, "nmap(%s): unnecessary, we always do --send-eth\n", name);
    } else if (EQUALS("send-ip", name)) {
        fprintf(stderr, "nmap(%s): unsupported, we only do --send-eth\n", name);
        exit(1);
    } else if (EQUALS("selftest", name) || EQUALS("self-test", name) || EQUALS("regress", name)) {
        masscan->op = Operation_Selftest;
        return;
    } else if (EQUALS("source-port", name) || EQUALS("sourceport", name)) {
        masscan_set_parameter(masscan, "adapter-port", value);
    } else if (EQUALS("no-stylesheet", name)) {
        masscan->nmap.stylesheet[0] = '\0';
    } else if (EQUALS("stylesheet", name)) {
        strcpy_s(masscan->nmap.stylesheet, sizeof(masscan->nmap.stylesheet), value);
    } else if (EQUALS("system-dns", name)) {
        fprintf(stderr, "nmap(%s): DNS lookups will never be supported by this code\n", name);
        exit(1);
    } else if (EQUALS("top-ports", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("traceroute", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("ttl", name)) {
        unsigned x = strtoul(value, 0, 0);
        if (x >= 256) {
            fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        } else {
            masscan->nmap.ttl = x;
        }
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
        "system-dns", "traceroute", "version-light",
        "version-all", "version-trace",
        "osscan-limit", "osscan-guess",
        "badsum", "reason", "open",
        "packet-trace", "release-memory",
        "log-errors", "append-output", "webxml", "no-stylesheet",
        "no-stylesheet",
        "send-eth", "send-ip", "iflist", "randomize-hosts",
        0};
    size_t i;

    for (i=0; singletons[i]; i++) {
        if (EQUALS(singletons[i], name))
            return 1;
    }
    return 0;
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
			if (strcmp(argv[i], "--help") == 0)
				masscan_usage();
			else {
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
                    for (v=1; argv[i][v] == 'v'; v++)
                        verbosity++;
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
                        fprintf(stderr, "nmap(%s): quasi-supported, see documentation\n", argv[i]);
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
                    masscan->nmap.format = Output_All;
                    break;
                case 'N':
                    masscan->nmap.format = Output_Normal;
                    break;
                case 'X':
                    masscan->nmap.format = Output_XML;
                    break;
                case 'S':
                    masscan->nmap.format = Output_ScriptKiddie;
                    break;
                case 'G':
                    masscan->nmap.format = Output_Grepable;
                    break;
                default:
                    fprintf(stderr, "nmap(%s): unknown output format\n", argv[i]);
                    exit(1);
                }

                ++i;
                if (i >= argc || argv[i][0] == '-') {
                    fprintf(stderr, "missing output filename\n");
                    exit(1);
                }
                strcpy_s(masscan->nmap.filename, sizeof(masscan->nmap.filename), argv[i]);
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
            case 's':
                if (argv[i][3] == '\0' && !isdigit(argv[i][2]&0xFF)) {
                    /* This looks like an nmap option*/
                    switch (argv[i][2]) {
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
                        fprintf(stderr, "nmap(%s): list scan unsupported\n", argv[i]);
                        exit(1);
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
                    case 'S': /* SYN scan - THIS IS WHAT WE DO! */
                        break;
                    case 'T':
                        fprintf(stderr, "nmap(%s): connect() is too synchronous for cool kids\n", argv[i]);
                        exit(1);
                    case 'U':
                        fprintf(stderr, "nmap(%s): UDP scan not yet supported\n", argv[i]);
                        exit(1);
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
                        fprintf(stderr, "nmap(%s): SCTP scan not yet supported\n", argv[i]);
                        exit(1);
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
                        verbosity++;
                }
                break;
            case 'V': /* print version and exit */
                exit(1);
                break;
			case 'W':
				masscan->op = Operation_List_Adapters;
				return;
            case 'T':
                fprintf(stderr, "nmap(%s): unsupported, we do timing WAY different than nmap\n", argv[i]);
                exit(1);
                return;
			default:
				fprintf(stderr, "unknown option: %s\n", argv[i]);
			}
			continue;
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
trim(char *line)
{
    while (isspace(*line & 0xFF))
        memmove(line, line+1, strlen(line));
    while (isspace(line[strlen(line)-1] & 0xFF))
        line[strlen(line)-1] = '\0';
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
        exit(1);
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line);

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name);
        trim(value);

        masscan_set_parameter(masscan, name, value);
    }

    fclose(fp);
}
