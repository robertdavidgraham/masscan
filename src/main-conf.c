/*
	Read in the configuration for MASSCAN.

	Configuration parameters can be read either from the command-line
	or a configuration file. Parameters have the same name in both.
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
    printf("masscan -T\n");
    printf(" run an offline regression test (no transmit)\n");
    printf("masscan --echo\n");
    printf(" view current configuration\n");
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

unsigned
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

int parse_mac_address(const char *text, unsigned char *mac)
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
    }
    else if (EQUALS("adapter-mac", name) || EQUALS("adapter.mac", name) || EQUALS("adaptermac", name)) {
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
    }
    else if (EQUALS("excludefile", name) || EQUALS("exclude-file", name) || EQUALS("exclude.file", name)) {
        ranges_from_file(&masscan->exclude_ip, value);
    }
    else if (EQUALS("includefile", name) || EQUALS("include-file", name) || EQUALS("include.file", name)) {
        ranges_from_file(&masscan->targets, value);
    }
    else if (EQUALS("debug", name)) {
        if (EQUALS("if", value)) {
            masscan->op = Operation_DebugIF;
        }
    }
    else if (EQUALS("echo", name)) {
        masscan_echo(masscan);
        exit(1);
    }
    else if (EQUALS("selftest", name) || EQUALS("self-test", name)) {
        masscan->op = Operation_Selftest;
        return;
    } else {
        fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
    }
}

static int
is_singleton(const char *name)
{
    if (EQUALS("echo", name)) return 1;
    if (EQUALS("selftest", name)) return 1;
    if (EQUALS("self-test", name)) return 1;
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
			case 'c':
				if (argv[i][2])
					arg = argv[i]+2;
				else
					arg = argv[++i];
                masscan_read_config_file(masscan, arg);
                break;

            case 'v':
                {
                    int v;
                    for (v=1; argv[i][v] == 'v'; v++)
                        verbosity++;
                }
                break;
			case 'i':
				if (argv[i][2])
					arg = argv[i]+2;
				else
					arg = argv[++i];
                masscan_set_parameter(masscan, "adapter", arg);
				break;
			case 'h':
			case '?':
				masscan_usage();
				break;
			case 'p':
				if (argv[i][2])
					arg = argv[i]+2;
				else
					arg = argv[++i];
                masscan_set_parameter(masscan, "ports", arg);
				break;
			case 'W':
				masscan->op = Operation_List_Adapters;
				return;
            case 'T':
                masscan->op = Operation_Selftest;
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
void masscan_read_config_file(struct Masscan *masscan, const char *filename)
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

}
