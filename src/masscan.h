#ifndef MASSCAN_H
#define MASSCAN_H
#include "string_s.h"
#include "main-src.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "ranges.h"
#include "ranges6.h"
#include "packet-queue.h"

struct Adapter;
struct TemplateSet;
struct Banner1;

/**
 * This is the "operationg" to be performed by masscan, which is almost always
 * to "scan" the network. However, there are some lesser operations to do
 * instead, like run a "regression self test", or "debug", or something else
 * instead of scanning. We parse the command-line in order to figure out the
 * proper operation
 */
enum Operation {
    Operation_Default = 0,          /* nothing specified, so print usage */
    Operation_List_Adapters = 1,    /* --listif */
    Operation_Selftest = 2,         /* --selftest or --regress */
    Operation_Scan = 3,         /* this is what you expect */
    Operation_DebugIF = 4,          /* --debug if */
    Operation_ListScan = 5,         /* -sL */
    Operation_ReadScan = 6,         /* --readscan <binary-output> */
    Operation_ReadRange = 7,        /* --readrange */
    Operation_Benchmark = 8,        /* --benchmark */
};

/**
 * The format of the output. If nothing is specified, then the default will
 * be "--interactive", meaning that we'll print to the command-line live as
 * results come in. Only one output format can be specified, except that
 * "--interactive" can be specified alongside any of the other ones.
 */
enum OutputFormat {
    Output_Default      = 0x0000,
    Output_Interactive  = 0x0001,   /* --interactive, print to cmdline */
    Output_List         = 0x0002,
    Output_Binary       = 0x0004,   /* -oB, "binary", the primary format */
    Output_XML          = 0x0008,   /* -oX, "xml" */
    Output_JSON         = 0x0010,   /* -oJ, "json" */
    Output_NDJSON       = 0x0011,   /* -oD, "ndjson" */
    Output_Nmap         = 0x0020,
    Output_ScriptKiddie = 0x0040,
    Output_Grepable     = 0x0080,   /* -oG, "grepable" */
    Output_Redis        = 0x0100, 
    Output_Unicornscan  = 0x0200,   /* -oU, "unicornscan" */
    Output_None         = 0x0400,
    Output_Certs        = 0x0800,
    Output_All          = 0xFFBF,   /* not supported */
};


/**
 * Holds the list of TCP "hello" payloads, specified with the "--hello-file"
 * or "--hello-string" options
 */
struct TcpCfgPayloads
{
    /** The "hello" data in base64 format. This is either the base64 string
     * specified in the cmdline/cfgfile with "--hello-string", or the 
     * contents of a file specified with "--hello-file" that we've converted
     * into base64 */
    char *payload_base64;
    
    /** The TCP port that this hello belongs to */
    unsigned port;
    
    /** These configuration options are stored as a linked-list */
    struct TcpCfgPayloads *next;
};




/**
 * This is the master MASSCAN configuration structure. It is created on startup
 * by reading the command-line and parsing configuration files.
 *
 * Once read in at the start, this structure doesn't change. The transmit
 * and receive threads have only a "const" pointer to this structure.
 */
struct Masscan
{
    /**
     * What this progrma is doing, which is normally "Operation_Scan", but
     * which can be other things, like "Operation_SelfTest"
     */
    enum Operation op;
    
    struct {
        unsigned tcp:1;
        unsigned udp:1;     /* -sU */
        unsigned sctp:1;
        unsigned ping:1;    /* --ping, ICMP echo */
        unsigned arp:1;     /* --arp, local ARP scan */
        unsigned oproto:1;  /* -sO */
    } scan_type;
    
    /**
     * After scan type has been configured, add these ports
     */
    unsigned top_ports;
    
    /**
     * Temporary file to echo parameters to, used for saving configuration
     * to a file
     */
    FILE *echo;
    unsigned echo_all;

    /**
     * One or more network adapters that we'll use for scanning. Each adapter
     * should have a separate set of IP source addresses, except in the case
     * of PF_RING dnaX:Y adapters.
     */
    struct {
        char ifname[256];
        struct Adapter *adapter;
        struct Source src;
        unsigned char my_mac[6];
        unsigned char router_mac[6];
        unsigned router_ip;
        int link_type; /* libpcap definitions */
        unsigned char my_mac_count; /*is there a MAC address? */
        unsigned vlan_id;
        unsigned is_vlan:1;
    } nic[8];
    unsigned nic_count;

    /**
     * The target ranges of IPv4 addresses that are included in the scan.
     * The user can specify anything here, and we'll resolve all overlaps
     * and such, and sort the target ranges.
     */
    struct RangeList targets;
    struct Range6List targets_ipv6;

    /**
     * The ports we are scanning for. The user can specify repeated ports
     * and overlapping ranges, but we'll deduplicate them, scanning ports
     * only once.
     * NOTE: TCP ports are stored 0-64k, but UDP ports are stored in the
     * range 64k-128k, thus, allowing us to scan both at the same time.
     */
    struct RangeList ports;
    
    /**
     * Only output these types of banners
     */
    struct RangeList banner_types;

    /**
     * IPv4 addresses/ranges that are to be exluded from the scan. This takes
     * precedence over any 'include' statement. What happens is this: after
     * all the configuration has been read, we then apply the exclude/blacklist
     * on top of the target/whitelist, leaving only a target/whitelist left.
     * Thus, during the scan, we only choose from the target/whitelist and
     * don't consult the exclude/blacklist.
     */
    struct RangeList exclude_ip;
    struct RangeList exclude_port;
    struct Range6List exclude_ipv6;


    /**
     * Maximum rate, in packets-per-second (--rate parameter). This can be
     * a fraction of a packet-per-second, or be as high as 30000000.0 (or
     * more actually, but I've only tested to 30megapps).
     */
    double max_rate;

    /**
     * Number of retries (--retries or --max-retries parameter). Retries
     * happen a few seconds apart.
     */
    unsigned retries;

    
    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
    unsigned is_banners:1;      /* --banners */
    unsigned is_offline:1;      /* --offline */
    unsigned is_noreset:1;      /* --noreset, don't transmit RST */
    unsigned is_gmt:1;          /* --gmt, all times in GMT */
    unsigned is_capture_cert:1; /* --capture cert */
    unsigned is_capture_html:1; /* --capture html */
    unsigned is_capture_heartbleed:1; /* --capture heartbleed */
    unsigned is_capture_ticketbleed:1; /* --capture ticket */
    unsigned is_test_csv:1;     /* (temporary testing feature) */
    unsigned is_infinite:1;     /* -infinite */
    unsigned is_readscan:1;     /* --readscan, Operation_Readscan */
    unsigned is_heartbleed:1;   /* --heartbleed, scan for this vuln */
    unsigned is_ticketbleed:1;  /* --ticketbleed, scan for this vuln */
    unsigned is_poodle_sslv3:1; /* --vuln poodle, scan for this vuln */
    unsigned is_hello_ssl:1;    /* --ssl, use SSL HELLO on all ports */
    unsigned is_hello_smbv1:1;  /* --smbv1, use SMBv1 hello, instead of v1/v2 hello */
    unsigned is_hello_http:1;    /* --hello=http, use HTTP on all ports */
    unsigned is_scripting:1;    /* whether scripting is needed */
        
    /**
     * Wait forever for responses, instead of the default 10 seconds
     */
    unsigned wait;

    /**
     * --resume
     * This structure contains options for pausing the scan (by exiting the
     * program) and restarting it later.
     */
    struct {
        /** --resume-index */
        uint64_t index;
        
        /** --resume-count */
        uint64_t count;
        
        /** Derives the --resume-index from the target ip:port */
        struct {
            unsigned ip;
            unsigned port;
        } target;
    } resume;

    /**
     * --shard n/m
     * This is used for distributin a scan acros multiple "shards". Every
     * shard in the scan must know the total number of shards, and must also
     * know which of those shards is it's identity. Thus, shard 1/5 scans
     * a different range than 2/5. These numbers start at 1, so it's
     * 1/3 (#1 out of three), 2/3, and 3/3 (but not 0/3).
     */
    struct {
        unsigned one;
        unsigned of;
    } shard;

    /**
     * The packet template set we are current using. We store a binary template
     * for TCP, UDP, SCTP, ICMP, and so on. All the scans using that protocol
     * are then scanned using that basic template. IP and TCP options can be
     * added to the basic template without affecting any other component
     * of the system.
     */
    struct TemplateSet *pkt_template;

    /**
     * A random seed for randomization if zero, otherwise we'll use
     * the configured seed for repeatable tests.
     */
    uint64_t seed;
    
    /**
     * This block configures what we do for the output files
     */
    struct OutputStuff {
        
        /**
         * --output-format
         * Examples are "xml", "binary", "json", "ndjson", "grepable", and so on.
         */
        enum OutputFormat format;
        
        /**
         * --output-filename
         * The name of the file where we are storing scan results.
         * Note: the filename "-" means that we should send the file to
         * <stdout> rather than to a file.
         */
        char filename[256];
        
        /**
         * A feature of the XML output where we can insert an optional 
         * stylesheet into the file for better rendering on web browsers
         */
        char stylesheet[256];

        /**
         * --append
         * We should append to the output file rather than overwriting it.
         */
        unsigned is_append:1;
        
        /**
         * --open
         * --open-only
         * --show open
         * Whether to show open ports
         */
        unsigned is_show_open:1;
        
        /**
         * --show closed
         * Whether to show closed ports (i.e. RSTs)
         */
        unsigned is_show_closed:1;
        
        /**
         * --show host
         * Whether to show host messages other than closed ports
         */
        unsigned is_show_host:1;
        
        /**
         * print reason port is open, which is redundant for us 
         */
        unsigned is_reason:1;
    
        /**
         * --interactive
         * Print to command-line while also writing to output file. This isn't
         * needed if the output format is already 'interactive' (the default),
         * but only if the default output format is anything else, and the
         * user also wants interactivity.
         */
        unsigned is_interactive:1;
        
        /**
        * Print state updates
        */
        unsigned is_status_updates:1;

        struct {
            /**
             * When we should rotate output into the target directory
             */
            unsigned timeout;
            
            /**
             * When doing "--rotate daily", the rotation is done at GMT. In 
             * orderto fix this, add an offset.
             */
            unsigned offset;
            
            /**
             * Instead of rotating by timeout, we can rotate by filesize 
             */
            uint64_t filesize;
            
            /**
             * The directory to which we store rotated files
             */
            char directory[256];
        } rotate;
    } output;

    struct {
        unsigned data_length; /* number of bytes to randomly append */
        unsigned ttl; /* starting IP TTL field */
        unsigned badsum; /* bad TCP/UDP/SCTP checksum */

        unsigned packet_trace:1; /* print transmit messages */
        
        char datadir[256];
    } nmap;

    char pcap_filename[256];

    struct {
        unsigned timeout;
    } tcb;

    struct {
        char *pcap_payloads_filename;
        char *nmap_payloads_filename;
        char *nmap_service_probes_filename;
    
        struct PayloadsUDP *udp;
        struct PayloadsUDP *oproto;
        struct TcpCfgPayloads *tcp;
        struct NmapServiceProbeList *probes;
    } payloads;
    
    unsigned char *http_user_agent;
    unsigned http_user_agent_length;
    unsigned tcp_connection_timeout;
    
    /** Number of seconds to wait for a 'hello' from the server before
     * giving up and sending a 'hello' from the client. Should be a small
     * value when doing scans that expect client-side hellos, like HTTP or
     * SSL, but should be a longer value when doing scans that expect server
     * hellos, such as FTP or VNC */
    unsigned tcp_hello_timeout;

    struct {
        const char *header_name;
        unsigned char *header_value;
        unsigned header_value_length;
    } http_headers[16];

    char *bpf_filter;

    struct {
        unsigned ip;
        unsigned port;
    } redis;



    /**
     * --min-packet
     */
    unsigned min_packet_size;

    /**
     * Number of rounds for randomization
     * --blackrock-rounds
     */
    unsigned blackrock_rounds;
    
    /**
     * --script <name>
     */
    struct {
        /* The name (filename) of the script to run */
        char *name;
        
        /* The script VM */
        struct lua_State *L;
    } scripting;

    
    /**
     * --vuln <name>
     * The name of a vuln to check, like "poodle"
     */
    const char *vuln_name;

};


int mainconf_selftest(void);
void masscan_read_config_file(struct Masscan *masscan, const char *filename);
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]);
void masscan_usage(void);
void masscan_save_state(struct Masscan *masscan);
void main_listscan(struct Masscan *masscan);

/**
 * Load databases, such as:
 *  - nmap-payloads
 *  - nmap-service-probes
 *  - pcap-payloads
 */
void masscan_load_database_files(struct Masscan *masscan);

/**
 * Pre-scan the command-line looking for options that may affect how
 * previous options are handled. This is a bit of a kludge, really.
 */
int masscan_conf_contains(const char *x, int argc, char **argv);

/**
 * Called to set a <name=value> pair.
 */
void
masscan_set_parameter(struct Masscan *masscan,
                      const char *name, const char *value);



int
masscan_initialize_adapter(
    struct Masscan *masscan,
    unsigned index,
    unsigned char *adapter_mac,
    unsigned char *router_mac);

#endif
