#ifndef MASSCAN_H
#define MASSCAN_H
#include "string_s.h"
#include "main-src.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "ranges.h"
#include "packet-queue.h"

struct Adapter;
struct TemplateSet;
struct Banner1;

enum {
    Operation_Default = 0,      /* nothing specified, so print usage */
    Operation_List_Adapters = 1,
    Operation_Selftest = 2,
    Operation_Scan = 3,         /* this is what you expect */
    Operation_DebugIF = 4,
    Operation_ListScan = 5,
    Operation_ReadScan = 6,     /* re-interpret output files in different format */
};

enum OutpuFormat {
    Output_Interactive  = 0x0001,
    Output_List         = 0x0002,
    Output_Binary       = 0x0004,
    Output_XML          = 0x0008,
    Output_JSON         = 0x0010,
    Output_Nmap         = 0x0020,
    Output_ScriptKiddie = 0x0040,
    Output_Grepable     = 0x0080,
    Output_Redis        = 0x0100,
    Output_None         = 0x0200,
    Output_All          = 0xFFBF,
};



struct Masscan
{
    int op;

    /**
     * One or more network adapters that we'll use for scanning.
     */
    struct {
        char ifname[256];
        struct Adapter *adapter;
        struct Source src;
        unsigned char my_mac[6];
        unsigned char router_mac[6];
        unsigned router_ip;
        int link_type; /* libpcap definitions */
        unsigned char my_mac_count;
    } nic[8];
    unsigned nic_count;

    /**
     * The target ranges of IPv4 addresses that are included in the scan.
     */
    struct RangeList targets;

    /**
     * The ports we are scanning for
     */
    struct RangeList ports;

    /**
     * IPv4 addresses/ranges that are to be exluded from the scan. This teakes
     * precendence over any 'include' statement
     */
    struct RangeList exclude_ip;
    struct RangeList exclude_port;



    /**
     * Maximum rate, in packets-per-second (--rate parameter)
     */
    double max_rate;

    /**
     * Number of retries (--retries or --max-retries parameter)
     */
    unsigned retries;

    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
    unsigned is_banners:1;      /* --banners */
    unsigned is_offline:1;      /* --offline */
    unsigned is_interactive:1;  /* --interactive */
    unsigned is_arp:1;           /* --arp */
    unsigned is_gmt:1;          /* --gmt, all times in GMT */
    unsigned is_capture_cert:1; /* --capture cert */
    unsigned is_capture_html:1; /* --capture html */

    /**
     * Wait forever for responses, instead of the default 10 seconds
     */
    unsigned wait;


    struct {
        uint64_t index;
        uint64_t count;
        struct {
            unsigned ip;
            unsigned port;
        } target;
    } resume;

    struct {
        unsigned one;
        unsigned of;
    } shard;

    /**
     * The packet template we are current using
     */
    struct TemplateSet *pkt_template;

    /**
     * When we should rotate output into the target directory
     */
    unsigned rotate_output;

    /**
     * A random seed for randomization if zero, otherwise we'll use
     * the configured seed for repeatable tests.
     */
    uint64_t seed;

    /**
     * When doing "--rotate daily", the rotation is done at GMT. In order
     * to fix this, add an offset.
     */
    unsigned rotate_offset;

    struct {
        unsigned data_length; /* number of bytes to randomly append */
        unsigned ttl; /* starting IP TTL field */
        unsigned badsum; /* bad TCP/UDP/SCTP checksum */

        /* ouput options */
        unsigned packet_trace:1; /* print transmit messages */
        unsigned open_only:1; /* show only open ports */
        unsigned reason; /* print reason port is open, which is redundant for us */
        unsigned format; /* see enum OutputFormat */
        unsigned append; /* append instead of clobber file */

        char datadir[256];
        char filename[256];
        char stylesheet[256];

    } nmap;

    char rotate_directory[256];
    char pcap_filename[256];

    //PACKET_QUEUE *packet_buffers;
    //PACKET_QUEUE *transmit_queue;

    struct {
        unsigned timeout;
    } tcb;

    struct NmapPayloads *payloads;

    unsigned char *http_user_agent;
    unsigned http_user_agent_length;

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
     * --infinite
     * Restarts the scan from the beginning, for load testing, but
     * by incrementing the seed
     */
    unsigned is_infinite:1;
};


int mainconf_selftest(void);
void masscan_read_config_file(struct Masscan *masscan, const char *filename);
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]);
void masscan_usage(void);
void masscan_save_state(struct Masscan *masscan);
void main_listscan(struct Masscan *masscan);

int
masscan_initialize_adapter(
    struct Masscan *masscan,
    unsigned index,
    unsigned char *adapter_mac,
    unsigned char *router_mac);

#endif
