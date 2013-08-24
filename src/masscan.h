#ifndef MASSCAN_H
#define MASSCAN_H
#include "string_s.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "ranges.h"

struct Adapter;
struct TcpPacket;
extern time_t global_now;

enum {
    Operation_Default = 0,      /* nothing specified, so print usage */
    Operation_List_Adapters = 1,
    Operation_Selftest = 2,
    Operation_Scan = 3,         /* this is what you expect */
    Operation_DebugIF = 4,
    Operation_ListScan = 5,
};

enum OutpuFormat {
    Output_Interactive = 0,
    Output_Normal,
    Output_XML,
    Output_ScriptKiddie,
    Output_Grepable,
    Output_Binary,
    Output_All,
    Output_List /* specific to Masscan */
};

enum PortStatus {
    Port_Unknown,
    Port_Open,
    Port_Closed,
};

struct Masscan
{
    int op;

    /**
     * The network interface to use for scanning
     */
    char ifname[256];

    /**
     * The network adapter we'll use for transmitting packets
     */
    struct Adapter *adapter;

    unsigned adapter_ip;
    unsigned adapter_port;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];

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


    struct LCGParms {
        uint64_t m;     /* LCG modulus aka. the IP address range size */
        uint64_t a;     /* LCG multiplier */
        uint64_t c;     /* LCG increment */
    } lcg;

    /**
     * Maximum rate, in packets-per-second (--rate parameter)
     */
    double max_rate;

    /**
     * Number of retries (--retries or --max-retries parameter)
     */
    unsigned retries;

    unsigned is_pfring:1;
    unsigned is_sendq:1;

    /**
     * Wait forever for responses, instead of the default 10 seconds
     */
    unsigned wait;


    struct {
        uint64_t seed;
        uint64_t index;
    } resume;

    /**
     * The packet template we are current using
     */
    struct TcpPacket *pkt_template;

    /**
     * Are we there yet? The scanning thread sets this to 1 when its done.
     * The receive thread will wait a bit after this, then exit.
     */
    unsigned is_done;

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

    struct rte_ring *packet_buffers;
    struct rte_ring *pending_packets;
};


void masscan_read_config_file(struct Masscan *masscan, const char *filename);
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]);
void masscan_usage();
void masscan_save_state(struct Masscan *masscan);

int
masscan_initialize_adapter(struct Masscan *masscan,
    unsigned *r_adapter_ip,
    unsigned char *adapter_mac,
    unsigned char *router_mac);

#endif
