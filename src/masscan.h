#ifndef MASSCAN_H
#define MASSCAN_H
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "ranges.h"

struct Adapter;

enum {
	Operation_Default = 0,  /* nothing specified, so print usage */
	Operation_List_Adapters = 1,
    Operation_Selftest = 2,
    Operation_Scan = 3, /* this is what you expect */
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
		uint64_t c;		/* LCG increment */
	} lcg;

    /**
     * Maximum rate, in packets-per-second
     */
    double max_rate;
};


void masscan_read_config_file(struct Masscan *masscan, const char *filename);
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]);
void masscan_usage();


#endif
