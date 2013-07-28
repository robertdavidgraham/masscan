#define _CRT_SECURE_NO_WARNINGS
#include "masscan.h"
#include "rand-lcg.h"
#include "tcpkt.h"
#include "rawsock.h"
#include "logger.h"
#include "main-status.h"
#include "main-throttle.h"

#include <string.h>
#include <time.h>






/***************************************************************************
 * Do the scan. This is the main function of the program.
 * Called from main()
 ***************************************************************************/
int
main_scan(struct Masscan *masscan)
{
	struct TcpPacket pkt[1];
	uint64_t count_ips;
	uint64_t count_ports;
	uint64_t i;
    clock_t scan_start, scan_stop;
    unsigned adapter_ip;
    unsigned char adapter_mac[6];


    /*
     * Initialize the transmit adapter
     */
    masscan->adapter = rawsock_init_adapter(masscan->ifname);
    if (masscan->adapter == 0) {
        fprintf(stderr, "adapter[%s]: failed\n", masscan->ifname);
    }
    adapter_ip = masscan->adapter_ip;
    if (adapter_ip == 0) {
        adapter_ip = rawsock_get_adapter_ip(masscan->ifname);
        fprintf(stderr, "info: auto-detect: adapter-ip=%u.%u.%u.%u\n",
            (adapter_ip>>24)&0xFF,
            (adapter_ip>>16)&0xFF,
            (adapter_ip>> 8)&0xFF,
            (adapter_ip>> 0)&0xFF
            );
    }
    memcpy(adapter_mac, masscan->adapter_mac, 6);
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        rawsock_get_adapter_mac(masscan->ifname, adapter_mac);
        fprintf(stderr, "info: auto-detect: adapter-mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    }


	
    /*
	 * Initialize the TCP packet template.
	 */
	tcp_init_packet(pkt,
        adapter_ip,
        adapter_mac,
        masscan->router_mac);

	
    /*
	 * Initialize the task size
	 */
	count_ips = rangelist_count(&masscan->targets);
	if (count_ips == 0) {
		fprintf(stderr, "no IPv4 ranges were specified\n");
		return 1;
	}
	count_ports = rangelist_count(&masscan->ports);
	if (count_ports == 0) {
		fprintf(stderr, "no ports were specified, use \"-p<port>\"\n");
		return 1;
	}

	/*
     * Initialize LCG translator
     *
	 * This can take a couple seconds on a slow CPU
	 */
	masscan->lcg.m = count_ips * count_ports;
	lcg_calculate_constants(
		masscan->lcg.m,
		&masscan->lcg.a,
		&masscan->lcg.c,
		0);


	/*
	 * Now start grabbing random values from the range
	 */
    scan_start = clock();
	{
		uint64_t index = 0;
		uint64_t a = masscan->lcg.a;
		uint64_t c = masscan->lcg.c;
		uint64_t m = masscan->lcg.m;
		struct Status status;
        struct Throttler throttler;
        
        status_start(&status);
        throttler_start(&throttler, masscan->max_rate);

        /*
         * the main loop
         */
		for (i=0; i<masscan->lcg.m; ) {
            uint64_t batch_size;


            /*
             * do a batch of many packets at a time
             */
            batch_size = throttler_next_batch(&throttler, i);
            while (batch_size && i < m) {
			    unsigned ip;
			    unsigned port;

                batch_size--;

			    /* randomize the index
			     *  index = lcg_rand(index, a, c, m); */
			    index = (index * a + c) % m;

			    /* Pick the IPv4 address pointed to by this index */
			    ip = rangelist_pick(&masscan->targets, index%count_ips);
			    port = rangelist_pick(&masscan->ports, index/count_ips);

                /* Send the probe */
			    rawsock_send_probe(masscan->adapter, ip, port, pkt);

                i++;

                /* 
                 * update screen about once per second with statistics,
                 * namely packets/second.
                 */
			    if ((i & status.timer) == status.timer) 
                    status_print(&status, i, m);
            }
		}

        status_finish(&status);
    }
    scan_stop = clock();


    /*
     * Print final statustics, like how long it took and how fast it went
     */
    {
		double elapsed = ((double)scan_stop - (double)scan_start)/(double)CLOCKS_PER_SEC;

		printf("rate = %5.3f-megaprobes/sec  100%% done\n", ((double)masscan->lcg.m/elapsed)/1000000.0);
		printf("elapsed = %-1.0f-seconds\n", elapsed);
		printf("probes = %llu-probes (%5.3f-million)\n", masscan->lcg.m, (double)masscan->lcg.m/1000000.0);
	}

    return 0;
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
	struct Masscan masscan[1];

	memset(masscan, 0, sizeof(*masscan));


    /* We need to do a separate "raw socket" initialization step */
	rawsock_init();


	/*
	 * Read in the configuration from the command-line. We are looking for
     * either options or a list of IPv4 address ranges.
	 */
    masscan->max_rate = 1000.0; /* initialize: max rate 1000 packets-per-second */
	masscan_command_line(masscan, argc, argv);


    /*
     * Once we've read in the configuration, do the operation that was
     * specified
     */
	switch (masscan->op) {
	case Operation_Default:
        /* Print usage info and exit */
        masscan_usage();
		return 0;

	case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
		rawsock_list_adapters();
		break;

    case Operation_Scan:
        /*
         * THIS IS THE NORMAL THING
         */
        return main_scan(masscan);
        
    case Operation_Selftest:
        /*
         * Do a regression test of all the significant units
         */
        {
            int x = 0;
            x += rawsock_selftest();
            x += randlcg_selftest();
            x += tcpkt_selftest();
            x += ranges_selftest();

            if (x != 0) {
                /* one of the selftests failed, so return error */
                fprintf(stderr, "selftest: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "selftest: success!\n");
                return 1;
            }
        }
        break;
	}

   
    return 0;
}

