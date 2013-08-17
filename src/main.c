/*

    main

    This includes the main() function, as well as the inner loop of the
    scan function.
*/
#include "masscan.h"
#include "rand-lcg.h"
#include "tcpkt.h"
#include "rawsock.h"
#include "logger.h"
#include "main-status.h"
#include "main-throttle.h"

#include "pixie-timer.h"         /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "proto-preprocess.h"   /* quick parse of packets */

#include <string.h>
#include <time.h>



/***************************************************************************
 * This thread spews packets as fast as it can
 ***************************************************************************/
void scanning_thread(void *v)
{
    uint64_t i;
    struct Masscan *masscan = (struct Masscan *)v;
	uint64_t index = 0;
	uint64_t a = masscan->lcg.a;
	uint64_t c = masscan->lcg.c;
	uint64_t m = masscan->lcg.m;
    uint64_t count_ips = rangelist_count(&masscan->targets);
	struct Status status;
    struct Throttler throttler;
    struct TcpPacket *pkt_template = masscan->pkt_template;
        
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
			rawsock_send_probe(masscan->adapter, ip, port, pkt_template);

            i++;

            /* 
             * update screen about once per second with statistics,
             * namely packets/second.
             */
			if ((i & status.timer) == status.timer) 
                status_print(&status, i, m);
        }
	}

    /*
     * We are done, so wait for 10 seconds before exiting
     */
    {
        unsigned j;
        for (j=0; j<10; j++) {
            status_print(&status, i++, m);
            port_usleep(1000000);
        }
    }
    masscan->is_done = 1;
}



/***************************************************************************
 * Do the scan. This is the main function of the program.
 * Called from main()
 ***************************************************************************/
static int
main_scan(struct Masscan *masscan)
{
	struct TcpPacket pkt[1];
	uint64_t count_ips;
	uint64_t count_ports;
    unsigned adapter_ip;
    unsigned adapter_port;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];
    char *ifname;
    char ifname2[256];


    /*
     * Initialize the transmit adapter
     */
    if (masscan->ifname && masscan->ifname[0])
        ifname = masscan->ifname;
    else {
        /* no adapter specified, so find a default one */
        int err;
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err) {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return -1;
        } else {
            LOG(2, "auto-detected: interface=%s\n", ifname2);
        }
        ifname = ifname2;
        
    }
    masscan->adapter = rawsock_init_adapter(ifname);
    if (masscan->adapter == 0) {
        fprintf(stderr, "adapter[%s]: failed\n", ifname);
        return -1;
    }
    adapter_ip = masscan->adapter_ip;
    if (adapter_ip == 0) {
        adapter_ip = rawsock_get_adapter_ip(ifname);
        LOG(2, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (adapter_ip>>24)&0xFF,
            (adapter_ip>>16)&0xFF,
            (adapter_ip>> 8)&0xFF,
            (adapter_ip>> 0)&0xFF
            );
    }
    if (adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try \"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }
    memcpy(adapter_mac, masscan->adapter_mac, 6);
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        rawsock_get_adapter_mac(ifname, adapter_mac);
        LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    }
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect MAC address of interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try \"--adapter-mac 00-11-22-33-44\"\n");
        return -1;
    }

    memcpy(router_mac, masscan->router_mac, 6);
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        unsigned router_ipv4;
        int err;

        err = rawsock_get_default_gateway(ifname, &router_ipv4);
        if (err == 0) {
            LOG(2, "auto-detected: router-ip=%u.%u.%u.%u\n",
                (router_ipv4>>24)&0xFF,
                (router_ipv4>>16)&0xFF,
                (router_ipv4>> 8)&0xFF,
                (router_ipv4>> 0)&0xFF
                );

            err = arp_resolve_sync(
                    masscan->adapter,
                    adapter_ip,
                    adapter_mac,
                    router_ipv4,
                    router_mac);

            if (memcmp(router_mac, "\0\0\0\0\0\0", 6) != 0) {
                LOG(2, "auto-detected: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
                    router_mac[0],
                    router_mac[1],
                    router_mac[2],
                    router_mac[3],
                    router_mac[4],
                    router_mac[5]
                    );
            }
        }
    }
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect router for interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try \"--router-mac 66-55-44-33-22-11\"\n");
        return -1;
    }


    /*
     * Ignore transmits
     */
    rawsock_ignore_transmits(masscan->adapter, adapter_mac);
	
    /*
	 * Initialize the TCP packet template.
	 */
	tcp_init_packet(pkt,
        adapter_ip,
        adapter_mac,
        router_mac);
    masscan->pkt_template = pkt;
    adapter_port = tcpkt_get_source_port(pkt);

	
    /*
	 * Initialize the task size
	 */
	count_ips = rangelist_count(&masscan->targets);
	if (count_ips == 0) {
		fprintf(stderr, "FAIL: no IPv4 ranges were specified\n");
		return 1;
	} else
        LOG(2, "range = %u IP addresses\n", count_ips);
	count_ports = rangelist_count(&masscan->ports);
	if (count_ports == 0) {
		fprintf(stderr, "FAIL: no ports were specified, use \"-p<port>\"\n");
		return 1;
	} else
        LOG(2, "range = %u ports\n", count_ports);

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
    LOG(2, "lcg-constants = a(%llu) c(%llu) m(%llu)\n", 
		masscan->lcg.a,
		masscan->lcg.c,
		masscan->lcg.m
        );


    /*
     * Start the scanning thread
     */
    pixie_begin_thread(scanning_thread, 0, masscan);

    /*
     * Receive packets
     */
    while (!masscan->is_done) {
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;
        unsigned x;
        struct PreprocessedInfo parsed;
        unsigned dst;
        unsigned src;


        err = rawsock_recv_packet(
                    masscan->adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;


        /*
         * handle packet
         */
        x = preprocess_frame(px, length, 1, &parsed);
        if (!x)
            continue; /* corrupt packet */

        /* verify: my IP address */
        dst = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        if (adapter_ip != dst)
            continue;

        /* OOPS: handle arp instead */
        if (parsed.found == FOUND_ARP) {
            LOG(2, "found arp 0x%08x\n", parsed.ip_dst);
            arp_response(masscan->adapter, adapter_ip, adapter_mac, px, length);
            continue;
        }

        /* verify: TCP */
        if (parsed.found != FOUND_TCP)
            continue;

        /* verify: SYN-ACK */
        if ((px[parsed.transport_offset+13] & 0x12) != 0x12)
            continue;

        /* verify: my IP address */
        dst = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        if (adapter_ip != dst)
            continue;

        /* verify: my port number */
        if (adapter_port != parsed.port_dst)
            continue;


        /*
         * XXXX
         * TODO: add lots more verification, such as coming from one of
         * our sending port numbers, and having the right seqno/ackno
         * fields set.
         */
        src = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
        printf("found: %u.%u.%u.%u on port %u                      \n",
            (src>>24)&0xFF,
            (src>>16)&0xFF,
            (src>> 8)&0xFF,
            (src>> 0)&0xFF,
            parsed.port_src);
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
    masscan->max_rate = 100.0; /* initialize: max rate = hundred packets-per-second */
	masscan_command_line(masscan, argc, argv);


    /*
     * Once we've read in the configuration, do the operation that was
     * specified
     */
	switch (masscan->op) {
	case Operation_Default:
        /* Print usage info and exit */
        masscan_usage();
		break;

	case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
		rawsock_list_adapters();
		break;

    case Operation_Scan:
        /*
         * THIS IS THE NORMAL THING
         */
        return main_scan(masscan);

    case Operation_DebugIF:
        rawsock_selftest_if(masscan->ifname);
        return 0;

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
            x += port_time_selftest();

            if (x != 0) {
                /* one of the selftests failed, so return error */
                fprintf(stderr, "selftest: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "selftest: success!\n");
                return 0;
            }
        }
        break;
	}

   
    return 0;
}

