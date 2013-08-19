/*

    main

    This includes:
    
    * main()
    * scanning_thread() - transmits packets
    * main_scan() - launch and receive packets
*/
#include "masscan.h"

#include "rand-lcg.h"           /* the LCG randomization func */
#include "tcpkt.h"              /* packet template, that we use to send */
#include "rawsock.h"            /* api on top of Linux, Windows, Mac OS X*/
#include "logger.h"             /* adjust with -v command-line opt */
#include "main-status.h"        /* printf() regular status updates */
#include "main-throttle.h"      /* rate limit */
#include "main-dedup.h"         /* ignore duplicate responses */

#include "pixie-timer.h"        /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "proto-preprocess.h"   /* quick parse of packets */

#include <string.h>
#include <time.h>
#include <signal.h>



static unsigned control_c_pressed = 0;



/***************************************************************************
 * This thread spews packets as fast as it can
 *
 *      THIS IS WHERE ALL THE EXCITEMENT HAPPENS!!!!
 *      90% of CPU cycles are in the function.
 *
 ***************************************************************************/
static void
scanning_thread(void *v)
{
    uint64_t i;
    struct Masscan *masscan = (struct Masscan *)v;
	uint64_t a = masscan->lcg.a;
	uint64_t c = masscan->lcg.c;
	uint64_t m = masscan->lcg.m;
    uint64_t count_ips = rangelist_count(&masscan->targets);
	struct Status status;
    struct Throttler throttler;
    struct TcpPacket *pkt_template = masscan->pkt_template;
   	uint64_t seed;
    unsigned packet_trace = masscan->nmap.packet_trace;
    double timestamp_start;
    unsigned *picker;

    status_start(&status);
    throttler_start(&throttler, masscan->max_rate);

    timestamp_start = 1.0 * port_gettime() / 1000000.0;


    /*
     * Seed the LCG so that it does a different scan every time.
     */
    seed = masscan->resume.seed;

    picker = rangelist_pick2_create(&masscan->targets);

    /*
     * the main loop
     */
	for (i=masscan->resume.index; i<masscan->lcg.m; ) {
        uint64_t batch_size;

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the 
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one.
         */
        batch_size = throttler_next_batch(&throttler, i);
        while (batch_size && i < m) {
			unsigned ip;
			unsigned port;

            batch_size--;

			/* randomize the index
             *  index = lcg_rand(index, a, c, m); */
			seed = (seed * a + c) % m;

			/* Pick the IPv4 address pointed to by this index */
			ip = rangelist_pick2(&masscan->targets, seed%count_ips, picker);
			port = rangelist_pick(&masscan->ports, seed/count_ips);

            /* Send the probe */
			rawsock_send_probe(masscan->adapter, ip, port, pkt_template);


            i++;


            /* 
             * update screen about once per second with statistics,
             * namely packets/second.
             */
			if ((i & status.timer) == status.timer) 
                status_print(&status, i, m);

            /* Print packet if debugging */
            if (packet_trace)
                tcpkt_trace(pkt_template, ip, port, timestamp_start);
        }

        if (control_c_pressed) {
            masscan->resume.seed = seed;
            masscan->resume.index = i;
            masscan_save_state(masscan);
            fprintf(stderr, "waiting 10 seconds to exit...\n");
            fflush(stderr);
            control_c_pressed = 0;
            break;
        }
	}

    /*
     * We are done, so wait for 10 seconds before exiting
     */
    {
        unsigned j;
        for (j=0; j<10 && !control_c_pressed; j++) {
            status_print(&status, i++, m);
            port_usleep(1000000);
        }
        fprintf(stderr, "                                                                      \r");
    }

    /* Tell the other it's time to exit the program */
    masscan->is_done = 1;
}


/***************************************************************************
 * Initialize the network adapter.
 * 
 * This requires finding things like our IP address, MAC address, and router
 * MAC address. The user could configure these things manually instead.
 *
 * Note that we don't update the "static" configuration with the discovered
 * values, but instead return them as the "running" configuration. That's
 * so if we pause and resume a scan, autodiscovered values don't get saved
 * in the configuration file.
 ***************************************************************************/
static int
initialize_adapter(struct Masscan *masscan,
    unsigned *r_adapter_ip,
    unsigned char *adapter_mac,
    unsigned char *router_mac)
{
    char *ifname;
    char ifname2[256];

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first 
     * interface with a "default route" (aka. "gateway") defined
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

    /*
     * IP ADDRESS
     *
     * We need to figure out that IP address to send packets from. This
     * is done by queryin the adapter (or configured by user). If the 
     * adapter doesn't have one, then the user must configure one.
     */
    *r_adapter_ip = masscan->adapter_ip;
    if (*r_adapter_ip == 0) {
        *r_adapter_ip = rawsock_get_adapter_ip(ifname);
        LOG(2, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (*r_adapter_ip>>24)&0xFF,
            (*r_adapter_ip>>16)&0xFF,
            (*r_adapter_ip>> 8)&0xFF,
            (*r_adapter_ip>> 0)&0xFF
            );
    }
    if (*r_adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try something like \"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
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
        fprintf(stderr, "FAIL:... try something like \"--adapter-mac 00-11-22-33-44\"\n");
        return -1;
    }

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to 
     * turn it on.
     */
    masscan->adapter = rawsock_init_adapter(ifname);
    if (masscan->adapter == 0) {
        fprintf(stderr, "adapter[%s].init: failed\n", ifname);
        return -1;
    }
    rawsock_ignore_transmits(masscan->adapter, adapter_mac);

    /*
     * ROUTER MAC ADDRESS
     * 
     * NOTE: this is one of the least understood aspects of the code. We must
     * send packets to the local router, which means the MAC address (not
     * IP address) of the router.
     * 
     * Note: in order to ARP the router, we need to first enable the libpcap
     * code above.
     */
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
                    *r_adapter_ip,
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
        fprintf(stderr, "FAIL:... try something like \"--router-mac 66-55-44-33-22-11\"\n");
        return -1;
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
const char *status_string(int x)
{
    switch (x) {
    case Port_Open: return "open";
    case Port_Closed: return "closed";
    default: return "unknown";
    }
}

/***************************************************************************
 * Start the scan. This is the main function of the program.
 * Called from main()
 ***************************************************************************/
static int
main_scan(struct Masscan *masscan)
{
	struct TcpPacket pkt[1];
	uint64_t count_ips;
	uint64_t count_ports;
    unsigned adapter_ip = 0;
    unsigned adapter_port;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];
    int err;
    FILE *fpout = stdout;
    struct DedupTable *dedup;



    /*
     * Turn the adapter on, and get the running configuration
     */
    err = initialize_adapter(   masscan,
                        &adapter_ip,
                        adapter_mac,
                        router_mac);
    if (err != 0)
        return err;
	
    /*
	 * Initialize the TCP packet template. The way this works is that we parse
     * an existing TCP packet, and use that as the template for scanning. Then,
     * we adjust the template with additional features, such as the IP address
     * and so on.
	 */
	tcp_init_packet(pkt,
        adapter_ip,
        adapter_mac,
        router_mac);
    masscan->pkt_template = pkt;

    /*
     * Reconfigure the packet template according to command-line options
     */
    if (masscan->adapter_port < 0x10000)
        tcpkt_set_source_port(pkt, masscan->adapter_port);
    if (masscan->nmap.ttl)
        tcpkt_set_ttl(pkt, masscan->nmap.ttl);
    
    /*
     * Read back what we've set
     */
    adapter_port = tcpkt_get_source_port(pkt);

	
    /*
	 * Initialize the task size
	 */
	count_ips = rangelist_count(&masscan->targets);
	if (count_ips == 0) {
		fprintf(stderr, "FAIL: no IPv4 ranges were specified\n");
		return 1;
	}
	count_ports = rangelist_count(&masscan->ports);
	if (count_ports == 0) {
		fprintf(stderr, "FAIL: no ports were specified, use \"-p<port>\"\n");
		return 1;
	}

    fprintf(stderr, "Scanning %u hosts [%u port%s/host]\n",
        (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
	
    /*
     * Initialize LCG translator
     *
	 * This can take a couple seconds on a slow CPU. We have to find all the
     * primes out to 2^24 when doing large ranges.
	 */
    if (masscan->resume.index && masscan->resume.seed && masscan->lcg.m
        && masscan->lcg.a && masscan->lcg.c) {
        if (masscan->lcg.m != count_ips * count_ports) {
            fprintf(stderr, "FAIL: corrupt resume data\n");
            exit(1);
        } else
            fprintf(stderr, "resuming scan...\n");
    } else {
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
        masscan->resume.seed = time(0) % masscan->lcg.m;
        masscan->resume.index = 0;
    }


    /*
     * Open output
     */
    if (masscan->nmap.format != Output_Interactive && masscan->nmap.filename[0]) {
        FILE *fp;
        err = fopen_s(&fp, masscan->nmap.filename, masscan->nmap.append?"a":"w");
        if (err || fp == NULL) {
            perror(masscan->nmap.filename);
            exit(1);
        }
        fpout = fp;
    }
    dedup = dedup_create();

    /*
     * Start the scanning thread.
     * THIS IS WHERE THE PROGRAM STARTS SPEWING OUT PACKETS AT A HIGH
     * RATE OF SPEED.
     */
    pixie_begin_thread(scanning_thread, 0, masscan);

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    while (!masscan->is_done) {
        int status;
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
        dst = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        src = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;

        /* verify: my IP address */
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

        /* verify: my IP address */
        dst = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        if (adapter_ip != dst)
            continue;

        /* verify: my port number */
        if (adapter_port != parsed.port_dst)
            continue;

        /* verify: ignore duplicates */
        if (dedup_is_duplicate(dedup, src, parsed.port_src))
            continue;

        /* figure out the status */
        status = Port_Unknown;
        if ((px[parsed.transport_offset+13] & 0x2) == 0x2)
            status = Port_Open;
        if ((px[parsed.transport_offset+13] & 0x4) == 0x4)
            status = Port_Closed;
            

        /*
         * XXXX
         * TODO: add lots more verification, such as coming from one of
         * our sending port numbers, and having the right seqno/ackno
         * fields set.
         */
        if (masscan->nmap.format == Output_Interactive || masscan->nmap.format == Output_All) {
            fprintf(stdout, "Discovered %s port %u/tcp on %u.%u.%u.%u                          \n",
                status_string(status),
                parsed.port_src,
                (src>>24)&0xFF,
                (src>>16)&0xFF,
                (src>> 8)&0xFF,
                (src>> 0)&0xFF
                );
        }
        if (masscan->nmap.format == Output_List || masscan->nmap.format == Output_All) {
            fprintf(fpout, "%s tcp %u %u.%u.%u.%u\n",
                status_string(status),
                parsed.port_src,
                (src>>24)&0xFF,
                (src>>16)&0xFF,
                (src>> 8)&0xFF,
                (src>> 0)&0xFF
                );
        }
    }


    if (fpout != stdout)
        fclose(fpout);

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static void control_c_handler(int x)
{
	control_c_pressed = 1+x;
}

/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Masscan masscan[1];



    /* We need to do a separate "raw socket" initialization step */
	rawsock_init();


	/*
	 * Read in the configuration from the command-line. We are looking for
     * either options or a list of IPv4 address ranges.
	 */
	memset(masscan, 0, sizeof(*masscan));
    masscan->max_rate = 100.0; /* initialize: max rate = hundred packets-per-second */
    masscan->adapter_port = 0x10000; /* value not set */
	
    masscan_command_line(masscan, argc, argv);

    /*
     * Apply excludes
     */
    {
        unsigned i;

        for (i=0; i<masscan->exclude_ip.count; i++) {
            struct Range range = masscan->exclude_ip.list[i];
            rangelist_remove_range(&masscan->targets, range.begin, range.end);
        }

        for (i=0; i<masscan->exclude_port.count; i++) {
            struct Range range = masscan->exclude_port.list[i];
            rangelist_remove_range(&masscan->ports, range.begin, range.end);
        }

        rangelist_remove_range2(&masscan->targets, range_parse_ipv4("224.0.0.0/4", 0, 0));
    }


    /*
     * Once we've read in the configuration, do the operation that was
     * specified
     */
	switch (masscan->op) {
	case Operation_Default:
        /* Print usage info and exit */
        masscan_usage();
		break;

    case Operation_Scan:
        /*
         * THIS IS THE NORMAL THING
         */
    	
        /*
         * trap <ctrl-c> to pause
         */
        signal(SIGINT, control_c_handler);


        {
            char buffer[80];
            time_t now  = time(0);
            struct tm x;

            gmtime_s(&x, &now);
            strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x); 
            fprintf(stderr, "\nStarting masscan 1.0 (http://github.com/robertdavidgraham/masscan) at %s\n", buffer);
        }
        fprintf(stderr, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
        fprintf(stderr, "Initiating SYN Stealth Scan\n");
        return main_scan(masscan);

	case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
		rawsock_list_adapters();
		break;

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

