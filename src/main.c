/*

    main

    This includes:
    
    * main()
    * transmit_thread() - transmits probe packets
    * receive_thread() - receives response packets
*/
#include "masscan.h"

#include "rand-lcg.h"           /* the LCG randomization func */
#include "tcpkt.h"              /* packet template, that we use to send */
#include "rawsock.h"            /* api on top of Linux, Windows, Mac OS X*/
#include "logger.h"             /* adjust with -v command-line opt */
#include "main-status.h"        /* printf() regular status updates */
#include "main-throttle.h"      /* rate limit */
#include "main-dedup.h"         /* ignore duplicate responses */
#include "syn-cookie.h"         /* for SYN-cookies on send */
#include "output.h"             /* for outputing results */

#include "pixie-timer.h"        /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "proto-preprocess.h"   /* quick parse of packets */

#include <string.h>
#include <time.h>
#include <signal.h>



unsigned control_c_pressed = 0;
time_t global_now;


/***************************************************************************
 * This thread spews packets as fast as it can
 *
 *      THIS IS WHERE ALL THE EXCITEMENT HAPPENS!!!!
 *      90% of CPU cycles are in the function.
 *
 ***************************************************************************/
static void
transmit_thread(void *v) /*aka. scanning_thread() */
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

    LOG(1, "xmit: starting transmit thread...\n");

    /* "STATUS" is once-per-second <stderr> notification to the command
     * line as to what's going on */
    status_start(&status);

    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(&throttler, masscan->max_rate);

    /* needed for --packet-trace option so that we know when we started
     * the scan */
    timestamp_start = 1.0 * pixie_gettime() / 1000000.0;


    /* Seed the LCG for randomizing the scan*/
    seed = masscan->resume.seed;

    /* Optimize target selection so it's a quick binary search instead 
     * of walking large memory tables */
    picker = rangelist_pick2_create(&masscan->targets);

    /* -----------------
     * the main loop
     * -----------------*/
    LOG(3, "xmit: starting main loop\n");
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

			/* randomize the index. THIS IS WHERE RANDOMIZATION HAPPENS
             *  index = lcg_rand(index, a, c, m); */
			seed = (seed * a + c) % m;

			/* Pick the IPv4 address pointed to by this index */
			ip = rangelist_pick2(&masscan->targets, seed%count_ips, picker);
			port = rangelist_pick(&masscan->ports, seed/count_ips);

            /* Print packet if debugging */
            if (packet_trace)
                tcpkt_trace(pkt_template, ip, port, timestamp_start);

            /* Send the probe */
			rawsock_send_probe(
                    masscan->adapter, 
                    ip, 
                    port, 
                    syn_hash(ip, port), 
                    pkt_template);


            i++;


            /* 
             * update screen about once per second with statistics,
             * namely packets/second.
             */
			if ((i & status.timer) == status.timer) 
                status_print(&status, i, m);

        }

        /* If the user pressed <ctrl-c>, then we need to exit. but, in case
         * the user wants to resume the scan later, we save the current
         * state in a file */
        if (control_c_pressed) {
            masscan->resume.seed = seed;
            masscan->resume.index = i;
            masscan_save_state(masscan);
            fprintf(stderr, "waiting 10 seconds to exit...\n");
            fflush(stderr);
            control_c_pressed = 0; /* a second ^C press exits faster */
            break;
        }
	}

    /*
     * We are done transmitting. However, response packets will take several
     * seconds to arrive. Therefore, sit in short loop waiting for those 
     * packets to arrive. Pressing <ctrl-c> a second time will exit this
     * prematurely.
     */
    {
        unsigned j;
        for (j=0; j<10 && !control_c_pressed; j++) {
            status_print(&status, i++, m);
            pixie_usleep(1000000);
        }
        fprintf(stderr, "                                                                      \r");
    }

    /* Tell the other threads it's time to exit the program */
    masscan->is_done = 1;
}



/***************************************************************************
 ***************************************************************************/
static void
receive_thread(struct Masscan *masscan,
    unsigned adapter_ip,
    unsigned adapter_port,
    const unsigned char *adapter_mac)
{
    struct Output *out;
    struct DedupTable *dedup;

    /*
     * Open output. This is where results are reported.
     */
    out = output_create(masscan);

    /*
     * Create deduplication table
     */
    dedup = dedup_create();


    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(1, "begin receive thread\n");
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
        unsigned seqno;

        err = rawsock_recv_packet(
                    masscan->adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;


        /*
         * parse the response packet
         */
        x = preprocess_frame(px, length, 1, &parsed);
        if (!x)
            continue; /* corrupt packet */
        dst = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        src = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
        seqno = px[parsed.transport_offset+8]<<24 | px[parsed.transport_offset+9]<<16 
              | px[parsed.transport_offset+10]<<8 | px[parsed.transport_offset+11];
        seqno -= 1;


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

        /* verify: my port number */
        if (adapter_port != parsed.port_dst)
            continue;

        /* verify: syn-cookies */
        if (syn_hash(src, parsed.port_src) != seqno) {
            LOG(1, "bad packet: ackno=0x%08x expected=0x%08x\n", seqno, syn_hash(src, parsed.port_src));
        }

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
        output_report(
                    out,
                    status,
                    src,
                    parsed.port_src,
                    px[parsed.transport_offset + 13], /* tcp flags */
                    px[parsed.ip_offset + 8] /* ttl */
                    );
    }

    LOG(1, "end receive thread\n");

    /*
     * cleanup
     */
    dedup_destroy(dedup);
    output_destroy(out);
}

/***************************************************************************
 ***************************************************************************/
static void control_c_handler(int x)
{
	control_c_pressed = 1+x;
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


    /*
     * Turn the adapter on, and get the running configuration
     */
    err = masscan_initialize_adapter(   
                        masscan,
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
     * trap <ctrl-c> to pause
     */
    signal(SIGINT, control_c_handler);


    /*
     * Print helpful text
     */
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


    /*
     * Start the scanning thread.
     * THIS IS WHERE THE PROGRAM STARTS SPEWING OUT PACKETS AT A HIGH
     * RATE OF SPEED.
     */
    pixie_begin_thread(transmit_thread, 0, masscan);


    /*
     * Start the receive thread
     */
    receive_thread(masscan,
            adapter_ip,
            adapter_port,
            adapter_mac);

 

    return 0;
}


/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Masscan masscan[1];

    global_now = time(0);

    /*
     * Initialize those defaults that aren't zero
     */
	memset(masscan, 0, sizeof(*masscan));
    masscan->max_rate = 100.0; /* max rate = hundred packets-per-second */
    masscan->adapter_port = 0x10000; /* value not set */
    strcpy_s(   masscan->rotate_directory, 
                sizeof(masscan->rotate_directory),
                ".");
	

	/*
	 * Read in the configuration from the command-line. We are looking for
     * either options or a list of IPv4 address ranges.
	 */
    masscan_command_line(masscan, argc, argv);
    

    /* We need to do a separate "raw socket" initialization step. This is
     * for Windows and PF_RING. */
	rawsock_init();

    /* Set randomization seed for SYN-cookies */
    syn_set_entropy();

    /*
     * Apply excludes. People ask us not to scan them, so we maintain a list
     * of their ranges, and when doing wide scans, add the exclude list to
     * prevent them from being scanned.
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
            x += pixie_time_selftest();

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

