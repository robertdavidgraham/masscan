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
#include "proto-arp.h"          /* for responding to ARP requests */
#include "proto-banner1.h"
#include "proto-tcp.h"          /* for TCP/IP connection table */
#include "syn-cookie.h"         /* for SYN-cookies on send */
#include "output.h"             /* for outputing results */
#include "rte-ring.h"           /* producer/consumer ring buffer */
#include "rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */
#include "smack.h"              /* Aho-corasick state-machine pattern-matcher */

#include "pixie-timer.h"        /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "proto-preprocess.h"   /* quick parse of packets */

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>



unsigned control_c_pressed = 0;
time_t global_now;



/***************************************************************************
 * The recieve thread doesn't transmit packets. Instead, it queues them
 * up on the transmit thread. Every so often, the transmit thread needs
 * to flush this transmit queue and send everything.
 *
 * This is an inherent design issue trying to send things as batches rather
 * than individually. It increases latency, but increases performance. We
 * don't really care about latency.
 ***************************************************************************/
void
flush_packets(struct Masscan *masscan, struct Throttler *throttler, uint64_t *packets_sent)
{
    uint64_t batch_size;

    /*
     * Only send a few packets at a time, throttled according to the max
     * --rate set by the usser
     */
    batch_size = throttler_next_batch(throttler, *packets_sent);

    /*
     * Send a batch of queued packets
     */
    for ( ; batch_size; batch_size--) {
        int err;
        struct PacketBuffer *p;

        /*
         * Get the next packet from the transmit queue. This packet was 
         * put there by a receive thread, and will contain things like
         * an ACK or an HTTP request
         */
        err = rte_ring_sc_dequeue(masscan->transmit_queue, (void**)&p);
        if (err)
            break; /* queue is empty, nothing to send */

        /*
         * Actually send the packet
         */
        rawsock_send_packet(masscan->adapter, p->px, (unsigned)p->length, 1);

        /*
         * Now that we are done with the packet, put it on the free list
         * of buffers that the transmit thread can reuse
         */
        for (err=1; err; ) {
            err = rte_ring_sp_enqueue(masscan->packet_buffers, p);
            if (err) {
                LOG(0, "transmit queue full (should be impossible)\n");
                pixie_usleep(10000);
            }
        }
        

        /*
         * Remember that we sent a packet, which will be used in
         * throttling.
         */
        (*packets_sent)++;
    }
}


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
    struct Adapter *adapter = masscan->adapter;
    uint64_t packets_sent = 0;

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
        batch_size = throttler_next_batch(&throttler, packets_sent);
        packets_sent += batch_size;
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
                    adapter,
                    ip,
                    port,
                    syn_hash(ip, port),
                    !batch_size,        /* flush transmit queue on last packet */
                    pkt_template
                    );


            i++;


            /*
             * update screen about once per second with statistics,
             * namely packets/second.
             */
            if ((i & status.timer) == status.timer)
                status_print(&status, i, m);

        } /* end of batch */

        /* Transmit packets from other thread */
        flush_packets(masscan, &throttler, &packets_sent);

        /* If the user pressed <ctrl-c>, then we need to exit. but, in case
         * the user wants to resume the scan later, we save the current
         * state in a file */
        if (control_c_pressed) {
            masscan->resume.seed = seed;
            masscan->resume.index = i;
            masscan_save_state(masscan);
            fprintf(stderr, "waiting %u seconds to exit...\n", masscan->wait);
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
        for (j=0; j<masscan->wait && !control_c_pressed; j++) {
            unsigned k;
            status_print(&status, i++, m);

            for (k=0; k<1000; k++) {
                /* Transmit packets from other thread */
                flush_packets(masscan, &throttler, &packets_sent);

                pixie_usleep(1000);
            }
        }
        fprintf(stderr, "                                                                      \r");
    }

    /* Tell the other threads it's time to exit the program */
    masscan->is_done = 1;
}



/***************************************************************************
 * 
 * Asynchronous receive thread
 *
 * The transmit and receive threads run independently of each other. There
 * is no record what was transmitted. Instead, the transmit thread sets a 
 * "SYN-cookie" in transmitted packets, which the receive thread will then
 * use to match up requests with responses.
 ***************************************************************************/
static void
receive_thread(struct Masscan *masscan,
    unsigned adapter_ip,
    unsigned adapter_port,
    const unsigned char *adapter_mac)
{
    struct Output *out;
    struct DedupTable *dedup;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;



    /*
     * If configured, open a pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    if (masscan->pcap_filename[0])
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);

    /*
     * Open output. This is where results are reported.
     */
    out = output_create(masscan);

    /*
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    dedup = dedup_create();

    /*
     * Create a TCP connection table for interacting with live
     * connections
     */
    if (masscan->is_banners) {
        tcpcon = tcpcon_create_table(
            (size_t)(masscan->max_rate/5), 
            masscan->transmit_queue, 
            masscan->packet_buffers,
            masscan->pkt_template,
            output_report_banner,
            out
            );
    }

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
        unsigned ip_me;
        unsigned ip_them;
        unsigned seqno_them;
        unsigned seqno_me;

        err = rawsock_recv_packet(
                    masscan->adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0)
            continue;

        /*
         * Do any TCP event timeouts based on the current timestamp from
         * the packet. For example, if the connection has been open for
         * around 10 seconds, we'll close the connection.
         */
        if (tcpcon) {
            tcpcon_timeouts(tcpcon, secs, usecs);
        }

        /*
         * "Preprocess" the response packet. This means to go through and
         * figure out where the TCP/IP headers are and the locations of
         * some fields, like IP address and port numbers.
         */
        x = preprocess_frame(px, length, 1, &parsed);
        if (!x)
            continue; /* corrupt packet */
        ip_me = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        ip_them = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
        seqno_them = TCP_SEQNO(px, parsed.transport_offset);
        seqno_me = TCP_ACKNO(px, parsed.transport_offset);


        /* verify: my IP address */
        if (adapter_ip != ip_me)
            continue;


        /* OOPS: handle arp instead */
        if (parsed.found == FOUND_ARP) {
            LOG(2, "found arp 0x%08x\n", parsed.ip_dst);

            arp_response(
                adapter_ip, adapter_mac, px, length,
                masscan->packet_buffers,
                masscan->transmit_queue);
            continue;
        }

        /* verify: TCP */
        if (parsed.found != FOUND_TCP)
            continue; /*TODO: fix for UDP-scan and ICMP-scan */

        /* verify: my port number */
        if (adapter_port != parsed.port_dst)
            continue;

        /* Save raw packet (if configured to do so) */
        if (pcapfile) {
            pcapfile_writeframe(
                pcapfile,
                px,
                length,
                length,
                secs,
                usecs);
        }


        /* If recording banners, create a new "TCP Control Block (TCB)" */
        if (tcpcon) {
            struct TCP_Control_Block *tcb;

            /* does a TCB already exist for this connection? */
            tcb = tcpcon_lookup_tcb(tcpcon,
                            ip_me, ip_them,
                            parsed.port_dst, parsed.port_src);

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (syn_hash(ip_them, parsed.port_src) != seqno_me - 1) {
                    LOG(1, "bad packet: ackno=0x%08x expected=0x%08x\n", seqno_me-1, syn_hash(ip_them, parsed.port_src));
                    continue;
                }

                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them, 
                                    parsed.port_dst, 
                                    parsed.port_src, 
                                    seqno_me, seqno_them+1);
                }

                tcpcon_handle(tcpcon, tcb, TCP_WHAT_SYNACK, 0, 0, secs, usecs);

            } else if (tcb) {
                /* If this is an ACK, then handle that first */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_ACK, 0, seqno_me,
                        secs, usecs);
                }

                /* If this contains payload, handle that */
                if (parsed.app_length) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_DATA, 
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs);
                }

                /* If this is a FIN, handle that. Note that ACK + payload + FIN
                 * can come together */
                if (TCP_IS_FIN(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_FIN, 0, 0, 
                        secs, usecs);
                }

                /* If this is a RST, then we'll be closing the connection */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_RST, 0, 0,
                        secs, usecs);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                /* TODO: we ought to send FIN-ACK in response */
            }

        }

        /* figure out the status */
        status = Port_Unknown;
        if ((px[parsed.transport_offset+13] & 0x2) == 0x2)
            status = Port_Open;
        if ((px[parsed.transport_offset+13] & 0x4) == 0x4)
            status = Port_Closed;

        /* verify: syn-cookies */
        if (syn_hash(ip_them, parsed.port_src) != seqno_me - 1) {
            LOG(1, "bad packet: ackno=0x%08x expected=0x%08x\n", seqno_me-1, syn_hash(ip_them, parsed.port_src));
            continue;
        }

        /* verify: ignore duplicates */
        if (dedup_is_duplicate(dedup, ip_them, parsed.port_src))
            continue;

        /*
         * XXXX
         * TODO: add lots more verification, such as coming from one of
         * our sending port numbers, and having the right seqno/ackno
         * fields set.
         */
        output_report(
                    out,
                    status,
                    ip_them,
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
    if (pcapfile)
        pcapfile_close(pcapfile);
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
     * Initialize the task size
     */
    count_ips = rangelist_count(&masscan->targets);
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return 1;
    }
    count_ports = rangelist_count(&masscan->ports);
    if (count_ports == 0) {
        LOG(0, "FAIL: no ports were specified\n");
        LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
        LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
        return 1;
    }
    /* If the IP address range is very big, then require that that the 
     * user apply an exclude range */
    if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude_ip) == 0) {
        LOG(0, "FAIL: range too big, need confirmation\n");
        LOG(0, " [hint] to prevent acccidents, at least one --exclude must be specified\n");
        LOG(0, " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        exit(1);
    }

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



    LOG(0, "Scanning %u hosts [%u port%s/host]\n",
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
            LOG(0, "FAIL: corrupt resume data\n");
            exit(1);
        } else
            LOG(0, "resuming scan...\n");
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
        LOG(0, "\nStarting masscan 1.0 (http://github.com/robertdavidgraham/masscan) at %s\n", buffer);
    }
    LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
    LOG(0, "Initiating SYN Stealth Scan\n");

    /*
     * Allocate packet buffers for sending
     */
    masscan->packet_buffers = rte_ring_create(256, RING_F_SP_ENQ|RING_F_SC_DEQ);
    masscan->transmit_queue = rte_ring_create(256, RING_F_SP_ENQ|RING_F_SC_DEQ);
    {
        unsigned i;
        for (i=0; i<255 /*TODO: why not 256???*/; i++) {
            struct PacketBuffer *p = (struct PacketBuffer *)malloc(sizeof(*p));
            err = rte_ring_sp_enqueue(masscan->packet_buffers, p);
            if (err) {
                /* I dunno why but I can't queue all 256 packets, just 255 */
                LOG(0, "packet_buffers: enqueue: error %d\n", err);
            }
        }
    }




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
    masscan->wait = 10; /* how long to wait for responses when done */
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
    syn_set_entropy(masscan->seed);

    

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
            //x += xring_selftest();
            x += rte_ring_selftest();
            x += smack_selftest();
            x += banner1_selftest();



            if (x != 0) {
                /* one of the selftests failed, so return error */
                fprintf(stderr, "regression test: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "regression test: success!\n");
                return 0;
            }
        }
        break;
    }


    return 0;
}

