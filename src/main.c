/*

    main

    This includes:

    * main()
    * transmit_thread() - transmits probe packets
    * receive_thread() - receives response packets

    You'll be wanting to study the transmit/receive threads, because that's
    where all the action is.

    This is the lynch-pin of the entire program, so it includes a heckuva lot
    of headers, and the functions have a lot of local variables. I'm trying
    to make this file relative "flat" this way so that everything is visible.
*/
#include "masscan.h"

#include "rand-blackrock.h"     /* the BlackRock shuffling func */
#include "rand-lcg.h"           /* the LCG randomization func */
#include "tcpkt.h"              /* packet template, that we use to send */
#include "rawsock.h"            /* api on top of Linux, Windows, Mac OS X*/
#include "logger.h"             /* adjust with -v command-line opt */
#include "main-status.h"        /* printf() regular status updates */
#include "main-throttle.h"      /* rate limit */
#include "main-dedup.h"         /* ignore duplicate responses */
#include "proto-arp.h"          /* for responding to ARP requests */
#include "proto-banner1.h"      /* for snatching banners from systems */
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

#if defined(WIN32)
#include <WinSock.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

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
    unsigned is_queue_empty = 0;

    while (!is_queue_empty) {
        /*
         * Only send a few packets at a time, throttled according to the max
         * --max-rate set by the user
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
            if (err) {
                is_queue_empty = 1;
                break; /* queue is empty, nothing to send */
            }

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
    uint64_t start;
    uint64_t end;
    struct Masscan *masscan = (struct Masscan *)v;
    uint64_t seed;
    unsigned retries = masscan->retries;
    unsigned rate = (unsigned)masscan->max_rate;
    unsigned r = retries + 1;
    uint64_t range;
    struct BlackRock blackrock;
    uint64_t count_ips = rangelist_count(&masscan->targets);
    struct Status status;
    struct Throttler throttler;
    struct TcpPacket *pkt_template = masscan->pkt_template;
    unsigned packet_trace = masscan->nmap.packet_trace;
    double timestamp_start;
    unsigned *picker;
    struct Adapter *adapter = masscan->adapter;
    uint64_t packets_sent = 0;

    LOG(1, "xmit: starting transmit thread...\n");

    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports */
    range = rangelist_count(&masscan->targets) 
            * rangelist_count(&masscan->ports);
    blackrock_init(&blackrock, range);

    /* This allows you to begin a scan somewhere other than the index
     * of zero (--seed). In the future. I might automatically seed this off
     * of thecurrent time automatically, but for the moment, I'm just 
     * starting from zero. */
    seed = masscan->seed;
    if (seed == 0 && masscan->shard.one == 1 && masscan->shard.of == 1)
        ; //seed = time(0) % range;

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. Another reason to do this is so that we can bleed
     * a little bit past the end when we have --retries */
    if (masscan->resume.index != 0)
        start = masscan->resume.index;
    else
        start = (masscan->shard.one-1) * (range / masscan->shard.of);
    if (masscan->shard.of == 1)
        end = range;
    else
        end = masscan->shard.one * (range / masscan->shard.of);
    end += retries * rate;

    
    /* "STATUS" is once-per-second <stderr> notification to the command
     * line as to what's going on */
    status_start(&status);

    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(&throttler, masscan->max_rate);

    /* needed for --packet-trace option so that we know when we started
     * the scan */
    timestamp_start = 1.0 * pixie_gettime() / 1000000.0;

    /* Optimize target selection so it's a quick binary search instead
     * of walking large memory tables. When we scan the entire Internet
     * our --excludefile will chop up our pristine 0.0.0.0/0 range into
     * hundreds of subranges. This scans through them faster. */
    picker = rangelist_pick2_create(&masscan->targets);

    /* -----------------
     * the main loop
     * -----------------*/
    LOG(3, "xmit: starting main loop\n");
    for (i=start; i<end; ) {
        uint64_t batch_size;

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one. (--max-rate)
         */
        batch_size = throttler_next_batch(&throttler, packets_sent);
        packets_sent += batch_size;
        while (batch_size && i < end) {
            uint64_t xXx;
            unsigned ip;
            unsigned port;


            /*
             * RANDOMIZE THE TARGET:
             *  This is kinda a tricky bit that picks a random IP and port
             *  number in order to scan. We monotonically increment the
             *  index 'i' from [0..range]. We then shuffle (randomly transmog)
             *  that index into some other, but unique/1-to-1, number in the
             *  same range. That way we visit all targets, but in a random 
             *  order. Then, once we've shuffled the index, we "pick" the
             *  the IP address and port that the index refers to.
             */
            xXx = (i + (r--) * rate + seed);
            while (xXx > range)
                xXx -= range;
            xXx = blackrock_shuffle(&blackrock,  xXx);
            ip = rangelist_pick2(&masscan->targets, xXx % count_ips, picker);
            port = rangelist_pick(&masscan->ports, xXx / count_ips);

            /* Print --packet-trace if debugging */
            if (packet_trace)
                tcpkt_trace(pkt_template, ip, port, timestamp_start);

            /*
             * SEND THE PROBE
             *  This is sorta the entire point of the program, but little
             *  exciting happens here. The thing to note that this may
             *  be a "raw" transmit that bypasses the kernel, meaning
             *  we can call this function millions of times a second.
             */
            rawsock_send_probe(
                    adapter,
                    ip,
                    port,
                    syn_hash(ip, port),
                    !batch_size, /* flush queue on last packet in batch */
                    pkt_template
                    );
            batch_size--;

            /*
             * SEQUENTIALLY INCREMENT THROUGH THE RANGE
             *  Yea, I know this is a puny 'i++' here, but it's a core feature
             *  of the system that is linearly increments through the range,
             *  but produces from that a shuffled sequence of targets (as
             *  described above). Because we are linearly incrementing this
             *  number, we can do lots of creative stuff, like doing clever
             *  retransmits and sharding.
             */
            if (r == 0) {
                i++; /* <--------- look at that puny increment */
                r = retries + 1; /* --retries */
            }

            /*
             * update screen about once per second with statistics,
             * namely packets/second.
             */
            if ((i & status.timer) == status.timer)
                status_print(&status, i, end);

        } /* end of batch */

        /* Transmit packets from other thread, when doing --banners */
        flush_packets(masscan, &throttler, &packets_sent);

        /* If the user pressed <ctrl-c>, then we need to exit. but, in case
         * the user wants to --resume the scan later, we save the current
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
            status_print(&status, i++, end);

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
     * If configured, open a --pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    if (masscan->pcap_filename[0])
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);

    /*
     * Open output. This is where results are reported when saving
     * the --output-format to the --output-filename
     */
    out = output_create(masscan);

    /*
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    dedup = dedup_create();

    /*
     * Create a TCP connection table for interacting with live
     * connections when doing --banners
     */
    if (masscan->is_banners) {
        tcpcon = tcpcon_create_table(
            (size_t)(masscan->max_rate/5), 
            masscan->transmit_queue, 
            masscan->packet_buffers,
            masscan->pkt_template,
            output_report_banner,
            out,
            masscan->tcb.timeout
            );
    }

    if (masscan->is_offline) {
        while (!masscan->is_done)
            pixie_usleep(10000);
        return;
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


        /*
         * RECIEVE
         *
         * This is the boring part of actually receiving a packet
         */
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
         * around 10 seconds, we'll close the connection. (--banners)
         */
        if (tcpcon) {
            tcpcon_timeouts(tcpcon, secs, usecs);
        }

	if (length > 1514)
		continue;

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


        /* OOPS: handle arp instead. Since we may completely bypass the TCP/IP
         * stack, we may have to handle ARPs ourself, or the router will 
         * lose track of us. */
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

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(
                pcapfile,
                px,
                length,
                length,
                secs,
                usecs);
        }

        LOG(5, "%u.%u.%u.%u - ackno=0x%08x flags=%02x\n", 
            (ip_them>>24)&0xff, (ip_them>>16)&0xff, (ip_them>>8)&0xff, (ip_them>>0)&0xff, 
            seqno_me, TCP_FLAGS(px, parsed.transport_offset));


        /* If recording --banners, create a new "TCP Control Block (TCB)" */
        if (tcpcon) {
            struct TCP_Control_Block *tcb;

            /* does a TCB already exist for this connection? */
            tcb = tcpcon_lookup_tcb(tcpcon,
                            ip_me, ip_them,
                            parsed.port_dst, parsed.port_src);

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (syn_hash(ip_them, parsed.port_src) != seqno_me - 1) {
                    LOG(2, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n", 
                        (ip_them>>24)&0xff, (ip_them>>16)&0xff, (ip_them>>8)&0xff, (ip_them>>0)&0xff, 
                        seqno_me-1, syn_hash(ip_them, parsed.port_src));
                    continue;
                }

                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them, 
                                    parsed.port_dst, 
                                    parsed.port_src, 
                                    seqno_me, seqno_them+1);
                }

                tcpcon_handle(tcpcon, tcb, TCP_WHAT_SYNACK, 
                    0, 0, secs, usecs, seqno_them+1);

            } else if (tcb) {
                /* If this is an ACK, then handle that first */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_ACK, 
                        0, seqno_me, secs, usecs, seqno_them);
                }

                /* If this contains payload, handle that */
                if (parsed.app_length) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_DATA, 
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs, seqno_them);
                }

                /* If this is a FIN, handle that. Note that ACK + 
                 * payload + FIN can come together */
                if (TCP_IS_FIN(px, parsed.transport_offset) && !TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_FIN, 
                        0, 0, secs, usecs, seqno_them);
                }

                /* If this is a RST, then we'll be closing the connection */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_RST, 
                        0, 0, secs, usecs, seqno_them);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                /* 
                 * NO TCB!
                 *  This happens when we've sent a FIN, deleted our connection,
                 *  but the other side didn't get the packet.
                 */
                if (!TCP_IS_RST(px, parsed.transport_offset))
                tcpcon_send_FIN(
                    tcpcon,
                    ip_me, ip_them,
                    parsed.port_dst, parsed.port_src,
                    seqno_them, seqno_me);
            }

        }

        if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
            /* figure out the status */
            status = Port_Unknown;
            if ((px[parsed.transport_offset+13] & 0x2) == 0x2)
                status = Port_Open;
            if ((px[parsed.transport_offset+13] & 0x4) == 0x4)
                status = Port_Closed;

            /* verify: syn-cookies */
            if (syn_hash(ip_them, parsed.port_src) != seqno_me - 1) {
                LOG(2, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n", 
                    (ip_them>>24)&0xff, (ip_them>>16)&0xff, (ip_them>>8)&0xff, (ip_them>>0)&0xff, 
                    seqno_me-1, syn_hash(ip_them, parsed.port_src));
                continue;
            }

            /* verify: ignore duplicates */
            if (dedup_is_duplicate(dedup, ip_them, parsed.port_src))
                continue;

            /*
             * This is where we do the output
             */
            output_report_status(
                        out,
                        status,
                        ip_them,
                        parsed.port_src,
                        px[parsed.transport_offset + 13], /* tcp flags */
                        px[parsed.ip_offset + 8] /* ttl */
                        );
        }
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
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void control_c_handler(int x)
{
    control_c_pressed = 1+x;
}


/***************************************************************************
 * Called from main() to initiate the scan.
 * Launches the 'transmit_thread()' and 'receive_thread()' and waits for
 * them to exit.
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
#define BUFFER_COUNT 16384
    masscan->packet_buffers = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
    masscan->transmit_queue = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
    {
        unsigned i;
        for (i=0; i<BUFFER_COUNT-1; i++) {
            struct PacketBuffer *p = (struct PacketBuffer *)malloc(sizeof(*p));
            err = rte_ring_sp_enqueue(masscan->packet_buffers, p);
            if (err) {
                /* I dunno why but I can't queue all 256 packets, just 255 */
                LOG(0, "packet_buffers: enqueue: error %d\n", err);
            }
        }
    }


#if 0
    {
        int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (fd <= 0) {
            perror("socket");
        } else  {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = htons((unsigned short)masscan->adapter_port);
            sin.sin_addr.s_addr = 0;

            if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) != 0) {
                perror("bind");
            } else {
                int x = listen(fd, 5);
                if (x != 0)
                    perror("listen");
            }
            
        }
    }
#endif
    

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

#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101, &x);}
#endif

    global_now = time(0);

    /*
     * Initialize those defaults that aren't zero
     */
    memset(masscan, 0, sizeof(*masscan));
    masscan->wait = 10; /* how long to wait for responses when done */
    masscan->max_rate = 100.0; /* max rate = hundred packets-per-second */
    masscan->adapter_port = 0x10000; /* value not set */
    masscan->shard.one = 1;
    masscan->shard.of = 1;
    strcpy_s(   masscan->rotate_directory,
                sizeof(masscan->rotate_directory),
                ".");

#if !defined(WIN32)
    if (access("/etc/masscan/masscan.conf", 0) == 0) {
        masscan_read_config_file(masscan, "/etc/masscan/masscan.conf");
    }
#endif

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
            x += blackrock_selftest();
            x += rawsock_selftest();
            x += randlcg_selftest();
            x += tcpkt_selftest();
            x += ranges_selftest();
            x += pixie_time_selftest();
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

