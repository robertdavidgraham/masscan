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
#include "templ-pkt.h"          /* packet template, that we use to send */
#include "rawsock.h"            /* api on top of Linux, Windows, Mac OS X*/
#include "logger.h"             /* adjust with -v command-line opt */
#include "main-status.h"        /* printf() regular status updates */
#include "main-throttle.h"      /* rate limit */
#include "main-dedup.h"         /* ignore duplicate responses */
#include "main-ptrace.h"        /* for nmap --packet-trace feature */
#include "proto-arp.h"          /* for responding to ARP requests */
#include "proto-banner1.h"      /* for snatching banners from systems */
#include "proto-tcp.h"          /* for TCP/IP connection table */
#include "proto-preprocess.h"   /* quick parse of packets */
#include "proto-icmp.h"         /* handle ICMP responses */
#include "proto-udp.h"          /* handle UDP responses */
#include "syn-cookie.h"         /* for SYN-cookies on send */
#include "output.h"             /* for outputing results */
#include "rte-ring.h"           /* producer/consumer ring buffer */
#include "rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */
#include "smack.h"              /* Aho-corasick state-machine pattern-matcher */
#include "pixie-timer.h"        /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "templ-payloads.h"     /* UDP packet payloads */

#include <limits.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#if defined(WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

/*
 * yea I know globals suck
 */
unsigned control_c_pressed = 0;
static unsigned control_c_pressed_again = 0;
time_t global_now;
static unsigned global_wait = 10;

uint64_t foo_timestamp = 0;
uint64_t foo_count = 0;

/***************************************************************************
 * Parameters we send to each thread-PAIR. Threads come in pairs, a
 * transmit and receive thread, that share the same configuration.
 ***************************************************************************/
struct ThreadPair {
    /** This points to the central configuration. Note that it's 'const',
     * meaning that the thread cannot change the contents. That'd be
     * unsafe */
    const struct Masscan *masscan;

    /** The adapter used by the threads. Normally, thread-pairs have
     * their own network adapter, especially when doing PF_RING
     * clustering. */
    struct Adapter *adapter;

    /**
     * The thread-pair use a "packet_buffer" and "transmit_queue" to 
     * send packets to each other */
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;

    /**
     * The index of the network adapter that we are using for this
     * thread-pair
     */
    unsigned nic_index;

    /**
     * This is an optimized binary-search when looking up IP addresses
     * based on the index.
     */
    unsigned *picker;

    /* the master 'i' variable */
    uint64_t my_index;


    /* This is used both by the transmit and receive thread for
     * formatting packets */
    struct TemplateSet tmplset[1];

    unsigned adapter_ip;
    unsigned adapter_port;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];

    unsigned done_transmitting;
    unsigned done_receiving;

    struct Throttler throttler[1];
};


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
flush_packets(struct Adapter *adapter,
    PACKET_QUEUE *packet_buffers,
    PACKET_QUEUE *transmit_queue,
    struct Throttler *throttler, uint64_t *packets_sent)
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
            err = rte_ring_sc_dequeue(transmit_queue, (void**)&p);
            if (err) {
                is_queue_empty = 1;
                break; /* queue is empty, nothing to send */
            }

            /*
             * Actually send the packet
             */
            rawsock_send_packet(adapter, p->px, (unsigned)p->length, 1);

            /*
             * Now that we are done with the packet, put it on the free list
             * of buffers that the transmit thread can reuse
             */
            for (err=1; err; ) {
                err = rte_ring_sp_enqueue(packet_buffers, p);
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
    struct ThreadPair *parms = (struct ThreadPair *)v;
    uint64_t i;
    uint64_t start;
    uint64_t end;
    const struct Masscan *masscan = parms->masscan;
    unsigned retries = masscan->retries;
    unsigned rate = (unsigned)masscan->max_rate;
    unsigned r = retries + 1;
    uint64_t range;
    struct BlackRock blackrock;
    uint64_t count_ips = rangelist_count(&masscan->targets);
    struct Throttler *throttler = parms->throttler;
    struct TemplateSet *pkt_template = parms->tmplset;
    unsigned *picker = parms->picker;
    struct Adapter *adapter = parms->adapter;
    uint64_t packets_sent = 0;
    unsigned increment = masscan->shard.of + masscan->nic_count;

    LOG(1, "xmit: starting transmit thread #%u\n", parms->nic_index);

    /* Lock this thread to a CPU. Transmit threads are on even CPUs,
     * receive threads on odd CPUs */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = parms->nic_index * 2;
        while (cpu >= cpu_count) {
            cpu -= cpu_count;
            cpu++;
        }
        pixie_cpu_set_affinity(cpu);
        //pixie_cpu_raise_priority();
    }


    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports */
    range = rangelist_count(&masscan->targets) 
            * rangelist_count(&masscan->ports);
    blackrock_init(&blackrock, range, masscan->seed);

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. Another reason to do this is so that we can bleed
     * a little bit past the end when we have --retries. Yet another
     * thing to do here is deal with multiple network adapters, which
     * is essentially the same logic as shards. */
    start = masscan->resume.index + (masscan->shard.one-1) + parms->nic_index;
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += retries * rate;

    

    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(throttler, masscan->max_rate/masscan->nic_count);

    /* -----------------
     * the main loop
     * -----------------*/
    LOG(3, "xmit: starting main loop: [%llu..%llu]\n", start, end);
    for (i=start; i<end; ) {
        uint64_t batch_size;

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one. (--max-rate)
         */
        batch_size = throttler_next_batch(throttler, packets_sent);
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
            xXx = (i + (r--) * rate);
            while (xXx >= range)
                xXx -= range;
            xXx = blackrock_shuffle(&blackrock,  xXx);
            ip = rangelist_pick2(&masscan->targets, xXx % count_ips, picker);
            port = rangelist_pick(&masscan->ports, xXx / count_ips);
            
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
            foo_count++;

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
                i += increment; /* <------ increment by 1 normally, more with shards/nics */
                r = retries + 1;
            }

        } /* end of batch */

        /* Transmit packets from other thread, when doing --banners */
        flush_packets(adapter, parms->packet_buffers, parms->transmit_queue, 
                        throttler, &packets_sent);

        /* If the user pressed <ctrl-c>, then we need to exit. but, in case
         * the user wants to --resume the scan later, we save the current
         * state in a file */
        if (control_c_pressed) {
            break;
        }

        /* save our current location for resuming, if the user pressed
         * <ctrl-c> to exit early */
        parms->my_index = i;
    }


    /*
     * We are done transmitting. However, response packets will take several
     * seconds to arrive. Therefore, sit in short loop waiting for those
     * packets to arrive. Pressing <ctrl-c> a second time will exit this
     * prematurely.
     */
    while (!control_c_pressed_again) {
        unsigned k;

        for (k=0; k<1000; k++) {
            /* Transmit packets from the receive thread */
            flush_packets(  adapter, 
                            parms->packet_buffers, 
                            parms->transmit_queue, 
                            throttler, 
                            &packets_sent);

            pixie_usleep(1000);
        }
    }

    /* Thread is about to exit */
    parms->done_transmitting = 1;
    LOG(1, "xmit: stopping transmit thread #%u\n", parms->nic_index);
}


unsigned
is_my_ip_address(const struct Masscan *masscan, unsigned ip)
{
    unsigned i;
    for (i=0; i<masscan->nic_count; i++)
        if (ip == masscan->nic[i].adapter_ip)
            return 1;
    return 0;
}
unsigned
is_my_port(const struct Masscan *masscan, unsigned ip)
{
    unsigned i;
    for (i=0; i<masscan->nic_count; i++)
        if (ip == masscan->nic[i].adapter_port)
            return 1;
    return 0;
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
receive_thread(void *v)
{
    struct ThreadPair *parms = (struct ThreadPair *)v;
    const struct Masscan *masscan = parms->masscan;

    struct Output *out;
    struct DedupTable *dedup;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;


    LOG(1, "recv: start receive thread #%u\n", parms->nic_index);

    /* Lock this thread to a CPU. Transmit threads are on even CPUs,
     * receive threads on odd CPUs */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = parms->nic_index * 2 + 1;
        while (cpu >= cpu_count) {
            cpu -= cpu_count;
            cpu++;
        }
        pixie_cpu_set_affinity(cpu);
    }

    /*
     * If configured, open a --pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    /*if (masscan->pcap_filename[0])
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);*/

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
            (size_t)((masscan->max_rate/5) / masscan->nic_count), 
            parms->transmit_queue, 
            parms->packet_buffers,
            &parms->tmplset->pkts[Proto_TCP],
            output_report_banner,
            out,
            masscan->tcb.timeout
            );
    }

    if (masscan->is_offline) {
        while (!control_c_pressed_again)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        return;
    }

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(1, "begin receive thread\n");
    while (!control_c_pressed_again) {
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
                    parms->adapter,
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
        if (parms->adapter_ip != ip_me)
            continue;


        /*
         * Handle non-TCP protocols
         */
        switch (parsed.found) {
            case FOUND_ARP:
                /* OOPS: handle arp instead. Since we may completely bypass the TCP/IP
                 * stack, we may have to handle ARPs ourself, or the router will 
                 * lose track of us. */
                LOGip(2, ip_them, 0, "-> ARP [%u] \n", px[parsed.found_offset]);
                arp_response(   parms->adapter_ip,
                                parms->adapter_mac,
                                px, length,
                                parms->packet_buffers,
                                parms->transmit_queue);
                continue;
            case FOUND_UDP:
            case FOUND_DNS:
                if (!is_my_port(masscan, parsed.port_dst))
                    continue;
                handle_udp(out, px, length, &parsed);
                continue;
            case FOUND_ICMP:
                handle_icmp(out, px, length, &parsed);
                continue;
            case FOUND_TCP:
                /* fall down to below */
                break;
            default:
                continue;
        }


        /* verify: my port number */
        if (parms->adapter_port != parsed.port_dst)
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

        {
            char buf[64];
            LOGip(5, ip_them, parsed.port_src, "-> TCP ackno=0x%08x flags=0x%02x(%s)\n", 
                seqno_me, 
                TCP_FLAGS(px, parsed.transport_offset),
                reason_string(TCP_FLAGS(px, parsed.transport_offset), buf, sizeof(buf)));
        }

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
                if (TCP_IS_FIN(px, parsed.transport_offset) 
                    && !TCP_IS_RST(px, parsed.transport_offset)) {
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
                LOG(5, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n", 
                    (ip_them>>24)&0xff, (ip_them>>16)&0xff, 
                    (ip_them>>8)&0xff, (ip_them>>0)&0xff, 
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


    LOG(1, "recv: end receive thread #%u\n", parms->nic_index);

    /*
     * cleanup
     */
    dedup_destroy(dedup);
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    /* Thread is about to exit */
    parms->done_receiving = 1;
}


/***************************************************************************
 * We trap the <ctrl-c> so that instead of exiting immediately, we sit in
 * a loop for a few seconds waiting for any late response. But, the user
 * can press <ctrl-c> a second time to exit that waiting.
 ***************************************************************************/
static void control_c_handler(int x)
{
    if (control_c_pressed == 0) {
        fprintf(stderr, 
                "waiting %u seconds to exit..."
                "                                            \n", 
                global_wait);
        fflush(stderr);
        control_c_pressed = 1+x;
    } else
        control_c_pressed_again = 1;

}



/***************************************************************************
 * Called from main() to initiate the scan.
 * Launches the 'transmit_thread()' and 'receive_thread()' and waits for
 * them to exit.
 ***************************************************************************/
static int
main_scan(struct Masscan *masscan)
{
    struct ThreadPair parms_array[8];
    uint64_t count_ips;
    uint64_t count_ports;
    uint64_t range;
    unsigned index;
    unsigned *picker;
    time_t now = time(0);
    struct Status status;
    uint64_t min_index = UINT64_MAX;

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
    range = count_ips * count_ports + (uint64_t)(masscan->retries * masscan->max_rate);


    /* 
     * If the IP address range is very big, then require that that the 
     * user apply an exclude range 
     */
    if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude_ip) == 0) {
        LOG(0, "FAIL: range too big, need confirmation\n");
        LOG(0, " [hint] to prevent acccidents, at least one --exclude must be specified\n");
        LOG(0, " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        exit(1);
    }

    /*
     * trim the nmap UDP payloads down to only those ports we are using. This 
     * makes lookups faster at high packet rates.
     */
    payloads_trim(masscan->payloads, &masscan->ports);

    /* Optimize target selection so it's a quick binary search instead
     * of walking large memory tables. When we scan the entire Internet
     * our --excludefile will chop up our pristine 0.0.0.0/0 range into
     * hundreds of subranges. This scans through them faster. */
    picker = rangelist_pick2_create(&masscan->targets);

    /* needed for --packet-trace option so that we know when we started
     * the scan */
    global_timestamp_start = 1.0 * pixie_gettime() / 1000000.0;

    foo_timestamp = pixie_gettime();

    /*
     * Start scanning threats for each adapter
     */
    for (index=0; index<masscan->nic_count; index++) {
        struct ThreadPair *parms = &parms_array[index];
        int err;

        parms->masscan = masscan;
        parms->nic_index = index;
        parms->picker = picker;
        parms->my_index = masscan->resume.index;
        parms->done_transmitting = 0;
        parms->done_receiving = 0;
        

    
        /*
         * Turn the adapter on, and get the running configuration
         */
        err = masscan_initialize_adapter(
                            masscan,
                            index,
                            &parms->adapter_ip,
                            parms->adapter_mac,
                            parms->router_mac);
        if (err != 0)
            exit(1);
        parms->adapter = masscan->nic[index].adapter;

        /*
         * Initialize the TCP packet template. The way this works is that we parse
         * an existing TCP packet, and use that as the template for scanning. Then,
         * we adjust the template with additional features, such as the IP address
         * and so on.
         */
        template_packet_init(
                    parms->tmplset,
                    parms->adapter_ip,
                    parms->adapter_mac,
                    parms->router_mac,
                    masscan->payloads);

        /*
         * Set the "source port" of everything we transmit.
         */
        if (masscan->nic[index].adapter_port == 0x10000)
            masscan->nic[index].adapter_port = 40000 + now % 20000;
        template_set_source_port(   parms->tmplset, 
                                    masscan->nic[index].adapter_port);

        /*
         * Set the "TTL" (IP time-to-live) of everything we send.
         */
        if (masscan->nmap.ttl)
            template_set_ttl(parms->tmplset, masscan->nmap.ttl);

    
        /*
         * Read back what we've set
         */
        parms->adapter_port = template_get_source_port(parms->tmplset);

        /*
         * trap <ctrl-c> to pause
         */
        signal(SIGINT, control_c_handler);


        /*
         * Allocate packet buffers for sending
         */
#define BUFFER_COUNT 16384
        parms->packet_buffers = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
        parms->transmit_queue = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
        {
            unsigned i;
            for (i=0; i<BUFFER_COUNT-1; i++) {
                struct PacketBuffer *p = (struct PacketBuffer *)malloc(sizeof(*p));
                err = rte_ring_sp_enqueue(parms->packet_buffers, p);
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
        pixie_begin_thread(transmit_thread, 0, parms);


        /*
         * Start the MATCHING receive thread. Transmit and receive threads
         * come in matching pairs.
         */
        pixie_begin_thread(receive_thread, 0, parms);

    }

    /*
     * Print helpful text
     */
    {
        char buffer[80];
        time_t now  = time(0);
        struct tm x;

        gmtime_s(&x, &now);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
        LOG(0, "\nStarting masscan 1.0 (http://bit.ly/14GZzcT) at %s\n", buffer);
        LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
        LOG(0, "Initiating SYN Stealth Scan\n");
        LOG(0, "Scanning %u hosts [%u port%s/host]\n",
            (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
    }

    /*
     * Now wait for <ctrl-c> to be pressed OR for threads to exit
     */
    status_start(&status);
    while (!control_c_pressed) {
        unsigned i;
        double rate = 0;
        
        
        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;
        }

        if (min_index >= range) {
            control_c_pressed = 1;
        }

        /*
         * update screen about once per second with statistics,
         * namely packets/second.
         */
        status_print(&status, min_index, range, rate);
        
        /* Sleep for almost a second */
        pixie_mssleep(750);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (min_index < count_ips * count_ports) {
        masscan->resume.index = min_index;
        masscan_save_state(masscan);
    }

#if 0
    /* I'm figuring a bug in the status_print() function, it's reporting
     * values that are twice the correct value. This double checks that */
    {
        double elapsed = pixie_gettime() - foo_timestamp;
        double rate;

        rate = ((1000000.0 * foo_count) / elapsed);

        printf("\nrate = %5.3f\n", rate);
    }
#endif
            

    /*
     * Now wait for all threads to exit
     */
    now = time(0);
    for (;;) {
        unsigned transmit_count = 0;
        unsigned receive_count = 0;
        unsigned i;
        
        pixie_mssleep(750);
        
        status_print(&status, masscan->resume.index, range, 0);

        if (time(0) - now >= masscan->wait)
            control_c_pressed_again = 1;

        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            transmit_count += parms->done_transmitting;
            receive_count += parms->done_receiving;

        }

        if (transmit_count < masscan->nic_count)
            continue;
        control_c_pressed = 1;
        control_c_pressed_again = 1;
        if (receive_count < masscan->nic_count)
            continue;
        break;
    }    


    status_finish(&status);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Masscan masscan[1];
    unsigned i;

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
    for (i=0; i<8; i++)
        masscan->nic[i].adapter_port = 0x10000; /* value not set */
    masscan->nic_count = 1;
    masscan->shard.one = 1;
    masscan->shard.of = 1;
    masscan->payloads = payloads_create();
    strcpy_s(   masscan->rotate_directory,
                sizeof(masscan->rotate_directory),
                ".");

    /*
     * On non-Windows systems, read the defaults from the file in
     * the /etc directory. These defaults will contain things
     * like the output directory, max packet rates, and so on. Most
     * importanlty, the master "--excludefile" might be placed here,
     * so that blacklisted ranges won't be scanned, even if the user
     * makes a mistake
     */
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
    rangelist_exclude(&masscan->targets, &masscan->exclude_ip);
    rangelist_exclude(&masscan->ports, &masscan->exclude_port);
    rangelist_remove_range2(&masscan->targets, range_parse_ipv4("224.0.0.0/4", 0, 0));



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
            
        case Operation_ListScan:
            /* Create a randomized list of IP addresses */
            main_listscan(masscan);
            return 0;

    case Operation_List_Adapters:
        /* List the network adapters we might want to use for scanning */
        rawsock_list_adapters();
        break;

    case Operation_DebugIF:
        for (i=0; i<masscan->nic_count; i++)
            rawsock_selftest_if(masscan->nic[i].ifname);
        return 0;

    case Operation_Selftest:
        /*
         * Do a regression test of all the significant units
         */
        {
            int x = 0;
            x += payloads_selftest();
            x += blackrock_selftest();
            x += rawsock_selftest();
            x += randlcg_selftest();
            x += template_selftest();
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

