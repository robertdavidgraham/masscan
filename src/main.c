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
#include "masscan-version.h"
#include "masscan-status.h"     /* open or closed */
#include "massip-parse.h"
#include "massip-port.h"
#include "main-status.h"        /* printf() regular status updates */
#include "main-throttle.h"      /* rate limit */
#include "main-dedup.h"         /* ignore duplicate responses */
#include "main-ptrace.h"        /* for nmap --packet-trace feature */
#include "main-globals.h"       /* all the global variables in the program */
#include "main-readrange.h"
#include "crypto-siphash24.h"   /* hash function, for hash tables */
#include "crypto-blackrock.h"   /* the BlackRock shuffling func */
#include "crypto-lcg.h"         /* the LCG randomization func */
#include "crypto-base64.h"      /* base64 encode/decode */
#include "templ-pkt.h"          /* packet template, that we use to send */
#include "util-logger.h"             /* adjust with -v command-line opt */
#include "stack-ndpv6.h"        /* IPv6 Neighbor Discovery Protocol */
#include "stack-arpv4.h"        /* Handle ARP resolution and requests */
#include "rawsock.h"            /* API on top of Linux, Windows, Mac OS X*/
#include "rawsock-adapter.h"    /* Get Ethernet adapter configuration */
#include "rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */
#include "syn-cookie.h"         /* for SYN-cookies on send */
#include "output.h"             /* for outputting results */
#include "rte-ring.h"           /* producer/consumer ring buffer */
#include "stub-pcap.h"          /* dynamically load libpcap library */
#include "smack.h"              /* Aho-corasick state-machine pattern-matcher */
#include "pixie-timer.h"        /* portable time functions */
#include "pixie-threads.h"      /* portable threads */
#include "pixie-backtrace.h"    /* maybe print backtrace on crash */
#include "templ-payloads.h"     /* UDP packet payloads */
#include "in-binary.h"          /* convert binary output to XML/JSON */
#include "vulncheck.h"          /* checking vulns like monlist, poodle, heartblee */
#include "scripting.h"
#include "read-service-probes.h"
#include "misc-rstfilter.h"
#include "proto-x509.h"
#include "proto-arp.h"          /* for responding to ARP requests */
#include "proto-banner1.h"      /* for snatching banners from systems */
#include "stack-tcp-core.h"          /* for TCP/IP connection table */
#include "proto-preprocess.h"   /* quick parse of packets */
#include "proto-icmp.h"         /* handle ICMP responses */
#include "proto-udp.h"          /* handle UDP responses */
#include "proto-snmp.h"         /* parse SNMP responses */
#include "proto-ntp.h"          /* parse NTP responses */
#include "proto-coap.h"         /* CoAP selftest */
#include "proto-zeroaccess.h"
#include "proto-sctp.h"
#include "proto-oproto.h"       /* Other protocols on top of IP */
#include "util-malloc.h"
#include "util-checksum.h"

#include <assert.h>
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
unsigned volatile is_tx_done = 0;
unsigned volatile is_rx_done = 0;
time_t global_now;

uint64_t usec_start;


/***************************************************************************
 * We create a pair of transmit/receive threads for each network adapter.
 * This structure contains the parameters we send to each pair.
 ***************************************************************************/
struct ThreadPair {
    /** This points to the central configuration. Note that it's 'const',
     * meaning that the thread cannot change the contents. That'd be
     * unsafe */
    const struct Masscan *masscan;

    /** The adapter used by the thread-pair. Normally, thread-pairs have
     * their own network adapter, especially when doing PF_RING
     * clustering. */
    struct Adapter *adapter;

    struct stack_t *stack;

    /**
     * The index of the network adapter that we are using for this
     * thread-pair. This is an index into the "masscan->nic[]"
     * array.
     *
     * NOTE: this is also the "thread-id", because we create one
     * transmit/receive thread pair per NIC.
     */
    unsigned nic_index;

    /**
     * A copy of the master 'index' variable. This is just advisory for
     * other threads, to tell them how far we've gotten.
     */
    volatile uint64_t my_index;


    /* This is used both by the transmit and receive thread for
     * formatting packets */
    struct TemplateSet tmplset[1];

    /**
     * The current IP address we are using for transmit/receive.
     */
    struct stack_src_t _src_;

    macaddress_t source_mac;
    macaddress_t router_mac_ipv4;
    macaddress_t router_mac_ipv6;

    unsigned done_transmitting;
    unsigned done_receiving;

    double pt_start;

    struct Throttler throttler[1];

    uint64_t *total_synacks;
    uint64_t *total_tcbs;
    uint64_t *total_syns;

    size_t thread_handle_xmit;
    size_t thread_handle_recv;
};

struct source_t {
    unsigned ipv4;
    unsigned ipv4_mask;
    unsigned port;
    unsigned port_mask;
    ipv6address ipv6;
    ipv6address ipv6_mask;
};

/***************************************************************************
 * We support a range of source IP/port. This function converts that
 * range into useful variables we can use to pick things form that range.
 ***************************************************************************/
static void
adapter_get_source_addresses(const struct Masscan *masscan,
            unsigned nic_index,
            struct source_t *src)
{
    const struct stack_src_t *ifsrc = &masscan->nic[nic_index].src;
    static ipv6address mask = {~0ULL, ~0ULL};

    src->ipv4 = ifsrc->ipv4.first;
    src->ipv4_mask = ifsrc->ipv4.last - ifsrc->ipv4.first;

    src->port = ifsrc->port.first;
    src->port_mask = ifsrc->port.last - ifsrc->port.first;

    src->ipv6 = ifsrc->ipv6.first;

    /* TODO: currently supports only a single address. This needs to
     * be fixed to support a list of addresses */
    src->ipv6_mask = mask;
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
    uint64_t retries = masscan->retries;
    uint64_t rate = (uint64_t)masscan->max_rate;
    unsigned r = (unsigned)retries + 1;
    uint64_t range;
    uint64_t range_ipv6;
    struct BlackRock blackrock;
    uint64_t count_ipv4 = rangelist_count(&masscan->targets.ipv4);
    uint64_t count_ipv6 = range6list_count(&masscan->targets.ipv6).lo;
    struct Throttler *throttler = parms->throttler;
    struct TemplateSet pkt_template = templ_copy(parms->tmplset);
    struct Adapter *adapter = parms->adapter;
    uint64_t packets_sent = 0;
    unsigned increment = masscan->shard.of * masscan->nic_count;
    struct source_t src;
    uint64_t seed = masscan->seed;
    uint64_t repeats = 0; /* --infinite repeats */
    uint64_t *status_syn_count;
    uint64_t entropy = masscan->seed;

    /* Wait to make sure receive_thread is ready */
    pixie_usleep(1000000);
    LOG(1, "[+] starting transmit thread #%u\n", parms->nic_index);

    /* export a pointer to this variable outside this threads so
     * that the 'status' system can print the rate of syns we are
     * sending */
    status_syn_count = MALLOC(sizeof(uint64_t));
    *status_syn_count = 0;
    parms->total_syns = status_syn_count;


    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    adapter_get_source_addresses(masscan, parms->nic_index, &src);


    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(throttler, masscan->max_rate/masscan->nic_count);

infinite:
    
    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports.
     * IPv6: low index will pick addresses from the IPv6 ranges, and high
     * indexes will pick addresses from the IPv4 ranges. */
    range = count_ipv4 * rangelist_count(&masscan->targets.ports)
            + count_ipv6 * rangelist_count(&masscan->targets.ports);
    range_ipv6 = count_ipv6 * rangelist_count(&masscan->targets.ports);
    blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. Another reason to do this is so that we can bleed
     * a little bit past the end when we have --retries. Yet another
     * thing to do here is deal with multiple network adapters, which
     * is essentially the same logic as shards. */
    start = masscan->resume.index + (masscan->shard.one-1) * masscan->nic_count + parms->nic_index;
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += retries * range;


    /* -----------------
     * the main loop
     * -----------------*/
    LOG(3, "THREAD: xmit: starting main loop: [%llu..%llu]\n", start, end);
    for (i=start; i<end; ) {
        uint64_t batch_size;

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one. (--max-rate)
         */
        batch_size = throttler_next_batch(throttler, packets_sent);

        /*
         * Transmit packets from other thread, when doing --banners. This
         * takes priority over sending SYN packets. If there is so much
         * activity grabbing banners that we cannot transmit more SYN packets,
         * then "batch_size" will get decremented to zero, and we won't be
         * able to transmit SYN packets.
         */
        stack_flush_packets(parms->stack, adapter,
                        &packets_sent, &batch_size);


        /*
         * Transmit a bunch of packets. At any rate slower than 100,000
         * packets/second, the 'batch_size' is likely to be 1. At higher
         * rates, we can't afford to throttle on a per-packet basis and 
         * instead throttle on a per-batch basis. In other words, throttle
         * based on 2-at-a-time, 3-at-time, and so on, with the batch
         * size increasing as the packet rate increases. This gives us
         * very precise packet-timing for low rates below 100,000 pps,
         * while not incurring the overhead for high packet rates.
         */
        while (batch_size && i < end) {
            uint64_t xXx;
            uint64_t cookie;
            


            /*
             * RANDOMIZE THE TARGET:
             *  This is kinda a tricky bit that picks a random IP and port
             *  number in order to scan. We monotonically increment the
             *  index 'i' from [0..range]. We then shuffle (randomly transmog)
             *  that index into some other, but unique/1-to-1, number in the
             *  same range. That way we visit all targets, but in a random
             *  order. Then, once we've shuffled the index, we "pick" the
             *  IP address and port that the index refers to.
             */
            xXx = (i + (r--) * rate);
            if (rate > range)
                xXx %= range;
            else
                while (xXx >= range)
                    xXx -= range;
            xXx = blackrock_shuffle(&blackrock,  xXx);
            
            if (xXx < range_ipv6) {
                ipv6address ip_them;
                unsigned port_them;
                ipv6address ip_me;
                unsigned port_me;

                ip_them = range6list_pick(&masscan->targets.ipv6, xXx % count_ipv6);
                port_them = rangelist_pick(&masscan->targets.ports, xXx / count_ipv6);

                ip_me = src.ipv6;
                port_me = src.port;
                
                cookie = syn_cookie_ipv6(ip_them, port_them, ip_me, port_me, entropy);

                rawsock_send_probe_ipv6(
                        adapter,
                        ip_them, port_them,
                        ip_me, port_me,
                        (unsigned)cookie,
                        !batch_size, /* flush queue on last packet in batch */
                        &pkt_template
                        );

                /* Our index selects an IPv6 target */
            } else {
                /* Our index selects an IPv4 target. In other words, low numbers
                 * index into the IPv6 ranges, and high numbers index into the
                 * IPv4 ranges. */
                ipv4address ip_them;
                ipv4address port_them;
                unsigned ip_me;
                unsigned port_me;

                xXx -= range_ipv6;

                ip_them = rangelist_pick(&masscan->targets.ipv4, xXx % count_ipv4);
                port_them = rangelist_pick(&masscan->targets.ports, xXx / count_ipv4);

                /*
                 * SYN-COOKIE LOGIC
                 *  Figure out the source IP/port, and the SYN cookie
                 */
                if (src.ipv4_mask > 1 || src.port_mask > 1) {
                    uint64_t ck = syn_cookie_ipv4((unsigned)(i+repeats),
                                            (unsigned)((i+repeats)>>32),
                                            (unsigned)xXx, (unsigned)(xXx>>32),
                                            entropy);
                    port_me = src.port + (ck & src.port_mask);
                    ip_me = src.ipv4 + ((ck>>16) & src.ipv4_mask);
                } else {
                    ip_me = src.ipv4;
                    port_me = src.port;
                }
                cookie = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy);

                /*
                 * SEND THE PROBE
                 *  This is sorta the entire point of the program, but little
                 *  exciting happens here. The thing to note that this may
                 *  be a "raw" transmit that bypasses the kernel, meaning
                 *  we can call this function millions of times a second.
                 */
                rawsock_send_probe_ipv4(
                        adapter,
                        ip_them, port_them,
                        ip_me, port_me,
                        (unsigned)cookie,
                        !batch_size, /* flush queue on last packet in batch */
                        &pkt_template
                        );
            }

            batch_size--;
            packets_sent++;
            (*status_syn_count)++;

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
                r = (unsigned)retries + 1;
            }

        } /* end of batch */


        /* save our current location for resuming, if the user pressed
         * <ctrl-c> to exit early */
        parms->my_index = i;

        /* If the user pressed <ctrl-c>, then we need to exit. In case
         * the user wants to --resume the scan later, we save the current
         * state in a file */
        if (is_tx_done) {
            break;
        }
    }

    /*
     * --infinite
     *  For load testing, go around and do this again
     */
    if (masscan->is_infinite && !is_tx_done) {
        seed++;
        repeats++;
        goto infinite;
    }

    /*
     * Flush any untransmitted packets. High-speed mechanisms like Windows
     * "sendq" and Linux's "PF_RING" queue packets and transmit many together,
     * so there may be some packets that we've queued but not yet transmitted.
     * This call makes sure they are transmitted.
     */
    rawsock_flush(adapter);

    /*
     * Wait until the receive thread realizes the scan is over
     */
    LOG(1, "[+] transmit thread #%u complete\n", parms->nic_index);

    /*
     * We are done transmitting. However, response packets will take several
     * seconds to arrive. Therefore, sit in short loop waiting for those
     * packets to arrive. Pressing <ctrl-c> a second time will exit this
     * prematurely.
     */
    while (!is_rx_done) {
        unsigned k;
        uint64_t batch_size;

        for (k=0; k<1000; k++) {
            
            /*
             * Only send a few packets at a time, throttled according to the max
             * --max-rate set by the user
             */
            batch_size = throttler_next_batch(throttler, packets_sent);


            /* Transmit packets from the receive thread */
            stack_flush_packets(  parms->stack, adapter,
                            &packets_sent,
                            &batch_size);

            /* Make sure they've actually been transmitted, not just queued up for
             * transmit */
            rawsock_flush(adapter);

            pixie_usleep(100);
        }
    }

    /* Thread is about to exit */
    parms->done_transmitting = 1;
    LOG(1, "[+] exiting transmit thread #%u                    \n", parms->nic_index);
}


/***************************************************************************
 ***************************************************************************/
static unsigned
is_nic_port(const struct Masscan *masscan, unsigned ip)
{
    unsigned i;
    for (i=0; i<masscan->nic_count; i++)
        if (is_my_port(&masscan->nic[i].src, ip))
            return 1;
    return 0;
}

static unsigned
is_ipv6_multicast(ipaddress ip_me)
{
    /* If this is an IPv6 multicast packet, one sent to the IPv6
     * address with a prefix of FF02::/16 */
    return ip_me.version == 6 && (ip_me.ipv6.hi>>48ULL) == 0xFF02;
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
    struct Adapter *adapter = parms->adapter;
    int data_link = stack_if_datalink(adapter);
    struct Output *out;
    struct DedupTable *dedup;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;
    uint64_t *status_synack_count;
    uint64_t *status_tcb_count;
    uint64_t entropy = masscan->seed;
    struct ResetFilter *rf;
    struct stack_t *stack = parms->stack;
    struct source_t src = {0};

    
    
    /* For reducing RST responses, see rstfilter_is_filter() below */
    rf = rstfilter_create(entropy, 16384);

    /* some status variables */
    status_synack_count = MALLOC(sizeof(uint64_t));
    *status_synack_count = 0;
    parms->total_synacks = status_synack_count;

    status_tcb_count = MALLOC(sizeof(uint64_t));
    *status_tcb_count = 0;
    parms->total_tcbs = status_tcb_count;

    LOG(1, "[+] starting receive thread #%u\n", parms->nic_index);
    
    /* Lock this thread to a CPU. Transmit threads are on even CPUs,
     * receive threads on odd CPUs */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = parms->nic_index * 2 + 1;
        while (cpu >= cpu_count) {
            cpu -= cpu_count;
            cpu++;
        }
        //TODO:
        //pixie_cpu_set_affinity(cpu);
    }

    /*
     * If configured, open a --pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    if (masscan->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);
    }

    /*
     * Open output. This is where results are reported when saving
     * the --output-format to the --output-filename
     */
    out = output_create(masscan, parms->nic_index);

    /*
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    dedup = dedup_create();

    /*
     * Create a TCP connection table (per thread pair) for interacting with live
     * connections when doing --banners
     */
    if (masscan->is_banners) {
        struct TcpCfgPayloads *pay;
        size_t i;

        /*
         * Create TCP connection table
         */
        tcpcon = tcpcon_create_table(
            (size_t)((masscan->max_rate/5) / masscan->nic_count),
            parms->stack,
            &parms->tmplset->pkts[Proto_TCP],
            output_report_banner,
            out,
            masscan->tcb.timeout,
            masscan->seed
            );
        
        /*
         * Initialize TCP scripting
         */
        scripting_init_tcp(tcpcon, masscan->scripting.L);

        /*
         * Get the possible source IP addresses and ports that masscan
         * might be using to transmit from.
         */
        adapter_get_source_addresses(masscan, parms->nic_index, &src);
                               

        /*
         * Set some flags [kludge]
         */
        tcpcon_set_banner_flags(tcpcon,
                masscan->is_capture_cert,
                masscan->is_capture_servername,
                masscan->is_capture_html,
                masscan->is_capture_heartbleed,
				masscan->is_capture_ticketbleed);
        if (masscan->is_hello_smbv1)
            tcpcon_set_parameter(tcpcon, "hello", 1, "smbv1");
        if (masscan->is_hello_http)
            tcpcon_set_parameter(tcpcon, "hello", 1, "http");
        if (masscan->is_hello_ssl)
            tcpcon_set_parameter(tcpcon, "hello", 1, "ssl");
        if (masscan->is_heartbleed)
            tcpcon_set_parameter(tcpcon, "heartbleed", 1, "1");
        if (masscan->is_ticketbleed)
            tcpcon_set_parameter(tcpcon, "ticketbleed", 1, "1");
        if (masscan->is_poodle_sslv3)
            tcpcon_set_parameter(tcpcon, "sslv3", 1, "1");

        if (masscan->http.payload)
            tcpcon_set_parameter(   tcpcon,
                                    "http-payload",
                                    masscan->http.payload_length,
                                    masscan->http.payload);
        if (masscan->http.user_agent)
            tcpcon_set_parameter(   tcpcon,
                                    "http-user-agent",
                                    masscan->http.user_agent_length,
                                    masscan->http.user_agent);
        if (masscan->http.host)
            tcpcon_set_parameter(   tcpcon,
                                    "http-host",
                                    masscan->http.host_length,
                                    masscan->http.host);
        if (masscan->http.method)
            tcpcon_set_parameter(   tcpcon,
                                    "http-method",
                                    masscan->http.method_length,
                                    masscan->http.method);
        if (masscan->http.url)
            tcpcon_set_parameter(   tcpcon,
                                    "http-url",
                                    masscan->http.url_length,
                                    masscan->http.url);
        if (masscan->http.version)
            tcpcon_set_parameter(   tcpcon,
                                    "http-version",
                                    masscan->http.version_length,
                                    masscan->http.version);


        if (masscan->tcp_connection_timeout) {
            char foo[64];
            snprintf(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "timeout",
                                 strlen(foo),
                                 foo);
        }
        if (masscan->tcp_hello_timeout) {
            char foo[64];
            snprintf(foo, sizeof(foo), "%u", masscan->tcp_hello_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "hello-timeout",
                                 strlen(foo),
                                 foo);
        }
        
        for (i=0; i<masscan->http.headers_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        masscan->http.headers[i].name,
                        masscan->http.headers[i].value_length,
                        masscan->http.headers[i].value,
                        http_field_replace);
        }
        for (i=0; i<masscan->http.cookies_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        "Cookie",
                        masscan->http.cookies[i].value_length,
                        masscan->http.cookies[i].value,
                        http_field_add);
        }
        for (i=0; i<masscan->http.remove_count; i++) {
            tcpcon_set_http_header(tcpcon,
                        masscan->http.headers[i].name,
                        0,
                        0,
                        http_field_remove);
        }

        for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
            char name[64];
            snprintf(name, sizeof(name), "hello-string[%u]", pay->port);
            tcpcon_set_parameter(   tcpcon, 
                                    name, 
                                    strlen(pay->payload_base64), 
                                    pay->payload_base64);
        }

    }

    /*
     * In "offline" mode, we don't have any receive threads, so simply
     * wait until transmitter thread is done then go to the end
     */
    if (masscan->is_offline) {
        while (!is_rx_done)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        goto end;
    }

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(2, "[+] THREAD: recv: starting main loop\n");
    while (!is_rx_done) {
        int status;
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;
        unsigned x;
        struct PreprocessedInfo parsed;
        ipaddress ip_me;
        unsigned port_me;
        ipaddress ip_them;
        unsigned port_them;
        unsigned seqno_me;
        unsigned seqno_them;
        unsigned cookie;
        unsigned Q = 0;

        /*
         * RECEIVE
         *
         * This is the boring part of actually receiving a packet
         */
        err = rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);
        if (err != 0) {
            if (tcpcon)
                tcpcon_timeouts(tcpcon, (unsigned)time(0), 0);
            continue;
        }
        

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
        x = preprocess_frame(px, length, data_link, &parsed);
        if (!x)
            continue; /* corrupt packet */
        ip_me = parsed.dst_ip;
        ip_them = parsed.src_ip;
        port_me = parsed.port_dst;
        port_them = parsed.port_src;
        seqno_them = TCP_SEQNO(px, parsed.transport_offset);
        seqno_me = TCP_ACKNO(px, parsed.transport_offset);
        
        assert(ip_me.version != 0);
        assert(ip_them.version != 0);

        switch (parsed.ip_protocol) {
        case 132: /* SCTP */
            cookie = syn_cookie(ip_them, port_them | (Proto_SCTP<<16), ip_me, port_me, entropy) & 0xFFFFFFFF;
            break;
        default:
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF;
        }

        /* verify: my IP address */
        if (!is_my_ip(stack->src, ip_me)) {
            /* NDP Neighbor Solicitations don't come to our IP address, but to
             * a multicast address */
            if (is_ipv6_multicast(ip_me)) {
                if (parsed.found == FOUND_NDPv6 && parsed.opcode == 135) {
                    stack_ndpv6_incoming_request(stack, &parsed, px, length);
                }
            }
            continue;
        }

        /*
         * Handle non-TCP protocols
         */
        switch (parsed.found) {
            case FOUND_NDPv6:
                switch (parsed.opcode) {
                case 133: /* Router Solicitation */
                    /* Ignore router solicitations, since we aren't a router */
                    continue;
                case 134: /* Router advertisement */
                    /* TODO: We need to process router advertisements while scanning
                     * so that we can print warning messages if router information
                     * changes while scanning. */
                    continue;
                case 135: /* Neighbor Solicitation */
                    /* When responses come back from our scans, the router will send us
                     * these packets. We need to respond to them, so that the router
                     * can then forward the packets to us. If we don't respond, we'll
                     * get no responses. */
                    stack_ndpv6_incoming_request(stack, &parsed, px, length);
                    continue;
                case 136: /* Neighbor Advertisement */
                    /* TODO: If doing an --ndpscan, the scanner subsystem needs to deal
                     * with these */
                    continue;
                case 137: /* Redirect */
                    /* We ignore these, since we really don't have the capability to send
                     * packets to one router for some destinations and to another router
                     * for other destinations */
                    continue;
                default:
                    break;
                }
                continue;
            case FOUND_ARP:
                LOGip(2, ip_them, 0, "-> ARP [%u] \n", px[parsed.found_offset]);

                switch (parsed.opcode) {
                case 1: /* request */
                    /* This function will transmit a "reply" to somebody's ARP request
                     * for our IP address (as part of our user-mode TCP/IP).
                     * Since we completely bypass the TCP/IP stack, we  have to handle ARPs
                     * ourself, or the router will lose track of us.*/
                     stack_arp_incoming_request(stack,
                                      ip_me.ipv4,
                                      parms->source_mac,
                                      px, length);
                    break;
                case 2: /* response */
                    /* This is for "arp scan" mode, where we are ARPing targets rather
                     * than port scanning them */

                    /* If we aren't doing an ARP scan, then ignore ARP responses */
                    if (!masscan->scan_type.arp)
                        break;

                    /* If this response isn't in our range, then ignore it */
                    if (!rangelist_is_contains(&masscan->targets.ipv4, ip_them.ipv4))
                        break;

                    /* Ignore duplicates */
                    if (dedup_is_duplicate(dedup, ip_them, 0, ip_me, 0))
                        continue;

                    /* ...everything good, so now report this response */
                    arp_recv_response(out, secs, px, length, &parsed);
                    break;
                }
                continue;
            case FOUND_UDP:
            case FOUND_DNS:
                if (!is_nic_port(masscan, port_me))
                    continue;
                if (parms->masscan->nmap.packet_trace)
                    packet_trace(stdout, parms->pt_start, px, length, 0);
                handle_udp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_ICMP:
                handle_icmp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_SCTP:
                handle_sctp(out, secs, px, length, cookie, &parsed, entropy);
                break;
            case FOUND_OPROTO: /* other IP proto */
                handle_oproto(out, secs, px, length, &parsed, entropy);
                break;
            case FOUND_TCP:
                /* fall down to below */
                break;
            default:
                continue;
        }


        /* verify: my port number */
        if (!is_my_port(stack->src, port_me))
            continue;
        if (parms->masscan->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start, px, length, 0);

        Q = 0;

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
            LOGip(5, ip_them, port_them, "-> TCP ackno=0x%08x flags=0x%02x(%s)\n",
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
                            port_me, port_them);

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (cookie != seqno_me - 1) {
                    ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                    LOG(0, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n",
                        fmt.string, seqno_me-1, cookie);
                    continue;
                }
                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them,
                                    port_me, port_them,
                                    seqno_me, seqno_them+1,
                                    parsed.ip_ttl, NULL,
                                    secs, usecs);
                    (*status_tcb_count)++;
                }
                Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_SYNACK,
                    0, 0, secs, usecs, seqno_them+1, seqno_me);

            } else if (tcb) {
                /* If this is an ACK, then handle that first */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_ACK,
                        0, 0, secs, usecs, seqno_them, seqno_me);
                }

                /* If this contains payload, handle that second */
                if (parsed.app_length) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_DATA,
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs, seqno_them, seqno_me);
                }

                /* If this is a FIN, handle that. Note that ACK +
                 * payload + FIN can come together */
                if (TCP_IS_FIN(px, parsed.transport_offset)
                    && !TCP_IS_RST(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_FIN,
                            0, 0, 
                            secs, usecs, 
                            seqno_them + parsed.app_length, /* the FIN comes after any data in the packet */
                            seqno_me);
                }

                /* If this is a RST, then we'll be closing the connection */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    Q += stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_RST,
                        0, 0, secs, usecs, seqno_them, seqno_me);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                ipaddress_formatted_t fmt;
                /*
                 * NO TCB!
                 *  This happens when we've sent a FIN, deleted our connection,
                 *  but the other side didn't get the packet.
                 */
                fmt = ipaddress_fmt(ip_them);
                LOG(4, "%s: received FIN but no TCB\n", fmt.string);
                if (TCP_IS_RST(px, parsed.transport_offset))
                    ; /* ignore if it's own TCP flag is set */
                else {
                    int is_suppress;
                    
                    is_suppress = rstfilter_is_filter(rf, ip_me, port_me, ip_them, port_them);
                    if (!is_suppress)
                        tcpcon_send_RST(
                            tcpcon,
                            ip_me, ip_them,
                            port_me, port_them,
                            seqno_them, seqno_me);
                }
            }

        }

        if (Q == 0)
            ; //printf("\nerr\n");
   
        if (TCP_IS_SYNACK(px, parsed.transport_offset)
            || TCP_IS_RST(px, parsed.transport_offset)) {
            /* figure out the status */
            status = PortStatus_Unknown;
            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                status = PortStatus_Open;
            if (TCP_IS_RST(px, parsed.transport_offset)) {
                status = PortStatus_Closed;
            }

            /* verify: syn-cookies */
            if (cookie != seqno_me - 1) {
                ipaddress_formatted_t fmt = ipaddress_fmt(ip_them);
                LOG(2, "%s - bad cookie: ackno=0x%08x expected=0x%08x\n",
                    fmt.string, seqno_me-1, cookie);
                continue;
            }

            /* verify: ignore duplicates */
            if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me))
                continue;

            /* keep statistics on number received */
            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                (*status_synack_count)++;

            /*
             * This is where we do the output
             */
            output_report_status(
                        out,
                        global_now,
                        status,
                        ip_them,
                        6, /* ip proto = tcp */
                        port_them,
                        px[parsed.transport_offset + 13], /* tcp flags */
                        parsed.ip_ttl,
                        parsed.mac_src
                        );
            

            /*
             * Send RST so other side isn't left hanging (only doing this in
             * complete stateless mode where we aren't tracking banners)
             */
            if (tcpcon == NULL && !masscan->is_noreset)
                tcp_send_RST(
                    &parms->tmplset->pkts[Proto_TCP],
                    parms->stack,
                    ip_them, ip_me,
                    port_them, port_me,
                    0, seqno_me);

        }
    }


    LOG(1, "[+] exiting receive thread #%u                    \n", parms->nic_index);
    
    /*
     * cleanup
     */
end:
    if (tcpcon)
        tcpcon_destroy_table(tcpcon);
    dedup_destroy(dedup);
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    /*TODO: free stack packet buffers */

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
    static unsigned control_c_pressed = 0;
    static unsigned control_c_pressed_again = 0;
    if (control_c_pressed == 0) {
        fprintf(stderr,
                "waiting several seconds to exit..."
                "                                            \n"
                );
        fflush(stderr);
        control_c_pressed = 1+x;
        is_tx_done = control_c_pressed;
    } else {
        if (is_rx_done) {
            fprintf(stderr, "\nERROR: threads not exiting %d\n", is_rx_done);
            if (is_rx_done++ > 1)
                exit(1);
        } else {
            control_c_pressed_again = 1;
            is_rx_done = control_c_pressed_again;
        }
    }

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
    time_t now = time(0);
    struct Status status;
    uint64_t min_index = UINT64_MAX;
    struct MassVulnCheck *vulncheck = NULL;
    struct stack_t *stack;

    memset(parms_array, 0, sizeof(parms_array));

    /*
     * Vuln check initialization
     */
    if (masscan->vuln_name) {
        unsigned i;
		unsigned is_error;
        vulncheck = vulncheck_lookup(masscan->vuln_name);
        
        /* If no ports specified on command-line, grab default ports */
        is_error = 0;
        if (rangelist_count(&masscan->targets.ports) == 0)
            rangelist_parse_ports(&masscan->targets.ports, vulncheck->ports, &is_error, 0);
        
        /* Kludge: change normal port range to vulncheck range */
        for (i=0; i<masscan->targets.ports.count; i++) {
            struct Range *r = &masscan->targets.ports.list[i];
            r->begin = (r->begin&0xFFFF) | Templ_VulnCheck;
            r->end = (r->end & 0xFFFF) | Templ_VulnCheck;
        }
    }
    
    /*
     * Initialize the task size
     */
    count_ips = rangelist_count(&masscan->targets.ipv4) + range6list_count(&masscan->targets.ipv6).lo;
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return 1;
    }
    count_ports = rangelist_count(&masscan->targets.ports);
    if (count_ports == 0) {
        LOG(0, "FAIL: no ports were specified\n");
        LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
        LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
        return 1;
    }
    range = count_ips * count_ports;
    range += (uint64_t)(masscan->retries * range);

    /*
     * If doing an ARP scan, then don't allow port scanning
     */
    if (rangelist_is_contains(&masscan->targets.ports, Templ_ARP)) {
        if (masscan->targets.ports.count != 1) {
            LOG(0, "FAIL: cannot arpscan and portscan at the same time\n");
            return 1;
        }
    }

    /*
     * If the IP address range is very big, then require that that the
     * user apply an exclude range
     */
    if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude.ipv4) == 0) {
        LOG(0, "FAIL: range too big, need confirmation\n");
        LOG(0, " [hint] to prevent accidents, at least one --exclude must be specified\n");
        LOG(0, " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        exit(1);
    }

    /*
     * trim the nmap UDP payloads down to only those ports we are using. This
     * makes lookups faster at high packet rates.
     */
    payloads_udp_trim(masscan->payloads.udp, &masscan->targets);
    payloads_oproto_trim(masscan->payloads.oproto, &masscan->targets);


#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

    /*
     * Start scanning threats for each adapter
     */
    for (index=0; index<masscan->nic_count; index++) {
        struct ThreadPair *parms = &parms_array[index];
        int err;

        parms->masscan = masscan;
        parms->nic_index = index;
        parms->my_index = masscan->resume.index;
        parms->done_transmitting = 0;
        parms->done_receiving = 0;

        /* needed for --packet-trace option so that we know when we started
         * the scan */
        parms->pt_start = 1.0 * pixie_gettime() / 1000000.0;


        /*
         * Turn the adapter on, and get the running configuration
         */
        err = masscan_initialize_adapter(
                            masscan,
                            index,
                            &parms->source_mac,
                            &parms->router_mac_ipv4,
                            &parms->router_mac_ipv6
                            );
        if (err != 0)
            exit(1);
        parms->adapter = masscan->nic[index].adapter;
        if (!masscan->nic[index].is_usable) {
            LOG(0, "FAIL: failed to detect IP of interface\n");
            LOG(0, " [hint] did you spell the name correctly?\n");
            LOG(0, " [hint] if it has no IP address, "
                    "manually set with \"--adapter-ip 192.168.100.5\"\n");
            exit(1);
        }


        /*
         * Initialize the TCP packet template. The way this works is that
         * we parse an existing TCP packet, and use that as the template for
         * scanning. Then, we adjust the template with additional features,
         * such as the IP address and so on.
         */
        parms->tmplset->vulncheck = vulncheck;
        template_packet_init(
                    parms->tmplset,
                    parms->source_mac,
                    parms->router_mac_ipv4,
                    parms->router_mac_ipv6,
                    masscan->payloads.udp,
                    masscan->payloads.oproto,
                    stack_if_datalink(masscan->nic[index].adapter),
                    masscan->seed,
                    masscan->templ_opts);

        /*
         * Set the "source port" of everything we transmit.
         */
        if (masscan->nic[index].src.port.range == 0) {
            unsigned port = 40000 + now % 20000;
            masscan->nic[index].src.port.first = port;
            masscan->nic[index].src.port.last = port + 16;
            masscan->nic[index].src.port.range = 16;
        }

        stack = stack_create(parms->source_mac, &masscan->nic[index].src);
        parms->stack = stack;

        /*
         * Set the "TTL" (IP time-to-live) of everything we send.
         */
        if (masscan->nmap.ttl)
            template_set_ttl(parms->tmplset, masscan->nmap.ttl);

        if (masscan->nic[0].is_vlan)
            template_set_vlan(parms->tmplset, masscan->nic[0].vlan_id);


        /*
         * trap <ctrl-c> to pause
         */
        signal(SIGINT, control_c_handler);

    }

    /*
     * Print helpful text
     */
    {
        char buffer[80];
        struct tm x;

        now = time(0);
        safe_gmtime(&x, &now);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
        LOG(0, "Starting masscan " MASSCAN_VERSION " (http://bit.ly/14GZzcT) at %s\n",
            buffer);

        if (count_ports == 1 && \
            masscan->targets.ports.list->begin == Templ_ICMP_echo && \
            masscan->targets.ports.list->end == Templ_ICMP_echo)
            { /* ICMP only */
                //LOG(0, " -- forced options: -sn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating ICMP Echo Scan\n");
                LOG(0, "Scanning %u hosts\n",(unsigned)count_ips);
             }
        else /* This could actually also be a UDP only or mixed UDP/TCP/ICMP scan */
            {
                //LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating SYN Stealth Scan\n");
                LOG(0, "Scanning %u hosts [%u port%s/host]\n",
                    (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
            }
    }
    
    /*
     * Start all the threads
     */
    for (index=0; index<masscan->nic_count; index++) {
        struct ThreadPair *parms = &parms_array[index];
        
        /*
         * Start the scanning thread.
         * THIS IS WHERE THE PROGRAM STARTS SPEWING OUT PACKETS AT A HIGH
         * RATE OF SPEED.
         */
        parms->thread_handle_xmit = pixie_begin_thread(transmit_thread, 0, parms);

        /*
         * Start the MATCHING receive thread. Transmit and receive threads
         * come in matching pairs.
         */
        parms->thread_handle_recv = pixie_begin_thread(receive_thread, 0, parms);
    }

    /*
     * Now wait for <ctrl-c> to be pressed OR for threads to exit
     */
    pixie_usleep(1000 * 100);
    LOG(1, "[+] waiting for threads to finish\n");
    status_start(&status);
    status.is_infinite = masscan->is_infinite;
    while (!is_tx_done && masscan->output.is_status_updates) {
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }

        if (min_index >= range && !masscan->is_infinite) {
            /* Note: This is how we can tell the scan has ended */
            is_tx_done = 1;
        }

        /*
         * update screen about once per second with statistics,
         * namely packets/second.
         */
        if (masscan->output.is_status_updates)
            status_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns,
                0, masscan->output.is_status_ndjson);

        /* Sleep for almost a second */
        pixie_mssleep(750);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (min_index < count_ips * count_ports) {
        masscan->resume.index = min_index;

        /* Write current settings to "paused.conf" so that the scan can be restarted */
        masscan_save_state(masscan);
    }



    /*
     * Now wait for all threads to exit
     */
    now = time(0);
    for (;;) {
        unsigned transmit_count = 0;
        unsigned receive_count = 0;
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }



        if (time(0) - now >= masscan->wait) {
            is_rx_done = 1;
        }

        if (time(0) - now - 10 > masscan->wait) {
            LOG(0, "[-] Passed the wait window but still running, forcing exit...\n");
            exit(0);
        }

        if (masscan->output.is_status_updates) {
            status_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns,
                masscan->wait - (time(0) - now),
                masscan->output.is_status_ndjson);

            for (i=0; i<masscan->nic_count; i++) {
                struct ThreadPair *parms = &parms_array[i];

                transmit_count += parms->done_transmitting;
                receive_count += parms->done_receiving;

            }

            pixie_mssleep(250);

            if (transmit_count < masscan->nic_count)
                continue;
            is_tx_done = 1;
            is_rx_done = 1;
            if (receive_count < masscan->nic_count)
                continue;

        } else {
            /* [AFL-fuzz]
             * Join the threads, which doesn't allow us to print out 
             * status messages, but allows us to exit cleanly without
             * any waiting */
            for (i=0; i<masscan->nic_count; i++) {
                struct ThreadPair *parms = &parms_array[i];

                pixie_thread_join(parms->thread_handle_xmit);
                parms->thread_handle_xmit = 0;
                pixie_thread_join(parms->thread_handle_recv);
                parms->thread_handle_recv = 0;
            }
            is_tx_done = 1;
            is_rx_done = 1;
        }

        break;
    }


    /*
     * Now cleanup everything
     */
    status_finish(&status);

    if (!masscan->output.is_status_updates) {
        uint64_t usec_now = pixie_gettime();

        printf("%u milliseconds elapsed\n", (unsigned)((usec_now - usec_start)/1000));
    }
    
    LOG(1, "[+] all threads have exited                    \n");

    return 0;
}




/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Masscan masscan[1];
    unsigned i;
    int has_target_addresses = 0;
    int has_target_ports = 0;
    
    usec_start = pixie_gettime();
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101, &x);}
#endif

    global_now = time(0);

    /* Set system to report debug information on crash */
    {
        int is_backtrace = 1;
        for (i=1; i<(unsigned)argc; i++) {
            if (strcmp(argv[i], "--nobacktrace") == 0)
                is_backtrace = 0;
        }
        if (is_backtrace)
            pixie_backtrace_init(argv[0]);
    }
    
    /*
     * Initialize those defaults that aren't zero
     */
    memset(masscan, 0, sizeof(*masscan));
    /* 14 rounds seem to give way better statistical distribution than 4 with a 
    very low impact on scan rate */
    masscan->blackrock_rounds = 14;
    masscan->output.is_show_open = 1; /* default: show syn-ack, not rst */
    masscan->output.is_status_updates = 1; /* default: show status updates */
    masscan->wait = 10; /* how long to wait for responses when done */
    masscan->max_rate = 100.0; /* max rate = hundred packets-per-second */
    masscan->nic_count = 1;
    masscan->shard.one = 1;
    masscan->shard.of = 1;
    masscan->min_packet_size = 60;
    masscan->redis.password = NULL;
    masscan->payloads.udp = payloads_udp_create();
    masscan->payloads.oproto = payloads_oproto_create();
    safe_strcpy(   masscan->output.rotate.directory,
                sizeof(masscan->output.rotate.directory),
                ".");
    masscan->is_capture_cert = 1;

    /*
     * Pre-parse the command-line
     */
    if (masscan_conf_contains("--readscan", argc, argv)) {
        masscan->is_readscan = 1;
    }

    /*
     * On non-Windows systems, read the defaults from the file in
     * the /etc directory. These defaults will contain things
     * like the output directory, max packet rates, and so on. Most
     * importantly, the master "--excludefile" might be placed here,
     * so that blacklisted ranges won't be scanned, even if the user
     * makes a mistake
     */
#if !defined(WIN32)
    if (!masscan->is_readscan) {
        if (access("/etc/masscan/masscan.conf", 0) == 0) {
            masscan_read_config_file(masscan, "/etc/masscan/masscan.conf");
        }
    }
#endif

    /*
     * Read in the configuration from the command-line. We are looking for
     * either options or a list of IPv4 address ranges.
     */
    masscan_command_line(masscan, argc, argv);
    if (masscan->seed == 0)
        masscan->seed = get_entropy(); /* entropy for randomness */

    /*
     * Load database files like "nmap-payloads" and "nmap-service-probes"
     */
    masscan_load_database_files(masscan);

    /*
     * Load the scripting engine if needed and run those that were
     * specified.
     */
    if (masscan->is_scripting)
        scripting_init(masscan);

    /* We need to do a separate "raw socket" initialization step. This is
     * for Windows and PF_RING. */
    if (pcap_init() != 0)
        LOG(2, "libpcap: failed to load\n");
    rawsock_init();

    /* Init some protocol parser data structures */
    snmp_init();
    x509_init();


    /*
     * Apply excludes. People ask us not to scan them, so we maintain a list
     * of their ranges, and when doing wide scans, add the exclude list to
     * prevent them from being scanned.
     */
    has_target_addresses = massip_has_ipv4_targets(&masscan->targets) || massip_has_ipv6_targets(&masscan->targets);
    has_target_ports = massip_has_target_ports(&masscan->targets);
    massip_apply_excludes(&masscan->targets, &masscan->exclude);
    if (!has_target_ports && masscan->op == Operation_ListScan)
        massip_add_port_string(&masscan->targets, "80", 0);




    /* Optimize target selection so it's a quick binary search instead
     * of walking large memory tables. When we scan the entire Internet
     * our --excludefile will chop up our pristine 0.0.0.0/0 range into
     * hundreds of subranges. This allows us to grab addresses faster. */
    massip_optimize(&masscan->targets);
    
    /* FIXME: we only support 63-bit scans at the current time.
     * This is big enough for the IPv4 Internet, where scanning
     * for all TCP ports on all IPv4 addresses results in a 48-bit
     * scan, but this isn't big enough even for a single port on
     * an IPv6 subnet (which are 64-bits in size, usually). However,
     * even at millions of packets per second scanning rate, you still
     * can't complete a 64-bit scan in a reasonable amount of time.
     * Nor would you want to attempt the feat, as it would overload
     * the target IPv6 subnet. Since implementing this would be
     * difficult for 32-bit processors, for now, I'm going to stick
     * to a simple 63-bit scan.
     */
    if (massint128_bitcount(massip_range(&masscan->targets)) > 63) {
        fprintf(stderr, "[-] FAIL: scan range too large, max is 63-bits, requested is %u bits\n",
                massint128_bitcount(massip_range(&masscan->targets)));
        fprintf(stderr, "    Hint: scan range is number of IP addresses times number of ports\n");
        fprintf(stderr, "    Hint: IPv6 subnet must be at least /66 \n");
        exit(1);
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
        if (rangelist_count(&masscan->targets.ipv4) == 0 && massint128_is_zero(range6list_count(&masscan->targets.ipv6))) {
            /* We check for an empty target list here first, before the excludes,
             * so that we can differentiate error messages after excludes, in case
             * the user specified addresses, but they were removed by excludes. */
            LOG(0, "FAIL: target IP address list empty\n");
            if (has_target_addresses) {
                LOG(0, " [hint] all addresses were removed by exclusion ranges\n");
            } else {
                LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
                LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
            }
            exit(1);
        }
        if (rangelist_count(&masscan->targets.ports) == 0) {
            if (has_target_ports) {
                LOG(0, " [hint] all ports were removed by exclusion ranges\n");
            } else {
                LOG(0, "FAIL: no ports were specified\n");
                LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
                LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
            }
            return 1;
        }
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

    case Operation_ReadRange:
        main_readrange(masscan);
        return 0;

    case Operation_ReadScan:
        {
            unsigned start;
            unsigned stop;

            /* find first file */
            for (start=1; start<(unsigned)argc; start++) {
                if (memcmp(argv[start], "--readscan", 10) == 0) {
                    start++;
                    break;
                }
            }

            /* find last file */
            for (stop=start+1; stop<(unsigned)argc && argv[stop][0] != '-'; stop++)
                ;

            /*
             * read the binary files, and output them again depending upon
             * the output parameters
             */
            readscan_binary_scanfile(masscan, start, stop, argv);

        }
        break;

    case Operation_Benchmark:
        printf("=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void*)*8);
        blackrock_benchmark(masscan->blackrock_rounds);
        blackrock2_benchmark(masscan->blackrock_rounds);
        smack_benchmark();
        exit(1);
        break;

    case Operation_Echo:
        masscan_echo(masscan, stdout, 0);
        exit(0);
        break;

    case Operation_EchoAll:
        masscan_echo(masscan, stdout, 0);
        exit(0);
        break;

    case Operation_EchoCidr:
        masscan_echo_cidr(masscan, stdout, 0);
        exit(0);
        break;

    case Operation_Selftest:
        /*
         * Do a regression test of all the significant units
         */
        {
            int x = 0;
            extern int proto_isakmp_selftest(void);
            
            x += massip_selftest();
            x += ranges6_selftest();
            x += dedup_selftest();
            x += checksum_selftest();
            x += ipv4address_selftest();
            x += ipv6address_selftest();
            x += proto_coap_selftest();
            x += smack_selftest();
            x += sctp_selftest();
            x += base64_selftest();
            x += banner1_selftest();
            x += output_selftest();
            x += siphash24_selftest();
            x += ntp_selftest();
            x += snmp_selftest();
            x += proto_isakmp_selftest();
            x += templ_payloads_selftest();
            x += blackrock_selftest();
            x += rawsock_selftest();
            x += lcg_selftest();
            x += template_selftest();
            x += ranges_selftest();
            x += massip_parse_selftest();
            x += pixie_time_selftest();
            x += rte_ring_selftest();
            x += mainconf_selftest();
            x += zeroaccess_selftest();
            x += nmapserviceprobes_selftest();
            x += rstfilter_selftest();
            x += masscan_app_selftest();


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


