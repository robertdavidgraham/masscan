/*
    TCP connection table
*/
#include "proto-tcp.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include "syn-cookie.h"
#include "event-timeout.h"      /* for tracking future events */
#include "rawsock.h"
#include "logger.h"
#include "templ-pkt.h"
#include "pixie-timer.h"
#include "packet-queue.h"
#include "proto-banner1.h"
#include "proto-ssl.h"
#include "proto-http.h"
#include "output.h"
#include "string_s.h"
#include "main-globals.h"
#include "crypto-base64.h"
#include "lua-probe.h"
#include "proto-tcp-transmit.h"
#include "misc-name-equals.h"

#ifdef WIN32
#include <direct.h>
#endif

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10

/***************************************************************************
 * A "TCP control block" is what most operating-systems/network-stack
 * calls the structure that corresponds to a TCP connection. It contains
 * things like the IP addresses, port numbers, sequence numbers, timers,
 * and other things.
 ***************************************************************************/
struct TCP_Control_Block
{

    unsigned ip_me;
    unsigned ip_them;

    unsigned short port_me;
    unsigned short port_them;

    uint32_t seqno_me;      /* next seqno I will use for transmit */
    uint32_t seqno_them;    /* the next seqno I expect to receive */
    uint32_t ackno_me;
    uint32_t ackno_them;

    struct TCP_Control_Block *next;
    struct TimeoutEntry timeout[1];

    unsigned char ttl;
    unsigned tcpstate:5;

    /**
     * Whether this connection is in the state of closing
     */
    unsigned is_fin_received:1;
    unsigned is_fin_sent:1;

    /**
     * Has there payload variable been malloced(). If so, then we'll need
     * to free it. Otherwise, it points to static memory somewhere else. Most
     * built-in protocols use static memory, so there is no need to free
     * this variable [XMIT] */
    unsigned payload_is_alloc:1;

    /** The length of the total payload field [XMIT] */
    unsigned short payload_length;

    /** The length of the payload that has already been sent. I this is less
     * than payload length, then we need to transmit all the packets [XMIT]*/
    unsigned short payload_sent;

    /** When this structure was created, so that we know when to time it out */
    time_t when_created;

    /** A pointer to the TCP payload that is currently outstanding, either
     * unsent or unacked. [XMIT]*/
    unsigned char *payload;

    /** [LUAPROBE] This is a per-connection Lua state structure,
     * which has a linkto the global Lua thread state */
    struct lua_State *L;

    struct BannerOutput banout;

    struct ProtocolState banner1_state;
};

struct TCP_ConnectionTable {
    struct TCP_Control_Block **entries;
    struct TCP_Control_Block *freed_list;
    unsigned count;
    unsigned mask;
    unsigned timeout_connection;
    unsigned timeout_hello;

    uint64_t active_count;
    uint64_t entropy;

    struct Timeouts *timeouts;
    struct TemplatePacket *pkt_template;
    PACKET_QUEUE *transmit_queue;
    PACKET_QUEUE *packet_buffers;

    struct Banner1 *banner1;
    OUTPUT_REPORT_BANNER report_banner;
    struct Output *out;

};

enum {
    STATE_SYN_SENT,
    STATE_SYN_RCVD,
    STATE_HELLO,
    STATE_ESTABLISHED,
    STATE_FIN_WAIT_1,
    STATE_FIN_WAIT_2,
    STATE_CLOSING,
    STATE_TIME_WAIT,
    STATE_CLOSE_WAIT,
    STATE_LAST_ACK,
    STATE_CLOSED,
    STATE_LISTEN,
};



/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs)
{
    uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

    for (;;) {
        struct TCP_Control_Block *tcb;

        /*
         * Get the next event that is older than the current time
         */
        tcb = (struct TCP_Control_Block *)timeouts_remove(tcpcon->timeouts,
                                                          timestamp);

        /*
         * If everything up to the current time has already been processed,
         * then exit this loop
         */
        if (tcb == NULL)
            break;

        /*
         * Process this timeout
         */
        tcpcon_handle(
            tcpcon,
            tcb,
            TCP_WHAT_TIMEOUT,
            0, 0,
            secs, usecs,
            0, 0);

        /* If the TCB hasn't been destroyed, then we need to make sure
         * there is a timeout associated with it. KLUDGE: here is the problem:
         * there must ALWAYS be a 'timeout' associated with a TCB, otherwise,
         * we'll lose track of it and leak memory. In theory, this should be
         * automatically handled elsewhere, but I have bugs, and it's not,
         * so I put some code here as a catch-all: if the TCB hasn't been
         * deleted, but hasn't been inserted back into the timeout system,
         * then insert it here. */
        if (tcb->timeout->prev == 0 && tcb->ip_them != 0 && tcb->port_them != 0) {
            timeouts_add(   tcpcon->timeouts,
                            tcb->timeout,
                            offsetof(struct TCP_Control_Block, timeout),
                            TICKS_FROM_TV(secs+2, usecs));
        }
    }
}


/***************************************************************************
 * When setting parameters, this will parse integers from the config
 * parameter strings.
 ***************************************************************************/
static uint64_t
parseInt(const void *vstr, size_t length)
{
    const char *str = (const char *)vstr;
    uint64_t result = 0;
    size_t i;

    for (i=0; i<length; i++) {
        result = result * 10 + (str[i] - '0');
    }
    return result;
}

/***************************************************************************
 * [LUAPROBE] [SCRIPTING]
 ***************************************************************************/
void
tcpcon_init_luaprobe(struct TCP_ConnectionTable *tcpcon, const char *scriptname)
{

    tcpcon->banner1->L = scripting_init(scriptname);
    if (tcpcon->banner1->L == NULL) {
#ifdef WIN32
        {
            /* because I can't figure out in VisualStudio where the debugger
             * thinks the current directory is, I print it here */
            char path[1024];
            fprintf(stderr, "path: %s       \n", 
                _getcwd(path, sizeof(path)));
        }
#endif
        exit(1);
    }
}

/***************************************************************************
 * Called at startup, when processing command-line options, to set
 * parameters specific to TCP processing.
 ***************************************************************************/
void
tcpcon_set_parameter(struct TCP_ConnectionTable *tcpcon,
                        const char *name,
                        size_t value_length,
                        const void *value)
{
    struct Banner1 *banner1 = tcpcon->banner1;

    /*
     * You can reset your user-agent here. Whenever I do a scan, I always
     * reset my user-agent. That's now you know it's not me scanning
     * you on the open Internet -- I would never use the default user-agent
     * string built into masscan
     */
    if (name_equals(name, "http-user-agent")) {
        banner_http.set_parameter(banner1, &banner_http,
                                  name, value_length, value);
        return;
    }

    if (name_equals(name, "timeout") || name_equals(name, "connection-timeout")) {
        uint64_t n = parseInt(value, value_length);
        tcpcon->timeout_connection = (unsigned)n;
        LOG(1, "TCP connection-timeout = %u\n", tcpcon->timeout_connection);
        return;
    }
    if (name_equals(name, "hello-timeout")) {
        uint64_t n = parseInt(value, value_length);
        tcpcon->timeout_hello = (unsigned)n;
        LOG(1, "TCP hello-timeout = \"%.*s\"\n", value_length, value);
        LOG(1, "TCP hello-timeout = %u\n", (unsigned)tcpcon->timeout_hello);
        return;
    }

    /*
     * 2014-04-08: scan for Neel Mehta's "heartbleed" bug
     */
    if (name_equals(name, "heartbleed")) {
        unsigned i;

        banner_ssl.set_parameter(banner1, &banner_ssl,
                                name, value_length, value);

        tcpcon->banner1->is_heartbleed = 1;

        for (i=0; i<65535; i++) {
            banner1->tcp_payloads[i] = &banner_ssl;
        }

        return;
    }

    if (name_equals(name, "ticketbleed")) {
        unsigned i;

        /* Change the hello message to including negotiating the use of 
         * the "heartbeat" extension */
        banner_ssl.hello = ssl_hello(ssl_hello_ticketbleed_template);
        banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
        tcpcon->banner1->is_ticketbleed = 1;

        for (i=0; i<65535; i++) {
            banner1->tcp_payloads[i] = &banner_ssl;
        }

        return;
    }

    /*
     * 2014-10-16: scan for SSLv3 servers (POODLE)
     */
    if (name_equals(name, "poodle") || name_equals(name, "sslv3")) {
        unsigned i;

        banner_ssl.set_parameter(banner1, &banner_ssl,
                                name, value_length, value);

        tcpcon->banner1->is_poodle_sslv3 = 1;

        for (i=0; i<65535; i++) {
            banner1->tcp_payloads[i] = &banner_ssl;
        }
        
        return;
    }

    
    /*
     * You can reconfigure the "hello" message to be anything
     * you want.
     */
    if (name_equals(name, "hello-string")) {
        struct ProtocolParserStream *x;
        const char *p ;
        unsigned port;

        /*
         * Extract the port number from brackets [] 
         */
        p = strchr(name, '[');
        if (p == NULL) {
            fprintf(stderr, "tcpcon: parmeter: expected array []: %s\n", name);
            exit(1);
        }
        port = strtoul(p+1, 0, 0);

        /*
         * Get the 'stream' object for that port
         */
        x = banner1->tcp_payloads[port];
        if (x == NULL) {
            x = (struct ProtocolParserStream *)malloc(sizeof(*x));
            memset(x, 0, sizeof(*x));

            x->name = "(allocated)";
        }

        /*
         * Set the 'hello' string
         */
        x->set_parameter(banner1, x, name, value_length, value);

        /*
         * If we had to create a new 'stream' object for this port,
         * then set it
         */
        banner1->tcp_payloads[port] = x;
    }

}


/***************************************************************************
 ***************************************************************************/
void
tcpcon_set_banner_flags(struct TCP_ConnectionTable *tcpcon,
    unsigned is_capture_cert,
    unsigned is_capture_html,
    unsigned is_capture_heartbleed,
	unsigned is_capture_ticketbleed)
{
    tcpcon->banner1->is_capture_cert = is_capture_cert;
    tcpcon->banner1->is_capture_html = is_capture_html;
    tcpcon->banner1->is_capture_heartbleed = is_capture_heartbleed;
    tcpcon->banner1->is_capture_ticketbleed = is_capture_ticketbleed;
}

/***************************************************************************
 * Called at startup, by a receive thread, to create a TCP connection
 * table.
 ***************************************************************************/
struct TCP_ConnectionTable *
tcpcon_create_table(    size_t entry_count,
                        PACKET_QUEUE *transmit_queue,
                        PACKET_QUEUE *packet_buffers,
                        struct TemplatePacket *pkt_template,
                        OUTPUT_REPORT_BANNER report_banner,
                        struct Output *out,
                        unsigned connection_timeout,
                        uint64_t entropy
                        )
{
    struct TCP_ConnectionTable *tcpcon;
    //printf("\nsizeof(TCB) = %u\n\n", (unsigned)sizeof(struct TCP_Control_Block));
    
    
    tcpcon = (struct TCP_ConnectionTable *)malloc(sizeof(*tcpcon));
    if (tcpcon == NULL)
        exit(1);
    memset(tcpcon, 0, sizeof(*tcpcon));
    tcpcon->timeout_connection = connection_timeout;
    if (tcpcon->timeout_connection == 0)
        tcpcon->timeout_connection = 30; /* half a minute before destroying tcb */
    tcpcon->timeout_hello = 2;
    tcpcon->entropy = entropy;

    /* Find nearest power of 2 to the tcb count, but don't go
     * over the number 16-million */
    {
        size_t new_entry_count;
        new_entry_count = 1;
        while (new_entry_count < entry_count) {
            new_entry_count *= 2;
            if (new_entry_count == 0) {
                new_entry_count = (1<<24);
                break;
            }
        }
        if (new_entry_count > (1<<24))
            new_entry_count = (1<<24);
        if (new_entry_count < (1<<10))
            new_entry_count = (1<<10);
        entry_count = new_entry_count;
    }

    /* Create the table. If we can't allocate enough memory, then shrink
     * the desired size of the table */
    while (tcpcon->entries == 0) {
        tcpcon->entries = (struct TCP_Control_Block**)
                            malloc(entry_count * sizeof(*tcpcon->entries));
        if (tcpcon->entries == NULL) {
            entry_count >>= 1;
        }
    }
    memset(tcpcon->entries, 0, entry_count * sizeof(*tcpcon->entries));


    /* fill in the table structure */
    tcpcon->count = (unsigned)entry_count;
    tcpcon->mask = (unsigned)(entry_count-1);

    /* create an event/timeouts structure */
    tcpcon->timeouts = timeouts_create(TICKS_FROM_SECS(time(0)));


    tcpcon->pkt_template = pkt_template;

    tcpcon->transmit_queue = transmit_queue;
    tcpcon->packet_buffers = packet_buffers;


    tcpcon->banner1 = banner1_create();

    tcpcon->report_banner = report_banner;
    tcpcon->out = out;
    return tcpcon;
}

#define EQUALS(lhs,rhs) (memcmp((lhs),(rhs),12)==0)

/***************************************************************************
 ***************************************************************************/
static unsigned
tcb_hash(   unsigned ip_me, unsigned port_me, 
            unsigned ip_them, unsigned port_them,
            uint64_t entropy)
{
    unsigned index;

    /* TCB hash table uses symmetric hash, so incoming/outgoing packets
     * get the same hash. FIXME: does this really nee to be symmetric? */
    index = (unsigned)syn_cookie(   ip_me   ^ ip_them,
                                    port_me ^ port_them,
                                    ip_me   ^ ip_them,
                                    port_me ^ port_them,
                                    entropy
                                    );
    return index;
}

enum DestroyReason {
    Reason_Timeout = 1,
    Reason_FIN = 2,
    Reason_RST = 3,
    Reason_Foo = 4,
    Reason_Shutdown = 5,
    Reason_StateDone = 6,

};

/***************************************************************************
 * Destroy a TCP connection entry. We have to unlink both from the
 * TCB-table as well as the timeout-table.
 * Called from 
 ***************************************************************************/
static void
tcpcon_destroy_tcb(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    enum DestroyReason reason)
{
    unsigned index;
    struct TCP_Control_Block **r_entry;
    struct BannerOutput *banout;

    UNUSEDPARM(reason);

//printf("." "tcb age = %u-sec, reason=%u                                   \n", time(0) - tcb->when_created, reason);

    /*
     * The TCB doesn't point to it's location in the table. Therefore, we
     * have to do a lookup to find the head pointer in the table.
     */
    index = tcb_hash(   tcb->ip_me, tcb->port_me, 
                        tcb->ip_them, tcb->port_them, 
                        tcpcon->entropy);

    /*
     * At this point, we have the head of a linked list of TCBs. Now,
     * traverse that linked list until we find our TCB
     */
    r_entry = &tcpcon->entries[index & tcpcon->mask];
    while (*r_entry && *r_entry != tcb)
        r_entry = &(*r_entry)->next;

    if (*r_entry == NULL) {
        /* TODO: this should be impossible, but it's happening anyway, about
         * 20 times on a full Internet scan. I don't know why, and I'm too
         * lazy to fix it right now, but I'll get around to eventually */
        LOG(1, "tcb: double free: %u.%u.%u.%u : %u (0x%x)\n",
                (tcb->ip_them>>24)&0xFF,
                (tcb->ip_them>>16)&0xFF,
                (tcb->ip_them>> 8)&0xFF,
                (tcb->ip_them>> 0)&0xFF,
                tcb->port_them,
                tcb->seqno_them
                );
        return;
    }

    /*
     * Print out any banners associated with this TCP session. Most of the
     * time, there'll only be one.
     */
    for (banout = &tcb->banout; banout != NULL; banout = banout->next) {
        if (banout->length && banout->protocol) {
            tcpcon->report_banner(
                tcpcon->out,
                global_now,
                tcb->ip_them,
                6, /*TCP protocol*/
                tcb->port_them,
                banout->protocol & 0x0FFFFFFF,
                tcb->ttl,
                banout->banner,
                banout->length);
        }
    }

    /*
     * If there are multiple banners, then free the additional ones
     */
    banout_release(&tcb->banout);

    /* [LUAPROBE]
     * Free the Lua thread information for this connection
     */
    if (tcb->L)
        luaprobe_event_close(tcb->L, tcb);

    /*
     * Unlink this from the timeout system.
     */
    timeout_unlink(tcb->timeout);

    tcb->ip_them = 0;
    tcb->port_them = 0;
    tcb->ip_me = 0;
    tcb->port_me = 0;

    (*r_entry) = tcb->next;
    tcb->next = tcpcon->freed_list;
    tcpcon->freed_list = tcb;
    tcpcon->active_count--;
}


/***************************************************************************
 * Called at shutdown to free up all the memory used by the TCP
 * connection table.
 ***************************************************************************/
void
tcpcon_destroy_table(struct TCP_ConnectionTable *tcpcon)
{
    unsigned i;

    if (tcpcon == NULL)
        return;

    /*
     * Do a graceful destruction of all the entires. If they have banners,
     * they will be sent to the output
     */
    for (i=0; i<=tcpcon->mask; i++) {
        while (tcpcon->entries[i])
            tcpcon_destroy_tcb(tcpcon, tcpcon->entries[i], Reason_Shutdown);
    }

    /*
     * Now free the memory
     */
    while (tcpcon->freed_list) {
        struct TCP_Control_Block *tcb = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
        free(tcb);
    }

    banner1_destroy(tcpcon->banner1);
    free(tcpcon->entries);
    free(tcpcon);
}


/***************************************************************************
 *
 * Called when we receive a "SYN-ACK" packet with the correct SYN-cookie.
 *
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_create_tcb(
    struct TCP_ConnectionTable *tcpcon,
    unsigned ip_me, unsigned ip_them,
    unsigned port_me, unsigned port_them,
    unsigned seqno_me, unsigned seqno_them,
    unsigned ttl)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }
    if (tcb == NULL) {
        if (tcpcon->freed_list) {
            tcb = tcpcon->freed_list;
            tcpcon->freed_list = tcb->next;
        } else {
            tcb = (struct TCP_Control_Block*)malloc(sizeof(*tcb));
            if (tcb == NULL) {
                fprintf(stderr, "tcb: out of memory\n");
                exit(1);
            }
        }
        memset(tcb, 0, sizeof(*tcb));
        tcb->next = tcpcon->entries[index & tcpcon->mask];
        tcpcon->entries[index & tcpcon->mask] = tcb;
        memcpy(tcb, &tmp, 12);
        tcb->seqno_me = seqno_me;
        tcb->seqno_them = seqno_them;
        tcb->ackno_me = seqno_them;
        tcb->ackno_them = seqno_me;
        tcb->when_created = global_now;
        tcb->banner1_state.port = tmp.port_them;
        tcb->ttl = (unsigned char)ttl;

        timeout_init(tcb->timeout);
        banout_init(&tcb->banout);

        tcpcon->active_count++;
    }

    return tcb;
}



/***************************************************************************
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_lookup_tcb(
    struct TCP_ConnectionTable *tcpcon,
    unsigned ip_me, unsigned ip_them,
    unsigned port_me, unsigned port_them)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);

    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }

    return tcb;
}


/***************************************************************************
 ***************************************************************************/
void
tcp_add_xmit(struct TCP_Control_Block *tcb, const void *data, size_t length, int type)
{

    if (length == 0 || tcb == 0)
        return;

    /* If it's a static item, then simply point to it */
    if (tcb->payload_length == 0 && type == XMIT_STATIC) {
        tcb->payload = (unsigned char *)data;
        tcb->payload_length = (unsigned short)length;
        tcb->payload_is_alloc = 0;
        return;
    }

    /* If it's a new dynamic item, then make a copy */
    if (tcb->payload_length == 0) {
        tcb->payload = malloc(length);
        if (tcb->payload == 0) {
            fprintf(stderr, "out of memory\n");
            exit(1);
        }
        memcpy(tcb->payload, data, length);
        tcb->payload_length = (unsigned short)length;
        tcb->payload_is_alloc = 1;
        return;
    }

    /* If we've queued existing static data, then change it to dynamic */
    if (tcb->payload_length > 0 && tcb->payload_is_alloc  == 0) {
        unsigned char *new_data;
        new_data = malloc(tcb->payload_length);
        memcpy(new_data, tcb->payload, tcb->payload_length);
        tcb->payload = new_data;
        tcb->payload_is_alloc = 1;
    }

    /* Append the data */
    tcb->payload = realloc(tcb->payload, tcb->payload_length + length);
    if (tcb->payload == 0) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    memcpy(tcb->payload + tcb->payload_length,
            data,
            length);
    tcb->payload_length = (unsigned short)(tcb->payload_length + length);

}

/***************************************************************************
 ***************************************************************************/
static void
tcpcon_send_packet(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    unsigned tcp_flags)
{
    for (;;) {
        struct PacketBuffer *response = 0;
        int err = 0;
        uint64_t wait = 100;
        const unsigned char *payload = tcb->payload + tcb->payload_sent;
        unsigned payload_length;

        /* Figure out how much data to send */
        payload_length = tcb->payload_length - tcb->payload_sent;
        if (payload_length > 1400)
            payload_length = 1400;
        if (payload_length)
            tcp_flags |= PSH;

        /* Get a buffer for sending the response packet. This thread doesn't
         * send the packet itself. Instead, it formats a packet, then hands
         * that packet off to a transmit thread for later transmission. */
        for (err=1; err; ) {
            err = rte_ring_sc_dequeue(tcpcon->packet_buffers, (void**)&response);
            if (err != 0) {
                static int is_warning_printed = 0;
                if (!is_warning_printed) {
                    LOG(0, "packet buffers empty (should be impossible)\n");
                    is_warning_printed = 1;
                }
                fflush(stdout);
                pixie_usleep(wait = (uint64_t)(wait *1.5)); /* no packet available */
            }
        }
        if (response == NULL)
            return;

        /* If this is the final segment AND we are closing the connection,
         * then set the FIN flag */
        if (tcb->is_fin_sent) {
            if (tcb->payload_sent + payload_length == tcb->payload_length)
                tcp_flags |= FIN;
        }

        /* Format the packet as requested. Note that there are really only
         * four types of packets:
         * 1. a SYN-ACK packet with no payload
         * 2. an ACK packet with no payload
         * 3. a RST packet with no pacyload
         * 4. a PSH-ACK packet WITH PAYLOAD
         */
        response->length = tcp_create_packet(
            tcpcon->pkt_template,
            tcb->ip_them, tcb->port_them,
            tcb->ip_me, tcb->port_me,
            tcb->seqno_me, tcb->seqno_them + tcb->is_fin_received,
            tcp_flags,
            payload, payload_length,
            response->px, sizeof(response->px)
            );

        /*
         * KLUDGE:
         */
        if (tcpcon->banner1->is_heartbleed) {
            tcp_set_window(response->px, response->length, 600);
        } else {
            tcp_set_window(response->px, response->length, 600);
        }

        /* Put this buffer on the transmit queue. Remember: transmits happen
         * from a transmit-thread only, and this function is being called
         * from a receive-thread. Therefore, instead of transmiting ourselves,
         * we hae to queue it up for later transmission. */
        for (err=1; err; ) {
            err = rte_ring_sp_enqueue(tcpcon->transmit_queue, response);
            if (err != 0) {
                LOG(0, "transmit queue full (should be impossible)\n");
                pixie_usleep(100); /* no space available */
            }
        }

        /* Increment the amount of data sent. If we have not completed all our
         * transmits, then we'll loop again and transmit another packet */
        tcb->seqno_me += (uint32_t)payload_length;
        tcb->payload_sent = (unsigned short)(tcb->payload_sent + payload_length);
        if (tcb->payload_sent == tcb->payload_length)
            break;
    }
}

/***************************************************************************
 ***************************************************************************/
void
tcp_send_RST(
    struct TemplatePacket *templ,
    PACKET_QUEUE *packet_buffers,
    PACKET_QUEUE *transmit_queue,
    unsigned ip_them, unsigned ip_me,
    unsigned port_them, unsigned port_me,
    unsigned seqno_them, unsigned seqno_me
)
{
    struct PacketBuffer *response = 0;
    int err = 0;
    uint64_t wait = 100;


    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    for (err=1; err; ) {
        err = rte_ring_sc_dequeue(packet_buffers, (void**)&response);
        if (err != 0) {
            static int is_warning_printed = 0;
            if (!is_warning_printed) {
                LOG(0, "packet buffers empty (should be impossible)\n");
                is_warning_printed = 1;
            }
            fflush(stdout);
            pixie_usleep(wait = (uint64_t)(wait *1.5)); /* no packet available */
        }
        //if (wait != 100)
        //    ;//printf("\n"); FIXME
    }
    if (response == NULL)
        return;

    response->length = tcp_create_packet(
        templ,
        ip_them, port_them,
        ip_me, port_me,
        seqno_me, seqno_them,
        0x04, /*RST*/
        0, 0,
        response->px, sizeof(response->px)
        );


    /* Put this buffer on the transmit queue. Remember: transmits happen
     * from a transmit-thread only, and this function is being called
     * from a receive-thread. Therefore, instead of transmiting ourselves,
     * we hae to queue it up for later transmission. */
    for (err=1; err; ) {
        err = rte_ring_sp_enqueue(transmit_queue, response);
        if (err != 0) {
            LOG(0, "transmit queue full (should be impossible)\n");
            pixie_usleep(100); /* no space available */
        }
    }
}

/***************************************************************************
 * KLUDGE: if we receive FIN for a connection we no longer have, then
 * response to the packet as if we did have a valid connections. This is
 * because we are much more aggressive at closing connections and freeing
 * memory than other stacks.
 ***************************************************************************/
void
tcpcon_send_FIN(
    struct TCP_ConnectionTable *tcpcon,
    unsigned ip_me, unsigned ip_them,
    unsigned port_me, unsigned port_them,
    uint32_t seqno_them, uint32_t ackno_them)
{
    struct TCP_Control_Block tcb;

    memset(&tcb, 0, sizeof(tcb));

    tcb.ip_me = ip_me;
    tcb.ip_them = ip_them;
    tcb.port_me = (unsigned short)port_me;
    tcb.port_them = (unsigned short)port_them;
    tcb.seqno_me = ackno_them;
    tcb.ackno_me = seqno_them + 1;
    tcb.seqno_them = seqno_them + 1;
    tcb.ackno_them = ackno_them;

    tcpcon_send_packet(tcpcon, &tcb, FIN|ACK);
}


/***************************************************************************
 * Parse the information we get from the server we are scanning. Typical
 * examples are SSH banners, FTP banners, or the response from HTTP
 * requests
 ***************************************************************************/
static unsigned
parse_banner(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    const unsigned char *payload,
    size_t payload_length)
{
    assert(tcb->banout.max_length);
    
    banner1_parse(
                                    tcpcon->banner1,
                                    &tcb->banner1_state,
                                    payload,
                                    payload_length,
                                    &tcb->banout,
                                    tcb);

    if (tcb->banner1_state.state == STATE_DONE)
        return STATE_DONE;
    else if (tcb->banner1_state.is_done)
        return STATE_DONE;
    else
        return 0;
}


/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
state_to_string(int state)
{
    switch (state) {
    case STATE_SYN_SENT:    return "[SYN_SENT]";
    case STATE_SYN_RCVD:    return "[SYN_RCVD]";
    case STATE_HELLO:       return "[HELLO]";
    case STATE_ESTABLISHED: return "[ESTABLISHED]";
    case STATE_FIN_WAIT_1:  return "[FIN_WAIT_1]";
    case STATE_FIN_WAIT_2:  return "[FIN_WAIT_2]";
    case STATE_CLOSING:     return "[CLOSING]";
    case STATE_TIME_WAIT:   return "[TIME_WAIT]";
    case STATE_CLOSE_WAIT:  return "[CLOSE_WAIT]";
    case STATE_LAST_ACK:    return "[LAST_ACK]";
    case STATE_CLOSED:      return "[CLOSED]";
    case STATE_LISTEN:      return "[LISTEN]";
    default:                return "[(null)]";
    }
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
what_to_string(int state)
{
    static char buf[64];
    switch (state) {
    case TCP_WHAT_NOTHING:  return "WHAT_NOTHING";
    case TCP_WHAT_TIMEOUT:  return "WHAT_TIMEOUT";
    case TCP_WHAT_SYNACK:   return "WHAT_SYNACK";
    case TCP_WHAT_RST:      return "WHAT_RST";
    case TCP_WHAT_FIN:      return "WHAT_FIN";
    case TCP_WHAT_ACK:      return "WHAT_ACK";
    case TCP_WHAT_DATA:     return "WHAT_DATA";
    case TCP_WHAT_DONE_SENDING:return "WHAT_DONE_SENDING";
    default:
        sprintf_s(buf, sizeof(buf), "%d", state);
        return buf;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
handle_ack(
    struct TCP_Control_Block *tcb,
    uint32_t ackno)
{

    LOG(4,  "%u.%u.%u.%u - %u-sending, %u-reciving\n",
            (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF,
            tcb->seqno_me - ackno,
            ackno - tcb->ackno_them
            );

    /* Normal: just discard repeats */
    if (ackno == tcb->ackno_them) {
        return;
    }

    /* Make sure this isn't a duplicate ACK from past
     * WRAPPING of 32-bit arithmetic happens here */
    if (ackno - tcb->ackno_them > 10000) {
        LOG(4,  "%u.%u.%u.%u - "
                "tcb: ackno from past: "
                "old ackno = 0x%08x, this ackno = 0x%08x\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF,
                tcb->ackno_me, ackno);
        return;
    }

    /* Make sure this isn't invalid ACK from the future
     * WRAPPING of 32-bit arithmatic happens here */
    if (tcb->seqno_me - ackno > 10000) {
        LOG(4, "%u.%u.%u.%u - "
                "tcb: ackno from future: "
                "my seqno = 0x%08x, their ackno = 0x%08x\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF,
                tcb->seqno_me, ackno);
        return;
    }

    /* now that we've verified this is a good ACK, record this number */
    tcb->ackno_them = ackno;
}


/*****************************************************************************
 * Notifies the user that the system has connected to the target
 *****************************************************************************/
static void
tcpuser_connect(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb)
{
    struct Banner1 *banner1 = tcpcon->banner1;

    if (banner1->L) {

        /* [LUAPROBE]
         * If we have a script, then run it, and createa coroutine/thread
         * structure for the script.
         */
        assert(tcb->L == 0);
        tcb->L = luaprobe_event_connect(banner1->L, tcb);

    } else if (banner1->tcp_payloads[tcb->port_them]) {
        banner1->tcp_payloads[tcb->port_them]->hello(
            banner1,
            0,
            &tcb->banner1_state,
            tcb);

        /* kludge */
        if (banner1->tcp_payloads[tcb->port_them] == &banner_ssl)
            tcb->banner1_state.is_sent_sslhello = 1;
    }
}

/*****************************************************************************
 * Notifies the user that a packet has arrived on the connection
 *****************************************************************************/
static void
tcpuser_receive(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    const void *payload,
    unsigned payload_length)
{
    struct Banner1 *banner1 = tcpcon->banner1;

    if (banner1->L) {
        /* [LUAPROBE] 
         * If we are doing Lua scripting, then parse this packet with the 
         * script.
         */
        luaprobe_event_packet(tcb->L,
                                tcb,
                                payload,
                                payload_length);
                                        
    } else {
        /* [--banners]
         * If we are doing banners without scripting, then parse this with
         * our internal protocol parsers.
         */
        parse_banner(
                    tcpcon,
                    tcb,
                    payload,
                    payload_length);
    }
}

/*****************************************************************************
 * Called when we receive a "fin" from the other side.
 *****************************************************************************/
static void
tcpuser_receive_close(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    int is_reset)
{
    UNUSEDPARM(tcpcon);
    UNUSEDPARM(tcb);
    UNUSEDPARM(is_reset);
}

/*****************************************************************************
 * Handles incoming events, like timeouts and packets, that cause a change
 * in the TCP control block "state".
 *
 * This is the part of the code that implements the famous TCP state-machine
 * you see drawn everywhere, where they have states like "TIME_WAIT". Only
 * we don't really have those states.
 *****************************************************************************/
void
tcpcon_handle(struct TCP_ConnectionTable *tcpcon,
              struct TCP_Control_Block *tcb,
              int what, const void *vpayload, unsigned payload_length,
              unsigned secs, unsigned usecs,
              unsigned seqno_them, unsigned seqno_me)
{
    const unsigned char *payload = (const unsigned char *)vpayload;

    if (tcb == NULL)
        return;

    /* Make sure no connection lasts more than ~30 seconds */
    if (what == TCP_WHAT_TIMEOUT) {
        if (tcb->when_created + tcpcon->timeout_connection < secs) {
            LOGip(8, tcb->ip_them, tcb->port_them,
                "%s                \n",
                "CONNECTION TIMEOUT---");
            tcpcon_send_packet(tcpcon, tcb, RST);
            tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
            return;
        }
    }

    LOGip(8, tcb->ip_them, tcb->port_them, "=%s : %s                  \n",
            state_to_string(tcb->tcpstate),
            what_to_string(what));

    switch (tcb->tcpstate<<8 | what) {
    case STATE_SYN_SENT<<8      | TCP_WHAT_SYNACK:
        /* Send "ACK" to acknowlege their "SYN-ACK", which is the second
         * step in the three-way-handshake */
        LOGip(8, tcb->ip_them, tcb->port_them, "ACK\n");
        tcpcon_send_packet(tcpcon, tcb, ACK);

        /*
         * Wait a few seconds for "server hello" (like SSH), and if that's
         * not found, then transmit a "client hello"
         */
        tcb->tcpstate = STATE_HELLO;
        timeouts_add(   tcpcon->timeouts,
                        tcb->timeout,
                        offsetof(struct TCP_Control_Block, timeout),
                        TICKS_FROM_TV(secs+tcpcon->timeout_hello,usecs)
                        );
        break;

    case STATE_ESTABLISHED<<8   | TCP_WHAT_SYNACK:
    case STATE_HELLO<<8         | TCP_WHAT_SYNACK:
        /* If we get duplicate SYN-ACKs, then just retransmit an
         * acknowledgement */
        tcpcon_send_packet(tcpcon, tcb, ACK);
        break;

    case STATE_HELLO<<8         | TCP_WHAT_ACK:
    case STATE_ESTABLISHED<<8   | TCP_WHAT_ACK:
        /* NOTE: the arg 'payload_length' was overloaded here to be the
         * 'ackno' instead */
        handle_ack( tcb, seqno_me);
        break;

    case STATE_HELLO<<8         | TCP_WHAT_TIMEOUT:
        /* We received a timeout in the 'hello' state, meaning
         * that we didn't receive any unexpected response from the server,
         * (like FTP on an HTTP port), so now we should transmit
         * our hello request */
        tcb->tcpstate = STATE_ESTABLISHED;
        tcpuser_connect(tcpcon, tcb);
        goto established_timeout;

    case STATE_ESTABLISHED<<8   | TCP_WHAT_TIMEOUT:
    established_timeout:
        /*
         * If there are queued data payload to send, then send ALL of the
         * payload. We don't have any slow-start stuff in our stack -- we
         * just flush all the payload out all the time 
         */
        tcpcon_send_packet(tcpcon, tcb, ACK);

        /* Add a timeout so that we can resend the data in case it
         * goes missing. Note that we put this back in the timeout
         * system regardless if we've sent data. */
        timeouts_add(   tcpcon->timeouts,
                        tcb->timeout,
                        offsetof(struct TCP_Control_Block, timeout),
                        TICKS_FROM_TV(secs+2,usecs)
                        );
        break;
    
    case STATE_HELLO<<8         | TCP_WHAT_DATA:
    case STATE_ESTABLISHED<<8   | TCP_WHAT_DATA:
        /* GAP
         * Ignore out-of-order incoming packets. This tests to see if the
         * incoming packet skips a gap. In which case, instead of buffering it
         * like a normal TCP stack, we simply discard it.
         */
        if ((unsigned)(tcb->seqno_them - seqno_them) > payload_length)  {
            tcpcon_send_packet(tcpcon, tcb, ACK);
            return;
        }

        /* OVERLAP
         * Fix any overlap. NOTE: INTEGER OVERFLOW HAPPENS HERE
         * Kludge: I have a bug in my integer-overflow arithmetic, so I just
         * implement by 1 each time. I need to fix this performance issue.
         */
        while (seqno_them != tcb->seqno_them && payload_length) {
            seqno_them++;
            payload_length--;
            payload++;
        }

        /* EMPTY
         * If the incoming packet is empty, then there is no payload, so such
         * ack the payload we currently have and return. Note that since we 
         * ACK every ACK, this gets pretty chatty. Two masscans talking to each
         * other will endless ping-pong ACKs back and forth.
         */
        if (payload_length == 0) {
            tcpcon_send_packet(tcpcon, tcb, ACK);
            return;
        }
            

        /*
         * Once we've figured out how much payload (if any) has been received,
         * send it to the user USER script
         */
        tcpuser_receive(tcpcon, tcb, payload, payload_length);


        /* move their sequence number forward, to indicate that we've successfully
         * received this packet. Note that a normal TCP stack ACKs data it has
         * received, whereas we have ACKed the data we have parsed. */
        tcb->seqno_them += (unsigned)payload_length;
            
        /* Send ACK for data received. If data was queued up for transmit,
         * data packets will be sent at this point. */
        tcpcon_send_packet(tcpcon, tcb, ACK);
        break;

    case STATE_HELLO<<8         | TCP_WHAT_FIN:
    case STATE_ESTABLISHED<<8   | TCP_WHAT_FIN:
    case STATE_CLOSE_WAIT       | TCP_WHAT_FIN:
        if (tcb->seqno_them == seqno_them) {
            if (!tcb->is_fin_received)
                tcpuser_receive_close(tcpcon, tcb, 0);
            tcb->is_fin_received = 1;
            tcb->tcpstate = STATE_CLOSE_WAIT;
            tcpcon_send_packet(tcpcon, tcb, ACK);
        }
        break;

    case STATE_CLOSE_WAIT       | TCP_WHAT_DONE_SENDING:
        tcb->is_fin_sent = 1;
        tcpcon_send_packet(tcpcon, tcb, ACK);
        tcb->tcpstate = STATE_LAST_ACK;
        break;

    case STATE_LAST_ACK         | TCP_WHAT_ACK:
        tcpcon_destroy_tcb(tcpcon, tcb, Reason_FIN);
        break;

    default:
        LOGip(3, tcb->ip_them, tcb->port_them, "tcb: unknown event %s : %s\n",
            state_to_string(tcb->tcpstate),
            what_to_string(what));
    }

}

