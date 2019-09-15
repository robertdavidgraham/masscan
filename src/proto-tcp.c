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
#include "proto-smb.h"
#include "output.h"
#include "string_s.h"
#include "main-globals.h"
#include "crypto-base64.h"
#include "proto-interactive.h"
#include "util-malloc.h"
#include "scripting.h"
#include "versioning.h"



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
    unsigned tcpstate:4;
    
    /* If the payload we've sent was dynamically allocated with
     * malloc() from the heap, in which case we'll have to free()
     * it. (Most payloads are static memory) */
    unsigned is_payload_dynamic:1;

    unsigned established;

    unsigned short payload_length;
    time_t when_created;
    const unsigned char *payload;

    /*
     * If Running a script, the thread object
     */
    struct ScriptingThread *scripting_thread;
    
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
    
    struct ScriptingVM *scripting_vm;
};

enum {
    STATE_SYN_SENT,
    //STATE_SYN_RECEIVED,
    STATE_ESTABLISHED_SEND, /* our own special state, can only send */
    STATE_ESTABLISHED_RECV, /* our own special state, can only receive */
    //STATE_CLOSE_WATI,
    STATE_LAST_ACK,
    STATE_FIN_WAIT1,
    STATE_FIN_WAIT2,
    STATE_CLOSING,
    STATE_TIME_WAIT,
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
            0);

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
 ***************************************************************************/
static int
name_equals(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (*rhs == '\0' && *lhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
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
        banner_http.hello_length = http_change_field(
                                (unsigned char**)&banner_http.hello,
                                (unsigned)banner_http.hello_length,
                                "User-Agent:",
                                (const unsigned char *)value,
                                (unsigned)value_length);
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
        LOG(1, "TCP hello-timeout = \"%.*s\"\n", (int)value_length, (const char *)value);
        LOG(1, "TCP hello-timeout = %u\n", (unsigned)tcpcon->timeout_hello);
        return;
    }

    /*
     * Force SSL processing on all ports
     */
    if (name_equals(name, "hello") && name_equals(value, "ssl")) {
        unsigned i;
        
        LOG(2, "HELLO: setting SSL hello message\n");
        for (i=0; i<65535; i++) {
            banner1->payloads.tcp[i] = &banner_ssl;
        }
        
        return;
    }
    
    /*
     * Force HTTP processing on all ports
     */
    if (name_equals(name, "hello") && name_equals(value, "http")) {
        unsigned i;
        
        LOG(2, "HELLO: setting HTTP hello message\n");
        for (i=0; i<65535; i++) {
            banner1->payloads.tcp[i] = &banner_http;
        }
        
        return;
    }
    
    /*
     * Downgrade SMB hello from v1/v2 to use only v1
     */
    if (name_equals(name, "hello") && name_equals(value, "smbv1")) {
        smb_set_hello_v1(&banner_smb1);        
        return;
    }

    /*
     * 2014-04-08: scan for Neel Mehta's "heartbleed" bug
     */
    if (name_equals(name, "heartbleed")) {
        unsigned i;

        /* Change the hello message to including negotiating the use of 
         * the "heartbeat" extension */
        banner_ssl.hello = ssl_hello(ssl_hello_heartbeat_template);
        banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
        tcpcon->banner1->is_heartbleed = 1;

        for (i=0; i<65535; i++) {
            banner1->payloads.tcp[i] = &banner_ssl;
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
            banner1->payloads.tcp[i] = &banner_ssl;
        }

        return;
    }

    /*
     * 2014-10-16: scan for SSLv3 servers (POODLE)
     */
    if (name_equals(name, "poodle") || name_equals(name, "sslv3")) {
        unsigned i;
        void *px;
        
        /* Change the hello message to including negotiating the use of 
         * the "heartbeat" extension */
        px = ssl_hello(ssl_hello_sslv3_template);
        banner_ssl.hello = ssl_add_cipherspec(px, 0x5600, 1);
        banner_ssl.hello_length = ssl_hello_size(banner_ssl.hello);
        tcpcon->banner1->is_poodle_sslv3 = 1;

        for (i=0; i<65535; i++) {
            banner1->payloads.tcp[i] = &banner_ssl;
        }
        
        return;
    }

    
    /*
     * You can reconfigure the "hello" message to be anything
     * you want.
     */
    if (name_equals(name, "hello-string")) {
        struct ProtocolParserStream *x;
        const char *p = strchr(name, '[');
        unsigned port;


        if (p == NULL) {
            fprintf(stderr, "tcpcon: parmeter: expected array []: %s\n", name);
            exit(1);
        }
        port = (unsigned)strtoul(p+1, 0, 0);

        x = banner1->payloads.tcp[port];
        if (x == NULL) {
            x = CALLOC(1, sizeof(*x));
            x->name = "(allocated)";
        }

        x->hello = MALLOC(value_length);
        x->hello_length = base64_decode((char*)x->hello, value_length, value, value_length);

        banner1->payloads.tcp[port] = x;
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
 ***************************************************************************/
void scripting_init_tcp(struct TCP_ConnectionTable *tcpcon, struct lua_State *L)
{
    tcpcon->banner1->L = L;
    
    banner_scripting.init(tcpcon->banner1);
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
    
    
    tcpcon = CALLOC(1, sizeof(*tcpcon));
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
        tcpcon->entries = malloc(entry_count * sizeof(*tcpcon->entries));
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
     * get the same hash. */
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
 * Flush all the banners asssociated with this TCP connection. This always
 * called when TCB is destroyed. This may also be called earlier, such
 * as when a FIN is received.
 ***************************************************************************/
static void
tcpcon_flush_banners(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *tcb)
{
    struct BannerOutput *banout;
    
    /* Go through and print all the banners. Some protocols have 
     * multiple banners. For example, web servers have both
     * HTTP and HTML banners, and SSL also has several 
     * X.509 certificate banners */
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
     * Free up all the banners.
     */
    banout_release(&tcb->banout);

}

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
    
    UNUSEDPARM(reason);

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
     * time, there'll only be one. After printing them out, delete the
     * banners.
     */
    tcpcon_flush_banners(tcpcon, tcb);
    if (tcb->is_payload_dynamic && tcb->payload_length && tcb->payload)
        free((void*)tcb->payload);
    
    if (tcb->scripting_thread)
        ; //scripting_thread_close(tcb->scripting_thread);
    tcb->scripting_thread = 0;
    
    /* KLUDGE: this needs to be made more elegant */
    switch (tcb->banner1_state.app_proto) {
        case PROTO_SMB:
            banner_smb1.cleanup(&tcb->banner1_state);
            break;
    }

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
            tcb = MALLOC(sizeof(*tcb));
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
static void
tcpcon_send_packet(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    unsigned tcp_flags,
    const unsigned char *payload, size_t payload_length,
    unsigned ctrl)
{
    struct PacketBuffer *response = 0;
    int err = 0;
    uint64_t wait = 100;


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
        //if (wait != 100)
        //    ; //printf("\n");FIXME
    }
    if (response == NULL)
        return;

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
        tcb->seqno_me, tcb->seqno_them,
        tcp_flags,
        payload, payload_length,
        response->px, sizeof(response->px)
        );

    /*
     * KLUDGE:
     */
    if (ctrl & CTRL_SMALL_WINDOW) {
        tcp_set_window(response->px, response->length, 600);
    }
    //tcp_set_window(response->px, response->length, 600);

    /* If we have payload, then:
     * 1. remember the payload so we can resend it
     */
    tcb->payload = payload;
    tcb->payload_length = (unsigned short)payload_length;

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
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
state_to_string(int state)
{
    static char buf[64];
    switch (state) {
            //STATE_SYN_RECEIVED,
            //STATE_CLOSE_WATI,
        case STATE_LAST_ACK:        return "LAST-ACK";
        case STATE_FIN_WAIT1:       return "FIN-WAIT-1";
        case STATE_FIN_WAIT2:       return "FIN-WAIT-2";
        case STATE_CLOSING:         return "CLOSING";
        case STATE_TIME_WAIT:       return "TIME-WAIT";
        case STATE_SYN_SENT:        return "SYN_SENT";
        case STATE_ESTABLISHED_SEND:return "ESTABLISHED_SEND";
        case STATE_ESTABLISHED_RECV:return "ESTABLISHED_RECV";
            
        default:
            sprintf_s(buf, sizeof(buf), "%d", state);
            return buf;
    }
}

/***************************************************************************
 * DEBUG: when printing debug messages (-d option), this prints a string
 * for the given state.
 ***************************************************************************/
static const char *
what_to_string(enum TCP_What state)
{
    static char buf[64];
    switch (state) {
        case TCP_WHAT_TIMEOUT: return "TIMEOUT";
        case TCP_WHAT_SYNACK: return "SYNACK";
        case TCP_WHAT_RST: return "RST";
        case TCP_WHAT_FIN: return "FIN";
        case TCP_WHAT_ACK: return "ACK";
        case TCP_WHAT_DATA: return "DATA";
        default:
            sprintf_s(buf, sizeof(buf), "%d", state);
            return buf;
    }
}


/***************************************************************************
 ***************************************************************************/

static void
LOGSEND(struct TCP_Control_Block *tcb, const char *what)
{
    if (tcb == NULL)
        return;
    LOGip(5, tcb->ip_them, tcb->port_them, "=%s : --->> %s                  \n",
          state_to_string(tcb->tcpstate),
          what);
}


/***************************************************************************
 * Sends a fake FIN when we've already closed our connection, on the
 * assumption this will help the other side close their side more
 * gracefully. Maybe we shoulid do a RST instead.
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
    
    LOGSEND(&tcb, "peer(FIN) fake");
    tcpcon_send_packet(tcpcon, &tcb, 0x11, 0, 0, 0);
}

void
tcpcon_send_RST(
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
    
    LOGSEND(&tcb, "peer(RST) fake");
    tcpcon_send_packet(tcpcon, &tcb, 0x04, 0, 0, 0);
}


/***************************************************************************
 * Parse the information we get from the server we are scanning. Typical
 * examples are SSH banners, FTP banners, or the response from HTTP
 * requests
 ***************************************************************************/
static size_t
parse_banner(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    const unsigned char *payload,
    size_t payload_length,
    struct InteractiveData *more)
{
    assert(tcb->banout.max_length);
    
    banner1_parse(
                                    tcpcon->banner1,
                                    &tcb->banner1_state,
                                    payload,
                                    payload_length,
                                    &tcb->banout,
                                    more);
    return payload_length;
}


/***************************************************************************
 ***************************************************************************/
static int
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
        return 0;
    }

    /* Make sure this isn't a duplicate ACK from past
     * WRAPPING of 32-bit arithmetic happens here */
    if (ackno - tcb->ackno_them > 10000) {
        LOG(4,  "%u.%u.%u.%u - "
                "tcb: ackno from past: "
                "old ackno = 0x%08x, this ackno = 0x%08x\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF,
                tcb->ackno_me, ackno);
        return 0;
    }

    /* Make sure this isn't invalid ACK from the future
     * WRAPPING of 32-bit arithmatic happens here */
    if (tcb->seqno_me - ackno > 10000) {
        LOG(4, "%u.%u.%u.%u - "
                "tcb: ackno from future: "
                "my seqno = 0x%08x, their ackno = 0x%08x\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF,
                tcb->seqno_me, ackno);
        return 0;
    }

    /* now that we've verified this is a good ACK, record this number */
    tcb->ackno_them = ackno;
    
    /* Mark that this was a good ack */
    return 1;
}

enum AppAction {
    APP_CONNECTED,
    APP_RECV_TIMEOUT,
    APP_RECV_PAYLOAD,
    APP_SEND_SENT,
};


/***************************************************************************
 ***************************************************************************/
static void
application(struct TCP_ConnectionTable *tcpcon,
                 struct TCP_Control_Block *tcb,
                 enum AppAction action, const void *payload, size_t payload_length,
                 unsigned secs, unsigned usecs)
{
    struct Banner1 *banner1 = tcpcon->banner1;
    
    enum {
        App_Connect,
        App_ReceiveHello,
        App_ReceiveNext,
        App_SendNext,
    };
    
    switch (tcb->established) {
        case App_Connect:
            if (banner1->payloads.tcp[tcb->port_them] == &banner_scripting) {
                //int x;
                ; //tcb->scripting_thread = scripting_thread_new(tcpcon->scripting_vm);
                ; //x = scripting_thread_run(tcb->scripting_thread);
            } else {
                /*
                 * Wait 1 second for "server hello" (like SSH), and if that's
                 * not found, then transmit a "client hello"
                 */
                assert(action == APP_CONNECTED);
                LOGSEND(tcb, "+timeout");
                timeouts_add( tcpcon->timeouts,
                             tcb->timeout,
                             offsetof(struct TCP_Control_Block, timeout),
                             TICKS_FROM_TV(secs+tcpcon->timeout_hello,usecs)
                             );
                /* Start of connection */
                tcb->tcpstate = STATE_ESTABLISHED_RECV;
                tcb->established = App_ReceiveHello;
            }
            break;
        case App_ReceiveHello:
            if (action == APP_RECV_TIMEOUT) {
                struct ProtocolParserStream *stream = banner1->payloads.tcp[tcb->port_them];
                
                if (stream) {
                    struct InteractiveData more = {0};
                    unsigned ctrl = 0;
                    
                    if (stream->transmit_hello)
                        stream->transmit_hello(banner1, &more);
                    else {
                        more.m_length = (unsigned)banner1->payloads.tcp[tcb->port_them]->hello_length;
                        more.m_payload = banner1->payloads.tcp[tcb->port_them]->hello;
                        more.is_payload_dynamic = 0;
                    }
                    
                    /*
                     * Kludge
                     */
                    if (banner1->payloads.tcp[tcb->port_them] == &banner_ssl) {
                        tcb->banner1_state.is_sent_sslhello = 1;
                    }
                    
                    /*
                     * KLUDGE
                     */
                    if (tcpcon->banner1->is_heartbleed) {
                        ctrl = CTRL_SMALL_WINDOW;
                    }
                    
                    /*
                     * Queue up the packet to be sent
                     */
                    LOGip(4, tcb->ip_them, tcb->port_them, "sending payload %u bytes\n", more.m_length);
                    LOGSEND(tcb, "peer(payload)");
                    tcpcon_send_packet(tcpcon, tcb, 0x18, more.m_payload, more.m_length, ctrl);
                    tcb->seqno_me += (uint32_t)more.m_length;
                    tcb->is_payload_dynamic = more.is_payload_dynamic;
                    tcb->tcpstate = STATE_ESTABLISHED_SEND;
                    
                    //tcb->established = App_SendNext;
                }
                
                /* Add a timeout so that we can resend the data in case it
                 * goes missing. Note that we put this back in the timeout
                 * system regardless if we've sent data. */
                LOGSEND(tcb, "+timeout");
                timeouts_add(   tcpcon->timeouts,
                             tcb->timeout,
                             offsetof(struct TCP_Control_Block, timeout),
                             TICKS_FROM_TV(secs+1,usecs)
                             );
                break;
            } else if (action == APP_RECV_PAYLOAD) {
                tcb->established = App_ReceiveNext;
                /* fall through */
            }
            /* fall through */
        case App_ReceiveNext:
            if (action == APP_RECV_PAYLOAD) {
                struct InteractiveData more = {0};
                
                /* [--banners]
                 * This is an important part of the system, where the TCP
                 * stack passes incoming packet payloads off to the application
                 * layer protocol parsers. This is where, in Sockets API, you
                 * might call the 'recv()' function.
                 */
                parse_banner(
                                   tcpcon,
                                   tcb,
                                   payload,
                                   payload_length,
                                   &more);
                
                /* move their sequence number forward */
                tcb->seqno_them += (unsigned)payload_length;
                
                /* acknowledge the bytes received */
                if (more.m_length) {
                    //printf("." "sending more data %u bytes\n", more.length);
                    LOGSEND(tcb, "peer(ACK)");
                    LOGSEND(tcb, "peer(payload)");
                    tcpcon_send_packet(tcpcon, tcb, 0x18, more.m_payload, more.m_length, 0);
                    tcb->seqno_me += (uint32_t)more.m_length;
                    tcb->is_payload_dynamic = more.is_payload_dynamic;
                    tcb->tcpstate = STATE_ESTABLISHED_SEND;
                    tcb->established = App_SendNext;
                    LOGip(4, tcb->ip_them, tcb->port_them, "sending payload %u bytes\n", more.m_length);
                    
                } else {
                    LOGSEND(tcb, "peer(ACK)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x10,
                                       0, 0, 0);
                }
                
                if (more.is_closing) {
                    /* Send FIN packet */
                    LOGSEND(tcb, "peer(FIN)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x11,
                                       0, 0, 0);
                    tcb->seqno_me++;
                    
                    tcb->tcpstate = STATE_FIN_WAIT1;
                    LOGSEND(tcb, "+timeout");

                    timeouts_add(   tcpcon->timeouts,
                                 tcb->timeout,
                                 offsetof(struct TCP_Control_Block, timeout),
                                 TICKS_FROM_TV(secs+1,usecs)
                                 );
                    //tcpcon_destroy_tcb(tcpcon, tcb, Reason_StateDone);
                }
            }
            break;
        case App_SendNext:
            if (action == APP_SEND_SENT) {
                tcb->tcpstate = STATE_ESTABLISHED_RECV;
                tcb->established = App_ReceiveNext;
            }
            break;
        default:
            LOG(0, "TCP state error\n");
            exit(1);
            break;
    }
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
              int in_what, const void *vpayload, size_t payload_length,
              unsigned secs, unsigned usecs,
              unsigned seqno_them)
{
    enum TCP_What what = in_what;
    const unsigned char *payload = (const unsigned char *)vpayload;

    if (tcb == NULL)
        return;
    
    LOGip(5, tcb->ip_them, tcb->port_them, "=%s : %s                  \n",
          state_to_string(tcb->tcpstate),
          what_to_string(what));

    /* Make sure no connection lasts more than ~30 seconds */
    if (what == TCP_WHAT_TIMEOUT) {
        if (tcb->when_created + tcpcon->timeout_connection < secs) {
            LOGip(8, tcb->ip_them, tcb->port_them,
                "%s                \n",
                "CONNECTION TIMEOUT---");
            LOGSEND(tcb, "peer(RST)");
            tcpcon_send_packet(tcpcon, tcb,
                0x04,
                0, 0, 0);
            tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
            return;
        }
    }
    
    if (what == TCP_WHAT_RST) {
        LOGSEND(tcb, "tcb(destroy)");
        tcpcon_destroy_tcb(tcpcon, tcb, Reason_RST);
        return;
    }
    
    
    /*
     *
     *
     *
     *
     *
     *
     */
    switch (tcb->tcpstate) {
            /* TODO: validate any SYNACK is real before sending it here
             * to the state-machine, by validating that it's acking
             * something */
        case STATE_SYN_SENT:
            switch (what) {
                case TCP_WHAT_RST:
                case TCP_WHAT_TIMEOUT:
                //case TCP_WHAT_SYNACK:
                case TCP_WHAT_FIN:
                case TCP_WHAT_ACK:
                case TCP_WHAT_DATA:
                    break;
                case TCP_WHAT_SYNACK:
                    /* Send "ACK" to acknowlege their "SYN-ACK" */
                    LOGSEND(tcb, "peer(ACK)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x10,
                                       0, 0, 0);
                    LOGSEND(tcb, "app(connected)");
                    application(tcpcon, tcb, APP_CONNECTED, 0, 0, secs, usecs);
                    break;
                }
            break;
        case STATE_ESTABLISHED_SEND:
        case STATE_ESTABLISHED_RECV:
            switch (what) {
                case TCP_WHAT_RST:
                    break;
                case TCP_WHAT_SYNACK:
                    /* Send "ACK" to acknowlege their "SYN-ACK" */
                    LOGSEND(tcb, "peer(ACK)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x10, /* ACK */
                                       0, 0, 0);
                    break;
                case TCP_WHAT_FIN:
                    if (tcb->tcpstate == STATE_ESTABLISHED_RECV) {
                        tcb->seqno_them = seqno_them + 1;
                        
                        LOGSEND(tcb, "peer(FIN)");
                        tcpcon_send_packet(tcpcon, tcb,
                                           0x11, /* FIN-ACK */
                                           0, 0, 0);
                        tcb->seqno_me++;
                        tcb->tcpstate = STATE_LAST_ACK;
                    } else if (tcb->tcpstate == STATE_ESTABLISHED_RECV) {
                        /* Do nothing, the same thing as if we received data
                         * during the SENd state. The other side will send it
                         * again after it has acknolwedged our data */
                        ;
                    }
                    break;
                case TCP_WHAT_ACK:
                    /* There's actually nothing that goes on in this state. We are
                     * just waiting for the timer to expire. In the meanwhile,
                     * though, the other side is might acknowledge that we sent
                     * a SYN-ACK */
                     
                    /* NOTE: the arg 'payload_length' was overloaded here to be the
                     * 'ackno' instead */
                    handle_ack( tcb, (uint32_t)payload_length);
                    if (tcb->tcpstate == STATE_ESTABLISHED_SEND) {
                        if (tcb->ackno_them - tcb->seqno_me == 0) {
                            /* All the payload has been sent */
                            if (tcb->is_payload_dynamic)
                                free((void*)tcb->payload);
                            tcb->payload = 0;
                            tcb->payload_length = 0;
                            tcb->is_payload_dynamic = 0;
                            
                            LOGSEND(tcb, "app(sent)");
                            application(tcpcon, tcb, APP_SEND_SENT, 0, 0, secs, usecs);
                            tcb->tcpstate = STATE_ESTABLISHED_RECV;
                            LOGSEND(tcb, "+timeout");
                            timeouts_add(   tcpcon->timeouts,
                                         tcb->timeout,
                                         offsetof(struct TCP_Control_Block, timeout),
                                         TICKS_FROM_TV(secs+10,usecs)
                                         );
                        } else {
                            /* Reset the timeout, waiting for more data to arrive */
                            LOGSEND(tcb, "+timeout");
                            timeouts_add(   tcpcon->timeouts,
                                         tcb->timeout,
                                         offsetof(struct TCP_Control_Block, timeout),
                                         TICKS_FROM_TV(secs+1,usecs)
                                         );
                            
                        }
                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    if (tcb->tcpstate == STATE_ESTABLISHED_RECV) {
                        /* Didn't receive data in the expected timeframe. This is
                         * often a normal condition, such as during the start
                         * of a scanned connection, when we don't understand the
                         * protocol and are simply waiting for anything the
                         * server might send us.
                         */
                        LOGSEND(tcb, "app(timeout)");
                        application(tcpcon, tcb, APP_RECV_TIMEOUT, 0, 0, secs, usecs);
                    } else if (tcb->tcpstate == STATE_ESTABLISHED_SEND) {
                        /*
                         * We did not get a complete ACK of our sent data, so retransmit
                         * it to the server
                         */
                        uint32_t len;
                        
                        
                        len = tcb->seqno_me - tcb->ackno_them;
                        
                        /* Resend the payload */
                        tcb->seqno_me -= len;
                        LOGSEND(tcb, "peer(payload) retransmit");
                        
                        /* kludge: should never be NULL< but somehow is */
                        if (tcb->payload) 
                        tcpcon_send_packet(tcpcon, tcb,
                                           0x18,
                                           tcb->payload + tcb->payload_length - len,
                                           len, 0);
                        tcb->seqno_me += len;
                        
                        
                        /* Now that we've resent the packet, register another
                         * timeout in order to resend it yet again if not
                         * acknolwedgeld. */
                        LOGSEND(tcb, "+timeout");
                        timeouts_add(tcpcon->timeouts,
                                     tcb->timeout,
                                     offsetof(struct TCP_Control_Block, timeout),
                                     TICKS_FROM_TV(secs+2,usecs)
                                     );
                    }
        
                    break;
                case TCP_WHAT_DATA:
                    
                    if ((unsigned)(tcb->seqno_them - seqno_them) > payload_length)  {
                        LOGSEND(tcb, "peer(ACK)");
                        tcpcon_send_packet(tcpcon, tcb,
                                           0x10,
                                           0, 0, 0);
                        return;
                    }
                    
                    while (seqno_them != tcb->seqno_them && payload_length) {
                        seqno_them++;
                        payload_length--;
                        payload++;
                    }
                    
                    if (payload_length == 0) {
                        LOGSEND(tcb, "peer(ACK)");
                        tcpcon_send_packet(tcpcon, tcb,
                                           0x10,
                                           0, 0, 0);
                        return;
                    }
                    
                    LOGSEND(tcb, "app(payload)");
                    application(tcpcon, tcb, APP_RECV_PAYLOAD, payload, payload_length, secs, usecs);
                    
                    /* Send ack for the data */
                    LOGSEND(tcb, "peer(ACK)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x10,
                                       0, 0, 0);
                    break;

            }
            break;
        case STATE_FIN_WAIT1:
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    /* resend FIN packet */
                    LOGSEND(tcb, "peer(FIN)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x11,
                                       0, 0, 0);
                    
                    /* reset timeout */
                    LOGSEND(tcb, "+timeout");
                    timeouts_add(   tcpcon->timeouts,
                                 tcb->timeout,
                                 offsetof(struct TCP_Control_Block, timeout),
                                 TICKS_FROM_TV(secs+1,usecs)
                                 );
                    break;
                case TCP_WHAT_ACK:
                    if (handle_ack( tcb, (uint32_t)payload_length)) {
                        tcb->tcpstate = STATE_FIN_WAIT2;
                        LOGSEND(tcb, "+timeout");
                        timeouts_add(   tcpcon->timeouts,
                                     tcb->timeout,
                                     offsetof(struct TCP_Control_Block, timeout),
                                     TICKS_FROM_TV(secs+5,usecs)
                                     );
                    }
                    break;
                case TCP_WHAT_FIN:
                    break;
                case TCP_WHAT_SYNACK:
                case TCP_WHAT_RST:
                case TCP_WHAT_DATA:
                    break;
            }
            break;
            
        case STATE_FIN_WAIT2:
        case STATE_TIME_WAIT:
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    if (tcb->tcpstate == STATE_TIME_WAIT) {
                        tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
                        return;
                    }
                    break;
                case TCP_WHAT_ACK:
                    break;
                case TCP_WHAT_FIN:
                    tcb->seqno_them = seqno_them + 1;
                    LOGSEND(tcb, "peer(ACK)");
                    tcpcon_send_packet(tcpcon, tcb,
                                       0x10,
                                       0, 0, 0);
                    tcb->tcpstate = STATE_TIME_WAIT;
                    LOGSEND(tcb, "+timeout");
                    timeouts_add(   tcpcon->timeouts,
                                 tcb->timeout,
                                 offsetof(struct TCP_Control_Block, timeout),
                                 TICKS_FROM_TV(secs+5,usecs)
                                 );
                    break;
                case TCP_WHAT_SYNACK:
                case TCP_WHAT_RST:
                case TCP_WHAT_DATA:
                    break;
            }
            break;

        default:
            LOG(1, "TCP-state: unknown state\n");
    }
}

