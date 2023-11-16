/*
 * This is the core TCP layer in the stack. It's notified of incoming
 * IP datagrams containing TCP protocols. This is where the TCP state
 * diagram is handled.
 *
 *                                    
 *                              +---------+ ---------\      active OPEN  
 *                              |  CLOSED |            \    -----------  
 *                              +---------+<---------\   \   create TCB  
 *                                |     ^              \   \  snd SYN    
 *                   passive OPEN |     |   CLOSE        \   \           
 *                   ------------ |     | ----------       \   \         
 *                    create TCB  |     | delete TCB         \   \       
 *                                V     |                      \   \     
 *                              +---------+            CLOSE    |    \   
 *                              |  LISTEN |          ---------- |     |  
 *                              +---------+          delete TCB |     |  
 *                   rcv SYN      |     |     SEND              |     |  
 *                  -----------   |     |    -------            |     V  
 * +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 * |         |<-----------------           ------------------>|         |
 * |   SYN   |                    rcv SYN                     |   SYN   |
 * |   RCVD  |<-----------------------------------------------|   SENT  |
 * |         |                    snd ACK                     |         |
 * |         |------------------           -------------------|         |
 * +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
 *   |           --------------   |     |   -----------                  
 *   |                  x         |     |     snd ACK                    
 *   |                            V     V                                
 *   |  CLOSE                   +---------+                              
 *   | -------                  |  ESTAB  |                              
 *   | snd FIN                  +---------+                              
 *   |                   CLOSE    |     |    rcv FIN                     
 *   V                  -------   |     |    -------                     
 * +---------+          snd FIN  /       \   snd ACK          +---------+
 * |  FIN    |<-----------------           ------------------>|  CLOSE  |
 * | WAIT-1  |------------------                              |   WAIT  |
 * +---------+          rcv FIN  \                            +---------+
 *   | rcv ACK of FIN   -------   |                            CLOSE  |  
 *   | --------------   snd ACK   |                           ------- |  
 *   V        x                   V                           snd FIN V  
 * +---------+                  +---------+                   +---------+
 * |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 * +---------+                  +---------+                   +---------+
 *   |                rcv ACK of FIN |                 rcv ACK of FIN |  
 *   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |  
 *   |  -------              x       V    ------------        x       V  
 *    \ snd ACK                 +---------+delete TCB         +---------+
 *     ------------------------>|TIME WAIT|------------------>| CLOSED  |
 *                              +---------+                   +---------+
 *
 */
#include "stack-tcp-core.h"
#include "stack-tcp-api.h"
#include "stack-tcp-app.h"
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdarg.h>
#include "syn-cookie.h"
#include "event-timeout.h"      /* for tracking future events */
#include "rawsock.h"
#include "util-logger.h"
#include "templ-pkt.h"
#include "pixie-timer.h"
#include "stack-queue.h"
#include "proto-banner1.h"
#include "proto-ssl.h"
#include "proto-http.h"
#include "proto-smb.h"
#include "proto-versioning.h"
#include "output.h"
#include "util-safefunc.h"
#include "main-globals.h"
#include "crypto-base64.h"
#include "util-malloc.h"
#include "util-errormsg.h"
#include "scripting.h"


#ifdef _MSC_VER
#pragma warning(disable:4204)
#define snprintf _snprintf
#pragma warning(disable:4996)
#endif

struct TCP_Segment {
    unsigned seqno;
    unsigned char *buf;
    size_t length;
    enum TCP__flags flags;
    bool is_fin; /* was fin sent */
    struct TCP_Segment *next;
};



/***************************************************************************
 * A "TCP control block" is what most operating-systems/network-stack
 * calls the structure that corresponds to a TCP connection. It contains
 * things like the IP addresses, port numbers, sequence numbers, timers,
 * and other things.
 ***************************************************************************/
struct TCP_Control_Block
{
    ipaddress ip_me;
    ipaddress ip_them;

    unsigned short port_me;
    unsigned short port_them;

    uint32_t seqno_me;      /* next seqno I will use for transmit */
    uint32_t seqno_them;    /* the next seqno I expect to receive */
    uint32_t ackno_me;
    uint32_t ackno_them;

    uint32_t seqno_me_first;
    uint32_t seqno_them_first;
    
    struct TCP_Control_Block *next;
    struct TimeoutEntry timeout[1];

    unsigned char ttl;
    unsigned char syns_sent; /* reconnect */
    unsigned short mss; /* maximum segment size 1460 */
    unsigned tcpstate:4;
    unsigned is_ipv6:1;
    unsigned is_small_window:1; /* send with smaller window */
    unsigned is_their_fin:1;

    /** Set to true when the TCB is in-use/allocated, set to zero
     * when it's about to be deleted soon */
    unsigned is_active:1;
    
    /* If the payload we've sent was dynamically allocated with
     * malloc() from the heap, in which case we'll have to free()
     * it. (Most payloads are static memory) */
    unsigned is_payload_dynamic:1;

    unsigned app_state;

    struct TCP_Segment *segments;

    /*
    unsigned short payload_length;
    const unsigned char *payload;
    */
    time_t when_created;

    /*
     * If Running a script, the thread object
     */
    struct ScriptingThread *scripting_thread;
    const struct ProtocolParserStream *stream;
    
    struct BannerOutput banout;

    struct StreamState banner1_state;

    unsigned packet_number;
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
    struct stack_t *stack;

    struct Banner1 *banner1;
    OUTPUT_REPORT_BANNER report_banner;
    struct Output *out;
    
    struct ScriptingVM *scripting_vm;

    /** This is for creating follow-up connections based on the first
     * connection. Given an existing IP/port, it returns a different
     * one for the new conenction. */
    struct {
        const void *data;
        void *(*cb)(const void *in_src, const ipaddress ip, unsigned port,
                    ipaddress *next_ip, unsigned *next_port);
    } next_ip_port;
};

enum {
    STATE_SYN_SENT=0, /* must be zero */
    //STATE_SYN_RECEIVED,
    STATE_ESTABLISHED_SEND, /* our own special state, can only send */
    STATE_ESTABLISHED_RECV, /* our own special state, can only receive */
    STATE_CLOSE_WAIT,
    STATE_LAST_ACK,
    STATE_FIN_WAIT1_SEND,
    STATE_FIN_WAIT1_RECV,
    STATE_FIN_WAIT2,
    STATE_CLOSING,
    STATE_TIME_WAIT,
};

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
        case STATE_CLOSE_WAIT:      return "CLOSE-WAIT";
        case STATE_LAST_ACK:        return "LAST-ACK";
        case STATE_FIN_WAIT1_SEND:  return "FIN-WAIT-1-SEND";
        case STATE_FIN_WAIT1_RECV:  return "FIN-WAIT-1-RECV";
        case STATE_FIN_WAIT2:       return "FIN-WAIT-2";
        case STATE_CLOSING:         return "CLOSING";
        case STATE_TIME_WAIT:       return "TIME-WAIT";
        case STATE_SYN_SENT:        return "SYN_SENT";
        case STATE_ESTABLISHED_SEND:return "ESTABLISHED_SEND";
        case STATE_ESTABLISHED_RECV:return "ESTABLISHED_RECV";

        default:
            snprintf(buf, sizeof(buf), "%d", state);
            return buf;
    }
}

static void
vLOGtcb(const struct TCP_Control_Block *tcb, int dir, const char *fmt, va_list marker)
{
    char sz[256];
    ipaddress_formatted_t fmt1 = ipaddress_fmt(tcb->ip_them);

    snprintf(sz, sizeof(sz), "[%s:%u %4u,%4u] %s:%5u [%4u,%4u] {%s} ",
             fmt1.string, tcb->port_them,
             tcb->seqno_them - tcb->seqno_them_first,
             tcb->ackno_me - tcb->seqno_them_first,
             (dir > 0) ? "-->" : "<--",
             tcb->port_me,
             tcb->seqno_me - tcb->seqno_me_first,
             tcb->ackno_them - tcb->seqno_me_first,
             state_to_string(tcb->tcpstate)
             );
    if (dir == 2) {
        char *brace = strchr(sz, '{');
        memset(sz, ' ', brace-sz);
    }
    fprintf(stderr, "%s", sz);
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}
int is_tcp_debug = 0;

static void
LOGtcb(const struct TCP_Control_Block *tcb, int dir, const char *fmt, ...)
{
    va_list marker;

    if (!is_tcp_debug)
        return;
    va_start(marker, fmt);
    vLOGtcb(tcb, dir, fmt, marker);
    va_end(marker);
}



/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs)
{
    uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

    for (;;) {
        struct TCP_Control_Block *tcb;
        enum TCB_result x;

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
        x = stack_incoming_tcp(tcpcon, tcb, TCP_WHAT_TIMEOUT,
            0, 0,
            secs, usecs,
            tcb->seqno_them,
            tcb->ackno_them);

        /* If the TCB hasn't been destroyed, then we need to make sure
         * there is a timeout associated with it. KLUDGE: here is the problem:
         * there must ALWAYS be a 'timeout' associated with a TCB, otherwise,
         * we'll lose track of it and leak memory. In theory, this should be
         * automatically handled elsewhere, but I have bugs, and it's not,
         * so I put some code here as a catch-all: if the TCB hasn't been
         * deleted, but hasn't been inserted back into the timeout system,
         * then insert it here. */
        if (x != TCB__destroyed && timeout_is_unlinked(tcb->timeout)) {
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
 * an HTTP field.
 ***************************************************************************/
void
tcpcon_set_http_header(struct TCP_ConnectionTable *tcpcon,
                        const char *name,
                        size_t value_length,
                        const void *value,
                        enum http_field_t what)
{
    UNUSEDPARM(tcpcon);
    banner_http.hello_length = http_change_field(
                            (unsigned char**)&banner_http.hello,
                            banner_http.hello_length,
                            name,
                            (const unsigned char *)value,
                            value_length,
                            what);
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

    if (name_equals(name, "http-payload")) {
        char lenstr[64];
        snprintf(lenstr, sizeof(lenstr), "%u", (unsigned)value_length);

        banner_http.hello_length = http_change_requestline(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                (const unsigned char *)value,
                                value_length,
                                3); /* payload*/

        banner_http.hello_length = http_change_field(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                "Content-Length:",
                                (const unsigned char *)lenstr,
                                strlen(lenstr),
                                http_field_replace);
        return;
    }

    /*
     * You can reset your user-agent here. Whenever I do a scan, I always
     * reset my user-agent. That's now you know it's not me scanning
     * you on the open Internet -- I would never use the default user-agent
     * string built into masscan
     */
    if (name_equals(name, "http-user-agent")) {
        banner_http.hello_length = http_change_field(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                "User-Agent:",
                                (const unsigned char *)value,
                                value_length,
                                http_field_replace);
        return;
    }
    if (name_equals(name, "http-host")) {
        banner_http.hello_length = http_change_field(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                "Host:",
                                (const unsigned char *)value,
                                value_length,
                                http_field_replace);
        return;
    }

    /**
     * Changes the URL
     */
    if (name_equals(name, "http-method")) {
        banner_http.hello_length = http_change_requestline(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                (const unsigned char *)value,
                                value_length,
                                0); /* method*/
        return;
    }
    if (name_equals(name, "http-url")) {
        banner_http.hello_length = http_change_requestline(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                (const unsigned char *)value,
                                value_length,
                                1); /* url */
        return;
    }
    if (name_equals(name, "http-version")) {
        banner_http.hello_length = http_change_requestline(
                                (unsigned char**)&banner_http.hello,
                                banner_http.hello_length,
                                (const unsigned char *)value,
                                value_length,
                                2); /* version */
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
            ERRMSG("tcpcon: parameter: expected array []: %s\n", name);
            return;
        }
        port = (unsigned)strtoul(p+1, 0, 0);

        x = CALLOC(1, sizeof(*x));
        if (banner1->payloads.tcp[port])
            memcpy(x, banner1->payloads.tcp[port], sizeof (*x));
        x->name = "(allocated)";

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
    unsigned is_capture_servername,
    unsigned is_capture_html,
    unsigned is_capture_heartbleed,
	unsigned is_capture_ticketbleed)
{
    tcpcon->banner1->is_capture_cert = is_capture_cert;
    tcpcon->banner1->is_capture_servername = is_capture_servername;
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
                        struct stack_t *stack,
                        struct TemplatePacket *pkt_template,
                        OUTPUT_REPORT_BANNER report_banner,
                        struct Output *out,
                        unsigned connection_timeout,
                        uint64_t entropy
                        )
{
    struct TCP_ConnectionTable *tcpcon;
    
    
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

    tcpcon->stack = stack;
    

    tcpcon->banner1 = banner1_create();

    tcpcon->report_banner = report_banner;
    tcpcon->out = out;
    return tcpcon;
}

static int TCB_EQUALS(const struct TCP_Control_Block *lhs, const struct TCP_Control_Block *rhs)
{
    if (lhs->port_me != rhs->port_me || lhs->port_them != rhs->port_them)
        return 0;
    if (lhs->ip_me.version != rhs->ip_me.version)
        return 0;
    if (lhs->ip_me.version == 6) {
        if (memcmp(&lhs->ip_me.ipv6, &rhs->ip_me.ipv6, sizeof(rhs->ip_me.ipv6)) != 0)
            return 0;
        if (memcmp(&lhs->ip_them.ipv6, &rhs->ip_them.ipv6, sizeof(rhs->ip_them.ipv6)) != 0)
            return 0;
    } else {
        if (lhs->ip_me.ipv4 != rhs->ip_me.ipv4)
            return 0;
        if (lhs->ip_them.ipv4 != rhs->ip_them.ipv4)
            return 0;
    }

    return 1;
}

/***************************************************************************
 ***************************************************************************/
static void
_tcb_change_state_to(struct TCP_Control_Block *tcb, unsigned new_state) {

    LOGtcb(tcb, 2, "to {%s}\n", state_to_string(new_state));
    tcb->tcpstate = new_state;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
tcb_hash(   ipaddress ip_me, unsigned port_me, 
            ipaddress ip_them, unsigned port_them,
            uint64_t entropy)
{
    unsigned index;

    /* TCB hash table uses symmetric hash, so incoming/outgoing packets
     * get the same hash. */
    if (ip_me.version == 6) {
        ipv6address ipv6 = ip_me.ipv6;
        ipv6.hi ^= ip_them.ipv6.hi;
        ipv6.lo ^= ip_them.ipv6.lo;
        index = (unsigned)syn_cookie_ipv6(
                                    ipv6, 
                                    port_me ^ port_them,
                                    ipv6, 
                                    port_me ^ port_them,
                                    entropy);

    } else {
        index = (unsigned)syn_cookie_ipv4(   ip_me.ipv4   ^ ip_them.ipv4,
                                        port_me ^ port_them,
                                        ip_me.ipv4   ^ ip_them.ipv4,
                                        port_me ^ port_them,
                                        entropy
                                        );
    }
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
 * Flush all the banners associated with this TCP connection. This always
 * called when TCB is destroyed. This may also be called earlier, such
 * as when a FIN is received.
 ***************************************************************************/
void
banner_flush(struct stack_handle_t *socket)
{
    struct TCP_ConnectionTable *tcpcon = socket->tcpcon;
    struct TCP_Control_Block *tcb = socket->tcb;
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
        LOG(1, "tcb: double free\n");
        return;
    }

    /*
     * Print out any banners associated with this TCP session. Most of the
     * time, there'll only be one. After printing them out, delete the
     * banners.
     */
    {
        struct stack_handle_t socket = {tcpcon, tcb, 0, 0};
        banner_flush(&socket);
    }

    LOGtcb(tcb, 2, "--DESTROYED--\n");

    /*
     * If there are any queued segments to transmit, then free them
     */
    while (tcb->segments) {
        struct TCP_Segment *seg;
        seg = tcb->segments;
        tcb->segments = seg->next;
        if (seg->flags == TCP__copy || seg->flags == TCP__adopt) {
            free(seg->buf);
            seg->buf = 0;
        }
        free(seg);
    }
    
    if (tcb->scripting_thread)
        ; //scripting_thread_close(tcb->scripting_thread);
    tcb->scripting_thread = 0;
    
    /* KLUDGE: this needs to be made elegant */
    switch (tcb->banner1_state.app_proto) {
        case PROTO_SMB:
            banner_smb1.cleanup(&tcb->banner1_state);
            break;
    }

    /*
     * Unlink this from the timeout system.
     */
    timeout_unlink(tcb->timeout);

    tcb->ip_them.ipv4 = (unsigned)~0;
    tcb->port_them = (unsigned short)~0;
    tcb->ip_me.ipv4 = (unsigned)~0;
    tcb->port_me = (unsigned short)~0;

    tcb->is_active = 0;




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
    ipaddress ip_me, ipaddress ip_them,
    unsigned port_me, unsigned port_them,
    unsigned seqno_me, unsigned seqno_them,
    unsigned ttl,
    const struct ProtocolParserStream *stream,
    unsigned secs, unsigned usecs)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;


    assert(ip_me.version != 0 && ip_them.version != 0);

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    /* Lookup the location in the hash table where this tcb should be
     * placed */
    index = tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !TCB_EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }
    if (tcb != NULL) {
        /* If it already exists, just return the existing one */
        return tcb;
    }

    /* Allocate a new TCB, using a pool */
    if (tcpcon->freed_list) {
        tcb = tcpcon->freed_list;
        tcpcon->freed_list = tcb->next;
    } else {
        tcb = MALLOC(sizeof(*tcb));
    }
    memset(tcb, 0, sizeof(*tcb));

    /* Add it to this spot in the hash table */
    tcb->next = tcpcon->entries[index & tcpcon->mask];
    tcpcon->entries[index & tcpcon->mask] = tcb;

    /*
     * Initialize the entry
     */
    tcb->ip_me = ip_me;
    tcb->ip_them = ip_them;
    tcb->port_me = (unsigned short)port_me;
    tcb->port_them = (unsigned short)port_them;
    tcb->seqno_them_first = seqno_them;
    tcb->seqno_me_first = seqno_me;
    tcb->seqno_me = seqno_me;
    tcb->seqno_them = seqno_them;
    tcb->ackno_me = seqno_them;
    tcb->ackno_them = seqno_me;
    tcb->when_created = global_now;
    tcb->ttl = (unsigned char)ttl;
    tcb->mss = 1400;

    /* Insert the TCB into the timeout. A TCB must always have a timeout
     * active. */
    timeout_init(tcb->timeout);
    timeouts_add(tcpcon->timeouts,
                 tcb->timeout,
                 offsetof(struct TCP_Control_Block, timeout),
                 TICKS_FROM_TV(secs+1,usecs)
                 );

    /* Get the protocol handler assigned to this port */
    tcb->banner1_state.port = (unsigned short)port_them;
    if (stream == NULL) {
        struct Banner1 *banner1 = tcpcon->banner1;
        stream = banner1->payloads.tcp[port_them];
    }
    tcb->stream = stream;
    banout_init(&tcb->banout);

    /* The TCB is now allocated/in-use */
    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);
    tcb->is_active = 1;

    tcpcon->active_count++;

    tcpcon_lookup_tcb(tcpcon, ip_me, ip_them, port_me, port_them);

    return tcb;
}



/***************************************************************************
 ***************************************************************************/
struct TCP_Control_Block *
tcpcon_lookup_tcb(
    struct TCP_ConnectionTable *tcpcon,
    ipaddress ip_me, ipaddress ip_them,
    unsigned port_me, unsigned port_them)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;
    ipaddress_formatted_t fmt1;
    ipaddress_formatted_t fmt2;

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = tcb_hash(ip_me, port_me, ip_them, port_them, tcpcon->entropy);

    fmt1 = ipaddress_fmt(ip_me);
    fmt2 = ipaddress_fmt(ip_them);
    LOG(1, "tcb_hash(0x%08x) = %s %u %s %u\n", 
        (unsigned)index,
        fmt1.string, port_me,
        fmt2.string, port_them);

    /* Hash to an entry in the table, then follow a linked list from
     * that point forward. */
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !TCB_EQUALS(tcb, &tmp)) {
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
    const unsigned char *payload, size_t payload_length)
{
    struct PacketBuffer *response = 0;
    unsigned is_syn = (tcp_flags == 0x02);
    
    assert(tcb->ip_me.version != 0 && tcb->ip_them.version != 0);

    /* If sending an ACK, print a message */
    if ((tcp_flags & 0x10) == 0x10) {
        LOGtcb(tcb, 0, "xmit ACK ackingthem=%u\n", tcb->seqno_them-tcb->seqno_them_first);
    }

    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    response = stack_get_packetbuffer(tcpcon->stack);
    if (response == NULL) {
        static int is_warning_printed = 0;
        if (!is_warning_printed) {
            LOG(0, "packet buffers empty (should be impossible)\n");
            is_warning_printed = 1;
        }
        fflush(stdout);
        
        /* FIXME: I'm no sure the best way to handle this.
         * This would result from a bug in the code,
         * but I'm not sure what should be done in response */
        pixie_usleep(100); /* no packet available */
    }
    if (response == NULL)
        return;

    /* Format the packet as requested. Note that there are really only
     * four types of packets:
     * 1. a SYN-ACK packet with no payload
     * 2. an ACK packet with no payload
     * 3. a RST packet with no payload
     * 4. a PSH-ACK packet WITH PAYLOAD
     */
    response->length = tcp_create_packet(
        tcpcon->pkt_template,
        tcb->ip_them, tcb->port_them,
        tcb->ip_me, tcb->port_me,
        tcb->seqno_me - is_syn, tcb->seqno_them,
        tcp_flags,
        payload, payload_length,
        response->px, sizeof(response->px)
        );

    /*
     * KLUDGE:
     */
    if (tcb->is_small_window)
        tcp_set_window(response->px, response->length, 600);
    
    /* Put this buffer on the transmit queue. Remember: transmits happen
     * from a transmit-thread only, and this function is being called
     * from a receive-thread. Therefore, instead of transmiting ourselves,
     * we hae to queue it up for later transmission. */
    stack_transmit_packetbuffer(tcpcon->stack, response);
}

/***************************************************************************
 ***************************************************************************/
void
tcp_send_RST(
    struct TemplatePacket *templ,
    struct stack_t *stack,
    ipaddress ip_them, ipaddress ip_me,
    unsigned port_them, unsigned port_me,
    unsigned seqno_them, unsigned seqno_me
)
{
    struct PacketBuffer *response = 0;
    

    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    response = stack_get_packetbuffer(stack);
    if (response == NULL) {
        static int is_warning_printed = 0;
        if (!is_warning_printed) {
            LOG(0, "packet buffers empty (should be impossible)\n");
            is_warning_printed = 1;
        }
        fflush(stdout);
        pixie_usleep(100); /* no packet available */
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
     * from a receive-thread. Therefore, instead of transmitting ourselves,
     * we have to queue it up for later transmission. */
    stack_transmit_packetbuffer(stack, response);
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
        case TCP_WHAT_CLOSE: return "CLOSE";
        default:
            snprintf(buf, sizeof(buf), "%d", state);
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



void
tcpcon_send_RST(
                struct TCP_ConnectionTable *tcpcon,
                ipaddress ip_me, ipaddress ip_them,
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
    
    LOGSEND(&tcb, "send RST");
    tcpcon_send_packet(tcpcon, &tcb, 0x04 /*RST*/, 0, 0);
}


/***************************************************************************
 * Called upon timeouts when an acknowledgement hasn't been received in
 * time. Will resend the segments.
 ***************************************************************************/
static void
_tcb_seg_resend(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *tcb) {
    struct TCP_Segment *seg = tcb->segments;

    if (seg) {
        if (tcb->seqno_me != seg->seqno) {
            ERRMSG("SEQNO FAILURE diff=%d %s\n", tcb->seqno_me - seg->seqno, seg->is_fin?"FIN":"");
            return;
        }

        if (seg->is_fin && seg->length == 0) {
            tcpcon_send_packet(tcpcon, tcb,
                                0x11, /*FIN-ACK*/
                                0, /*FIN has no data */
                                0 /*logically is 1 byte, but not payload byte */);
        } else {
            tcpcon_send_packet(tcpcon, tcb,
                                0x18 | (seg->is_fin?0x01:0x00),
                                seg->buf,
                                seg->length);
        }
    }
                        
}

/***************************************************************************
 ***************************************************************************/
static unsigned
application_notify(struct TCP_ConnectionTable *tcpcon,
                   struct TCP_Control_Block *tcb,
                   enum App_Event event, const void *payload, size_t payload_length,
                   unsigned secs, unsigned usecs)
{
    struct Banner1 *banner1 = tcpcon->banner1;
    const struct ProtocolParserStream *stream = tcb->stream;
    struct stack_handle_t socket = {
        tcpcon, tcb, secs, usecs};

    return application_event(&socket,
                             tcb->app_state, event,
                             stream, banner1,
                             payload, payload_length
                             );
}


/***************************************************************************
 ***************************************************************************/
static void 
_tcb_seg_send(void *in_tcpcon, void *in_tcb, 
        const void *buf, size_t length, 
        enum TCP__flags flags) {

    struct TCP_ConnectionTable *tcpcon = (struct TCP_ConnectionTable *)in_tcpcon;
    struct TCP_Control_Block *tcb = (struct TCP_Control_Block *)in_tcb;
    struct TCP_Segment *seg;
    struct TCP_Segment **next;
    unsigned seqno = tcb->seqno_me;
    size_t length_more = 0;
    bool is_fin = (flags == TCP__close_fin);

    if (length > tcb->mss) {
        length_more = length - tcb->mss;
        length = tcb->mss;
    }


    if (length == 0 && !is_fin)
        return;

    /* Go to the end of the segment list */
    for (next = &tcb->segments; *next; next = &(*next)->next) {
        seqno = (unsigned)((*next)->seqno + (*next)->length);
        if ((*next)->is_fin) {
            /* can't send past a FIN */
            LOGip(0, tcb->ip_them, tcb->port_them, "can't send past a FIN\n");
            if (flags == TCP__adopt) {
                free((void*)buf); /* discard const */
                buf = NULL;
            }
            return;
        }
    }

    /* Append this segment to the list */
    seg = calloc(1, sizeof(*seg));
    *next = seg;

    /* Fill in this segment's members */
    seg->seqno = seqno;
    seg->length = length;
    seg->flags = flags;
    switch (flags) {
        case TCP__static:
        case TCP__adopt:
            seg->buf = (void *)buf;
            break;
        case TCP__copy:
            seg->buf = malloc(length);
            memcpy(seg->buf, buf, length);
            break;
        case TCP__close_fin:
            seg->buf = 0;
            break;
    }
    if (length_more == 0)
        seg->is_fin = is_fin;

    if (!seg->is_fin && seg->length && tcb->tcpstate != STATE_ESTABLISHED_SEND)
        application_notify(tcpcon, tcb, APP_SENDING, seg->buf, seg->length, 0, 0);

    LOGtcb(tcb, 0, "send = %u-bytes %s @ %u\n", length, is_fin?"FIN":"",
           seg->seqno-tcb->seqno_me_first);
    


    /* If this is the head of the segment list, then transmit right away */
    if (tcb->segments == seg) {
        LOGtcb(tcb, 0, "xmit = %u-bytes %s @ %u\n", length, is_fin?"FIN":"",
               seg->seqno-tcb->seqno_me_first);
        tcpcon_send_packet(tcpcon, tcb, 0x18 | (is_fin?1:0), seg->buf, seg->length);
        if (!is_fin)
            _tcb_change_state_to(tcb, STATE_ESTABLISHED_SEND);
    }

    /* If the input buffer was too large to fit a single segment, then
     * split it up into multiple segments */
    if (length_more) {
        if (flags == TCP__adopt)
            flags = TCP__copy;

        _tcb_seg_send(tcpcon, tcb,
                      (unsigned char*)buf + length, length_more,
                      flags);
    }

    //tcb->established = App_SendNext;

}

/***************************************************************************
 ***************************************************************************/
static int
_tcp_seg_acknowledge(
    struct TCP_Control_Block *tcb,
    uint32_t ackno)
{

    /*LOG(4,  "%s - %u-sending, %u-reciving\n",
            fmt.string,
            tcb->seqno_me - ackno,
            ackno - tcb->ackno_them
            );*/
    /* Normal: just discard repeats */
    if (ackno == tcb->seqno_me) {
        return 0;
    }

    /* Make sure this isn't a duplicate ACK from past
     * WRAPPING of 32-bit arithmetic happens here */
    if (ackno - tcb->seqno_me > 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(4,  "%s - "
                "tcb: ackno from past: "
                "old ackno = 0x%08x, this ackno = 0x%08x\n",
                fmt.string,
                tcb->ackno_me, ackno);
        return 0;
    }

    /* Make sure this isn't invalid ACK from the future
     * WRAPPING of 32-bit arithmetic happens here */
    if (tcb->seqno_me - ackno < 100000) {
        ipaddress_formatted_t fmt = ipaddress_fmt(tcb->ip_them);
        LOG(0, "%s - "
                "tcb: ackno from future: "
                "my seqno = 0x%08x, their ackno = 0x%08x\n",
                fmt.string,
                tcb->seqno_me, ackno);
        return 0;
    }

    /* Handle FIN specially */
handle_fin:
    if (tcb->segments && tcb->segments->is_fin) {
        struct TCP_Segment *seg = tcb->segments;

        if (seg->seqno+1 == ackno) {
            LOGtcb(tcb, 1, "ACKed FIN\n");
            tcb->seqno_me += 1;
            tcb->ackno_them += 1;
            return 1;
        } else if (seg->seqno == ackno) {
            return 0;
        } else {
            LOGtcb(tcb, 1, "@@@@@BAD ACK of FIN@@@@\n", seg->length);
            return 0;
        }
    }

    /* Retire outstanding segments */
    {
        unsigned length = ackno - tcb->seqno_me;
        while (tcb->segments && length >= tcb->segments->length) {
            struct TCP_Segment *seg = tcb->segments;

            if (seg->is_fin)
                goto handle_fin;

            tcb->segments = seg->next;

            length -= seg->length;
            tcb->seqno_me += seg->length;
            tcb->ackno_them += seg->length;
            
            LOGtcb(tcb, 1, "ACKed %u-bytes\n", seg->length);

            /* free the old segment */
            switch (seg->flags) {
                case TCP__static:
                    break;
                case TCP__adopt:
                case TCP__copy:
                    if (seg->buf) {
                        free(seg->buf);
                        seg->buf = NULL;
                    }
                    break;
                default:
                    ;
            }
            free(seg);
            if (ackno == tcb->ackno_them)
                return 1; /* good ACK */
        }

        if (tcb->segments && length < tcb->segments->length) {
            struct TCP_Segment *seg = tcb->segments;
            
            tcb->seqno_me += length + seg->is_fin;
            tcb->ackno_them += length + seg->is_fin;
            LOGtcb(tcb, 1, "ACKed %u-bytes %s\n", length, seg->is_fin?"FIN":"");

            /* This segment needs to be reduced */
            if (seg->flags == TCP__adopt || seg->flags == TCP__copy) {
                size_t new_length = seg->length - length;
                unsigned char *buf = malloc(new_length);
                memcpy(buf, seg->buf + length, new_length);
                free(seg->buf);
                seg->buf = buf;
                seg->length -= length;
                seg->flags = TCP__copy;
            } else {
                seg->buf += length;
            }
            
        }
    }
    
    /* Mark that this was a good ack */
    return 1;
}


void
banner_set_sslhello(struct stack_handle_t *socket, bool is_true) {
    struct TCP_Control_Block *tcb = socket->tcb;
    tcb->banner1_state.is_sent_sslhello = is_true;
}

void
banner_set_small_window(struct stack_handle_t *socket, bool is_true) {
    struct TCP_Control_Block *tcb = socket->tcb;
    tcb->is_small_window = is_true;
}

bool
banner_is_heartbleed(const struct stack_handle_t *socket) {
    struct TCP_ConnectionTable *tcpcon = socket->tcpcon;
    return tcpcon->banner1->is_heartbleed != 0;
}

/***************************************************************************
 * Parse the information we get from the server we are scanning. Typical
 * examples are SSH banners, FTP banners, or the response from HTTP
 * requests
 ***************************************************************************/
size_t
banner_parse(
             struct stack_handle_t *socket,
    const unsigned char *payload,
    size_t payload_length
    )
{
    struct TCP_ConnectionTable *tcpcon = socket->tcpcon;
    struct TCP_Control_Block *tcb = socket->tcb;
    assert(tcb->banout.max_length);
    
    banner1_parse(
                                    tcpcon->banner1,
                                    &tcb->banner1_state,
                                    payload,
                                    payload_length,
                                    &tcb->banout,
                                    socket);
    return payload_length;
}




/***************************************************************************
 ***************************************************************************/
static void
_next_IP_port(struct TCP_ConnectionTable *tcpcon,
              ipaddress *ip_me,
              unsigned *port_me) {
    const struct stack_src_t *src = tcpcon->stack->src;
    unsigned index;

    /* Get another source port, because we can't use the existing
     * one for new connection */
    index = *port_me - src->port.first + 1;
    *port_me = src->port.first + index;
    if (*port_me >= src->port.last) {
        *port_me = src->port.first;

        /* We've wrapped the ports, so therefore choose another source
         * IP address as well. */
        switch (ip_me->version) {
            case 4:
                index = ip_me->ipv4 - src->ipv4.first + 1;
                ip_me->ipv4 = src->ipv4.first + index;
                if (ip_me->ipv4 >= src->ipv4.last)
                    ip_me->ipv4 = src->ipv4.first;
                break;
            case 6: {
                /* TODO: this code is untested, yolo */
                ipv6address_t diff;

                diff = ipv6address_subtract(ip_me->ipv6, src->ipv6.first);
                diff = ipv6address_add_uint64(diff, 1);
                ip_me->ipv6 = ipv6address_add(src->ipv6.first, diff);
                if (ipv6address_is_lessthan(src->ipv6.last, ip_me->ipv6))
                    ip_me->ipv6 = src->ipv6.first;
                break;
            }
            default:
                break;
        }
    }

}

/***************************************************************************
 ***************************************************************************/
static void
_do_reconnect(struct TCP_ConnectionTable *tcpcon,
              const struct TCP_Control_Block *old_tcb,
              const struct ProtocolParserStream *stream,
              unsigned secs, unsigned usecs,
              unsigned established) {
    struct TCP_Control_Block *new_tcb;

    ipaddress ip_them = old_tcb->ip_them;
    unsigned port_them = old_tcb->port_them;
    ipaddress ip_me = old_tcb->ip_me;
    unsigned port_me = old_tcb->port_me;
    unsigned seqno;


    /*
     * First, get another port number and potentially ip address
     */
    {
        ipaddress prev_ip = ip_me;
        unsigned prev_port = port_me;
        _next_IP_port(tcpcon, &ip_me, &port_me);

        if (ipaddress_is_equal(ip_me, prev_ip) && port_me == prev_port)
            ERRMSG("There must be multiple source ports/addresses for reconnection\n");

    }

    /*
     * Calculate the SYN cookie, the same algorithm as for when spewing
     * SYN packets. However, since we'll probably be using a different
     * port or IP address, it'll be different in practice.
     */
    seqno = (unsigned)syn_cookie(ip_them, port_them,
                                 ip_me, port_me,
                                 tcpcon->entropy);

    /*
     * Now create a new TCB for this new connection
     */
    new_tcb = tcpcon_create_tcb(
                    tcpcon,
                    ip_me, ip_them,
                    port_me, port_them,
                    seqno+1, 0,
                    255,
                    stream,
                    secs, usecs);
    new_tcb->app_state = established;
}

static void
_tcb_seg_close(void *in_tcpcon,
              void *in_tcb,
              unsigned secs, unsigned usecs) {
    struct TCP_ConnectionTable *tcpcon = (struct TCP_ConnectionTable *)in_tcpcon;
    struct TCP_Control_Block *tcb = (struct TCP_Control_Block *)in_tcb;

    stack_incoming_tcp(tcpcon, tcb,
                  TCP_WHAT_CLOSE,
                  0, 0, 
                  secs, usecs,
                  tcb->seqno_them, tcb->ackno_them);
}

/***************************************************************************
 ***************************************************************************/
int
tcpapi_set_timeout(struct stack_handle_t *socket,
                        unsigned secs,
                        unsigned usecs
                        ) {
    struct TCP_ConnectionTable *tcpcon = socket->tcpcon;
    struct TCP_Control_Block *tcb = socket->tcb;

    if (socket == NULL)
        return SOCKERR_EBADF;

    timeouts_add(tcpcon->timeouts,
             tcb->timeout,
             offsetof(struct TCP_Control_Block, timeout),
             TICKS_FROM_TV(socket->secs+secs, socket->usecs + usecs)
             );
    return 0;
}


/***************************************************************************
 ***************************************************************************/
int
tcpapi_recv(struct stack_handle_t *socket) {
    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;
    tcb = socket->tcb;

    switch (tcb->tcpstate) {
        default:
        case STATE_ESTABLISHED_SEND:
            _tcb_change_state_to(socket->tcb, STATE_ESTABLISHED_RECV);
            break;
        case STATE_FIN_WAIT1_RECV:
            _tcb_change_state_to(socket->tcb, STATE_FIN_WAIT1_RECV);
            break;
        case STATE_FIN_WAIT1_SEND:
            _tcb_change_state_to(socket->tcb, STATE_FIN_WAIT1_RECV);
            break;
    }
    return 0;
}

int
tcpapi_send(struct stack_handle_t *socket,
            const void *buf, size_t length,
            enum TCP__flags flags) {
    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;
    switch (tcb->tcpstate) {
        case STATE_ESTABLISHED_RECV:
            _tcb_change_state_to(tcb, STATE_ESTABLISHED_SEND);
            /*follow through*/
        case STATE_ESTABLISHED_SEND:
            _tcb_seg_send(socket->tcpcon, tcb, buf, length, flags);
            return 0;
        default:
            LOG(1, "TCP app attempted SEND in wrong state\n");
            return 1;
    }
}

int
tcpapi_reconnect(struct stack_handle_t *old_socket,
               struct ProtocolParserStream *new_stream,
               unsigned new_app_state) {
    if (old_socket == 0 || old_socket->tcb == 0)
        return SOCKERR_EBADF;

    _do_reconnect(old_socket->tcpcon,
                  old_socket->tcb,
                  new_stream,
                  old_socket->secs, old_socket->usecs,
                  new_app_state);
    return 0;
}

unsigned
tcpapi_change_app_state(struct stack_handle_t *socket, unsigned new_app_state) {
    struct TCP_Control_Block *tcb;

    if (socket == 0 || socket->tcb == 0)
        return SOCKERR_EBADF;

    tcb = socket->tcb;

    //printf("%u --> %u\n", tcb->app_state, new_app_state);

    tcb->app_state = new_app_state;
    return new_app_state;
}


int
tcpapi_close(struct stack_handle_t *socket) {
    if (socket == NULL || socket->tcb == NULL)
        return SOCKERR_EBADF;
    _tcb_seg_close(socket->tcpcon,
                   socket->tcb,
                   socket->secs,
                   socket->usecs);
    return 0;
}



static bool
_tcb_they_have_acked_my_fin(struct TCP_Control_Block *tcb) {
    if (tcb->segments && tcb->segments->is_fin && tcb->segments->length == 0) {
        if (tcb->ackno_them >= tcb->segments->seqno + 1)
            return true;
        return false;
    } else
        return false;
}


static void
_tcb_send_ack(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *tcb) {
        tcpcon_send_packet(tcpcon, tcb, 0x10, 0, 0);
}



static int
_tcb_seg_recv(struct TCP_ConnectionTable *tcpcon,
                  struct TCP_Control_Block *tcb,
                  const unsigned char *payload, size_t payload_length,
                  unsigned seqno_them,
                  unsigned secs, unsigned usecs,
                  bool is_fin)
{
    /* Special case when packet contains only a FIN */
    if (payload_length == 0 && is_fin && (tcb->seqno_them - seqno_them) == 0) {
        tcb->is_their_fin = 1;
        tcb->seqno_them += 1;
        tcb->ackno_me += 1;
        tcpcon_send_packet(tcpcon, tcb, 0x10/*ACK*/, 0, 0);
        return 1;
    }


    if ((tcb->seqno_them - seqno_them) > payload_length)  {
        LOGSEND(tcb, "peer(ACK) [acknowledge payload 1]");
        tcpcon_send_packet(tcpcon, tcb, 0x10 /*ACK*/, 0, 0);
        return 1;
    }

    while (seqno_them != tcb->seqno_them && payload_length) {
        seqno_them++;
        payload_length--;
        payload++;
    }

    if (tcb->is_their_fin) {
        /* payload cannot be received after a FIN */
        return 1;
    }

    if (payload_length == 0) {
        tcpcon_send_packet(tcpcon, tcb, 0x10/*ACK*/, 0, 0);
        return 1;
    }

    LOGtcb(tcb, 2, "received %u bytes\n", payload_length);

    tcb->seqno_them += payload_length + is_fin;
    tcb->ackno_me += payload_length + is_fin;

    application_notify(tcpcon, tcb, APP_RECV_PAYLOAD,
                       payload, payload_length, secs, usecs);



    if (is_fin)
        tcb->is_their_fin = true;

    /* Send ack for the data */
    _tcb_send_ack(tcpcon, tcb);

    return 0;
}

/*****************************************************************************
 * Handles incoming events, like timeouts and packets, that cause a change
 * in the TCP control block "state".
 *
 * This is the part of the code that implements the famous TCP state-machine
 * you see drawn everywhere, where they have states like "TIME_WAIT". Only
 * we don't really have those states.
 *****************************************************************************/
enum TCB_result
stack_incoming_tcp(struct TCP_ConnectionTable *tcpcon,
              struct TCP_Control_Block *tcb,
              enum TCP_What what, const unsigned char *payload, size_t payload_length,
              unsigned secs, unsigned usecs,
              unsigned seqno_them, unsigned ackno_them)
{

    /* FILTER
     * Reject out-of-order payloads 
     */
    if (payload_length) {
        /* Wrapping technique: If there is a gap between this
         * packet and the last one, then it means there is a missing
         * packet somewhere. In that case, this calculation will
         * wrap and `payload_offset` will be some huge number in the future.
         * If there is no gap, then this will be zero.
         * If there's overlap between this packet and the previous, `payload_offset`
         * will be a small number less than the `length` of this packet.
         * If it's a retransmission, the numbers will be the same
         */
        int payload_offset = seqno_them - tcb->seqno_them;
        if (payload_offset < 0) {
            /* This is a retrnasmission that we've already acknowledged */
            if (payload_offset <= 0 - (int)payload_length) {
                /* Both begin and end are old, so simply discard it */
                return TCB__okay;
            } else {
                /* Otherwise shorten the payload */
                payload_length += payload_offset;
                payload -= payload_offset;
                seqno_them -= payload_offset;
                assert(payload_length < 2000);
            }
        } else if (payload_offset > 0) {
            /* This is an out-of-order fragment in the future. an important design
             * of this light-weight stack is that we don't support this, and
             * force the other side to retransmit such packets */
            return TCB__okay;
        }
    }
    
    /* FILTER:
     * Reject out-of-order FINs.
     * Handle duplicate FINs here
     */
    if (what == TCP_WHAT_FIN) {
        if (seqno_them == tcb->seqno_them - 1) {
            /* Duplicate FIN, respond with ACK */
            LOGtcb(tcb, 1, "duplicate FIN\n");
            _tcb_send_ack(tcpcon, tcb);
            return TCB__okay;
        } else if (seqno_them != tcb->seqno_them) {
            /* out of order FIN, so drop it */
            LOGtcb(tcb, 1, "out-of-order FIN\n");
            return TCB__okay;
        }
    }

    LOGtcb(tcb, 1, "##%s##\n", what_to_string(what));

    /* Make sure no connection lasts longer than ~30 seconds */
    if (what == TCP_WHAT_TIMEOUT) {
        if (tcb->when_created + tcpcon->timeout_connection < secs) {
            LOGip(8, tcb->ip_them, tcb->port_them,
                "%s                \n",
                "CONNECTION TIMEOUT---");
            LOGSEND(tcb, "peer(RST)");
            tcpcon_send_packet(tcpcon, tcb, 0x04 /*RST*/, 0, 0);
            tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
            return TCB__destroyed;
        }
    }
    
    if (what == TCP_WHAT_RST) {
        LOGSEND(tcb, "tcb(destroy)");
        tcpcon_destroy_tcb(tcpcon, tcb, Reason_RST);
        return TCB__destroyed;
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
                case TCP_WHAT_TIMEOUT:
                    /* We've sent a SYN, but didn't get SYN-ACK, so
                        * send another */
                    tcb->syns_sent++;

                    /* Send a SYN */
                    tcpcon_send_packet(tcpcon, tcb, 0x02 /*SYN*/, 0, 0);
                    break;
                case TCP_WHAT_SYNACK:
                    tcb->seqno_them = seqno_them;
                    tcb->seqno_them_first = seqno_them - 1;
                    tcb->seqno_me = ackno_them;
                    tcb->seqno_me_first = ackno_them - 1;

                    LOGtcb(tcb, 1, "%s connection established\n",
                           what_to_string(what));

                    /* Send "ACK" to acknowlege their "SYN-ACK" */
                    _tcb_send_ack(tcpcon, tcb);
                    _tcb_change_state_to(tcb, STATE_ESTABLISHED_RECV);
                    application_notify(tcpcon, tcb, APP_CONNECTED, 0, 0, secs, usecs);
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));

                    break;
            }
            break;


        case STATE_ESTABLISHED_SEND:
            switch (what) {
                case TCP_WHAT_CLOSE:
                    _tcb_seg_send(tcpcon, tcb, 0, 0, TCP__close_fin);
                    _tcb_change_state_to(tcb, STATE_FIN_WAIT1_SEND);
                    break;
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process this */
                        _tcb_seg_recv(tcpcon, tcb, 0, 0, seqno_them, secs, usecs, true);
                        _tcb_change_state_to(tcb, STATE_FIN_WAIT1_SEND);
                        _tcb_send_ack(tcpcon, tcb);
                    } else {
                        /* I haven't received all their data, so ignore it until I do */
                        _tcb_send_ack(tcpcon, tcb);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);

                    if (tcb->segments == NULL || tcb->segments->length == 0) {
                        /* We've finished sending everything, so switch our application state
                         * back to sending */
                        _tcb_change_state_to(tcb, STATE_ESTABLISHED_RECV);

                        /* All the payload has been sent. Notify the application of this, so that they
                         * can send more if the want, or switch to listening. */
                        application_notify(tcpcon, tcb, APP_SEND_SENT, 0, 0, secs, usecs);

                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    /* They haven't acknowledged everything yet, so resend the last segment */
                    _tcb_seg_resend(tcpcon, tcb);
                    break;
                case TCP_WHAT_DATA:
                    /* We don't receive data while in the sending state. We force them
                     * to keep re-sending it until we are prepared to receive it. This
                     * saves us from having to buffer it in this stack.
                     */
                    break;
                case TCP_WHAT_SYNACK:
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;

        case STATE_ESTABLISHED_RECV:
            switch (what) {
                case TCP_WHAT_CLOSE:
                    _tcb_seg_send(tcpcon, tcb, 0, 0, TCP__close_fin);
                    _tcb_change_state_to(tcb, STATE_FIN_WAIT1_RECV);
                    break;
                case TCP_WHAT_FIN:
                    if (seqno_them == tcb->seqno_them) {
                        /* I have ACKed all their data, so therefore process this */
                        _tcb_seg_recv(tcpcon, tcb, 0, 0, seqno_them, secs, usecs, true);
                        _tcb_change_state_to(tcb, STATE_CLOSE_WAIT);
                        //_tcb_send_ack(tcpcon, tcb);
                        application_notify(tcpcon, tcb, APP_CLOSE,
                                0, payload_length, secs, usecs);

                    } else {
                        /* I haven't received all their data, so ignore it until I do */
                        _tcb_send_ack(tcpcon, tcb);
                    }
                    break;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);
                    break;
                case TCP_WHAT_TIMEOUT:
                    application_notify(tcpcon, tcb, APP_RECV_TIMEOUT, 0, 0, secs, usecs);
                    break;
                case TCP_WHAT_DATA:
                    _tcb_seg_recv(tcpcon, tcb, payload, payload_length, seqno_them, secs, usecs, false);
                    break;
                case TCP_WHAT_SYNACK:
                    /* This happens when a delayed SYN-ACK arrives from the target.
                     * I see these fairly often from host 178.159.37.125.
                     * We are going to make them silent for now, but eventually, keep
                     * statistics about this sort of thing. */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;

        /*
         SYN-RCVD + FIN = FIN-WAIT-1
         ESTAB + FIN = FIN-WAIT-1
             +---------+
             |  FIN    |
             | WAIT-1  |
             +---------+
         FIN-WAIT-1 + FIN --> CLOSING
         FIN-WAIT-1 + ACK-of-FIN --> FIN-WAIT-2
        */
        case STATE_FIN_WAIT1_SEND:
            switch (what) {
                case TCP_WHAT_FIN:
                    /* Ignore their FIN while in the SENDing state. */
                    break;
                case TCP_WHAT_ACK:
                    /* Apply the ack */
                    if (_tcp_seg_acknowledge(tcb, ackno_them)) {

                        /* Same a in ESTABLISHED_SEND, once they've acknowledged
                         * all reception BEFORE THE FIN, then change the state */
                        if (tcb->segments == NULL || tcb->segments->length == 0) {
                            /* All the payload has been sent. Notify the application of this, so that they
                             * can send more if the want, or switch to listening. */
                            _tcb_change_state_to(tcb, STATE_FIN_WAIT1_RECV);
                            application_notify(tcpcon, tcb, APP_SEND_SENT, 0, 0, secs, usecs);
                        }
                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    _tcb_seg_resend(tcpcon, tcb); /* also resends FINs */
                    break;
                case TCP_WHAT_DATA:
                    /* Ignore any data received while in the SEND state */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;
        case STATE_FIN_WAIT1_RECV:
            switch (what) {
                case TCP_WHAT_FIN:
                    _tcb_seg_recv(tcpcon, tcb, 0, 0, seqno_them, secs, usecs, true);
                    _tcb_change_state_to(tcb, STATE_CLOSING);
                    _tcb_send_ack(tcpcon, tcb);
                    application_notify(tcpcon, tcb, APP_CLOSE, 0, 0, secs, usecs);
                    break;
                case TCP_WHAT_ACK:
                    /* Apply the ack */
                    if (_tcp_seg_acknowledge(tcb, ackno_them)) {
                        if (_tcb_they_have_acked_my_fin(tcb)) {
                            _tcb_change_state_to(tcb, STATE_FIN_WAIT2);
                            application_notify(tcpcon, tcb, APP_CLOSE, 0, 0, secs, usecs);
                        }
                    }
                    break;
                case TCP_WHAT_TIMEOUT:
                    _tcb_seg_resend(tcpcon, tcb); /* also recv FIN */
                    break;
                case TCP_WHAT_DATA:
                    _tcb_seg_recv(tcpcon, tcb, payload, payload_length, seqno_them, secs, usecs, false);
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;


        case STATE_CLOSING:
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
                    return TCB__destroyed;
                case TCP_WHAT_ACK:
                    _tcp_seg_acknowledge(tcb, ackno_them);
                    if (_tcb_they_have_acked_my_fin(tcb)) {
                        tcpcon_destroy_tcb(tcpcon, tcb, Reason_FIN);
                        return TCB__destroyed;
                    }
                    break;
                case TCP_WHAT_FIN:
                    /* I've already acknowledged their FIN, but hey, do it again */
                    _tcb_send_ack(tcpcon, tcb);
                    break;
                case TCP_WHAT_CLOSE:
                    /* The application this machine has issued a second `tcpapi_close()` request.
                     * This represents a bug in the application process. One place where I see this
                     * when scanning 193.109.9.122:992.
                     * FIXME TODO */
                    ; /* make this silent for now */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;


        case STATE_FIN_WAIT2:
        case STATE_TIME_WAIT:
            switch (what) {
                case TCP_WHAT_TIMEOUT:
                    /* giving up */
                    if (tcb->tcpstate == STATE_TIME_WAIT) {
                        tcpcon_destroy_tcb(tcpcon, tcb, Reason_Timeout);
                        return TCB__destroyed;
                    }
                    break;
                case TCP_WHAT_ACK:
                    break;
                case TCP_WHAT_FIN:
                    /* Processing incoming FIN as an empty paylaod */
                    _tcb_seg_recv(tcpcon, tcb, 0, 0, seqno_them, secs, usecs, true);

                    _tcb_change_state_to(tcb, STATE_TIME_WAIT);

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
                case TCP_WHAT_CLOSE:
                    /* FIXME: to reach this state, we've already done a close.
                     * FIXME: but this happens twice, because only have
                     * FIXME: a single close function. */
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;
        case STATE_CLOSE_WAIT:
            /* Waiting for app to call `close()` */
            switch (what) {
                case TCP_WHAT_CLOSE:
                    _tcb_seg_send(tcpcon, tcb, 0, 0, TCP__close_fin);
                    _tcb_change_state_to(tcb, STATE_LAST_ACK);
                    break;
                case TCP_WHAT_TIMEOUT:
                    /* Remind the app that it's waiting for it to be closed */
                    application_notify(tcpcon, tcb, APP_CLOSE,
                            0, payload_length, secs, usecs);
                    break;
                default:
                    ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n",
                            state_to_string(tcb->tcpstate), what_to_string(what));
                    break;
            }
            break;
        case STATE_LAST_ACK:
            switch (what) {
            case TCP_WHAT_TIMEOUT:
                /* They haven't acknowledged everything yet, so resend the last segment */
                _tcb_seg_resend(tcpcon, tcb);
                break;
            case TCP_WHAT_ACK:
                if (_tcp_seg_acknowledge(tcb, ackno_them)) {
                    tcpcon_destroy_tcb(tcpcon, tcb, Reason_Shutdown);
                    return TCB__destroyed;
                }
                break;
            default:
                ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
                break;
            }
            break;
            break;
        default:
            ERRMSGip(tcb->ip_them, tcb->port_them, "%s:%s **** UNHANDLED EVENT ****\n", 
                        state_to_string(tcb->tcpstate), what_to_string(what));
            break;
    }
    return TCB__okay;
}

