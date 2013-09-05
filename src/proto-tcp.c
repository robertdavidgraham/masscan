/*
    TCP connection table
*/
#include "proto-tcp.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "syn-cookie.h"
#include "event-timeout.h"      /* for tracking future events */
#include "rawsock.h"
#include "logger.h"
#include "tcpkt.h"
#include "pixie-timer.h"
#include "packet-queue.h"
#include "proto-banner1.h"
#include "output.h"
#include "string_s.h"

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

    time_t  furthest_timeout;
    unsigned counter;
    unsigned *p_counter;
    unsigned tcpstate:4;


    unsigned short payload_length;
    const unsigned char *payload;

    unsigned char banner[128];
    unsigned banner_length;
    unsigned banner_state;
    unsigned char banner_proto;
};

struct TCP_ConnectionTable {
    struct TCP_Control_Block **entries;
    struct TCP_Control_Block *freed_list;
    unsigned count;
    unsigned mask;

    uint64_t active_count;

    struct Timeouts *timeouts;
    struct TcpPacket *pkt_template;
    PACKET_QUEUE *transmit_queue;
    PACKET_QUEUE *packet_buffers;

    struct Banner1 *banner1;
    OUTPUT_REPORT_BANNER report_banner;
    struct Output *out;
};

enum {
    STATE_SYN_SENT,
    STATE_READY_TO_SEND,
    STATE_PAYLOAD_SENT,
    STATE_WAITING_FOR_RESPONSE,
};

/***************************************************************************
 * Process all events, up to the current time, that need timing out.
 ***************************************************************************/
void
tcpcon_timeouts(struct TCP_ConnectionTable *tcpcon, unsigned secs, unsigned usecs)
{
    uint64_t timestamp = TICKS_FROM_TV(secs, usecs);

    for (;;) {
        struct TimeoutEvent e;
        struct TCP_Control_Block *tcb;
        
        /* Remove any/all timeouts older than the current time */
        e = timeouts_remove(tcpcon->timeouts, timestamp);
        tcb = (struct TCP_Control_Block *)e.p;

        /* If this is NULL, it means we've done processing all timeouts
         * up to this point in time */
        if (tcb == NULL)
            break;

        /* Check for stale timeouts. Incoming traffic may change the
         * the timeout, leaving behind stale ones that should be ignored
         * in deference to the newer ones */
        if (tcb->counter != e.counter) {
            LOG(15, "%u.%u.%u.%u: stale counter: event=%u tcb=%u\n",
                (unsigned char)(tcb->ip_them>>24),
                (unsigned char)(tcb->ip_them>>16),
                (unsigned char)(tcb->ip_them>> 8),
                (unsigned char)(tcb->ip_them>> 0),
                e.counter,
                tcb->counter);
            continue;
        }

        /* Process this timeout */
        tcpcon_handle(
            tcpcon, 
            tcb,
            TCP_WHAT_TIMEOUT, 
            0, 0,
            secs, usecs);

    }
}

/***************************************************************************
 ***************************************************************************/
struct TCP_ConnectionTable *
tcpcon_create_table(    size_t entry_count,
                        PACKET_QUEUE *transmit_queue,
                        PACKET_QUEUE *packet_buffers,
                        struct TcpPacket *pkt_template,
                        OUTPUT_REPORT_BANNER report_banner,
                        struct Output *out
                        )
{
    struct TCP_ConnectionTable *tcpcon;

    tcpcon = (struct TCP_ConnectionTable *)malloc(sizeof(*tcpcon));
    memset(tcpcon, 0, sizeof(*tcpcon));

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
        tcpcon->entries = (struct TCP_Control_Block**)malloc(entry_count * sizeof(*tcpcon->entries));
        if (tcpcon->entries == 0) {
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
static void
tcpcon_destroy_tcb(
    struct TCP_ConnectionTable *tcpcon, 
    struct TCP_Control_Block *tcb)
{
    unsigned index;
    struct TCP_Control_Block **r_entry;

    index = syn_hash(   tcb->ip_me ^ tcb->ip_them, 
                        tcb->port_me ^ tcb->port_them);

    r_entry = &tcpcon->entries[index & tcpcon->mask];

    while (*r_entry) {
        if (*r_entry == tcb) {
            if (tcb->banner_length || tcb->banner_proto) {
                tcpcon->report_banner(
                    tcpcon->out,
                    tcb->ip_them,
                    tcb->port_them,
                    tcb->banner_proto,
                    tcb->banner,
                    tcb->banner_length);
            }
            tcb->counter += 100;
            *tcb->p_counter = 0;

            (*r_entry) = tcb->next;
            tcb->next = tcpcon->freed_list;
            tcpcon->freed_list = tcb;
            tcpcon->active_count--;
            return;
        } else
            r_entry = &(*r_entry)->next;
    }

    fprintf(stderr, "tcpcon:internal error\n");
    exit(1);

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
    unsigned seqno_me, unsigned seqno_them)
{
    unsigned index;
    struct TCP_Control_Block tmp;
    struct TCP_Control_Block *tcb;

    tmp.ip_me = ip_me;
    tmp.ip_them = ip_them;
    tmp.port_me = (unsigned short)port_me;
    tmp.port_them = (unsigned short)port_them;

    index = syn_hash(ip_me^ip_them, port_me ^ port_them);
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }
    if (tcb == NULL) {
        if (tcpcon->freed_list) {
            tcb = tcpcon->freed_list;
            tcpcon->freed_list = tcb->next;
        } else
            tcb = (struct TCP_Control_Block*)malloc(sizeof(*tcb));
        memset(tcb, 0, sizeof(*tcb));
        tcb->next = tcpcon->entries[index & tcpcon->mask];
        tcpcon->entries[index & tcpcon->mask] = tcb;
        memcpy(tcb, &tmp, 12);
        tcb->seqno_me = seqno_me;
        tcb->seqno_them = seqno_them;
        tcb->ackno_me = seqno_them;
        tcb->ackno_them = seqno_me;
        tcb->counter = seqno_me ^ seqno_them ^ ip_them;
        tcb->counter += (tcb->counter == 0); /* must not be zero */
        {
            static unsigned nothing = 0;
            tcb->p_counter = &nothing;
        }
        
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

    index = syn_hash(ip_me^ip_them, port_me ^ port_them);
    tcb = tcpcon->entries[index & tcpcon->mask];
    while (tcb && !EQUALS(tcb, &tmp)) {
        tcb = tcb->next;
    }

    return tcb;
}


/***************************************************************************
 ***************************************************************************/
void
tcpcon_send_packet(
    struct TCP_ConnectionTable *tcpcon,
    struct TCP_Control_Block *tcb,
    unsigned flags, 
    const unsigned char *payload, size_t payload_length)
{
    struct PacketBuffer *response = 0;
    int err = 0;
    
    
    /* Get a buffer for sending the response packet. This thread doesn't
     * send the packet itself. Instead, it formats a packet, then hands
     * that packet off to a transmit thread for later transmission. */
    for (err=1; err; ) {
        err = rte_ring_sc_dequeue(tcpcon->packet_buffers, (void**)&response);
        if (err != 0) {
            pixie_usleep(100); /* no packet available */
        }
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
        tcb->seqno_me, tcb->seqno_them,
        flags,
        payload, payload_length,
        response->px, sizeof(response->px)
        );

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
            pixie_usleep(100); /* no space available */
        }
    }
}

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

    tcpcon_send_packet(tcpcon, &tcb, 0x11, 0, 0);
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
    unsigned proto = tcb->banner_proto;

    tcb->banner_state = banner1_parse(
        tcpcon->banner1,
        tcb->banner_state,
        &proto,
        payload,
        payload_length,
        (char*)tcb->banner,
        &tcb->banner_length,
        sizeof(tcb->banner)
        );

    tcb->banner_proto = (unsigned char)proto;


    return tcb->banner_state;
}


/***************************************************************************
 ***************************************************************************/
static const char *
state_to_string(int state)
{
    static char buf[64];
    switch (state) {
    case STATE_SYN_SENT: return "STATE_SYN_SENT";
    case STATE_READY_TO_SEND: return "STATE_READY_TO_SEND";
    case STATE_PAYLOAD_SENT: return "STATE_PAYLOAD_SENT";
    case STATE_WAITING_FOR_RESPONSE: return "STATE_WAITING_FOR_RESPONSE";

    default:
        sprintf_s(buf, sizeof(buf), "%d", state);
        return buf;
    }
}
static const char *
what_to_string(int state)
{
    static char buf[64];
    switch (state) {
    case TCP_WHAT_NOTHING: return "TCP_WHAT_NOTHING";
    case TCP_WHAT_TIMEOUT: return "TCP_WHAT_TIMEOUT";
    case TCP_WHAT_SYNACK: return "TCP_WHAT_SYNACK";
    case TCP_WHAT_RST: return "TCP_WHAT_RST";
    case TCP_WHAT_FIN: return "TCP_WHAT_FIN";
    case TCP_WHAT_ACK: return "TCP_WHAT_ACK";
    case TCP_WHAT_DATA: return "TCP_WHAT_DATA";
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

/***************************************************************************
 ***************************************************************************/
void
tcpcon_handle(struct TCP_ConnectionTable *tcpcon, struct TCP_Control_Block *tcb,
    int what, const void *payload, size_t payload_length,
    unsigned secs, unsigned usecs)
{
    if (tcb == NULL)
        return;

    LOG(10, "%u.%u.%u.%u =%s : %s                  \n", 
            (unsigned char)(tcb->ip_them>>24),
            (unsigned char)(tcb->ip_them>>16),
            (unsigned char)(tcb->ip_them>> 8),
            (unsigned char)(tcb->ip_them>> 0),

            state_to_string(tcb->tcpstate), 
            what_to_string(what));

    switch (tcb->tcpstate<<8 | what) {
    case STATE_SYN_SENT<<8 | TCP_WHAT_SYNACK:
    case STATE_READY_TO_SEND<<8 | TCP_WHAT_SYNACK:
        /* This is where we respond to a SYN-ACK. Note that this can happen
         * in two places. We immediately transition to the "ready" state,
         * but if the other side doesn't receive our acknowledgement,
         * then it'll send a duplicate SYN-ACK which we'll have to process
         * in the "ready" state. That's okay, we'll simply reset our 
         * timers and try again.
         */

        /* Send "ACK" to acknowlege their "SYN-ACK" */
        tcpcon_send_packet(tcpcon, tcb,
                    0x10, 
                    0, 0);

        /* Change ourselves to the "ready" state.*/
        tcb->tcpstate = STATE_READY_TO_SEND;
        
        /*
         * Wait 1 second for "server hello" (like SSH), and if that's
         * not found, then transmit a "client hello"
         */
        *tcb->p_counter = 0;
        tcb->p_counter = timeouts_add(   
                        tcpcon->timeouts, 
                        tcb, 
                        TICKS_FROM_TV(secs+2,usecs),
                        ++tcb->counter);
        break;

    case STATE_READY_TO_SEND<<8 | TCP_WHAT_ACK:
        /* There's actually nothing that goes on in this state. We are just waiting
         * for the timer to expire. In the meanwhile, though, the other side is 
         * might acknowledge that we sent a SYN-ACK */

        /* NOTE: the arg 'payload_length' was overloaded here to be the
         * 'ackno' instead */
        handle_ack( tcb, (uint32_t)payload_length);
        break;

    case STATE_READY_TO_SEND<<8 | TCP_WHAT_TIMEOUT:
        {
            size_t x_len = 0;
            const unsigned char *x;
            switch (tcb->port_them) {
            case 80: 
                x = (const unsigned char *)
                    "HEAD / HTTP/1.0\r\n"
                    "User-Agent: test\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n"; 
                    break;
            default:
                x = 0;
            }
            if (!x) {
                break;
            }



            /* send request */
            x_len = strlen((const char*)x);
            tcpcon_send_packet(tcpcon, tcb,
                0x18, 
                x, x_len);
            LOG(4, "%u.%u.%u.%u - sending payload %u bytes\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF, 
                x_len);

            /* Increment our sequence number */
            tcb->seqno_me += (uint32_t)x_len;

            /* change our state to reflect that we are now waiting for 
             * acknowledgement of the data we've sent */
            tcb->tcpstate = STATE_PAYLOAD_SENT;

            /* Add a timeout so that we can resend the data in case it
             * goes missing */
            *tcb->p_counter = 0;
            tcb->p_counter = timeouts_add(   
                            tcpcon->timeouts, 
                            tcb, 
                            TICKS_FROM_TV(secs+1,usecs),
                            ++tcb->counter);

        }
        break;


    case STATE_READY_TO_SEND<<8 | TCP_WHAT_DATA:
    case STATE_WAITING_FOR_RESPONSE<<8 | TCP_WHAT_DATA:
        {
            unsigned err;

            /* extract a banner if we can */
            err = parse_banner(
                        tcpcon,
                        tcb, 
                        (const unsigned char*)payload, 
                        payload_length);

            /* move their sequence number forward */
            tcb->seqno_them += (unsigned)payload_length;

            /* acknowledge the bytes sent */
            tcpcon_send_packet(tcpcon, tcb,
                        0x10, 
                        0, 0);

            if (err == STATE_DONE) {
                tcpcon_send_packet(tcpcon, tcb,
                    0x11, 
                    0, 0);
                tcb->seqno_me++;
                tcpcon_destroy_tcb(tcpcon, tcb);
            }
        }
        break;

    case STATE_READY_TO_SEND<<8 | TCP_WHAT_FIN:
        tcb->seqno_them = (uint32_t)payload_length + 1;
        tcpcon_send_packet(tcpcon, tcb,
                    0x14, /*reset */
                    0, 0);
        break;

   case STATE_PAYLOAD_SENT<<8 | TCP_WHAT_SYNACK:
       /* ignore duplciate SYN-ack */
       break;

   case STATE_PAYLOAD_SENT<<8 | TCP_WHAT_ACK:
        /* There's actually nothing that goes on in this state. We are just waiting
         * for the timer to expire. In the meanwhile, though, the other side is 
         * might acknowledge that we sent a SYN-ACK */

        /* NOTE: the arg 'payload_length' was overloaded here to be the
         * 'ackno' instead */
        handle_ack(tcb, (uint32_t)payload_length);

        if (tcb->ackno_them - tcb->seqno_me == 0) {
            /* Now wait for response */
            tcb->tcpstate = STATE_WAITING_FOR_RESPONSE;
            *tcb->p_counter = 0;
            tcb->p_counter = timeouts_add(   
                            tcpcon->timeouts, 
                            tcb, 
                            TICKS_FROM_TV(secs+10,usecs),
                            ++tcb->counter);
        } else {
            /* Reset the timeout, waiting for more data to arrive */
            *tcb->p_counter = 0;
            tcb->p_counter = timeouts_add(   
                            tcpcon->timeouts, 
                            tcb, 
                            TICKS_FROM_TV(secs+1,usecs),
                            ++tcb->counter);

        }
        break;

    case STATE_PAYLOAD_SENT<<8 | TCP_WHAT_TIMEOUT:
        {
            uint32_t len;


            len = tcb->seqno_me - tcb->ackno_them;

            /* Resend the payload */
            tcb->seqno_me -= len;
            tcpcon_send_packet(tcpcon, tcb,
                0x18, 
                tcb->payload + tcb->payload_length - len,
                len);
            LOG(4, "%u.%u.%u.%u - re-sending payload %u bytes\n",
                (tcb->ip_them>>24)&0xFF, (tcb->ip_them>>16)&0xFF, (tcb->ip_them>>8)&0xFF, (tcb->ip_them>>0)&0xFF, 
                len);
            tcb->seqno_me += len;


            /*  */
            *tcb->p_counter = 0;
            tcb->p_counter = timeouts_add(   
                            tcpcon->timeouts, 
                            tcb, 
                            TICKS_FROM_TV(secs+2,usecs),
                            ++tcb->counter);
        }
        break;
    case STATE_PAYLOAD_SENT<<8 | TCP_WHAT_FIN:
        /* ignore this, since they havne't acked our payload */
        break;

    case STATE_WAITING_FOR_RESPONSE<<8 | TCP_WHAT_ACK:
        handle_ack(tcb, (uint32_t)payload_length);
        break;

    
    case STATE_WAITING_FOR_RESPONSE<<8 | TCP_WHAT_FIN:
        tcb->seqno_them = (uint32_t)payload_length + 1;
        tcpcon_send_packet(tcpcon, tcb,
            0x11, 
            0, 0);
        break;
    case STATE_WAITING_FOR_RESPONSE<<8 | TCP_WHAT_TIMEOUT:
        tcpcon_send_packet(tcpcon, tcb,
            0x04, 
            0, 0);
        tcpcon_destroy_tcb(tcpcon, tcb);
        break;
    
    case STATE_WAITING_FOR_RESPONSE<<8 | TCP_WHAT_RST:
    case STATE_READY_TO_SEND<<8 | TCP_WHAT_RST:
    case STATE_PAYLOAD_SENT<<8 | TCP_WHAT_RST:
        tcpcon_destroy_tcb(tcpcon, tcb);
        break;

    default:
        LOG(3, "tcp: unknown event %s : %s\n", 
            state_to_string(tcb->tcpstate), 
            what_to_string(what));
    }
}

