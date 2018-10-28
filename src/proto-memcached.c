/*
    memcached banner check 
*/

#include "proto-memcached.h"
#include "proto-banner1.h"
#include "smack.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "output.h"
#include "proto-interactive.h"
#include "proto-preprocess.h"
#include "proto-ssl.h"
#include "proto-udp.h"
#include "syn-cookie.h"
#include "templ-port.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

struct SMACK *sm_memcached_responses;
struct SMACK *sm_memcached_stats;

enum {
    MC_ERROR,
    MC_CLIENT_ERROR,
    MC_SERVER_ERROR,
    MC_STORED,
    MC_NOT_STORED,
    MC_EXISTS,
    MC_NOT_FOUND,
    MC_END,
    MC_VALUE,
    MC_DELETED,
    MC_TOUCHED,
    MC_OK,
    MC_BUSY,
    MC_BADCLASS,
    MC_NOSPARE,
    MC_NOTFULL,
    MC_UNSAFE,
    MC_SAME,
    MC_STAT,
    MC_empty,
};
static struct Patterns memcached_responses[] = {
    {"ERROR",          0, MC_ERROR,          SMACK_ANCHOR_BEGIN},
    {"CLIENT_ERROR",   0, MC_CLIENT_ERROR,   SMACK_ANCHOR_BEGIN},
    {"SERVER_ERROR",   0, MC_SERVER_ERROR,   SMACK_ANCHOR_BEGIN},
    {"STORED",         0, MC_STORED,         SMACK_ANCHOR_BEGIN},
    {"NOT_STORED",     0, MC_NOT_STORED,     SMACK_ANCHOR_BEGIN},
    {"EXISTS",         0, MC_EXISTS,         SMACK_ANCHOR_BEGIN},
    {"NOT_FOUND",      0, MC_NOT_FOUND,      SMACK_ANCHOR_BEGIN},
    {"END",            0, MC_END,            SMACK_ANCHOR_BEGIN},
    {"VALUE",          0, MC_VALUE,          SMACK_ANCHOR_BEGIN},
    {"DELETED",        0, MC_DELETED,        SMACK_ANCHOR_BEGIN},
    {"TOUCHED",        0, MC_TOUCHED,        SMACK_ANCHOR_BEGIN},
    {"OK",             0, MC_OK,             SMACK_ANCHOR_BEGIN},
    {"BUSY",           0, MC_BUSY,           SMACK_ANCHOR_BEGIN},
    {"BADCLASS",       0, MC_BADCLASS,       SMACK_ANCHOR_BEGIN},
    {"NOSPARE",        0, MC_NOSPARE,        SMACK_ANCHOR_BEGIN},
    {"NOTFULL",        0, MC_NOTFULL,        SMACK_ANCHOR_BEGIN},
    {"UNSAFE",         0, MC_UNSAFE,         SMACK_ANCHOR_BEGIN},
    {"SAME",           0, MC_SAME,           SMACK_ANCHOR_BEGIN},
    {"STAT",           0, MC_STAT,           SMACK_ANCHOR_BEGIN},
    {"",               0, MC_empty,          SMACK_ANCHOR_BEGIN},
    {0,0,0,0}
};

enum {
    MS_PID,
    MS_UPTIME,
    MS_TIME,
    MS_VERSION,
    MS_POINTER_SIZE,
    MS_RUSAGE_USER,
    MS_RUSAGE_SYSTEM,
    MS_CURR_TIMES,
    MS_TOTAL_ITEMS,
    MS_BYTES,
    MS_MAX_CONNECTIONS,
    MS_CURR_CONNECTIONS,
    MS_TOTAL_CONNECTIONS,
};

static struct Patterns memcached_stats[] = {
{"pid",                  0, MS_PID,                SMACK_ANCHOR_BEGIN},
{"uptime",               0, MS_UPTIME,             SMACK_ANCHOR_BEGIN},
{"time",                 0, MS_TIME,               SMACK_ANCHOR_BEGIN},
{"version",              0, MS_VERSION,            SMACK_ANCHOR_BEGIN},
{"pointer_size",         0, MS_POINTER_SIZE,       SMACK_ANCHOR_BEGIN},
{"rusage_user",          0, MS_RUSAGE_USER,        SMACK_ANCHOR_BEGIN},
{"rusage_system",        0, MS_RUSAGE_SYSTEM,      SMACK_ANCHOR_BEGIN},
{"curr_items",           0, MS_CURR_TIMES,         SMACK_ANCHOR_BEGIN},
{"total_items",          0, MS_TOTAL_ITEMS,        SMACK_ANCHOR_BEGIN},
{"bytes",                0, MS_BYTES,              SMACK_ANCHOR_BEGIN},
{"max_connections",      0, MS_MAX_CONNECTIONS,    SMACK_ANCHOR_BEGIN},
{"curr_connections",     0, MS_CURR_CONNECTIONS,   SMACK_ANCHOR_BEGIN},
{"total_connections",    0, MS_TOTAL_CONNECTIONS,  SMACK_ANCHOR_BEGIN},
{0,0,0,0}
};

/***************************************************************************
 ***************************************************************************/
static void
memcached_tcp_parse(  
          const struct Banner1 *banner1,
          void *banner1_private,
          struct ProtocolState *pstate,
          const unsigned char *px, size_t length,
          struct BannerOutput *banout,
          struct InteractiveData *more)
{
    unsigned state = pstate->state;
    unsigned i;
    struct MEMCACHEDSTUFF *memcached = &pstate->sub.memcached;
    size_t id;

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    UNUSEDPARM(more);

    if (sm_memcached_responses == 0)
        return;

    for (i=0; i<length; i++) {
        switch (state) {
            case 0: /* command */
                memcached->match = 0;
                /* drop through */
            case 1:
                id = smack_search_next(
                        sm_memcached_responses,
                        &memcached->match,
                        px, &i, (unsigned)length);
                i--;
                switch (id) {
                case SMACK_NOT_FOUND:
                    /* continue processing */
                    break;
                case MC_STAT:
                    if (px[i] == '\n')
                        state = 2; /* premature end of line */
                    else
                        state = 100;
                    break;
                case MC_END:
                    state = 3;
                    break;
                default:
                    state = 2;
                }
                break;

            /* We've reached the end of input */
            case 3:
                i = (unsigned)length;
                break;

            /* Ignore until end of line */
            case 2:
                while (i < length && px[i] != '\n')
                    i++;
                if (px[i] == '\n')
                    state = 0;
                break;
            
            /* process stat */
            case 100:
            case 200:
                if (px[i] == '\n')
                    state = 0;
                else if (isspace(px[i]))
                    continue; /* stay in this space until end of whitespace */
                else {
                    state++;
                    memcached->match = 0;
                    i--;
                }
                break;
            case 101:
                id = smack_search_next(
                        sm_memcached_stats,
                        &memcached->match,
                        px, &i, (unsigned)length);
                i--;
                switch (id) {
                case SMACK_NOT_FOUND:
                    /* continue processing */
                    break;
                case MS_UPTIME:
                case MS_TIME:
                case MS_VERSION:
                    banout_append(banout, PROTO_MEMCACHED, memcached_stats[id].pattern, AUTO_LEN);
                    if (px[i] == '\n')
                        state = 0;
                    else
                        state = 200;
                    banout_append_char(banout, PROTO_MEMCACHED, '=');
                    break;
                default:
                    if (px[i] == '\n')
                        state = 0;
                    else
                        state = 2;
                }
                break;

            case 201:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    banout_append_char(banout, PROTO_MEMCACHED, ' ');
                    state = 0;
                    break;
                } else
                    banout_append_char(banout, PROTO_MEMCACHED, px[i]);
                break;
        }
    }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *
memcached_init(struct Banner1 *b)
{
    unsigned i;

    /*
     * These match response codes
     */
    b->memcached_responses = smack_create("memcached-responses", SMACK_CASE_INSENSITIVE);
    for (i=0; memcached_responses[i].pattern; i++) {
        char *tmp;
        unsigned j;
        size_t len;

        len = strlen(memcached_responses[i].pattern);
        tmp = malloc(len + 2);
        memcpy(tmp, memcached_responses[i].pattern, len);
        tmp[len+1] = '\0';

        /* Add all patterns 4 times, once each for the possible whitespace */
        for (j=0; j<4; j++) {
            tmp[len] = " \t\r\n"[j];
            smack_add_pattern(
                          b->memcached_responses,
                          tmp,
                          (unsigned)len+1,
                          memcached_responses[i].id,
                          memcached_responses[i].is_anchored);
        }

        free(tmp);
    }
    smack_compile(b->memcached_responses);
    sm_memcached_responses = b->memcached_responses;

    /*
     * These match stats we might be interested in
     */
    b->memcached_stats = smack_create("memcached-stats", SMACK_CASE_INSENSITIVE);
    for (i=0; memcached_stats[i].pattern; i++) {
        char *tmp;
        unsigned j;
        size_t len;

        len = strlen(memcached_stats[i].pattern);
        tmp = malloc(len + 2);
        memcpy(tmp, memcached_stats[i].pattern, len);
        tmp[len+1] = '\0';

        /* Add all patterns 4 times, once each for the possible whitespace */
        for (j=0; j<4; j++) {
            tmp[len] = " \t\r\n"[j];
            smack_add_pattern(
                          b->memcached_stats,
                          tmp,
                          (unsigned)len+1,
                          memcached_stats[i].id,
                          memcached_stats[i].is_anchored);
        }

        free(tmp);
    }
    smack_compile(b->memcached_stats);
    sm_memcached_stats = b->memcached_stats;

    return b->http_fields;
}


/***************************************************************************
 ***************************************************************************/
unsigned
memcached_udp_parse(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            )
{
    unsigned ip_them;
    unsigned ip_me;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    unsigned request_id = 0;
    unsigned sequence_num = 0;
    unsigned total_dgrams = 0;
    unsigned reserved = 0;
    unsigned cookie = 0;
    struct BannerOutput banout[1];

    /* All memcached responses will be at least 8 bytes */
    if (length < 8)
        return 0;

    /*
    The frame header is 8 bytes long, as follows (all values are 16-bit integers
    in network byte order, high byte first):

    0-1 Request ID
    2-3 Sequence number
    4-5 Total number of datagrams in this message
    6-7 Reserved for future use; must be 0
    */
    request_id = px[0]<<8 | px[1];
    sequence_num = px[2]<<8 | px[3];
    total_dgrams = px[4]<<8 | px[5];
    reserved = px[6]<<8 | px[7];

    /* Ignore high sequence numbers. This should be zero normally */
    if (sequence_num > 100)
        goto not_memcached;

    /* Ignore too many dgrams, should be one normally */
    if (total_dgrams > 100)
        goto not_memcached;

    /* Make sure reserved field is zero */
    if (reserved != 0)
        goto not_memcached;

    /* Grab IP addresses */
    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
            | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;

    /* Validate the "syn-cookie" style information. In the case of SNMP,
     * this will be held in the "request-id" field. If the cookie isn't
     * a good one, then we'll ignore the response */
    cookie = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);
    /*if ((seqno&0xffff) != request_id)
        return 1;*/

    /* Initialize the "banner output" module that we'll use to print
     * pretty text in place of the raw packet */
    banout_init(banout);

    /* Parse the remainder of the packet as if this were TCP */
    {
        struct ProtocolState stuff[1];

        memset(stuff, 0, sizeof(stuff[0]));

        memcached_tcp_parse(
            0, 0,
            stuff, px+8, length-8, banout, 
            0);
    }

    if ((cookie&0xffff) != request_id)
        banout_append(banout, PROTO_MEMCACHED, " IP-MISMATCH", AUTO_LEN);
            
    /* Print the banner information, or save to a file, depending */
    output_report_banner(
        out, timestamp,
        ip_them, 17 /*udp*/, parsed->port_src,
        PROTO_MEMCACHED,
        parsed->ip_ttl,
        banout_string(banout, PROTO_MEMCACHED),
        banout_string_length(banout, PROTO_MEMCACHED));

    /* Free memory for the banner, if there was any allocated */
    banout_release(banout);

    return 0;
    
not_memcached:
    return default_udp_parse(out, timestamp, px, length, parsed, entropy);
}

/****************************************************************************
 ****************************************************************************/
unsigned
memcached_udp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    /*
    The frame header is 8 bytes long, as follows (all values are 16-bit integers
    in network byte order, high byte first):

    0-1 Request ID
    2-3 Sequence number
    4-5 Total number of datagrams in this message
    6-7 Reserved for future use; must be 0
    */

    if (length < 2)
        return 0;

    px[0] = (unsigned char)(seqno >> 8);
    px[1] = (unsigned char)(seqno >> 0);


    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int
memcached_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_memcached = {
    "memcached", 11211, "stats\r\n", 7, 0,
    memcached_selftest,
    memcached_init,
    memcached_tcp_parse,
};
                             
