/*
7    state machine for receiving banners
*/
#include "smack.h"
#include "rawsock-pcapfile.h"
#include "proto-preprocess.h"
#include "proto-banner1.h"
#include "proto-http.h"
#include "proto-ssl.h"
#include "proto-ssh.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>



struct Patterns patterns[] = {
    {"SSH-1.",      6, PROTO_SSH1, SMACK_ANCHOR_BEGIN},
    {"SSH-2.",      6, PROTO_SSH2, SMACK_ANCHOR_BEGIN},
    {"HTTP/1.",     7, PROTO_HTTP, SMACK_ANCHOR_BEGIN},
    {"220-",        4, PROTO_FTP1, SMACK_ANCHOR_BEGIN},
    {"220 ",        4, PROTO_FTP2, SMACK_ANCHOR_BEGIN},
    {"+OK ",        4, PROTO_POP3, SMACK_ANCHOR_BEGIN},
    {"* OK ",       5, PROTO_IMAP4, SMACK_ANCHOR_BEGIN},
    {"\x16\x03\x00",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x16\x03\x01",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x16\x03\x02",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x16\x03\x03",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x15\x03\x00",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x15\x03\x01",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x15\x03\x02",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {"\x15\x03\x03",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN},
    {0,0}
};




/***************************************************************************
 ***************************************************************************/
void
banner1_parse(
        struct Banner1 *banner1,
        struct Banner1State *pstate, 
        unsigned *proto,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    size_t x;
    unsigned offset = 0;

    switch (*proto) {
    case PROTO_UNKNOWN:
        x = smack_search_next(
                        banner1->smack,
                        &pstate->state,
                        px, &offset, (unsigned)length);
        if (x != SMACK_NOT_FOUND
            && !(x == PROTO_SSL3 && !pstate->is_sent_sslhello)) {
            unsigned i;
            
            /* Kludge: patterns look confusing, so add port info to the
             * pattern */
            switch (*proto) {
            case PROTO_FTP2:
                if (pstate->port == 25 || pstate->port == 587)
                    *proto = PROTO_SMTP;
                break;
            }

            *proto = (unsigned)x;

            /* reset the state back again */
            pstate->state = 0;

            /* re-read the stuff that we missed */
            for (i=0; patterns[i].id != *proto; i++)
                ;

            *banner_offset = 0;

            banner1_parse(
                            banner1, 
                            pstate, proto, 
                            (const unsigned char*)patterns[i].pattern, patterns[i].pattern_length,
                            banner, banner_offset, banner_max);
            banner1_parse(
                            banner1, 
                            pstate, proto, 
                            px+offset, length-offset,
                            banner, banner_offset, banner_max);
        } else {
            size_t len = length;
            if (len > banner_max - *banner_offset)
                len = banner_max - *banner_offset;
            memcpy(banner + *banner_offset, px, len);
            (*banner_offset) += (unsigned)len;
        }
        break;
    case PROTO_SSH1:
    case PROTO_SSH2:
    case PROTO_FTP1:
    case PROTO_FTP2:
    case PROTO_SMTP:
    case PROTO_POP3:
    case PROTO_IMAP4:
        /* generic text-based parser 
         * TODO: in future, need to split these into separate protocols,
         * especially when binary parsing is added to SSH */
        banner_ssh.parse(   banner1, 
                            banner1->http_fields,
                            pstate,
                            px, length,
                            banner, banner_offset, banner_max);
        break;
    case PROTO_HTTP:
        banner_http.parse(
                        banner1, 
                        banner1->http_fields,
                        pstate,
                        px, length,
                        banner, banner_offset, banner_max);
        break;
    case PROTO_SSL3:
        banner_ssl.parse(
                        banner1, 
                        banner1->http_fields,
                        pstate,
                        px, length,
                        banner, banner_offset, banner_max);
        break;
    default:
        fprintf(stderr, "banner1: internal error\n");
        break;

    }
}

/***************************************************************************
 ***************************************************************************/
struct Banner1 *
banner1_create(void)
{
    struct Banner1 *b;
    unsigned i;

    b = (struct Banner1 *)malloc(sizeof(*b));
    if (b == NULL)
        exit(1);
    memset(b, 0, sizeof(*b));

    /*
     * These patterns match the start of the TCP stream
     */
    b->smack = smack_create("banner1", SMACK_CASE_INSENSITIVE);
    for (i=0; patterns[i].pattern; i++)
        smack_add_pattern(
                    b->smack,
                    patterns[i].pattern,
                    patterns[i].pattern_length,
                    patterns[i].id,
                    patterns[i].is_anchored);
    smack_compile(b->smack);


    banner_http.init(b);

    return b;
}

/***************************************************************************
 ***************************************************************************/
void
banner_append(const void *vsrc, size_t src_len,
              void *vbanner, unsigned *banner_offset, size_t banner_max)
{
    const unsigned char *src = (const unsigned char *)vsrc;
    unsigned char *banner = (unsigned char *)vbanner;
    size_t i;
    
    for (i=0; i<src_len; i++) {
        if (*banner_offset < banner_max)
            banner[(*banner_offset)++] = src[i];
    }
}


/***************************************************************************
 ***************************************************************************/
void
banner1_destroy(struct Banner1 *b)
{
    if (b == NULL)
        return;
    if (b->smack)
        smack_destroy(b->smack);
    if (b->http_fields)
        smack_destroy(b->http_fields);
    free(b);
}


/***************************************************************************
 * Test the banner1 detection system by throwing random frames at it
 ***************************************************************************/
void
banner1_test(const char *filename)
{
    struct PcapFile *cap;
    unsigned link_type;
    
    cap = pcapfile_openread(filename);
    if (cap == NULL) {
        fprintf(stderr, "%s: can't open capture file\n", filename);
        return;
    }

    link_type = pcapfile_datalink(cap);

    for (;;) {
        int packets_read;
        unsigned secs;
        unsigned usecs;
        unsigned origlength;
        unsigned length;
        unsigned char px[65536];
        struct PreprocessedInfo parsed;
        unsigned x;

        
        packets_read = pcapfile_readframe(
                    cap,    /* capture dump file */
                    &secs, &usecs,
                    &origlength, &length,
                    px, sizeof(px));
        if (packets_read == 0)
            break;

        
        x = preprocess_frame(px, length, link_type, &parsed);
        if (x == 0)
            continue;

    }

    pcapfile_close(cap);
}

/***************************************************************************
 ***************************************************************************/
int banner1_selftest()
{
    unsigned i;
    struct Banner1 *b;
    char banner[128];
    unsigned banner_offset;
    struct Banner1State pstate[1];
    unsigned proto;
    const unsigned char *px;
    unsigned length;
    static const char *http_header =
        "HTTP/1.0 302 Redirect\r\n"
        "Date: Tue, 03 Sep 2013 06:50:01 GMT\r\n"
        "Connection: close\r\n"
        "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f ])\r\n"
        "Server: YTS/1.20.13\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Type: text/html\r\n"
        "Content-Language: en\r\n"
        "Location: http://failsafe.fp.yahoo.com/404.html\r\n"
        "Content-Length: 227\r\n"
        "\r\n";
    px = (const unsigned char *)http_header;
    length = (unsigned)strlen(http_header);


    /*
     * Test one character at a time
     */
    b = banner1_create();
    memset(banner, 0xa3, sizeof(banner));
    memset(pstate, 0, sizeof(pstate[0]));
    proto = 0;
    banner_offset = 0;
    for (i=0; i<length; i++)
        banner1_parse(
                    b,
                    pstate,
                    &proto,
                    px+i, 1,
                    banner, &banner_offset, sizeof(banner)
                    );
    banner1_destroy(b);
    /*if (memcmp(banner, "Via:HTTP/1.1", 11) != 0) {
        printf("banner1: test failed\n");
        return 1;
    }*/

    /*
     * Test whole buffer
     */
    b = banner1_create();
    memset(banner, 0xa3, sizeof(banner));
    memset(pstate, 0, sizeof(pstate[0]));
    proto = 0;
    banner_offset = 0;
    banner1_parse(
                    b,
                    pstate,
                    &proto,
                    px, length,
                    banner, &banner_offset, sizeof(banner)
                    );
    banner1_destroy(b);
    /*if (memcmp(banner, "Via:HTTP/1.1", 11) != 0) {
        printf("banner1: test failed\n");
        return 1;
    }*/


    return 0;
}

