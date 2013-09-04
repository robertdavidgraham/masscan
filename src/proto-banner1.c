/*
7    state machine for receiving banners
*/
#include "smack.h"
#include "rawsock-pcapfile.h"
#include "proto-preprocess.h"
#include "proto-banner1.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>


struct Patterns {
    const char *pattern;
    unsigned pattern_length;
    unsigned id;
    unsigned is_anchored;
};

struct Patterns patterns[] = {
    {"SSH-1.",      6, PROTO_SSH1, SMACK_ANCHOR_BEGIN},
    {"SSH-2.",      6, PROTO_SSH2, SMACK_ANCHOR_BEGIN},
    {"HTTP/1.",     7, PROTO_HTTP, SMACK_ANCHOR_BEGIN},
    {"220-",        4, PROTO_FTP1, SMACK_ANCHOR_BEGIN},
    {"220 ",        4, PROTO_FTP2, SMACK_ANCHOR_BEGIN},
    {0,0}
};

enum {
    HTTPFIELD_INCOMPLETE,
    HTTPFIELD_SERVER,
    HTTPFIELD_UNKNOWN,
    HTTPFIELD_NEWLINE,
};
struct Patterns http_fields[] = {
    {"Server:",     7, HTTPFIELD_SERVER, SMACK_ANCHOR_BEGIN},
    {":",           1, HTTPFIELD_UNKNOWN, 0},
    {"\n",          1, HTTPFIELD_NEWLINE, 0}, 
    {0,0,0,0}
};

struct Banner1
{
    struct SMACK *smack;
    struct SMACK *http_fields;
};


/***************************************************************************
 ***************************************************************************/
static unsigned
b_http(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned i;
    unsigned state2;
    size_t id;
    enum {
        FIELD_START = 9,
        FIELD_NAME,
        FIELD_COLON,
        FIELD_VALUE,

    };

    state2 = (state>>16) & 0xFFFF;
    id = (state>>8) & 0xFF;
    state = (state>>0) & 0xFF;

    for (i=0; i<length; i++)
    switch (state) {
    case 0: case 1: case 2: case 3: case 4:
        if (toupper(px[i]) != "HTTP/"[state])
            state = STATE_DONE;
        else
            state++;
        break;
    case 5:
        if (px[i] == '.')
            state++;
        else if (!isdigit(px[i]))
            state = STATE_DONE;
        break;
    case 6:
        if (isspace(px[i]))
            state++;
        else if (!isdigit(px[i]))
            state = STATE_DONE;
        break;
    case 7:
        /* TODO: look for 1xx response code */
        if (px[i] == '\n')
            state = FIELD_START;
        break;
    case FIELD_START:
        if (px[i] == '\r')
            break;
        else if (px[i] == '\n') {
            state = STATE_DONE;
            break;
        } else {
            state2 = 0;
            state = FIELD_NAME;
            /* drop down */
        }

    case FIELD_NAME:
        if (px[i] == '\r')
            break;
        id = smack_search_next(
                        banner1->http_fields,
                        &state2, 
                        px, &i, (unsigned)length);
        if (id == HTTPFIELD_NEWLINE) {
            state2 = 0;
            state = FIELD_START;
        } else if (id == SMACK_NOT_FOUND)
            ; /* continue here */
        else if (id == HTTPFIELD_UNKNOWN) {
            size_t id2;

            id2 = smack_next_match(banner1->http_fields, &state2);
            if (id2 != SMACK_NOT_FOUND)
                id = id2;
        
            state = FIELD_COLON;
        } else
            state = STATE_DONE;
        break;
    case FIELD_COLON:
        if (px[i] == '\n') {
            state = FIELD_START;
            break;
        } else if (isspace(px[i])) {
            break;
        } else {
            state = FIELD_VALUE;
            /* drop down */
        }

    case FIELD_VALUE:
        if (px[i] == '\r')
            break;
        else if (px[i] == '\n') {
            state = FIELD_START;
            break;
        }
        if (id == HTTPFIELD_SERVER) {
            if (*banner_offset < banner_max) {
                banner[(*banner_offset)++] = px[i];
            }
        }
        break;

    case STATE_DONE:
    default:
        i = (unsigned)length;
        break;
    }


    if (state == STATE_DONE)
        return state;
    else
        return (state2 & 0xFFFF) << 16
                | (id & 0xFF) << 8
                | (state & 0xFF);
}

/***************************************************************************
 ***************************************************************************/
static unsigned
b_ssh(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned i;

    banner1=banner1;

    for (i=0; i<length; i++)
    switch (state) {
    case 0:
        if (px[i] == '\r')
            continue;
        if (px[i] == '\n' || px[i] == '\0' || !isprint(px[i])) {
            state = STATE_DONE;
            continue;
        }
        if (*banner_offset < banner_max)
            banner[(*banner_offset)++] = px[i];
        break;
    default:
        i = (unsigned)length;
        break;
    }
    return state;
}

/***************************************************************************
 ***************************************************************************/
unsigned
banner1_parse(
        struct Banner1 *banner1,
        unsigned state, unsigned *proto,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    size_t x;
    unsigned offset = 0;

    switch (*proto) {
    case PROTO_UNKNOWN:
        x = smack_search_next(
                        banner1->smack,
                        &state, 
                        px, &offset, (unsigned)length);
        if (x != SMACK_NOT_FOUND) {
            unsigned i;
            *proto = (unsigned)x;

            /* reset the state back again */
            state = 0;

            /* re-read the stuff that we missed */
            for (i=0; patterns[i].id != *proto; i++)
                ;

            state = banner1_parse(
                            banner1, 
                            state, proto, 
                            (const unsigned char*)patterns[i].pattern, patterns[i].pattern_length,
                            banner, banner_offset, banner_max);
            state = banner1_parse(
                            banner1, 
                            state, proto, 
                            px+offset, length-offset,
                            banner, banner_offset, banner_max);
        }
        break;
    case PROTO_SSH1:
    case PROTO_SSH2:
    case PROTO_FTP1:
    case PROTO_FTP2:
        state = b_ssh(banner1, state,
                        px, length,
                        banner, banner_offset, banner_max);
        break;
    case PROTO_HTTP:
        state = b_http(banner1, state,
                        px, length,
                        banner, banner_offset, banner_max);
        break;
    default:
        fprintf(stderr, "banner1: internal error\n");
        break;

    }

    return state;
}

/***************************************************************************
 ***************************************************************************/
struct Banner1 *
banner1_create(void)
{
    struct Banner1 *b;
    unsigned i;

    b = (struct Banner1 *)malloc(sizeof(*b));
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

    /*
     * These match HTTP Header-Field: names
     */
    b->http_fields = smack_create("http", SMACK_CASE_INSENSITIVE);
    for (i=0; http_fields[i].pattern; i++)
        smack_add_pattern(
                    b->http_fields,
                    http_fields[i].pattern,
                    http_fields[i].pattern_length,
                    http_fields[i].id,
                    http_fields[i].is_anchored);
    smack_compile(b->http_fields);

    return b;
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
    unsigned state;
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
    state = 0;
    proto = 0;
    banner_offset = 0;
    for (i=0; i<length; i++)
    state = banner1_parse(
                    b,
                    state,
                    &proto,
                    px+i, 1,
                    banner, &banner_offset, sizeof(banner)
                    );
    if (memcmp(banner, "YTS/1.20.13", 11) != 0) {
        printf("banner1: test failed\n");
        return 1;
    }
    banner1_destroy(b);

    /*
     * Test whole buffer
     */
    b = banner1_create();
    memset(banner, 0xa3, sizeof(banner));
    state = 0;
    proto = 0;
    banner_offset = 0;
    state = banner1_parse(
                    b,
                    state,
                    &proto,
                    px, length,
                    banner, &banner_offset, sizeof(banner)
                    );
    if (memcmp(banner, "YTS/1.20.13", 11) != 0) {
        printf("banner1: test failed\n");
        return 1;
    }
    banner1_destroy(b);


    return 0;
}

