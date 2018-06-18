#include "proto-http.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "smack.h"
#include "unusedparm.h"
#include "string_s.h"
#include "masscan-app.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    HTTPFIELD_INCOMPLETE,
    HTTPFIELD_SERVER,
    HTTPFIELD_CONTENT_LENGTH,
    HTTPFIELD_CONTENT_TYPE,
    HTTPFIELD_VIA,
    HTTPFIELD_LOCATION,
    HTTPFIELD_UNKNOWN,
    HTTPFIELD_NEWLINE,
};
static struct Patterns http_fields[] = {
    {"Server:",          7, HTTPFIELD_SERVER,           SMACK_ANCHOR_BEGIN},
    //{"Content-Length:", 15, HTTPFIELD_CONTENT_LENGTH,   SMACK_ANCHOR_BEGIN},
    //{"Content-Type:",   13, HTTPFIELD_CONTENT_TYPE,     SMACK_ANCHOR_BEGIN},
    {"Via:",             4, HTTPFIELD_VIA,              SMACK_ANCHOR_BEGIN},
    {"Location:",        9, HTTPFIELD_LOCATION,         SMACK_ANCHOR_BEGIN},
    {":",                1, HTTPFIELD_UNKNOWN, 0},
    {"\n",               1, HTTPFIELD_NEWLINE, 0},
    {0,0,0,0}
};
enum {
    HTML_INCOMPLETE,
    HTML_TITLE,
    HTML_UNKNOWN,
};
static struct Patterns html_fields[] = {
    {"<TiTle",          6, HTML_TITLE, 0},
    {0,0,0,0}
};

extern struct ProtocolParserStream banner_http;



/***************************************************************************
 ***************************************************************************/
unsigned
http_change_field(unsigned char **inout_header, unsigned header_length,
                    const char *field_name,
                    const unsigned char *field_value, unsigned field_value_len)
{
    unsigned char *hdr1 = *inout_header;
    unsigned char *hdr2;
    unsigned i;
    unsigned is_newline_seen = 0;
    unsigned field_name_len = (unsigned)strlen(field_name);

    hdr2 = (unsigned char *)malloc(header_length + field_value_len + 1 + 2);

    memcpy(hdr2, hdr1, header_length);

    /* Remove the previous header and remember the location in the header
     * where it was located */
    for (i=0; i<header_length; i++) {
        if (hdr2[i] == '\r')
            continue;
        if (hdr2[i] == '\n') {
            if (is_newline_seen) {
                /* We've reached the end of header without seing
                 * the field. Therefore, create space right here
                 * for it. */
                while (hdr2[i-1] == '\r')
                    i--;
                break;
            } else if (memcasecmp(&hdr2[i+1], field_name, field_name_len) == 0) {
                unsigned j;
                i++; /* skip previous newline */
                for (j=i; j<header_length && hdr2[j] != '\n'; j++)
                    ;
                if (j < header_length && hdr2[j] == '\n')
                    j++;
                memmove(    &hdr2[i],
                            &hdr2[j],
                            header_length - j);
                header_length -= (j - i);
                hdr2[header_length] = '\0';
                break;
            }
        }
    }

    /* Insert the new header at this location */
    memmove(    &hdr2[i + field_name_len + field_value_len + 1 + 2],
                &hdr2[i],
                header_length - i);
    memcpy( &hdr2[i],
            field_name,
            field_name_len);
    memcpy( &hdr2[i + field_name_len],
            " ",
            1);
    memcpy( &hdr2[i + field_name_len + 1],
            field_value,
            field_value_len);
    memcpy( &hdr2[i + field_name_len + 1 + field_value_len],
            "\r\n",
            2);

    header_length += field_name_len + 1 + field_value_len + 2;

    free(hdr1);
    *inout_header = hdr2;
    return header_length;
}

/***************************************************************************
 ***************************************************************************/
static const char
http_hello[] =      "GET / HTTP/1.0\r\n"
                    "User-Agent: masscan/1.0 (https://github.com/robertdavidgraham/masscan)\r\n"
                    "Accept: */*\r\n"
                    //"Connection: Keep-Alive\r\n"
                    //"Content-Length: 0\r\n"
                    "\r\n";


/*****************************************************************************
 *****************************************************************************/
void
field_name(struct BannerOutput *banout, size_t id,
           struct Patterns *xhttp_fields);
void
field_name(struct BannerOutput *banout, size_t id,
           struct Patterns *xhttp_fields)
{
    unsigned i;
    if (id == HTTPFIELD_INCOMPLETE)
        return;
    if (id == HTTPFIELD_UNKNOWN)
        return;
    if (id == HTTPFIELD_NEWLINE)
        return;
    for (i=0; xhttp_fields[i].pattern; i++) {
        if (xhttp_fields[i].id == id) {
            banout_newline(banout, PROTO_HTTP);
            banout_append(  banout, PROTO_HTTP,
                            (const unsigned char*)xhttp_fields[i].pattern
                                + ((xhttp_fields[i].pattern[0]=='<')?1:0), /* bah. hack. ugly. */
                            xhttp_fields[i].pattern_length
                                - ((xhttp_fields[i].pattern[0]=='<')?1:0) /* bah. hack. ugly. */
                          );
            return;
        }
    }
}

/*****************************************************************************
 * Initialize some stuff that's part of the HTTP state-machine-parser.
 *****************************************************************************/
static void *
http_init(struct Banner1 *b)
{
    unsigned i;

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

    /*
     * These match HTML <tag names
     */
    b->html_fields = smack_create("html", SMACK_CASE_INSENSITIVE);
    for (i=0; html_fields[i].pattern; i++)
        smack_add_pattern(
                          b->html_fields,
                          html_fields[i].pattern,
                          html_fields[i].pattern_length,
                          html_fields[i].id,
                          html_fields[i].is_anchored);
    smack_compile(b->html_fields);

    banner_http.hello = (unsigned char*)malloc(banner_http.hello_length);
    memcpy((char*)banner_http.hello, http_hello, banner_http.hello_length);

    return b->http_fields;
}

/***************************************************************************
 * BIZARRE CODE ALERT!
 *
 * This uses a "byte-by-byte state-machine" to parse the response HTTP
 * header. This is standard practice for high-performance network
 * devices, but is probably unfamiliar to the average network engineer.
 *
 * The way this works is that each byte of input causes a transition to
 * the next state. That means we can parse the response from a server
 * without having to buffer packets. The server can send the response
 * one byte at a time (one packet for each byte) or in one entire packet.
 * Either way, we don't. We don't need to buffer the entire response
 * header waiting for the final packet to arrive, but handle each packet
 * individually.
 *
 * This is especially useful with our custom TCP stack, which simply
 * rejects out-of-order packets.
 ***************************************************************************/
static void
http_parse(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
{
    unsigned state = pstate->state;
    unsigned i;
    unsigned state2;
    unsigned log_begin = 0;
    unsigned log_end = 0;
    size_t id;
    enum {
        FIELD_START = 9,
        FIELD_NAME,
        FIELD_COLON,
        FIELD_VALUE,
        CONTENT,
        CONTENT_TAG,
        CONTENT_FIELD,
        
        DONE_PARSING
    };

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(more);

    state2 = (state>>16) & 0xFFFF;
    id = (state>>8) & 0xFF;
    state = (state>>0) & 0xFF;

    for (i=0; i<length; i++)
    switch (state) {
    case 0: case 1: case 2: case 3: case 4:
        if (toupper(px[i]) != "HTTP/"[state]) {
            state = DONE_PARSING;
            tcp_close(more);
        } else
            state++;
        break;
    case 5:
        if (px[i] == '.')
            state++;
        else if (!isdigit(px[i])) {
            state = DONE_PARSING;
            tcp_close(more);
        }
        break;
    case 6:
        if (isspace(px[i]))
            state++;
        else if (!isdigit(px[i])) {
            state = DONE_PARSING;
            tcp_close(more);
        }
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
            state2 = 0;
            state = CONTENT;
            log_end = i;
            banout_append(banout, PROTO_HTTP, px+log_begin, log_end-log_begin);
            log_begin = log_end;
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
        i--;
        if (id == HTTPFIELD_NEWLINE) {
            state2 = 0;
            state = FIELD_START;
        } else if (id == SMACK_NOT_FOUND)
            ; /* continue here */
        else if (id == HTTPFIELD_UNKNOWN) {
            /* Oops, at this point, both ":" and "Server:" will match.
             * Therefore, we need to make sure ":" was found, and not
             * a known field like "Server:" */
            size_t id2;

            id2 = smack_next_match(banner1->http_fields, &state2);
            if (id2 != SMACK_NOT_FOUND)
                id = id2;

            state = FIELD_COLON;
        } else
            state = FIELD_COLON;
        break;
    case FIELD_COLON:
        if (px[i] == '\n') {
            state = FIELD_START;
            break;
        } else if (isspace(px[i])) {
            break;
        } else {
            //field_name(banout, id, http_fields);
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
        switch (id) {
        case HTTPFIELD_SERVER:
        case HTTPFIELD_LOCATION:
        case HTTPFIELD_VIA:
            //banner_append(&px[i], 1, banout);
            break;
        case HTTPFIELD_CONTENT_LENGTH:
                if (isdigit(px[i]&0xFF)) {
                    ; /*todo: add content length parsing */
                } else {
                    id = 0;
                }
            break;
        }
        break;
    case CONTENT:
        {
            unsigned next = i;

            id = smack_search_next(
                                   banner1->html_fields,
                                   &state2,
                                   px, &next, (unsigned)length);

            if (banner1->is_capture_html) {
                banout_append(banout, PROTO_HTML_FULL, &px[i], next-i);
            }

            if (id != SMACK_NOT_FOUND) {
                state = CONTENT_TAG;
            }

            i = next - 1;
        }
        break;
    case CONTENT_TAG:
        for (; i<length; i++) {
            if (banner1->is_capture_html) {
                banout_append_char(banout, PROTO_HTML_FULL, px[i]);
            }

            if (px[i] == '>') {
                state = CONTENT_FIELD;
                break;
            }
        }
        break;
    case CONTENT_FIELD:
        if (banner1->is_capture_html) {
            banout_append_char(banout, PROTO_HTML_FULL, px[i]);
        }
        if (px[i] == '<')
            state = CONTENT;
        else {
            banout_append_char(banout, PROTO_HTML_TITLE, px[i]);
        }
        break;
    case DONE_PARSING:
    default:
        i = (unsigned)length;
        break;
    }

    if (log_end == 0 && state < CONTENT)
        log_end = i;
    if (log_begin < log_end)
        banout_append(banout, PROTO_HTTP, px + log_begin, log_end-log_begin);



    if (state == DONE_PARSING)
        pstate->state = state;
    else
        pstate->state = (state2 & 0xFFFF) << 16
                | ((unsigned)id & 0xFF) << 8
                | (state & 0xFF);
}


/***************************************************************************
 ***************************************************************************/
static int
http_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
struct ProtocolParserStream banner_http = {
    "http", 80, http_hello, sizeof(http_hello)-1, 0,
    http_selftest,
    http_init,
    http_parse,
};

