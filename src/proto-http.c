#include "proto-http.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "smack.h"
#include "unusedparm.h"
#include "string_s.h"
#include "masscan-app.h"
#include "util-malloc.h"
#include "util-bool.h"
#include "proto-tcp.h"
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

/**
 * We might have an incomplete HTTP request header. Thus, as we insert
 * fields into it, we'll add missing components onto the end.
 */
static size_t
_http_append(unsigned char **inout_header, size_t length1, size_t length2, const char *str)
{
    size_t str_length = strlen(str);

    *inout_header = REALLOC(*inout_header, length1 + length2 + str_length + 1);
    memcpy(*inout_header + length1, str, str_length + 1);

    return str_length;
}

enum What {spaces, notspaces, end_of_line, end_of_field};
size_t _skip(enum What what, const unsigned char *hdr, size_t offset, size_t header_length)
{
    switch (what) {
    case notspaces:
        while (offset < header_length && !isspace(hdr[offset]&0xFF))
            offset++;
        break;
    case spaces:
        while (offset < header_length && hdr[offset] != '\n' && isspace(hdr[offset]&0xFF))
            offset++;
        if (offset < header_length && hdr[offset] == '\n') {
            while (offset > 0 && hdr[offset-1] == '\r')
                offset--;
        }
        break;
    case end_of_field:
        while (offset < header_length && hdr[offset] != '\n')
            offset++;
        if (offset < header_length && hdr[offset] == '\n') {
            while (offset > 0 && hdr[offset-1] == '\r')
                offset--;
        }
        break;
    case end_of_line:
        while (offset < header_length && hdr[offset] != '\n')
            offset++;
        if (offset < header_length && hdr[offset] == '\n')
            offset++;
        break;
    }
    return offset;
}

/**
 * Used when editing our HTTP prototype request, it replaces the existing
 * field (start..end) with the new field. The header is resized and data moved
 * to accommodate this insertion.
 */
static size_t
_http_insert(unsigned char **r_hdr, size_t start, size_t end, size_t header_length, size_t field_length, const void *field)
{
    size_t old_field_length = (end-start);
    size_t new_header_length = header_length + field_length - old_field_length;
    unsigned char *hdr;

    *r_hdr = REALLOC(*r_hdr, new_header_length + 1);
    hdr = *r_hdr;
    
    /* Shrink/expand the field */
    memmove(&hdr[start + field_length], &hdr[end], header_length - end + 1);

    /* Insert the new header at this location */
    memcpy(&hdr[start], field, field_length);

    return new_header_length;
}

/***************************************************************************
 ***************************************************************************/
size_t
http_change_requestline(unsigned char **hdr, size_t header_length,
                    const void *field, size_t field_length, int item)
{
    size_t offset;
    size_t start;

    /* If no length given, calculate length */
    if (field_length == ~(size_t)0)
        field_length = strlen((const char *)field);

    /*  GET /example.html HTTP/1.0 
     * 0111233333333333334
     * #0 skip leading whitespace
     * #1 skip past method
     * #2 skip past space after method
     * #3 skip past URL field
     * #4 skip past space after URL
     * #5 skip past version
     */

    /* #0 Skip leading whitespace */
    offset = 0;
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #1 Method */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "GET");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == 0) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* #2 Method space */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, " ");
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #3 URL */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "/");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == 1) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* #4 Space after url */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, " ");
    offset = _skip(spaces, *hdr, offset, header_length);

    /* #5 version */
    start = offset;
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "HTTP/1.0");
    offset = _skip(notspaces, *hdr, offset, header_length);
    if (item == 2) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }

    /* ending line */
    if (offset == header_length)
        header_length += _http_append(hdr, header_length, field_length, "\r\n");
    offset = _skip(spaces, *hdr, offset, header_length);
    offset = _skip(end_of_line, *hdr, offset, header_length);

    /* now find a blank line */
    for (;;) {
        /* make sure there's at least one line left */
        if (offset == header_length)
            header_length += _http_append(hdr, header_length, field_length, "\r\n");
        if (offset + 1 == header_length && (*hdr)[offset] == '\r')
            header_length += _http_append(hdr, header_length, field_length, "\n");

        start = offset;
        offset = _skip(end_of_field, *hdr, offset, header_length);
        if (start == offset) {
            /* We've reached the end of the header*/
            offset = _skip(end_of_line, *hdr, offset, header_length);
            break;
        }

        if (offset == header_length)
            header_length += _http_append(hdr, header_length, field_length, "\r\n");
        if (offset + 1 == header_length && (*hdr)[offset] == '\r')
            header_length += _http_append(hdr, header_length, field_length, "\n");
        offset = _skip(end_of_line, *hdr, offset, header_length);
    }

    start = offset;
    offset = header_length;
    if (item == 3) {
        return _http_insert(hdr, start, offset, header_length, field_length, field);
    }
    

    return header_length;
}

size_t _field_length(const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t original_offset = offset;

    /* Find newline */
    while (offset < hdr_length && hdr[offset] != '\n')
        offset++;

    /* Trim trailing whitespace */
    while (offset > original_offset && isspace(hdr[offset-1]&0xFF))
        offset--;

    return offset - original_offset;
}

static size_t _next_field(const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t original_offset = offset;

    /* Find newline */
    while (offset < hdr_length && hdr[offset] != '\n')
        offset++;

    /* Remove newline too*/
    if (offset > original_offset && isspace(hdr[offset-1]&0xFF))
        offset++;

    return offset;
}

static bool 
_has_field_name(const char *name, size_t name_length, const unsigned char *hdr, size_t offset, size_t hdr_length)
{
    size_t x;
    bool found_colon = false;

    /* Trim leading whitespace */
    while (offset < hdr_length && isspace(hdr[offset]&0xFF) && hdr[offset] != '\n')
        offset++;

    /* Make sure there's enough space left */
    if (hdr_length - offset < name_length)
        return false;

    /* Make sure there's colon after */
    for (x = offset + name_length; x<hdr_length; x++) {
        unsigned char c = hdr[x] & 0xFF;
        if (isspace(c))
            continue;
        else if (c == ':') {
            found_colon = true;
            break;
        } else {
            /* some unexpected character was found in the name */
            return false;
        }
    }
    if (!found_colon)
        return false;

    /* Compare the name (case insentive) */
    return memcasecmp(name, hdr + offset, name_length) == 0;
}


/***************************************************************************
 ***************************************************************************/
size_t
http_change_field(unsigned char **inout_header, size_t header_length,
                    const char *name,
                    const unsigned char *value, size_t value_length,
                    int what)
{
    unsigned char *hdr = *inout_header;
    size_t name_length = strlen(name);
    size_t offset;
    size_t next_offset;

    /* If field 'name' ends in a colon, trim that. Also, trim whitespace */
    while (name_length) {
        unsigned char c = name[name_length-1];
        if (c == ':' || isspace(c & 0xFF))
            name_length--;
        else
            break;
    }

    /* If length of the fiend value not specified, then assume
     * nul-terminated string */
    if (value_length == ~(size_t)0)
        value_length = strlen((const char *)value);

    /* Find our field */
    for (offset = _next_field(hdr, 0, header_length); 
        offset < header_length; 
        offset = _next_field(hdr, offset, header_length)) {

        if (_has_field_name(name, name_length, hdr, offset, header_length)) {
            break;
        } else if (_field_length(hdr, offset, header_length) == 0) {
            /* We reached end without finding field, so insert before end
             * instead of replacing an existing header. */
            if (what == http_field_remove)
                return header_length;
            what = http_field_add;
            break;
        }
    }

    /* Allocate a new header to replace the old one. We'll allocated
     * more space than we actually need */
    *inout_header = REALLOC(*inout_header, header_length + name_length + 2 + value_length + 2 + 1 + 2);
    hdr = *inout_header;

    /* If we reached the end without finding proper termination, then add
     * it */
    if (offset == header_length) {
        if (offset == 0 || hdr[offset-1] != '\n') {
            if (hdr[offset-1] == '\r')
                header_length = _http_append(&hdr, header_length, value_length+2, "\n");
            else
                header_length = _http_append(&hdr, header_length, value_length+2, "\r\n");
        }
    }


    /* Make room for the new header */
    next_offset = _next_field(hdr, offset, header_length);
    if (value == NULL || what == http_field_remove) {
        memmove(&hdr[offset + 0],
                &hdr[next_offset],
                header_length - next_offset + 1);
        header_length += 0 - (next_offset - offset);
        return header_length;
    } else if (what == http_field_replace) {
        /* Replace existing field */
        memmove(&hdr[offset + name_length + 2 + value_length + 2],
                &hdr[next_offset],
                header_length - offset + 1);
        header_length += (name_length + 2 + value_length + 2) - (next_offset - offset);
    } else {
        /* Add a new field onto the end */
        memmove(&hdr[offset + name_length + 2 + value_length + 2],
                &hdr[offset],
                header_length - offset + 1);
        header_length += (name_length + 2 + value_length + 2);
    }
    hdr[header_length] = '\0';

    /* Copy the new header */
    memcpy(&hdr[offset], name, name_length);
    memcpy(&hdr[offset + name_length], ": ", 2);
    memcpy(&hdr[offset + name_length + 2], value, value_length);
    memcpy(&hdr[offset + name_length + 2 + value_length], "\r\n", 2);

    return header_length;
}

/***************************************************************************
 ***************************************************************************/
static const char
http_hello[] =      "GET / HTTP/1.0\r\n"
                    "User-Agent: masscan/1.3 (https://github.com/robertdavidgraham/masscan)\r\n"
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

    banner_http.hello = MALLOC(banner_http.hello_length);
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
            banout_append(banout, PROTO_HTTP_SERVER, &px[i], 1);
            break;
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

static const char *test_response =
    "HTTP/1.0 200 OK\r\n"
    "Date: Wed, 13 Jan 2021 18:18:25 GMT\r\n"
    "Expires: -1\r\n"
    "Cache-Control: private, max-age=0\r\n"
    "Content-Type: text/html; charset=ISO-8859-1\r\n"
    "P3P: CP=\x22This is not a P3P policy! See g.co/p3phelp for more info.\x22\r\n"
    "Server: gws\r\n"
    "X-XSS-Protection: 0\r\n"
    "X-Frame-Options: SAMEORIGIN\r\n"
    "Set-Cookie: 1P_JAR=2021-01-13-18; expires=Fri, 12-Feb-2021 18:18:25 GMT; path=/; domain=.google.com; Secure\r\n"
    "Set-Cookie: NID=207=QioO2ZqRsR6k1wtvXjuuhLrXYtl6ki8SQhf56doo_wcADvldNoHfnKvFk1YXdxSVTWnmqHQVPC6ZudGneMs7vDftJ6vB36B0OCDy_KetZ3sOT_ZAHcmi1pAGeO0VekZ0SYt_UXMjcDhuvNVW7hbuHEeXQFSgBywyzB6mF2EVN00; expires=Thu, 15-Jul-2021 18:18:25 GMT; path=/; domain=.google.com; HttpOnly\r\n"
    "Accept-Ranges: none\r\n"
    "Vary: Accept-Encoding\r\n"
    "\r\n";


/***************************************************************************
 ***************************************************************************/
static int
http_selftest_parser(void)
{
    struct Banner1 *banner1 = NULL;
    struct ProtocolState pstate[1];
    struct BannerOutput banout[1];
    struct InteractiveData more[1];
    
    memset(pstate, 0, sizeof(pstate[0]));
    memset(banout, 0, sizeof(banout[0]));
    memset(more, 0, sizeof(more[0]));

    /*
     * Test start
     */
    banner1 = banner1_create();
    banner1->is_capture_servername = 1;
    memset(pstate, 0, sizeof(pstate[0]));
    banout_init(banout);

    /*
     * Run Test
     */
    http_parse(banner1, 0, pstate, (const unsigned  char *)test_response, strlen(test_response), banout, more);
    
    
    /*
     * Verify results
     */
    {
        const unsigned char *string;
        size_t length;
        
        string = banout_string(banout, PROTO_HTTP_SERVER);
        length = banout_string_length(banout, PROTO_HTTP_SERVER);
        
        if (length != 3 || memcmp(string, "gws", 3) != 0) {
            fprintf(stderr, "[-] HTTP parser failed: %s %u\n", __FILE__, __LINE__);
            return 1; /* failure */
        }
    }

    /*
     * Test end
     */
    banner1_destroy(banner1);
    banout_release(banout);
    
    return 0; /* success */
}

/***************************************************************************
 ***************************************************************************/
static int
http_selftest_config(void)
{
    size_t i;
    static const struct {const char *from; const char *to;} urlsamples[] = {
        {"", "GET /foo.html"},
        {"GET / HTTP/1.0\r\n\r\n", "GET /foo.html HTTP/1.0\r\n\r\n"},
        {"GET  /longerthan HTTP/1.0\r\n\r\n", "GET  /foo.html HTTP/1.0\r\n\r\n"},
        {0,0}
    };
    static const struct {const char *from; const char *to;} methodsamples[] = {
        {"", "POST"},
        {"GET / HTTP/1.0\r\n\r\n", "POST / HTTP/1.0\r\n\r\n"},
        {"O  /  HTTP/1.0\r\n\r\n", "POST  /  HTTP/1.0\r\n\r\n"},
        {0,0}
    };
    static const struct {const char *from; const char *to;} versionsamples[] = {
        {"", "GET / HTTP/1.1"},
        {"GET / FOO\r\n\r\n", "GET / HTTP/1.1\r\n\r\n"},
        {"GET  /  XXXXXXXXXXXX\r\n\r\n", "GET  /  HTTP/1.1\r\n\r\n"},
        {0,0}
    };
    static const struct {const char *from; const char *to;} fieldsamples[] = {
        {"GET / HTTP/1.0\r\nfoobar: a\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nfoobar: a\r\nHost: xyz\r\nfoo: bar\r\n\r\n"},
        {"GET / HTTP/1.0\r\nfoo:abc\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nfoo: bar\r\nHost: xyz\r\n\r\n"},
        {"GET / HTTP/1.0\r\nfoo: abcdef\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nfoo: bar\r\nHost: xyz\r\n\r\n"},
        {"GET / HTTP/1.0\r\nfoo: a\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nfoo: bar\r\nHost: xyz\r\n\r\n"},
        {"GET / HTTP/1.0\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nHost: xyz\r\nfoo: bar\r\n\r\n"},
        {0,0}
    };
    static const struct {const char *from; const char *to;} removesamples[] = {
        {"GET / HTTP/1.0\r\nfoo: a\r\nHost: xyz\r\n\r\n",  "GET / HTTP/1.0\r\nHost: xyz\r\n\r\n"},
        {"GET / HTTP/1.0\r\nfooa: a\r\nHost: xyz\r\n\r\n", "GET / HTTP/1.0\r\nfooa: a\r\nHost: xyz\r\n\r\n"},
        {0,0}
    };
    static const struct {const char *from; const char *to;} payloadsamples[] = {
        {"",  "GET / HTTP/1.0\r\n\r\nfoo"},
        {"GET / HTTP/1.0\r\nHost: xyz\r\n\r\nbar", "GET / HTTP/1.0\r\nHost: xyz\r\n\r\nfoo"},
        {0,0}
    };

    /* Test replacing URL */
    for (i=0; urlsamples[i].from; i++) {
        unsigned char *x = (unsigned char*)STRDUP(urlsamples[i].from);
        size_t len1 = strlen((const char *)x);
        size_t len2;
        size_t len3 = strlen(urlsamples[i].to);
        
        /* Replace whatever URL is in the header with this new one */
        len2 = http_change_requestline(&x, len1, "/foo.html", ~(size_t)0, 1);

        if (len2 != len3 && memcmp(urlsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config URL sample #%u\n", (unsigned)i);
            return 1;
        }
    }

    /* Test replacing method */
    for (i=0; methodsamples[i].from; i++) {
        unsigned char *x = (unsigned char*)STRDUP(methodsamples[i].from);
        size_t len1 = strlen((const char *)x);
        size_t len2;
        size_t len3 = strlen(methodsamples[i].to);
        
        len2 = http_change_requestline(&x, len1, "POST", ~(size_t)0, 0);

        if (len2 != len3 && memcmp(methodsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config method sample #%u\n", (unsigned)i);
            return 1;
        }
    }

    /* Test replacing version */
    for (i=0; versionsamples[i].from; i++) {
        unsigned char *x = (unsigned char*)STRDUP(versionsamples[i].from);
        size_t len1 = strlen((const char *)x);
        size_t len2;
        size_t len3 = strlen(versionsamples[i].to);
        
        len2 = http_change_requestline(&x, len1, "HTTP/1.1", ~(size_t)0, 2);

        if (len2 != len3 && memcmp(versionsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config version sample #%u\n", (unsigned)i);
            return 1;
        }
    }

    /* Test payload */
    for (i=0; payloadsamples[i].from; i++) {
        unsigned char *x = (unsigned char*)STRDUP(payloadsamples[i].from);
        size_t len1 = strlen((const char *)x);
        size_t len2;
        size_t len3 = strlen(payloadsamples[i].to);
        
        len2 = http_change_requestline(&x, len1, "foo", ~(size_t)0, 3);

        if (len2 != len3 && memcmp(payloadsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config payload sample #%u\n", (unsigned)i);
            return 1;
        }
    }

    /* Test adding fields */
    for (i=0; fieldsamples[i].from; i++) {
        unsigned char *x;
        size_t len1 = strlen((const char *)fieldsamples[i].from);
        size_t len2;
        size_t len3 = strlen(fieldsamples[i].to);
        
        /* Replace whatever URL is in the header with this new one */
        x = (unsigned char*)STRDUP(fieldsamples[i].from);
        len2 = http_change_field(&x, len1, "foo", (const unsigned char *)"bar", ~(size_t)0, http_field_replace);
        if (len2 != len3 || memcmp(fieldsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config header field sample #%u\n", (unsigned)i);
            return 1;
        }
        free(x);

        /* Same test as above, but when name specified with a colon */
        x = (unsigned char*)STRDUP(fieldsamples[i].from);
        len2 = http_change_field(&x, len1, "foo:", (const unsigned char *)"bar", ~(size_t)0, http_field_replace);
        if (len2 != len3 || memcmp(fieldsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config header field sample #%u\n", (unsigned)i);
            return 1;
        }
        free(x);

        /* Same test as above, but with name having additional space */
        x = (unsigned char*)STRDUP(fieldsamples[i].from);
        len2 = http_change_field(&x, len1, "foo : : ", (const unsigned char *)"bar", ~(size_t)0, http_field_replace);
        if (len2 != len3 || memcmp(fieldsamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config header field sample #%u\n", (unsigned)i);
            return 1;
        }
        free(x);

    }

    /* Removing fields */
    for (i=0; removesamples[i].from; i++) {
        unsigned char *x = (unsigned char*)STRDUP(removesamples[i].from);
        size_t len1 = strlen((const char *)x);
        size_t len2;
        size_t len3 = strlen(removesamples[i].to);
        
        /* Replace whatever URL is in the header with this new one */
        len2 = http_change_field(&x, len1, "foo", (const unsigned char *)"bar", ~(size_t)0, http_field_remove);

        if (len2 != len3 || memcmp(removesamples[i].to, x, len3) != 0) {
            fprintf(stderr, "[-] HTTP.selftest: config remove field sample #%u\n", (unsigned)i);
            return 1;
        }
        free(x);
    }

    return 0;
}

/***************************************************************************
 * Called when `--selftest` command-line parameter in order to do some
 * basic unit testing of this module.
 ***************************************************************************/
static int
http_selftest(void)
{
    int err;

    /* Test parsing HTTP responses */
    err = http_selftest_parser();
    if (err)
        return 1; /* failure */

    /* Test configuring HTTP requests */
    err = http_selftest_config();
    if (err)
        return 1; /* failure */

    return 0; /* success */
}

/***************************************************************************
 ***************************************************************************/
struct ProtocolParserStream banner_http = {
    "http", 80, http_hello, sizeof(http_hello)-1, 0,
    http_selftest,
    http_init,
    http_parse,
};

