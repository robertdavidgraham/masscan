/*
    CoAP - Constrained Application Protocol
    https://en.wikipedia.org/wiki/Constrained_Application_Protocol
 
 This is a very simple protocol for interacting with IoT devices
 that have a minimal amount of resources, such as less than a
 megabyte of RAM.
 
 From a scanner point of view, we want to execute the equivelent
 of:
    GET /.well-known/core
 This will return the list of additional items that we can access
 on the target device.
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Ver| T |  TKL  |      Code     |          Message ID           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Token (if any, TKL bytes) ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |   Options (if any) ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |1 1 1 1 1 1 1 1|    Payload (if any) ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#include "proto-coap.h"
#include "proto-banner1.h"
#include "smack.h"
#include "unusedparm.h"
#include "logger.h"
#include "masscan-app.h"
#include "output.h"
#include "proto-interactive.h"
#include "proto-preprocess.h"
#include "proto-ssl.h"
#include "proto-udp.h"
#include "syn-cookie.h"
#include "templ-port.h"
#include "util-malloc.h"
#include "string_s.h"
#include "util-bool.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

struct CoapLink
{
    unsigned link_offset;
    unsigned link_length;
    unsigned parms_offset;
    unsigned parms_length;
};

/****************************************************************************
 ****************************************************************************/
static const char *
response_code(unsigned code)
{
#define CODE(x,y) (((x)<<5) | (y))
    switch (code) {
        case CODE(2,0): return "Okay";
        case CODE(2,1): return "Created";
        case CODE(2,2): return "Deleted";
        case CODE(2,3): return "Valid";
        case CODE(2,4): return "Changed";
        case CODE(2,5): return "Content";
        
        case CODE(4,0): return "Bad Request";
        case CODE(4,1): return "Unauthorized";
        case CODE(4,2): return "Bad Option";
        case CODE(4,3): return "Forbidden";
        case CODE(4,4): return "Not Found";
        case CODE(4,5): return "Method Not Allowed";
        case CODE(4,6): return "Not Acceptable";
        case CODE(4,12): return "Precondition Failed";
        case CODE(4,13): return "Request Too Large";
        case CODE(4,15): return "Unsupported Content-Format";
            
        case CODE(5,0): return "Internal Server Error";
        case CODE(5,1): return "Not Implemented";
        case CODE(5,2): return "Bad Gateway";
        case CODE(5,3): return "Service Unavailable";
        case CODE(5,4): return "Gateway Timeout";
        case CODE(5,5): return "Proxying Not Supported";
    }
    
    switch (code>>5) {
        case 2: return "Okay";
        case 4: return "Error";
        default: return "PARSE_ERR";
    }
}

/****************************************************************************
 * RFC5987
 *  attr-char     = ALPHA / DIGIT
 *                  / "!" / "#" / "$" / "&" / "+" / "-" / "."
 *                  / "^" / "_" / "`" / "|" / "~"
 *                  ; token except ( "*" / "'" / "%" )
 * We need this in parsing the links, which may have parameters afterwards
 * whose names are in this format.
 ****************************************************************************/
static bool
is_attr_char(unsigned c)
{
    switch (c) {
        case '!': case '#': case '$': case '&': case '+': case '-': case '.':
        case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return isalnum(c) != 0;
    }
}

/****************************************************************************
 ****************************************************************************/
static struct CoapLink *
parse_links(const unsigned char *px, unsigned offset, unsigned length, size_t *r_count)
{
    struct CoapLink *l;
    struct CoapLink *links;
    unsigned count = 0;
    enum {
        LINK_BEGIN=0,
        LINK_VALUE,
        LINK_END,
        PARM_BEGIN,
        PARM_NAME_BEGIN,
        PARM_VALUE_BEGIN,
        PARM_QUOTED,
        PARM_QUOTED_ESCAPE,
        PARM_NAME,
        PARM_VALUE,
        INVALID
    } state = LINK_BEGIN;
    
    /* For selftesting purposes, we pass in nul-terminated strings,
     * indicated by a length of (~0) */
    if (length == ~0)
        length = (unsigned)strlen((const char *)px);
    
    /* Allocate space for at least one result */
    links = CALLOC(1, sizeof(*links));
    l = &links[0];
    l->parms_offset = offset;
    l->link_offset = offset;
    
    for (; offset < length; offset++)
    switch (state) {
        case INVALID:
            offset = length;
            break;
        case LINK_BEGIN:
            /* Ignore leading whitespace */
            if (isspace(px[offset]))
                continue;
            
            /* Links must start with "<" character */
            if (px[offset] != '<') {
                state = INVALID;
                break;
            }
            
            
            /* Reserve space for next link */
            links = REALLOCARRAY(links, ++count+1, sizeof(*links));
            links[count].link_offset = length; /* indicate end-of-list by pointing to end-of-input */
            links[count].link_length = 0;
            links[count].parms_offset = length;
            links[count].parms_length = 0;
            
            /* Grab a pointer to this <link> */
            l = &links[count-1];
            l->link_offset = offset+1;
            l->parms_offset = l->link_offset;
            
            state = LINK_VALUE;
            break;
        case LINK_VALUE:
            if (px[offset] == '>') {
                /* End of the link, it may be followed by parameters */
                state = LINK_END;
            } else {
                l->link_length++;
            }
            break;
        case LINK_END:
            l->parms_offset = offset+1;
            l->parms_length = 0;
            if (isspace(px[offset])) {
                continue;
            } else if (px[offset] == ',') {
                /* next link */
                state = LINK_BEGIN;
            } else if (px[offset] == ';') {
                state = PARM_NAME_BEGIN;
            } else {
                state = INVALID;
            }
            break;
        case PARM_BEGIN:
            if (isspace(px[offset])) {
                continue;
            } else if (px[offset] == ',') {
                /* next link */
                l->parms_length = offset - l->parms_offset;
                state = LINK_BEGIN;
            } else if (px[offset] == ';') {
                state = PARM_NAME_BEGIN;
            } else {
                state = INVALID;
            }
            break;
        case PARM_NAME_BEGIN:
            if (isspace(px[offset]))
                continue;
            if (!is_attr_char(px[offset]))
                state = INVALID;
            else
                state = PARM_NAME;
            break;
        case PARM_NAME:
            if (isspace(px[offset])) {
                continue;
            } else if (px[offset] == '=') {
                state = PARM_VALUE_BEGIN;
            } else if (!is_attr_char(px[offset])) {
                state = INVALID;
            }
            break;
        case PARM_VALUE_BEGIN:
            if (isspace(px[offset]))
                continue;
            else if (px[offset] == '\"') {
                state = PARM_QUOTED;
            } else if (offset == ';') {
                state = PARM_NAME_BEGIN;
            } else if (px[offset] == ',') {
                l->parms_length = offset - l->parms_offset;
                state = LINK_BEGIN;
            } else
                state = PARM_VALUE;
            break;
        case PARM_VALUE:
            if (isspace(px[offset]))
                continue;
            else if (px[offset] == ';')
                state = PARM_NAME_BEGIN;
            else if (px[offset] == ',') {
                l->parms_length = offset - l->parms_offset;
                state = LINK_BEGIN;
            } else {
                ; /* do nothing */
            }
            break;
        case PARM_QUOTED:
            /* RFC2616:
             quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
             qdtext         = <any TEXT except <">>
             quoted-pair    = "\" CHAR
             */
            if (px[offset] == '\\') {
                state = PARM_QUOTED_ESCAPE;
            } else if (px[offset] == '\"') {
                state = PARM_VALUE;
            }
            break;
        case PARM_QUOTED_ESCAPE:
            state = PARM_QUOTED;
            break;
        default:
            fprintf(stderr, "invalid state\n");
            state = INVALID;
            break;
                        
    }

    /* Return an array of links and a count of the number of links */
    *r_count = count;
    return links;
}

/****************************************************************************
 ****************************************************************************/
static bool
coap_parse(const unsigned char *px, size_t length, struct BannerOutput *banout,
           unsigned *request_id)
{
    unsigned version;
    unsigned type;
    unsigned code = 0;
    unsigned token_length = 0;
    unsigned long long token = 0;
    unsigned offset;
    unsigned optnum;
    unsigned content_format;
    size_t i;

    /* All coap responses will be at least 8 bytes */
    if (length < 4) {
        LOG(3, "[-] CoAP: short length\n");
        goto not_this_protocol;
    }
    
    /*
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Ver| T |  TKL  |      Code     |          Message ID           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Token (if any, TKL bytes) ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Options (if any) ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |1 1 1 1 1 1 1 1|    Payload (if any) ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    version = (px[0]>>6) & 3;
    type = (px[0]>>4) & 3;
    
    token_length = px[0] & 0x0F;
    code = px[1];
    *request_id = px[2]<<8 | px[3];
    
    /* Only version supported is v1 */
    if (version != 1) {
        LOG(3, "[-] CoAP: version=%u\n", version);
        goto not_this_protocol;
    }
    
    /* Only ACKs suported */
    if (type != 2) {
        LOG(3, "[-] CoAP: type=%u\n", type);
        goto not_this_protocol;
    }
    
    /* Only token lengths up to 8 bytes are supported.
     * Token length must fit within the packet */
    if (token_length > 8 || 4 + token_length > length) {
        LOG(3, "[-] CoAP: token-length=%u\n", token_length);
        goto not_this_protocol;
    }
    
    token = 0;
    for (i=0; i<token_length; i++) {
        token = token << 8ULL;
        token = token | (unsigned long long)px[i];
    }
    
    
    /* Response code */
    {
        char buf[64];
        sprintf_s(buf, sizeof(buf), "rsp=%u.%u(%s)", code>>5, code&0x1F, response_code(code));
        banout_append(banout, PROTO_COAP, buf, AUTO_LEN);
        //code >>= 5;
    }
    
    
    /* If there was a token, the print it. */
    if (token) {
        char buf[64];
        sprintf_s(buf, sizeof(buf), " token=0x%llu", token);
        banout_append(banout, PROTO_COAP, buf, AUTO_LEN);
    }
    
    /*
     * Now process the options fields
     
     0   1   2   3   4   5   6   7
     +---------------+---------------+
     |               |               |
     |  Option Delta | Option Length |   1 byte
     |               |               |
     +---------------+---------------+
     \                               \
     /         Option Delta          /   0-2 bytes
     \          (extended)           \
     +-------------------------------+
     \                               \
     /         Option Length         /   0-2 bytes
     \          (extended)           \
     +-------------------------------+
     \                               \
     /                               /
     \                               \
     /         Option Value          /   0 or more bytes
     \                               \
     /                               /
     \                               \
     +-------------------------------+
     */
    offset = 4 + token_length;
    optnum = 0;
    content_format = 0;
    while (offset < length) {
        unsigned delta;
        unsigned opt;
        unsigned optlen;
        
        /* Get the 'opt' byte */
        opt = px[offset++];
        if (opt == 0xFF)
            break;
        optlen = (opt>>0) & 0x0F;
        delta = (opt>>4) & 0x0F;
        
        /* Decode the delta field */
        switch (delta) {
            default:
                optnum += delta;
                break;
            case 13:
                if (offset >= length) {
                    banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
                    optnum = 0xFFFFFFFF;
                } else {
                    delta = px[offset++] + 13;
                    optnum += delta;
                }
                break;
            case 14:
                if (offset + 1 >= length) {
                    banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
                    optnum = 0xFFFFFFFF;
                } else {
                    delta = px[offset+0]<<8 | px[offset+1];
                    delta += 269;
                    offset += 2;
                    optnum += delta;
                }
                break;
            case 15:
                if (optlen != 15)
                    banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
                optnum = 0xFFFFFFFF;
        }
        
        /* Decode the optlen field */
        switch (optlen) {
            default:
                break;
            case 13:
                if (offset >= length) {
                    banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
                    optnum = 0xFFFFFFFF;
                } else {
                    optlen = px[offset++] + 13;
                }
                break;
            case 14:
                if (offset + 1 >= length) {
                    banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
                    optnum = 0xFFFFFFFF;
                } else {
                    optlen = px[offset+0]<<8 | px[offset+1];
                    optlen += 269;
                    offset += 2;
                }
                break;
        }
        if (offset + optlen > length) {
            banout_append(banout, PROTO_COAP, " PARSE_ERR", AUTO_LEN);
            optnum = 0xFFFFFFFF;
        }
        
        /* Process the option contents */
        switch (optnum) {
            case 0xFFFFFFFF:
                break;
            case  1: banout_append(banout, PROTO_COAP, " /If-Match/", AUTO_LEN); break;
            case  3: banout_append(banout, PROTO_COAP, " /Uri-Host/", AUTO_LEN); break;
            case  4: banout_append(banout, PROTO_COAP, " /Etag", AUTO_LEN); break;
            case  5: banout_append(banout, PROTO_COAP, " /If-None-Match/", AUTO_LEN); break;
            case  7: banout_append(banout, PROTO_COAP, " /Uri-Port/", AUTO_LEN); break;
            case  8: banout_append(banout, PROTO_COAP, " /Location-Path/", AUTO_LEN); break;
            case 11: banout_append(banout, PROTO_COAP, " /Uri-Path/", AUTO_LEN); break;
            case 12:
                banout_append(banout, PROTO_COAP, " /Content-Format/", AUTO_LEN);
                content_format = 0;
                
                for (i=0; i<optlen; i++) {
                    content_format = content_format<<8 | px[offset+i];
                }
                break;
            case 14: banout_append(banout, PROTO_COAP, " /Max-Age/", AUTO_LEN); break;
            case 15: banout_append(banout, PROTO_COAP, " /Uri-Query/", AUTO_LEN); break;
            case 17: banout_append(banout, PROTO_COAP, " /Accept/", AUTO_LEN); break;
            case 20: banout_append(banout, PROTO_COAP, " /Location-Query/", AUTO_LEN); break;
            case 35: banout_append(banout, PROTO_COAP, " /Proxy-Uri/", AUTO_LEN); break;
            case 39: banout_append(banout, PROTO_COAP, " /Proxy-Scheme/", AUTO_LEN); break;
            case 60: banout_append(banout, PROTO_COAP, " /Size1/", AUTO_LEN); break;
            default: banout_append(banout, PROTO_COAP, " /(Unknown)/", AUTO_LEN); break;
                
        }
        
        if (optnum == 0xFFFFFFFF)
            break;
        
        offset += optlen;
    }
    
    switch (content_format) {
        case  0: banout_append(banout, PROTO_COAP, " text-plain", AUTO_LEN); break;
        case 40:
            banout_append(banout, PROTO_COAP, " application/link-format", AUTO_LEN);
        {
            struct CoapLink *links;
            size_t count = 0;
            
            links = parse_links(px, offset, (unsigned)length, &count);
            for (i=0; i<count; i++) {
                banout_append(banout, PROTO_COAP, " ", AUTO_LEN);
                banout_append(banout, PROTO_COAP, px+links[i].link_offset, links[i].link_length);
            }
            free(links);
        }
            break;
        case 41: banout_append(banout, PROTO_COAP, " application/xml", AUTO_LEN); break;
        case 42: banout_append(banout, PROTO_COAP, " application/octet-stream", AUTO_LEN); break;
        case 47: banout_append(banout, PROTO_COAP, " application/exi", AUTO_LEN); break;
        case 50: banout_append(banout, PROTO_COAP, " application/json", AUTO_LEN); break;
        default: banout_append(banout, PROTO_COAP, " (unknown-content-type)", AUTO_LEN); break;
    }

    LOG(3, "[+] CoAP: valid\n");
    return true;
not_this_protocol:
    return false;
}

/***************************************************************************
 ***************************************************************************/
unsigned
coap_handle_response(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            )
{
    unsigned ip_them;
    unsigned ip_me;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    unsigned message_id = 0;
    unsigned cookie;
    struct BannerOutput banout[1];
    bool is_valid;
    
    LOG(1, "[+] COAP\n");
    /* Grab IP addresses */
    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
        | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
        | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;
    
    /* Initialize the "banner output" module that we'll use to print
     * pretty text in place of the raw packet */
    banout_init(banout);
    
    /*
     * Do the protocol parsing
     */
    is_valid = coap_parse(px, length, banout, &message_id);
    
    
    /* Validate the "syn-cookie" style information, which should match the "Message ID field*/
    cookie = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);
    /*if ((seqno&0xffff) != message_id)
     goto not_this_protocol;*/
    
    /* See if cookies match. So far, we are allowing responses with the
     * wrong cookie */
    if ((cookie&0xffff) != message_id)
        banout_append(banout, PROTO_COAP, " IP-MISMATCH", AUTO_LEN);

    
    /* Print the banner information, or save to a file, depending */
    if (is_valid) {
        output_report_banner(
            out, timestamp,
            ip_them, 17 /*udp*/, parsed->port_src,
            PROTO_COAP,
            parsed->ip_ttl,
            banout_string(banout, PROTO_COAP),
            banout_string_length(banout, PROTO_COAP));
        banout_release(banout);
        return 0;
    } else {
        banout_release(banout);
        return default_udp_parse(out, timestamp, px, length, parsed, entropy);
    }
}

/****************************************************************************
 ****************************************************************************/
unsigned
coap_udp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    /*
     The frame header is 4 bytes long, with bytes 2 and 3 being
     the Message ID.
     We can also put up to 8 bytes of a "token" here instead of
     just using the message ID.
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Ver| T |  TKL  |      Code     |          Message ID           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   Token (if any, TKL bytes) ...
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    if (length < 4)
        return 0;

    px[2] = (unsigned char)(seqno >> 8);
    px[3] = (unsigned char)(seqno >> 0);

    return 0;
}


/****************************************************************************
 * For the selftest code, tests whether the indicated link is within the
 * given list.
 ****************************************************************************/
static int
test_is_link(const char *name, const unsigned char *vinput, struct CoapLink *links, size_t count, int line_number)
{
    size_t i;
    size_t name_length = strlen(name);
    const char *input = (const char *)vinput;
    
    for (i=0; i<count; i++) {
        const char *name2;
        if (name_length != links[i].link_length)
            continue;
        name2 = input + links[i].link_offset;
        if (memcmp(name2, name, name_length) != 0)
            continue;
        return 1; /* found */
    }
    
    fprintf(stderr, "[-] proto-coap failed at line number %d\n", line_number);
    return 0; /* not found */
}

/****************************************************************************
 ****************************************************************************/
int
proto_coap_selftest(void)
{
    
    
    struct CoapLink *links;
    size_t count=0;

    /* test quoted */
    {
        static const unsigned char *input = (const unsigned char *)
        "</sensors/temp>;if=\"se\\\"\\;\\,\\<\\>\\\\nsor\",</success>";
        links = parse_links(input, 0, (unsigned)(~0), &count);
        if (!test_is_link("/success", input, links, count, __LINE__))
            return 1;
    }

    /* test a simple link */
    {
        static const unsigned char *input = (const unsigned char *)
            "</sensors/temp>;if=\"sensor\"";
        links = parse_links(input, 0, (unsigned)(~0), &count);
        if (!test_is_link("/sensors/temp", input, links, count, __LINE__))
            return 1;
    }


    /* Test a complex dump */
    {
        static const unsigned char *input = (const unsigned char *)
            "</sensors/temp>;if=\"sensor\","
            "</sensors/light>;if=\"sensor\","
            "</sensors>;ct=40,"
            "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\","
            "</sensors/light>;rt=\"light-lux\";if=\"sensor\","
            "</sensors/light>;rt=\"light-lux\";if=\"sensor\","
            "</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\","
            "</sensors>;ct=40;title=\"Sensor Index\","
            "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\","
            "</sensors/light>;rt=\"light-lux\";if=\"sensor\","
            "<http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\";rel=\"describedby\","
            "</t>;anchor=\"/sensors/temp\";rel=\"alternate\","
            "</firmware/v2.1>;rt=\"firmware\";sz=262144"
            ;
        links = parse_links(input, 0, (unsigned)(~0), &count);
        if (!test_is_link("/firmware/v2.1", input, links, count, __LINE__))
            return 1;
    }
    
    /* Now test an entire packet */
    {
        const char input[] =
            "\x60\x45\x01\xce\xc1\x28\xff\x3c\x2f\x72\x65\x67\x69\x73\x74\x65"
            "\x72\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x64\x69\x73\x3e\x2c\x3c\x2f"
            "\x6e\x64\x6d\x2f\x63\x69\x3e\x2c\x3c\x2f\x6d\x69\x72\x72\x6f\x72"
            "\x3e\x2c\x3c\x2f\x75\x68\x70\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x6c"
            "\x6f\x67\x6f\x75\x74\x3e\x2c\x3c\x2f\x6e\x64\x6d\x2f\x6c\x6f\x67"
            "\x69\x6e\x3e\x2c\x3c\x2f\x69\x6e\x66\x6f\x3e";
        unsigned request_id = 0;
        struct BannerOutput banout[1];
        bool is_valid;
        banout_init(banout);
        
        /* parse a test packet */
        is_valid = coap_parse( (const unsigned char*)input,
                   sizeof(input)-1,
                   banout,
                   &request_id
                   );
        //fprintf(stderr, "[+] %.*s\n", (int)banout_string_length(banout, PROTO_COAP), banout_string(banout, PROTO_COAP));
        
        if (!is_valid)
            return 1;
        if (request_id != 462)
            return 1;
        
        {
            const unsigned char *str = banout_string(banout, PROTO_COAP);
            size_t str_length = banout_string_length(banout, PROTO_COAP);
            if (str_length <= 16 && memcmp(str, "rsp=2.5(Content)", 16) != 0)
                return 1;
        }
        
        banout_release(banout);

    }
    
    return 0;
}
