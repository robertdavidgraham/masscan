#include "templ-payloads.h"
#include "ranges.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

struct Payload {
    unsigned port;
    unsigned source_port;
    unsigned length;
    unsigned xsum;
    unsigned char buf[1];
};

struct NmapPayloads {
    unsigned count;
    unsigned max;
    struct Payload **list;
};

/***************************************************************************
 * If we have the port, return the payload
 ***************************************************************************/
int
payloads_lookup(
        const struct NmapPayloads *payloads, 
        unsigned port, 
        const unsigned char **px, 
        unsigned *length, 
        unsigned *source_port, 
        unsigned *xsum)
{
    unsigned i;
    if (payloads == 0)
        return 0;
    
    port &= 0xFFFF;

    for (i=0; i<payloads->count; i++) {
        if (payloads->list[i]->port == port) {
            *px = payloads->list[i]->buf;
            *length = payloads->list[i]->length;
            *source_port = payloads->list[i]->source_port;
            *xsum = payloads->list[i]->xsum;
            return 1;
        }
    }
    return 0;
}

/***************************************************************************
 ***************************************************************************/
struct NmapPayloads *
payloads_create()
{
    struct NmapPayloads *payloads;
    payloads = (struct NmapPayloads *)malloc(sizeof(*payloads));
    memset(payloads, 0, sizeof(*payloads));
    return payloads;
}

/***************************************************************************
 ***************************************************************************/
void
payloads_destroy(struct NmapPayloads *payloads)
{
    unsigned i;
    if (payloads == NULL)
        return;
    
    for (i=0; i<payloads->count; i++)
        free(payloads->list[i]);

    if (payloads->list)
        free(payloads->list);

    free(payloads);
}

/***************************************************************************
 * We read lots of UDP payloads from the files. However, we probably
 * aren't using most, or even any, of them. Therefore, we use this
 * function to remove the ones we won't be using. This makes lookups
 * faster, ideally looking up only zero or one rather than twenty.
 ***************************************************************************/
void
payloads_trim(struct NmapPayloads *payloads, const struct RangeList *ports)
{
    unsigned i;

    for (i=payloads->count; i>0; i--) {
        struct Payload *p = payloads->list[i-1];

        if (!rangelist_is_contains(ports, p->port + 65536)) {
            free(p);
            memmove(payloads->list + i - 1, payloads->list + i, (payloads->count - i) * sizeof(payloads->list[0]));
            payloads->count--;
        }
    }
}

/***************************************************************************
 ***************************************************************************/
static void
trim(char *line)
{
    while (isspace(line[0]&0xFF))
        memmove(&line[0], &line[1], strlen(line));
    while (isspace(line[strlen(line)-1]&0xFF))
        line[strlen(line)-1] = '\0';
}

/***************************************************************************
 ***************************************************************************/
static int
is_comment(const char *line)
{
    if (line[0] == '#' || line[0] == '/' || line[0] == ';')
        return 1;
    else
        return 0;
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static void
append_byte(unsigned char *buf, size_t *buf_length, size_t buf_max, unsigned c)
{
    if (*buf_length < buf_max)
        buf[(*buf_length)++] = (unsigned char)c;

}

/***************************************************************************
 ***************************************************************************/
static int
isodigit(int c)
{
    if ('0' <= c && c <= '7')
        return 1;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(int c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static const char *
parse_c_string(unsigned char *buf, size_t *buf_length, size_t buf_max, const char *line)
{
    size_t offset;

    if (*line != '\"')
        return line;
    else
        offset = 1;

    while (line[offset] && line[offset] != '\"') {
        if (line[offset] == '\\') {
            offset++;
            switch (line[offset]) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                {
                    unsigned val = 0;

                    if (isodigit(line[offset]))
                        val = val * 8 + hexval(line[offset++]);
                    if (isodigit(line[offset]))
                        val = val * 8 + hexval(line[offset++]);
                    if (isodigit(line[offset]))
                        val = val * 8 + hexval(line[offset++]);
                    append_byte(buf, buf_length, buf_max, val);
                    continue;
                }
                break;
            case 'x':
                offset++;
                {
                    unsigned val = 0;

                    if (isxdigit(line[offset]))
                        val = val * 16 + hexval(line[offset++]);
                    if (isxdigit(line[offset]))
                        val = val * 16 + hexval(line[offset++]);
                    append_byte(buf, buf_length, buf_max, val);
                    continue;
                }
                break;

            case 'a':
                append_byte(buf, buf_length, buf_max, '\a');
                break;
            case 'b':
                append_byte(buf, buf_length, buf_max, '\b');
                break;
            case 'f':
                append_byte(buf, buf_length, buf_max, '\f');
                break;
            case 'n':
                append_byte(buf, buf_length, buf_max, '\n');
                break;
            case 'r':
                append_byte(buf, buf_length, buf_max, '\r');
                break;
            case 't':
                append_byte(buf, buf_length, buf_max, '\t');
                break;
            case 'v':
                append_byte(buf, buf_length, buf_max, '\v');
                break;
            default:
            case '\\':
                append_byte(buf, buf_length, buf_max, line[offset]);
                break;
            }
        } else 
            append_byte(buf, buf_length, buf_max, line[offset]);

        offset++;
    }

    if (line[offset] == '\"')
        offset++;

    return line + offset;

}

/***************************************************************************
 ***************************************************************************/
static char *
get_next_line(FILE *fp, unsigned *line_number, char *line, size_t sizeof_line)
{
    if (line[0] != '\0')
        return line;

    for (;;) {
        char *p;

        p = fgets(line, (unsigned)sizeof_line, fp);
        if (p == NULL) {
            line[0] = '\0';
            return NULL;
        }
        (*line_number)++;

        trim(line);
        if (is_comment(line))
            continue;
        if (line[0] == '\0')
            continue;

        return line;
    }
}


/***************************************************************************
 ***************************************************************************/
static void
payload_add(struct NmapPayloads *payloads, const unsigned char *buf, size_t length, struct RangeList *ports, unsigned source_port)
{
    struct Payload *p;
    uint64_t port_count = rangelist_count(ports);
    uint64_t i;

    for (i=0; i<port_count; i++) {
        /* grow the list if we need to */
        if (payloads->count + 1 > payloads->max) {
            unsigned new_max = payloads->max*2 + 1;
            struct Payload **new_list;

            new_list = (struct Payload**)malloc(new_max * sizeof(new_list[0]));
            memcpy(new_list, payloads->list, payloads->count * sizeof(new_list[0]));
            free(payloads->list);
            payloads->list = new_list;
            payloads->max = new_max;
        }

        /* allocate space for this record */
        p = (struct Payload *)malloc(sizeof(p[0]) + length);
        p->port = rangelist_pick(ports, i);
        p->source_port = source_port;
        p->length = (unsigned)length;
        memcpy(p->buf, buf, length);

        /* insert in sorted order */
        {
            unsigned j;

            for (j=0; j<payloads->count; j++) {
                if (p->port < payloads->list[j]->port)
                    break;
            }
            if (j < payloads->count)
                memmove(    payloads->list + j + 1,
                            payloads->list + j, 
                            (payloads->count-j) * sizeof(payloads->list[0]));
            payloads->list[j] = p;

            payloads->count++;
        }
    }

}

/***************************************************************************
 ***************************************************************************/
void
payloads_read_file(FILE *fp, const char *filename, struct NmapPayloads *payloads)
{
    char line[16384];
    unsigned line_number = 0;


    line[0] = '\0';

    for (;;) {
        const char *p;
        struct RangeList ports[1];
        unsigned source_port = 0x10000;
        unsigned char buf[1500];
        size_t buf_length = 0;

        memset(ports, 0, sizeof(ports[0]));

        /* [UDP] */
        if (!get_next_line(fp, &line_number, line, sizeof(line)))
            break;

        if (memcmp(line, "udp", 3) != 0) {
            fprintf(stderr, "%s:%u: syntax error, expected \"udp\".\n",
                filename, line_number);
            goto end;
        } else
            memmove(line, line+3, strlen(line));
        trim(line);


        /* [ports] */
        if (!get_next_line(fp, &line_number, line, sizeof(line)))
            break;
        p = rangelist_parse_ports(ports, line);
        memmove(line, p, strlen(p)+1);
        trim(line);

        /* [C string] */
        for (;;) {
            trim(line);
            if (!get_next_line(fp, &line_number, line, sizeof(line)))
                break;
            if (line[0] != '\"')
                break;

            p = parse_c_string(buf, &buf_length, sizeof(buf), line);
            memmove(line, p, strlen(p)+1);
            trim(line);
        }

        /* [source] */
        if (memcmp(line, "source", 6) == 0) {
            memmove(line, line+6, strlen(line+5));
            trim(line);
            if (!isdigit(line[0])) {
                fprintf(stderr, "%s:%u: expected source port\n", filename, line_number);
                goto end;
            }
            source_port = strtoul(line, 0, 0);
            line[0] = '\0';
        }

        /*
         * Now we've completely parsed the record, so add it to our
         * list of payloads
         */
        payload_add(payloads, buf, buf_length, ports, source_port);

        rangelist_free(ports);
    }

#if 0
    /* */
    {
        unsigned i;

        for (i=0; i<payloads->count; i++) {
            struct Payload *p = payloads->list[i];
            unsigned j;

            printf("udp %u\n", p->port);
            printf(" \"");
            for (j=0; j<p->length; j++) {
                if (isprint(p->buf[j]))
                    printf("%c", p->buf[j]);
                else
                    printf("\\x%02x", p->buf[j]);
            }
            printf("\"\n");
            if (p->source_port < 65536)
                printf("source %u\n", p->source_port);
            printf("\n");
        }
    }
#endif

end:
    fclose(fp);
}



/***************************************************************************
 ***************************************************************************/
int
payloads_selftest()
{
    unsigned char buf[1024];
    size_t buf_length;

    buf_length = 0;
    parse_c_string(buf, &buf_length, sizeof(buf), "\"\\t\\n\\r\\x1f\\123\"");
    if (memcmp(buf, "\t\n\r\x1f\123", 5) != 0)
        return 1;
    return 0;

        /*
        "OPTIONS sip:carol@chicago.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n"
        "Max-Forwards: 70\r\n"
        "To: <sip:carol@chicago.com>\r\n"
        "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710\r\n"
        "CSeq: 63104 OPTIONS\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n"
        "Accept: application/sdp\r\n"
        "Content-Length: 0\r\n"
        */

}