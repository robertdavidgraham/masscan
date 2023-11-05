#include "templ-nmap-payloads.h"
#include "massip-port.h"
#include "massip-rangesv4.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>


/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void
trim(char *line, size_t sizeof_line)
{
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
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

        trim(line, sizeof_line);
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
hexval(unsigned c)
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
parse_c_string(unsigned char *buf, size_t *buf_length,
               size_t buf_max, const char *line)
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
 * Called during processing of the "--nmap-payloads <filename>" directive.
 ***************************************************************************/
void
read_nmap_payloads(FILE *fp, const char *filename,
                      struct PayloadsUDP *payloads,
                      payloads_datagram_add_cb add_payload
                      )
{
    char line[16384];
    unsigned line_number = 0;


    line[0] = '\0';

    for (;;) {
        unsigned is_error = 0;
        const char *p;
        struct RangeList ports[1] = {{0}};
        unsigned source_port = 0x10000;
        unsigned char buf[1500] = {0};
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
        trim(line, sizeof(line));


        /* [ports] */
        if (!get_next_line(fp, &line_number, line, sizeof(line)))
            break;
        p = rangelist_parse_ports(ports, line, &is_error, 0);
        if (is_error) {
            fprintf(stderr, "%s:%u: syntax error, expected ports\n",
                    filename, line_number);
            goto end;
        }
        memmove(line, p, strlen(p)+1);
        trim(line, sizeof(line));

        /* [C string] */
        for (;;) {
            trim(line, sizeof(line));
            if (!get_next_line(fp, &line_number, line, sizeof(line)))
                break;
            if (line[0] != '\"')
                break;

            p = parse_c_string(buf, &buf_length, sizeof(buf), line);
            memmove(line, p, strlen(p)+1);
            trim(line, sizeof(line));
        }

        /* [source] */
        if (memcmp(line, "source", 6) == 0) {
            memmove(line, line+6, strlen(line+5));
            trim(line, sizeof(line));
            if (!isdigit(line[0])) {
                fprintf(stderr, "%s:%u: expected source port\n",
                        filename, line_number);
                goto end;
            }
            source_port = (unsigned)strtoul(line, 0, 0);
            line[0] = '\0';
        }

        /*
         * Now we've completely parsed the record, so add it to our
         * list of payloads
         */
        if (buf_length)
            add_payload(payloads, buf, buf_length, ports, source_port);

        rangelist_remove_all(ports);
    }

end:
    ;//fclose(fp);
}

/****************************************************************************
 ****************************************************************************/
int
templ_nmap_selftest(void)
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

