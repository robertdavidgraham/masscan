/*
    Reads in UDP payload templates.

    This supports two formats. The first format is the "nmap-payloads" file
    included with the nmap port scanner.

    The second is the "libpcap" format that reads in real packets,
    extracting just the payloads, associated them with the destination
    UDP port.

 */
#include "templ-payloads.h"
#include "templ-port.h"
#include "rawsock-pcapfile.h"   /* for reading payloads from pcap files */
#include "proto-preprocess.h"   /* parse packets */
#include "ranges.h"             /* for parsing IP addresses */
#include "logger.h"
#include "proto-zeroaccess.h"   /* botnet p2p protocol */
#include "proto-snmp.h"
#include "proto-memcached.h"
#include "proto-coap.h"         /* constrained app proto for IoT udp/5683*/
#include "proto-ntp.h"
#include "proto-dns.h"
#include "util-malloc.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

struct PayloadUDP_Item {
    unsigned port;
    unsigned source_port; /* not used yet */
    unsigned length;
    unsigned xsum;
    unsigned rarity;
    SET_COOKIE set_cookie;
    unsigned char buf[1];
};
struct PayloadUDP_Default {
    unsigned port;
    unsigned source_port;
    unsigned length;
    unsigned xsum;
    SET_COOKIE set_cookie;
    char *buf;

};

struct PayloadsUDP {
    unsigned count;
    size_t max;
    struct PayloadUDP_Item **list;
};


struct PayloadUDP_Default hard_coded_oproto_payloads[] = {
    /* ECHO protocol - echoes back whatever we send */
    {47, 65536, 4, 0, 0, "\0\0\0\0"},
    {0,0,0,0,0}
};


struct PayloadUDP_Default hard_coded_udp_payloads[] = {
    /* ECHO protocol - echoes back whatever we send */
    {7, 65536, 12, 0, 0, "masscan-test 0x00000000"},

    /* QOTD - quote of the day (amplifier) */
    {17, 65536, 12, 0, 0, "masscan-test"},
    
    /* chargen - character generator (amplifier) */
    {19, 65536, 12, 0, 0, "masscan-test"},
    
    {53, 65536, 0x1f, 0, dns_set_cookie,
        /* 00 */"\x50\xb6"  /* transaction id */
        /* 02 */"\x01\x20"  /* quer y*/
        /* 04 */"\x00\x01"  /* query = 1 */
        /* 06 */"\x00\x00\x00\x00\x00\x00"
        /* 0c */"\x07" "version"  "\x04" "bind" "\x00"
        /* 1b */"\x00\x10" /* TXT */           
        /* 1d */"\x00\x03" /* CHAOS */
        /* 1f */
    },
    {123, 65536, 48, 0, ntp_set_cookie,
        "\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },
    {137, 65536, 50, 0, dns_set_cookie,
        "\xab\x12" /* transaction id */
        "\x00\x00" /* query */
        "\x00\x01\x00\x00\x00\x00\x00\x00" /* one question */
        "\x20" /*name length*/
        "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\x00"
        "\x00\x21" /* type = nbt */
        "\x00\x01" /* class = iternet*/
    },
    {161, 65536, 59, 0, snmp_set_cookie,
     "\x30" "\x39"
       "\x02\x01\x00"                    /* version */
       "\x04\x06" "public"               /* community = public */
       "\xa0" "\x2c"                     /* type = GET */
        "\x02\x04\x00\x00\x00\x00"      /* transaction id = ???? */
        "\x02\x01\x00"                  /* error = 0 */
        "\x02\x01\x00"                  /* error index = 0 */
         "\x30\x1e"
          "\x30\x0d"
           "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x01\x00" /*sysName*/
           "\x05\x00"          /*^^^^_____IDS LULZ HAH HA HAH*/
         "\x30\x0d"
           "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x05\x00" /*sysDesc*/
           "\x05\x00"},        /*^^^^_____IDS LULZ HAH HA HAH*/

    /* UPnP SSDP - Univeral Plug-n-Play Simple Service Discovery Protocol */
    {1900, 65536, 0xFFFFFFFF, 0, 0,
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "USER-AGENT: unix/1.0 UPnP/1.1 masscan/1.x\r\n"},

    {5060, 65536, 0xFFFFFFFF, 0, 0,
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
    },
    
    /* CoAP (contrained app proto for IoT) GET /.well-known/core request */
    {5683, 65536, 21, 0, coap_udp_set_cookie,
        "\x40"      /* ver=1 type=con */
        "\x01"      /* code=GET */
        "\x01\xce"  /* message id (changed by set-cookie) */
        "\xbb" /* ".well-known */
            "\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e"
        "\x04" /* "core" */
            "\x63\x6f\x72\x65"

    },

    /* memcached "stats" request. This looks for memcached systems that can
     * be used for DDoS amplifiers */
    {11211, 65536, 15, 0, memcached_udp_set_cookie,
        "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
    },

    //16464,16465,16470, 16471
    {16464, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16465, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16470, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16471, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},

    /* Quake 3 (amplifier)
     * http://blog.alejandronolla.com/2013/06/24/amplification-ddos-attack-with-quake3-servers-an-analysis-1-slash-2/
     */
    {27960, 65536, 0xFFFFFFFF, 0, 0,
        "\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10"},


    {0,0,0,0,0}
};


/***************************************************************************
 * Calculate the partial checksum of the payload. This allows us to simply
 * add this to the checksum when transmitting instead of recalculating
 * everything.
 ***************************************************************************/
static unsigned
partial_checksum(const unsigned char *px, size_t icmp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    for (i=0; i<icmp_length; i += 2) {
        xsum += px[i]<<8 | px[i + 1];
    }

    xsum -= (icmp_length & 1) * px[i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}

/***************************************************************************
 * If we have the port, return the payload
 ***************************************************************************/
int
payloads_udp_lookup(
        const struct PayloadsUDP *payloads,
        unsigned port,
        const unsigned char **px,
        unsigned *length,
        unsigned *source_port,
        uint64_t *xsum,
        SET_COOKIE *set_cookie)
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
            *set_cookie = payloads->list[i]->set_cookie;
            return 1;
        }
    }
    return 0;
}


/***************************************************************************
 ***************************************************************************/
void
payloads_udp_destroy(struct PayloadsUDP *payloads)
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
payloads_udp_trim(struct PayloadsUDP *payloads, const struct RangeList *target_ports)
{
    unsigned i;
    struct PayloadUDP_Item **list2;
    unsigned count2 = 0;

    /* Create a new list */
    list2 = REALLOCARRAY(0, payloads->max, sizeof(list2[0]));

    /* Add to the new list any used ports */
    for (i=0; i<payloads->count; i++) {
        unsigned found;

        found = rangelist_is_contains(  target_ports,
                                        payloads->list[i]->port + Templ_UDP);
        if (found) {
            list2[count2++] = payloads->list[i];
        } else {
            free(payloads->list[i]);
        }
        //payloads->list[i] = 0;
    }

    /* Replace the old list */
    free(payloads->list);
    payloads->list = list2;
    payloads->count = count2;
}

void
payloads_oproto_trim(struct PayloadsUDP *payloads, const struct RangeList *target_ports)
{
    unsigned i;
    struct PayloadUDP_Item **list2;
    unsigned count2 = 0;
    
    /* Create a new list */
    list2 = REALLOCARRAY(0, payloads->max, sizeof(list2[0]));
    
    /* Add to the new list any used ports */
    for (i=0; i<payloads->count; i++) {
        unsigned found;
        
        found = rangelist_is_contains(  target_ports,
                                      payloads->list[i]->port + Templ_Oproto_first);
        if (found) {
            list2[count2++] = payloads->list[i];
        } else {
            free(payloads->list[i]);
        }
    }
    
    /* Replace the old list */
    free(payloads->list);
    payloads->list = list2;
    payloads->count = count2;
}

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
 * Adds a payloads template for the indicated datagram protocol, which
 * is UDP or Oproto ("other IP protocol").
 ***************************************************************************/
static unsigned
payloads_datagram_add(struct PayloadsUDP *payloads,
            const unsigned char *buf, size_t length,
            struct RangeList *ports, unsigned source_port,
            SET_COOKIE set_cookie)
{
    unsigned count = 1;
    struct PayloadUDP_Item *p;
    uint64_t port_count = rangelist_count(ports);
    uint64_t i;

    for (i=0; i<port_count; i++) {
        /* grow the list if we need to */
        if (payloads->count + 1 > payloads->max) {
            size_t new_max = payloads->max*2 + 1;
            payloads->list = REALLOCARRAY(payloads->list, new_max, sizeof(payloads->list[0]));
            payloads->max = new_max;
        }

        /* allocate space for this record */
        p = MALLOC(sizeof(p[0]) + length);
        p->port = rangelist_pick(ports, i);
        p->source_port = source_port;
        p->length = (unsigned)length;
        memcpy(p->buf, buf, length);
        p->xsum = partial_checksum(buf, length);
        p->set_cookie = set_cookie;

        /* insert in sorted order */
        {
            unsigned j;

            for (j=0; j<payloads->count; j++) {
                if (p->port <= payloads->list[j]->port)
                    break;
            }

            if (j < payloads->count) {
                if (p->port == payloads->list[j]->port) {
                    free(payloads->list[j]);
                    count = 0; /* don't increment count */
                } else
                    memmove(payloads->list + j + 1,
                            payloads->list + j,
                            (payloads->count-j) * sizeof(payloads->list[0]));
            }
            payloads->list[j] = p;

            payloads->count += count;
        }
    }
    return count; /* zero or one */
}

/***************************************************************************
 * Called during processing of the "--pcap-payloads <filename>" directive.
 * This is the well-known 'pcap' file format. This code strips off the
 * headers of the packets then preserves just the payload portion
 * and port number.
 ***************************************************************************/
void
payloads_read_pcap(const char *filename,
                   struct PayloadsUDP *payloads,
                   struct PayloadsUDP *oproto_payloads)
{
    struct PcapFile *pcap;
    unsigned count = 0;

    LOG(2, "payloads:'%s': opening packet capture\n", filename);

    /* open packet-capture */
    pcap = pcapfile_openread(filename);
    if (pcap == NULL) {
        fprintf(stderr, "payloads: can't read from file '%s'\n", filename);
        return;
    }

    /* for all packets in the capture file
     *  - read in packet
     *  - parse packet
     *  - save payload
     */
    for (;;) {
        unsigned x;
        unsigned captured_length;
        unsigned char buf[65536];
        struct PreprocessedInfo parsed;
        struct RangeList ports[1] = {{0}};
        struct Range range[1] = {{0}};

        /*
         * Read the next packet from the capture file
         */
        {
            unsigned time_secs;
            unsigned time_usecs;
            unsigned original_length;

            x = pcapfile_readframe(pcap,
                    &time_secs, &time_usecs,
                    &original_length, &captured_length,
                    buf, (unsigned)sizeof(buf));
        }
        if (!x)
            break;

        /*
         * Parse the packet up to its headers
         */
        x = preprocess_frame(buf, captured_length, 1, &parsed);
        if (!x)
            continue; /* corrupt packet */

        /*
         * Make sure it has UDP
         */
        switch (parsed.found) {
        case FOUND_DNS:
        case FOUND_UDP:
                /*
                 * Kludge: mark the port in the format the API wants
                 */
                ports->list = range;
                ports->count = 1;
                ports->max = 1;
                range->begin = parsed.port_dst;
                range->end = range->begin;
                
                /*
                 * Now we've completely parsed the record, so add it to our
                 * list of payloads
                 */
                count += payloads_datagram_add(   payloads,
                                          buf + parsed.app_offset,
                                          parsed.app_length,
                                          ports,
                                          0x10000,
                                          0);
            break;
        case FOUND_OPROTO:
                /*
                 * Kludge: mark the port in the format the API wants
                 */
                ports->list = range;
                ports->count = 1;
                ports->max = 1;
                range->begin = parsed.ip_protocol;
                range->end = range->begin;
                
                /*
                 * Now we've completely parsed the record, so add it to our
                 * list of payloads
                 */
                count += payloads_datagram_add(oproto_payloads,
                                          buf + parsed.transport_offset,
                                          parsed.transport_length,
                                          ports,
                                          0x10000,
                                          0);
            break;
        default:
            continue;
        }

    }

    LOG(2, "payloads:'%s': imported %u unique payloads\n", filename, count);
    LOG(2, "payloads:'%s': closed packet capture\n", filename);
    pcapfile_close(pcap);
}

/***************************************************************************
 * Called during processing of the "--nmap-payloads <filename>" directive.
 ***************************************************************************/
void
payloads_udp_readfile(FILE *fp, const char *filename,
                   struct PayloadsUDP *payloads)
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
			payloads_datagram_add(payloads, buf, buf_length, ports, source_port, 0);

        rangelist_remove_all(ports);
    }

end:
    ;//fclose(fp);
}

/***************************************************************************
 ***************************************************************************/
struct PayloadsUDP *
payloads_udp_create(void)
{
    unsigned i;
    struct PayloadsUDP *payloads;
    struct PayloadUDP_Default *hard_coded = hard_coded_udp_payloads;
    
    payloads = CALLOC(1, sizeof(*payloads));
    
    /*
     * For popular parts, include some hard-coded default UDP payloads
     */
    for (i=0; hard_coded[i].length; i++) {
        //struct Range range;
        struct RangeList list = {0};
        unsigned length;

        /* Kludge: create a pseudo-rangelist to hold the one port */
        /*list.list = &range;
        list.count = 1;
        range.begin = hard_coded[i].port;
        range.end = range.begin;*/
        rangelist_add_range(&list, hard_coded[i].port, hard_coded[i].port);

        length = hard_coded[i].length;
        if (length == 0xFFFFFFFF)
            length = (unsigned)strlen(hard_coded[i].buf);

        /* Add this to our real payloads. This will get overwritten
         * if the user adds their own with the same port */
        payloads_datagram_add(payloads,
                    (const unsigned char*)hard_coded[i].buf,
                    length,
                    &list,
                    hard_coded[i].source_port,
                    hard_coded[i].set_cookie);

        rangelist_remove_all(&list);
    }
    return payloads;
}

/***************************************************************************
 * (same code as for UDP)
 ***************************************************************************/
struct PayloadsUDP *
payloads_oproto_create(void)
{
    unsigned i;
    struct PayloadsUDP *payloads;
    struct PayloadUDP_Default *hard_coded = hard_coded_oproto_payloads;
    
    payloads = CALLOC(1, sizeof(*payloads));
    
    /*
     * Some hard-coded ones, like GRE
     */
    for (i=0; hard_coded[i].length; i++) {
        //struct Range range;
        struct RangeList list = {0};
        unsigned length;
        
        /* Kludge: create a pseudo-rangelist to hold the one port */
        rangelist_add_range(&list, hard_coded[i].port, hard_coded[i].port);
        
        length = hard_coded[i].length;
        if (length == 0xFFFFFFFF)
            length = (unsigned)strlen(hard_coded[i].buf);
        
        /* Add this to our real payloads. This will get overwritten
         * if the user adds their own with the same port */
        payloads_datagram_add(payloads,
                         (const unsigned char*)hard_coded[i].buf,
                         length,
                         &list,
                         hard_coded[i].source_port,
                         hard_coded[i].set_cookie);
        
        rangelist_remove_all(&list);
    }
    return payloads;
}


/****************************************************************************
 ****************************************************************************/
int
payloads_udp_selftest(void)
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
