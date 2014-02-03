#include "proto-netbios.h"
#include "proto-udp.h"
#include "proto-dns-parse.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan-app.h"
#include "proto-banner1.h"
#include "templ-port.h"
#include "masscan.h"
#include "unusedparm.h"

#include <ctype.h>

/***************************************************************************
 ***************************************************************************/
static void
append_char(unsigned char *banner, size_t banner_max, unsigned *banner_length, char c)
{
    if (*banner_length < banner_max)
        banner[(*banner_length)++] = c;
}


/***************************************************************************
 ***************************************************************************/
static void
append_name(unsigned char *banner, size_t banner_max, unsigned *banner_length, const unsigned char *name)
{
    unsigned i;
    unsigned char c;

    for (i=0; i<15; i++) {
        c = name[i];

        if (c == 0x20 || c == '\0')
            append_char(banner, banner_max, banner_length, ' ');
        else if (isalnum(c) || ispunct(c))
            append_char(banner, banner_max, banner_length, c);
        else {
            append_char(banner, banner_max, banner_length, '<');
            append_char(banner, banner_max, banner_length, "0123456789ABCDEF"[c>>4]);
            append_char(banner, banner_max, banner_length, "0123456789ABCDEF"[c&0xF]);
            append_char(banner, banner_max, banner_length, '>');
        }
    }

    c = name[i];
    append_char(banner, banner_max, banner_length, '<');
    append_char(banner, banner_max, banner_length, "0123456789ABCDEF"[c>>4]);
    append_char(banner, banner_max, banner_length, "0123456789ABCDEF"[c&0xF]);
    append_char(banner, banner_max, banner_length, '>');
    append_char(banner, banner_max, banner_length, '\n');
}

/*****************************************************************************
 * Process one of them many "resource-records" within the NBTSTAT response
 *****************************************************************************/
static unsigned
handle_nbtstat_rr(struct Output *out, time_t timestamp, unsigned ttl,
                  const unsigned char *px, unsigned length,
                  unsigned ip_them, unsigned port_them)
{
    unsigned char banner[65536];
    unsigned banner_length = 0;
    unsigned offset = 0;
    unsigned name_count;

    if (offset >= length)
        return 0;
    name_count = px[offset++];

    /* Report all the names */
    while (offset + 18 <= length && name_count) {
        append_name(banner, sizeof(banner), &banner_length, &px[offset]);
        offset += 18;
        name_count--;
    }

    /* Report the MAC address at the end */
    {
        unsigned i;

        for (i=0; i<6; i++) {
            if (offset + i < length) {
                unsigned char c = px[offset];
                append_char(banner, sizeof(banner), &banner_length, "0123456789ABCDEF"[c>>4]);
                append_char(banner, sizeof(banner), &banner_length, "0123456789ABCDEF"[c&0xF]);
                if (i < 5)
                    append_char(banner, sizeof(banner), &banner_length, '-');
            }
        }
    }


    output_report_banner(
            out, timestamp,
            ip_them, 17, port_them,
            PROTO_NBTSTAT,
            ttl,
            banner, banner_length);
    return 0;
}



/***************************************************************************
 ***************************************************************************/
unsigned
handle_nbtstat(struct Output *out, time_t timestamp,
    const unsigned char *px, unsigned length, 
    struct PreprocessedInfo *parsed,
    uint64_t entropy)
{
    unsigned ip_them;
    unsigned ip_me;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    struct DNS_Incoming dns[1];
    unsigned offset;
    uint64_t seqno;

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
            | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;

    seqno = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);

    proto_dns_parse(dns, px, parsed->app_offset, parsed->app_offset + parsed->app_length);

    if ((seqno & 0xFFFF) != dns->id)
        return 1;

    if (dns->qr != 1)
        return 0;
    if (dns->rcode != 0)
        return 0;
    if (dns->qdcount > 1)
        return 0;
    if (dns->ancount < 1)
        return 0;
    if (dns->rr_count < 1)
        return 0;


    offset = dns->rr_offset[dns->qdcount];
    offset = dns_name_skip(px, offset, length);
    if (offset + 10 >= length)
        return 0;

    {
        unsigned type = px[offset+0]<<8 | px[offset+1];
        unsigned xclass = px[offset+2]<<8 | px[offset+3];
        unsigned rrlen = px[offset+8]<<8 | px[offset+9];
        unsigned txtlen = px[offset+10];

        if (rrlen == 0 || txtlen > rrlen-1)
            return 0;
        if (type != 0x21 || xclass != 1)
            return 0;

        offset += 10;

        return handle_nbtstat_rr(out, timestamp, parsed->ip_ttl,
                                    px + offset,
                                    length - offset,
                                    ip_them,
                                    port_them);
    }

}
