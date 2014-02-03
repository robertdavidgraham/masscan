/*

    Parses DNS response information

    The scanner sends a CHAOS TXT query for "version.bind". This module parses
    DNS in order to find the response string.
*/
#include "proto-udp.h"
#include "proto-dns.h"
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




#define VERIFY_REMAINING(n) if (offset+(n) > length) return;


/****************************************************************************
 * This skips over a name field while parsing the packet. If the name
 * is just a two-byte compression field likce 0xc0 0x1a, then it'll skip
 * those two bytes. However, when it does the skip, it does validate
 * the name. Thus, if it's a compressed name, it'll follow the compression
 * links to validate things like long names and infinite recursion.
 ****************************************************************************/
static unsigned
dns_name_skip_validate(const unsigned char *px, unsigned offset, unsigned length, unsigned name_length)
{
    unsigned ERROR = length + 1;
    unsigned result = offset + 2;
    unsigned recursion = 0;

    /* 'for all labels' */
    for (;;) {
        unsigned len;

        /* validate: the eventual uncompressed name will be less than 255 */
        if (name_length >= 255)
            return ERROR;

        /* validate: haven't gone off end of packet */
        if (offset >= length)
            return ERROR;

        /* grab length of next label */
        len = px[offset];

        /* Do two types of processing, either a compression code or a
         * original label. Note that we can alternate back and forth
         * between these two states. */
        if (len & 0xC0) {
            /* validate: top 2 bits are 11*/
            if ((len & 0xC0) != 0xC0)
                return ERROR;

            /* validate: enough bytes left for 2 byte compression field */
            if (offset + 1 >= length)
                return ERROR;

            /* follow the compression pointer to the next location */
            offset = (px[offset]&0x3F)<<8 | px[offset+1];

            /* validate: follow a max of 4 links */
            if (++recursion > 4)
                return ERROR;
        } else {
            /* we have a normal label */
            recursion = 0;

            /* If the label-length is zero, then that meaans we've reached
             * the end of the name */
            if (len == 0) {
                return result; /* end of domain name */
            }

            /* There are more labels to come, therefore skip this and go
             * to the next one */
            name_length += len + 1;
            offset += len + 1;
        }
    }
}

/****************************************************************************
 * Just skip the name, without validating whether it's valid or not. This
 * is for re-parsing the packet usually, after we've validated that all
 * the names are ok.
 ****************************************************************************/
unsigned
dns_name_skip(const unsigned char px[], unsigned offset, unsigned max)
{
    unsigned name_length = 0;

    /* Loop through all labels
     * NOTE: the only way this loops around is in the case of a normal
     * label. All other conditions cause a 'return' from this function */
    for (;;) {
        if (name_length >= 255)
            return max + 1;

        if (offset >= max)
            return max + 1;

        switch (px[offset]>>6) {
        case 0:
            /* uncompressed label */
            if (px[offset] == 0) {
                return offset+1; /* end of domain name */
            } else {
                name_length += px[offset] + 1;
                offset += px[offset] + 1;
                continue;
            }
            break;
        case 3:
            /* 0xc0 = compressed name */
            return dns_name_skip_validate(px, offset, max, name_length);
        case 2:
            /* 0x40 - ENDS0 extended label type
             * rfc2671 section 3.1
             * I have no idea how to parse this */
            return max + 1; /* totally clueless how to parse it */
        case 1:
            return max + 1;
        }
    }
}

/****************************************************************************
 ****************************************************************************/
static void
dns_extract_name(const unsigned char px[], unsigned offset, unsigned max,
                 struct DomainPointer *name)
{
    name->length = 0;

    for (;;) {
        unsigned len;

        if (offset >= max)
            return;

        len = px[offset];
        if (len & 0xC0) {
            if ((len & 0xC0) != 0xC0)
                return;
            else if (offset + 1 >= max)
                return;
            else {
                offset = (px[offset]&0x3F)<<8 | px[offset+1];
            }
        } else {
            if (len == 0) {
                return; /* end of domain name */
            } else {
                memcpy((unsigned char*)name->name+name->length, px+offset, len+1);
                name->length = (unsigned char)(name->length + len + 1);
                offset += len + 1;
            }
        }
    }
}


/****************************************************************************
 ****************************************************************************/
void
proto_dns_parse(struct DNS_Incoming *dns, const unsigned char px[], unsigned offset, unsigned max)
{
    static const unsigned MAX_RRs = sizeof(dns->rr_offset)/sizeof(dns->rr_offset[0]);
    unsigned i;

    dns->is_valid = 0; /* not valid yet until we've successfully parsed*/

    dns->req = px;
    dns->req_length = max-offset;
    dns->edns0.payload_size = 512; /* rfc 1035 4.2.1 */


    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    if (max - offset < 12)
        return;
    dns->id = px[offset+0]<<8 | px[offset+1];
    dns->qr = (px[offset+2]>>7)&1;
    dns->aa = (px[offset+2]>>2)&1;
    dns->tc = (px[offset+2]>>1)&1;
    dns->rd = (px[offset+2]>>0)&1;
    dns->ra = (px[offset+3]>>7)&1;
    dns->z = (px[offset+3]>>4)&7;
    dns->opcode = (px[offset+2]>>3)&0xf;
    dns->rcode = (px[offset+3]>>0)&0xf;
    dns->qdcount = px[offset+4]<<8 | px[offset+5];
    dns->ancount = px[offset+6]<<8 | px[offset+7];
    dns->nscount = px[offset+8]<<8 | px[offset+9];
    dns->arcount = px[offset+10]<<8 | px[offset+11];
    dns->rr_count = 0; /* so far */
    offset += 12;
    dns->is_valid = 1;
    dns->is_formerr = 1; /* is "formate-error" until we've finished parsing */

    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    for (i=0; i<dns->qdcount; i++) {
        unsigned xclass;
        unsigned xtype;
        if (dns->rr_count >= MAX_RRs)
            return;
        dns->rr_offset[dns->rr_count++] = (unsigned short)offset;
        offset = dns_name_skip(px, offset, max);
        offset += 4; /* length of type and class */
        if (offset > max)
            return;
        xclass = px[offset-2]<<8 | px[offset-1];
        if (xclass != 1 && xclass != 255 && xclass != 3)
            return;
        xtype = px[offset-4]<<8 | px[offset-3];
        dns->query_type = xtype;
    }

    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    for (i=0; i<dns->ancount + dns->nscount; i++) {
        unsigned rdlength;
        if (dns->rr_count >= sizeof(dns->rr_offset)/sizeof(dns->rr_offset[0]))
            return;
        dns->rr_offset[dns->rr_count++] = (unsigned short)offset;
        offset = dns_name_skip(px, offset, max);
        offset += 10;
        if (offset > max)
            return;
        rdlength = px[offset-2]<<8 | px[offset-1];
        offset += rdlength;
        if (offset > max)
            return;
    }
    for (i=0; i<dns->arcount; i++) {
        unsigned rdlength;
        if (dns->rr_count >= sizeof(dns->rr_offset)/sizeof(dns->rr_offset[0]))
            return;
        dns->rr_offset[dns->rr_count++] = (unsigned short)offset;

        /* ENDS0 OPT parsing */
        if (offset + 11 <= max && px[offset] == 0 && px[offset+1] == 0 && px[offset+2] == 0x29) {
            dns->edns0.payload_size = px[offset+3]<<8 | px[offset+4];
            if (dns->edns0.payload_size < 512)
                return;
            dns->rcode |= px[offset+5]<<4;
            dns->edns0.version = px[offset+6];
            dns->is_edns0 = 1;
        }

        offset = dns_name_skip(px, offset, max);
        offset += 10;
        if (offset > max)
            return;
        rdlength = px[offset-2]<<8 | px[offset-1];
        offset += rdlength;
        if (offset > max)
            return;
    }

    dns->query_name.name = dns->query_name_buffer;
    dns_extract_name(px, dns->rr_offset[0], max, &dns->query_name);

    dns->is_formerr = 0;
    return;
}


/***************************************************************************
 * Set the "syn-cookie" style information so that we can validate replies
 * match a valid request. We don't hold "state" on the requests, so this
 * becomes a hash of the port/IP information.
 * DNS has a two-byte "transaction id" field, so we can't use the full
 * cookie, just the lower two bytes of it.
 * Below in "handle_dns", we validate that the cookie is correct.
 ***************************************************************************/
unsigned
dns_set_cookie(unsigned char *px, size_t length, uint64_t cookie)
{
    if (length > 2) {
        px[0] = (unsigned char)(cookie >> 8);
        px[1] = (unsigned char)(cookie >> 0);
        return cookie & 0xFFFF;
    } else
        return 0;
}

/***************************************************************************
 * Process a DNS packet received in response to UDP probes to port 53.
 * This function has three main tasks:
 *  - parse the DNS protocol, and make sure it's valid DNS.
 *  - make sure that the DNS response matches a valid request using
 *    the "syn-cookie" approach.
 *  - parse the "version.bind" response and report it as the version
 *    string for the banner.
 ***************************************************************************/
unsigned
handle_dns(struct Output *out, time_t timestamp,
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
    if (dns->qdcount != 1)
        return 0;
    if (dns->ancount < 1)
        return 0;
    if (dns->rr_count < 2)
        return 0;


    offset = dns->rr_offset[1];
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
        if (type != 0x10 || xclass != 3)
            return 0;

        offset += 11;

        output_report_banner(
                out, timestamp,
                ip_them, 17, port_them,
                PROTO_DNS_VERSIONBIND,
                parsed->ip_ttl,
                px + offset, txtlen);
    }


    return 0;
}
