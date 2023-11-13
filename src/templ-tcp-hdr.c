/*
 This module edits an existing TCP packet, adding and removing
 options, setting the values of certain fields.

 From RFC793:

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 TCP Window Scale Option (WSopt):
 Kind: 3 Length: 3 bytes
 +---------+---------+---------+
 | Kind=3  |Length=3 |shift.cnt|
 +---------+---------+---------+

 TCP Timestamps Option (TSopt):
 Kind: 8
 Length: 10 bytes
 +-------+-------+---------------------+---------------------+
 |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
 +-------+-------+---------------------+---------------------+
 1       1              4                     4

 TCP Sack-Permitted Option:
 Kind: 4
 +---------+---------+
 | Kind=4  | Length=2|
 +---------+---------+


 TCP SACK Option:
 Kind: 5
 Length: Variable

 +--------+--------+
 | Kind=5 | Length |
 +--------+--------+--------+--------+
 |      Left Edge of 1st Block       |
 +--------+--------+--------+--------+
 |      Right Edge of 1st Block      |
 +--------+--------+--------+--------+
 |                                   |
 /            . . .                  /
 |                                   |
 +--------+--------+--------+--------+
 |      Left Edge of nth Block       |
 +--------+--------+--------+--------+
 |      Right Edge of nth Block      |
 +--------+--------+--------+--------+

 */
#include "templ-tcp-hdr.h"
#include "templ-opts.h"
#include "util-logger.h"
#include "proto-preprocess.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

struct tcp_opt_t {
    const unsigned char *buf;
    size_t length;
    unsigned kind;
    bool is_found;
};

struct tcp_hdr_t {
    size_t begin;
    size_t max;
    size_t ip_offset;
    unsigned char ip_version;
    bool is_found;
};

/**
 * Do a memmove() of a chunk of memory within a buffer with bounds checking.
 */
static void
safe_memmove(unsigned char *buf, size_t length, size_t to, size_t from, size_t chunklength) {
    if (chunklength + to > length) {
        fprintf(stderr, "+"); fflush(stderr);
        chunklength = length - to;
    }
    if (chunklength + from > length) {
        fprintf(stderr, "-"); fflush(stderr);
        chunklength = length - from;
    }
    memmove(buf + to, buf + from, chunklength);
}

/**
 * Do a memset() of a chunk of memory within a buffer with bounds checking
 */
static void
safe_memset(unsigned char *buf, size_t length, size_t offset, int c, size_t chunklength) {
    if (chunklength + offset > length) {
        chunklength = length - offset;
        fprintf(stderr, "*"); fflush(stderr);
    }
    memset(buf + offset, c, chunklength);
}

/***************************************************************************
 * A typical hexdump function, but dumps specifically the <options-list>
 * section of a TCP header. An added feature is that it marks the byte
 * at "offset". This makes debugging easier, so I can see the <options-list>
 * as I'm stepping through code. You'll see this commented-out throughout
 * the code.
 ***************************************************************************/
static void
_HEXDUMP(const void *v, struct tcp_hdr_t hdr, size_t offset, const char *name)
{
    const unsigned char *p = ((const unsigned char *)v) + hdr.begin + 20;
    size_t i;
    size_t len = hdr.max - hdr.begin + 8 - 20;

    printf("%s:\n", name);
    offset -= hdr.begin + 20;

    for (i=0; i<len; i += 16) {
        size_t j;

        for (j=i; j<i+16 && j<len; j++) {
            char c = ' ';
            if (j == offset)
                c = '>';
            if (j + 1 == offset)
                c = '<';
            printf("%02x%c", p[j], c);
        }
        for (;j<i+16; j++)
            printf("   ");
        printf("  ");
        for (j=i; j<i+16 && j<len; j++) {
            char c = p[j];

            if (j == offset)
                c = '#';

            if (isprint(c&0xff) && !isspace(c&0xff))
                printf("%c", c);
            else
                printf(".");
        }
        printf("\n");
    }
}



/***************************************************************************
 * A quick macro to calculate the TCP header length, given a buffer
 * and an offset to the start of the TCP header.
 ***************************************************************************/
static unsigned inline
_tcp_header_length(const unsigned char *buf, size_t offset) {
    return (buf[offset + 12] >> 4) * 4;
}

/***************************************************************************
 * Does a consistency check of the whole packet, including IP header,
 * TCP header, and the options in the <options-list> field. This is used
 * in the self-test feature after test cases, to make sure the packet
 * hasn't bee corrupted.
 ***************************************************************************/
static int
_consistancy_check(const unsigned char *buf, size_t length,
                   const void *payload, size_t payload_length) {
    struct PreprocessedInfo parsed;
    unsigned is_success;

    /* Parse the packet */
    is_success = preprocess_frame(buf,
                                  (unsigned)length,
                                  1 /*enet*/,
                                  &parsed);
    if (!is_success || parsed.found != FOUND_TCP) {
        fprintf(stderr, "[-] check: TCP header not found\n");
        goto fail;
    }

    /* Check the lengths */
    switch (parsed.ip_version) {
        case 4:
            if (parsed.ip_length + 14 != length) {
                fprintf(stderr, "[-] check: IP length bad\n");
                goto fail;
            }
            break;
        case 6:
            break;
        default:
            fprintf(stderr, "[-] check: IPv?\n");
            goto fail;
    }

    /* Validate TCP header options */
    {
        size_t offset = parsed.transport_offset;
        size_t max = offset + _tcp_header_length(buf, offset);

        /* Get the start of the <options> section of the header. This is defined
         * as 20 bytes into the TCP header. */
        offset += 20;

        /* Enumerate any existing options one-by-one.  */
        while (offset < max) {
            unsigned kind;
            unsigned len;

            /* Get the option type (aka. "kind") */
            kind = buf[offset++];

            if (kind == 0x00) {
                /* EOL - end of options list
                 * According to the spec, processing should stop here, even if
                 * there are additional options after this point. */
                break;
            } else if (kind == 0x01) {
                /* NOP - No-operation
                 * This is a single byte option, used to pad other options to
                 * even 4 byte boundaries. Padding is optional. */
                continue;
            }

            /* If we've reached the end of */
            if (offset > max)
                goto fail;
            if (offset == max)
                break;
            len = buf[offset++];

            /* Check for corruption, the lenth field is inclusive, so should
             * equal at least two. It's maximum length should be bfore the end
             * of the packet */
            if (len < 2 || len > (max-offset+2)) {
                goto fail;
            }

            offset += len - 2;
        }
    }

    /* Check the payload */
    if (parsed.app_length != payload_length)
        goto fail;
    if (memcmp(buf + parsed.app_offset, payload, payload_length) != 0)
        goto fail;

    return 0;
fail:
    return 1;
}

/***************************************************************************
 * Find the TCP header in the packet. We can't be sure what's in the
 * current template because it could've been provided by the user, so
 * we instead parse it as if we've received it from the network wire.
 ***************************************************************************/
static struct tcp_hdr_t
_find_tcp_header(const unsigned char *buf, size_t length) {
    struct tcp_hdr_t hdr = {0};
    struct PreprocessedInfo parsed;
    unsigned is_success;

    /*
     * Parse the packet, telling us where the TCP header is. This works
     * for both IPv4 and IPv6, we care only about the TCP header portion.
     */
    is_success = preprocess_frame(buf, /* the packet, including Ethernet hdr */
                                  (unsigned)length,
                                  1 /*enet*/,
                                  &parsed);
    if (!is_success || parsed.found != FOUND_TCP) {
        /* We were unable to parse a well-formatted TCP packet. This
         * might've been UDP or something. */
        goto fail;
    }

    hdr.begin = parsed.transport_offset;
    hdr.max = hdr.begin + _tcp_header_length(buf, hdr.begin);
    hdr.ip_offset = parsed.ip_offset;
    hdr.ip_version = (unsigned char)parsed.ip_version;
    hdr.is_found = true;
    return hdr;

fail:
    hdr.is_found = false;
    return hdr;
}

/***************************************************************************
 * A quick macro at the start of for(;;) loops that enumerate all the
 * options in the <option-list>
 ***************************************************************************/
static inline size_t
_opt_begin(struct tcp_hdr_t hdr) {
    return hdr.begin + 20; /* start of <options> field */
}

/***************************************************************************
 * A quick macro in the for(;;) loop that enumerates all the options
 * in the <option-list>. It has three possibilities based on the KIND:
 * 0x00 - we've reached the end of the options-list
 * 0x01 - padding NOP byte, which we skipo
 * 0x?? - some option, the following byte is the length. We skip
 *        that `len` bytes.
 ***************************************************************************/
static inline size_t
_opt_next(struct tcp_hdr_t hdr, size_t offset, const unsigned char *buf) {
    unsigned kind = buf[offset];
    if (kind == 0x00) {
        return hdr.max;
    } else if (kind == 0x01) {
        return offset + 1;
    } else if (offset + 2 > hdr.max) {
        return hdr.max; /* corruption */
    } else {
        unsigned len = buf[offset+1];
        if (len < 2 || offset + len > hdr.max)
            return hdr.max; /* corruption */
        else
            return offset + len;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
_HEXDUMPopt(const unsigned char *buf, size_t length, const char *name) {
    struct tcp_hdr_t hdr;

    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found) {
        fprintf(stderr, "[-] templ.tcp.hdr: failure\n");
    }
    _HEXDUMP(buf, hdr, _opt_begin(hdr), name);
}

/***************************************************************************
 * Search throgh the <option-list> until we find the specified option,
 * 'kind', or reach the end of the list. An impossible 'kind', like 0x100,
 * will force finding the end of the list before padding starts.
 ***************************************************************************/
static size_t
_find_opt(const unsigned char *buf, struct tcp_hdr_t hdr, unsigned in_kind,
          unsigned *nop_count) {
    size_t offset;

    /* This field is optional, if used, set it to zero */
    if (nop_count)
        *nop_count = 0;

    /* enumerate all <options> looking for a match */
    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;

        /* get the option type/kind */
        kind = buf[offset];

        /* Stop search if we hit an EOL marker */
        if (kind == 0x00)
            break;

        /* Stop search when we find our option */
        if (kind == in_kind)
            break;

        /* Count the number of NOPs leading up to where we end */
        if (nop_count) {
            if (kind == 0x01)
                (*nop_count)++;
            else
                (*nop_count) = 0;
        }
    }
    return offset;
}

/***************************************************************************
 * Search the TCP header's <options> field for the specified kind/type.
 * Typical kinds of options are MSS, window scale, SACK, timestamp.
 ***************************************************************************/
static struct tcp_opt_t
tcp_find_opt(const unsigned char *buf, size_t length, unsigned in_kind) {
    struct tcp_opt_t result = {0};
    struct tcp_hdr_t hdr;
    size_t offset;

    /* Get the TCP header in the packet */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* Search for a matchin <option> */
    offset = _find_opt(buf, hdr, in_kind, 0);
    if (offset >= hdr.max || buf[offset] != in_kind)
        goto fail;

    /* We've found it! If we've passed all the checks above, we have
     * a well formatted field, so just return it. */
    result.kind = in_kind;
    result.buf = buf + offset + 2;
    result.length = buf[offset+1] - 2;
    if (offset + result.length >= hdr.max)
        goto fail;
    result.is_found = true;
    return result;

fail:
    result.is_found = false;
    return result;
}

/***************************************************************************
 * Adjusts the IP "total length" and TCP "header length" fields to match
 * recent additions/removals of options in the <option-list>
 ***************************************************************************/
static void
_adjust_length(unsigned char *buf, size_t length, int adjustment, struct tcp_hdr_t hdr) {
    size_t ip_offset = hdr.ip_offset;

    /* The adjustment should already have been aligned on an even 4 byte
     * boundary */
    if ((adjustment & 0x3) != 0) {
        fprintf(stderr, "[-] templ.tcp: impossible alignment error\n");
        return;
    }

    /* Adjust the IP header length */
    switch (hdr.ip_version) {
        case 4: {
            unsigned total_length;
            total_length = buf[ip_offset+2] << 8 | buf[ip_offset+3] << 0;
            total_length += adjustment;
            buf[ip_offset+2] = (unsigned char)(total_length>>8);
            buf[ip_offset+3] = (unsigned char)(total_length>>0);
            total_length = buf[ip_offset+2] << 8 |buf[ip_offset+3] << 0;
            if (total_length + 14 != length) {
                fprintf(stderr, "[-] IP length mismatch\n");
            }
            break;
        }
        case 6: {
            unsigned payload_length;
            payload_length = buf[ip_offset+4] << 8 | buf[ip_offset+5] << 0;
            payload_length += adjustment;
            buf[ip_offset+4] = (unsigned char)(payload_length>>8);
            buf[ip_offset+5] = (unsigned char)(payload_length>>0);
            break;
        }
    }

    /* Adjust the TCP header length */
    {
        size_t hdr_length;
        size_t offset = hdr.begin + 12;

        hdr_length = (buf[offset] >> 4) * 4;

        hdr_length += adjustment;

        if (hdr_length % 4 != 0) {
            fprintf(stderr, "[-] templ.tcp corruptoin\n");
        }

        buf[offset] = (unsigned char)((buf[offset] & 0x0F) | ((hdr_length/4) << 4));

        hdr_length = (buf[offset] >> 4) * 4;
        if (hdr.begin + hdr_length > length) {
            fprintf(stderr, "[-] templ.tcp corruptoin\n");
        }
    }
}

/***************************************************************************
 * After adding/removing an option, the <option-list> may no longer be
 * aligned on an even 4-byte boundary as required. This function
 * adds padding as necessary to align to the boundary.
 ***************************************************************************/
static void
_add_padding(unsigned char **inout_buf, size_t *inout_length, size_t offset, unsigned pad_count) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;

    length += pad_count;
    buf = realloc(buf, length);

    /* open space between headers and payload */
    safe_memmove(buf, length,
                offset + pad_count,
                offset,
                (length - pad_count) - offset);

    /* set padding to zero */
    safe_memset(buf, length,
                offset, 0, pad_count);

    /* Set the out parameters */
    *inout_buf = buf;
    *inout_length = length;
}

/***************************************************************************
 * Afte changes, there my be more padding bytes than necessary. This
 * reduces the number to 3 or less. Also, it changes any trailing NOPs
 * to EOL bytes, since there are no more options after that point.
 ***************************************************************************/
static bool
_normalize_padding(unsigned char **inout_buf, size_t *inout_length) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;
    struct tcp_hdr_t hdr;
    size_t offset;
    unsigned nop_count = 0;

    /* find TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;


    /* find the start of the padding field  */
    offset = _find_opt(buf, hdr, 0x100, &nop_count);
    if (offset >= hdr.max && nop_count == 0)
        goto success; /* no padding needing to be removed */

    /* If NOPs immediately before EOL, include them too */
    offset -= nop_count;

    {
        size_t remove_count = hdr.max - offset;

        /* the amount removed must be aligned on 4-byte boundary */
        while (remove_count % 4)
            remove_count--;

        /* If we have nothing left to remove, then exit.
         * THIS IS THE NORMAL CASE -- most of the time, we have no
         * extra padding to remove. */
        if (remove_count == 0)
            goto fail; /* likely, normal*/

        //_HEXDUMP(buf, hdr, offset, "before padding removal");

        safe_memmove(buf, length,
                        offset,
                        offset + remove_count,
                        length - (offset + remove_count));
        hdr.max -= remove_count;
        length -= remove_count;

        /* normalize all the bytes to zero, in case they aren't already */
        safe_memset(buf, length, offset, 0, hdr.max - offset);

        //_HEXDUMP(buf, hdr, offset, "after padding removal");

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, 0 - (int)remove_count, hdr);
    }

success:
    *inout_buf = buf;
    *inout_length = length;
    return true; /* success */
fail:
    *inout_buf = buf;
    *inout_length = length;
    return false; /* failure */

}


/***************************************************************************
 ***************************************************************************/
static bool
tcp_remove_opt(
        unsigned char **inout_buf, size_t *inout_length, unsigned in_kind
               ) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;
    struct tcp_hdr_t hdr;
    size_t offset;
    unsigned nop_count = 0;

    /* find the TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* enumerate all the <options> looking for a match  */
    offset = _find_opt(buf, hdr, in_kind, &nop_count);
    if (offset + 2 >= hdr.max)
        goto success; /* not found, no matching option type/kind */


    {
        unsigned opt_len = buf[offset+1];
        unsigned remove_length = opt_len;

        if (offset + opt_len > hdr.max)
            goto fail;

        /* Remove any trailing NOPs */
        while (offset + remove_length < hdr.max
               && buf[offset + remove_length] == 1)
            remove_length++;

        /* Remove any leading NOPs */
        offset -= nop_count;
        remove_length += nop_count;

        /* Remove the bytes from the current packet buffer.
         * Before this will be the ...IP/TCP headers plus maybe some options.
         * After this will be maybe some options, padding, then the TCP payload
         * */

        //_HEXDUMP(buf, hdr, offset, "before removal");

        safe_memmove(buf, length,
                        offset,
                        offset + remove_length,
                        length - (offset + remove_length));
        hdr.max -= remove_length;
        length -= remove_length;

        //_HEXDUMP(buf, hdr, offset, "after removal");


        /* Now we may need to add back padding  */
        if (remove_length % 4) {
            unsigned add_length = (remove_length % 4);
            _add_padding(&buf, &length, hdr.max, add_length);
            remove_length -= add_length;
            hdr.max += add_length;
        }

        //_HEXDUMP(buf, hdr, offset, "padding added");

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, 0 - remove_length, hdr);

        /* In case we've padded the packet with four 0x00, get rid
         * of them */
        _normalize_padding(&buf, &length);
    }

success:
    *inout_buf = buf;
    *inout_length = length;
    return true;

fail:
    *inout_buf = buf;
    *inout_length = length;
    return false;
}

/***************************************************************************
 ***************************************************************************/
static int
_insert_field(unsigned char **inout_buf,
              size_t *inout_length,
              size_t offset_begin,
              size_t offset_end,
              const unsigned char *new_data,
              size_t new_length
              ) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;
    int adjust = 0;

    /* can theoreitcally be negative, but that's ok */
    adjust = (int)new_length - ((int)offset_end - (int)offset_begin);
    if (adjust > 0) {
        length += adjust;
        buf = realloc(buf, length);
        safe_memmove(buf, length,
                        offset_begin + new_length,
                        offset_end,
                        (length - adjust) - offset_end);
    }
    if (adjust < 0) {
        safe_memmove(buf, length,
                        offset_begin + new_length,
                        offset_end,
                        length - offset_end);
        length += adjust;
        buf = realloc(buf, length);
    }

    /**/
    memcpy(buf + offset_begin,
           new_data,
           new_length);

    *inout_buf = buf;
    *inout_length = length;

    return adjust;
}

/** Calculate the total number of padding bytes, both NOPs in the middle
 * and EOLs at the end. We call this when there's not enough space for
 * another option, and we want to remove all the padding. */
#if 0
static unsigned
_calc_padding(const unsigned char *buf, struct tcp_hdr_t hdr) {
    size_t offset;
    unsigned result = 0;

    /* enumerate through all <option> fields */
    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;

        /* Get the kind: 0=EOL, 1=NOP, 2=MSS, 3=Wscale, etc. */
        kind = buf[offset];

        /* If EOL, we end here, and all the remainder bytes are counted
         * as padding. */
        if (kind == 0) {
            result += (hdr.max - offset);
            break;
        }

        /* If a NOP, then this is a padding byte */
        if (kind == 1)
            result++;
    }

    return result;
}
#endif

/***************************************************************************
 * Remove all the padding bytes, and return an offset to the beginning
 * of the rest of the option field.
 ***************************************************************************/
static size_t
_squeeze_padding(unsigned char *buf, size_t length, struct tcp_hdr_t hdr, unsigned in_kind) {
    size_t offset;
    unsigned nop_count = 0;

    for (offset = _opt_begin(hdr);
         offset < hdr.max;
         offset = _opt_next(hdr, offset, buf)) {
        unsigned kind;
        unsigned len;

        //_HEXDUMP(buf, hdr, offset, "squeeze");

        /* Get the kind: 0=EOL, 1=NOP, 2=MSS, 3=Wscale, etc. */
        kind = buf[offset];

        /* If a NOP padding, simply count it until we reach something
         * more interesting */
        if (kind == 0x01) {
            nop_count++;
            continue;
        }

        /* If end of option list, any remaining padding bytes are added */
        if (kind == 0x00) {
            /* normalize the padding at the end */
            offset -= nop_count;
            safe_memset(buf, length, offset, 0, hdr.max - offset);

            //_HEXDUMP(buf, hdr, offset, "null");

            return offset;
        }

        /* If we match an existing field, all those bytes become padding */
        if (kind == in_kind) {
            len = buf[offset+1];
            safe_memset(buf, length, offset, 0x01, len);
            nop_count++;

            //_HEXDUMP(buf, hdr, offset, "VVVVV");

            continue;
        }

        if (nop_count == 0)
            continue; /*no squeezing needed */

        /* move this field backward overwriting NOPs */
        len = buf[offset+1];
        safe_memmove(buf, length,
                        offset - nop_count,
                        offset,
                        len);

        //_HEXDUMP(buf, hdr, offset - nop_count, "<<<<");

        /* now write NOPs where this field used to be */
        safe_memset(buf, length, 
                    offset + len - nop_count, 0x01, nop_count);

        //_HEXDUMP(buf, hdr, offset + len - nop_count, "!!!!!");

        /* reset the <offset> to the end of this relocated field */
        offset -= nop_count;
        nop_count = 0;
    }

    /* if we reach the end, then there were only NOPs at the end and no
     * EOL byte, so simply zero them out */
    safe_memset(buf, length, 
                offset - nop_count, 0x00, nop_count);
    offset -= nop_count;

    //_HEXDUMP(buf, hdr, offset, "");

    return offset;
}


/***************************************************************************
 ***************************************************************************/
static bool
tcp_add_opt(unsigned char **inout_buf,
            size_t *inout_length,
            unsigned opt_kind,
            unsigned opt_length,
            const unsigned char *opt_data) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;
    struct tcp_hdr_t hdr;
    size_t offset;
    unsigned nop_count = 0;
    int adjust = 0;


    /* Check for corruption:
     * The maximum size of a TCP header is 60 bytes (0x0F * 4), and the
     * rest of the header takes up 20 bytes. The [kind,length] takes up
     * another 2 bytes. Thus, the max option length is 38 bytes */
    if (opt_length > 38) {
        fprintf(stderr, "[-] templ.tcp.add_opt: opt_len too large\n");
        goto fail;
    }


    /* find TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* enumerate all existing options looking match */
    offset = _find_opt(buf, hdr, opt_kind, &nop_count);

    {
        size_t old_begin;
        size_t old_end;
        unsigned char new_field[64];
        size_t new_length;

        /* Create a well-formatted field that will be inserted */
        new_length = 1 + 1 + opt_length;
        new_field[0] = (unsigned char)opt_kind;
        new_field[1] = (unsigned char)new_length;
        memcpy(new_field + 2, opt_data, opt_length);

        /* Calculate the begin/end of the existing field in the packet */
        old_begin = offset;
        if (old_begin >= hdr.max)
            old_end = hdr.max; /* will insert end of header */
        else if (buf[offset] == 0x00)
            old_end = hdr.max; /* will insert start of padding */
        else if (buf[offset] == opt_kind) { /* will replace old field */
            size_t len = buf[offset + 1];
            old_end = offset + len;
        } else {
            fprintf(stderr, "[-] not possible i09670t\n");
            return false;
        }

        /* If the existing space is too small, try to expand it by
         * using neighboring (leading, trailing) NOPs */
        while ((old_end-old_begin) < new_length) {
            if (nop_count) {
                nop_count--;
                old_begin--;
            } else if (old_end < hdr.max && buf[old_end] == 0x01) {
                old_end++;
            } else
                break;
        }

        /* If the existing space is too small, and we are at the end,
         * and there's pading, then try to use the padding */
        if ((old_end-old_begin) < new_length) {
            if (old_end < hdr.max) {
                if (buf[old_end] == 0x00) {
                    /* normalize padding to all zeroes */
                    safe_memset(buf, length, old_end, 0, hdr.max - old_end);

                    while ((old_end-old_begin) < new_length) {
                        if (old_end >= hdr.max)
                            break;
                        old_end++;
                    }
                }
            }
        }

        /* Make sure we have enough space in the header */
        {
            static const size_t max_tcp_hdr = (0xF0>>4) * 4; /* 60 */
            size_t added = new_length - (old_end - old_begin);
            if (hdr.max + added > hdr.begin + max_tcp_hdr) {
                //unsigned total_padding = _calc_padding(buf, hdr);
                old_begin = _squeeze_padding(buf, length, hdr, opt_kind);
                old_end = hdr.max;
            }
        }


        /* Now insert the option field into packet. This may change the
         * sizeof the packet. The amount changed is indicated by 'adjust' */
        adjust = _insert_field(&buf, &length,
                               old_begin, old_end,
                               new_field, new_length);
        hdr.max += adjust;
    }

    if (adjust) {

        /* TCP headers have to be aligned to 4 byte boundaries, so we may need
         * to add padding of 0 at the end of the header to handle this */
        if (adjust % 4 && adjust > 0) {
            unsigned add_length = 4 - (adjust % 4);
            _add_padding(&buf, &length, hdr.max, add_length);
            hdr.max += add_length;
            adjust += add_length;
        } else if (adjust % 4 && adjust < 0) {
            unsigned add_length = 0 - (adjust % 4);

            //_HEXDUMP(buf, hdr, hdr.max, "pad before");
            _add_padding(&buf, &length, hdr.max, add_length);
            hdr.max += add_length;
            adjust += add_length;

            //_HEXDUMP(buf, hdr, hdr.max, "pad after");
        }

        /* fix the IP and TCP length fields */
        _adjust_length(buf, length, adjust, hdr);

        /* In case we've padded the packet with four 0x00, get rid
         * of them */
        _normalize_padding(&buf, &length);
    }

    *inout_buf = buf;
    *inout_length = length;
    return true;

fail:
    /* no changes were made */
    *inout_buf = buf;
    *inout_length = length;
    return false;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
tcp_get_mss(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;
    unsigned result = 0;

    opt = tcp_find_opt(buf, length, 2 /* MSS */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 2) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    result = opt.buf[0] << 8 | opt.buf[1];

    return result;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
tcp_get_wscale(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;
    unsigned result = 0;

    opt = tcp_find_opt(buf, length, 3 /* Wscale */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 1) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    result = opt.buf[0];

    return result;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
tcp_get_sackperm(const unsigned char *buf, size_t length, bool *is_found) {
    struct tcp_opt_t opt;

    opt = tcp_find_opt(buf, length, 3 /* Wscale */);
    if (is_found)
        *is_found = opt.is_found;
    if (!opt.is_found)
        return 0xFFFFffff;

    if (opt.length != 1) {
        /* corrupt */
        if (is_found)
            *is_found = false;
        return 0xFFFFffff;
    }

    return 0;
}

/***************************************************************************
 * Called at the end of configuration, to change the TCP header template
 * according to configuration. For example, we might add a "sackperm" field,
 * or delete an "mss" field, or change the value of "mss".
 ***************************************************************************/
void
templ_tcp_apply_options(unsigned char **inout_buf, size_t *inout_length,
                  const struct TemplateOptions *templ_opts) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;

    if (templ_opts == NULL)
        return;

    /* --tcp-mss <num>
     * Sets maximum segment size */
    if (templ_opts->tcp.is_mss == Remove) {
        tcp_remove_opt(&buf, &length, 2 /* mss */);
    } else if (templ_opts->tcp.is_mss == Add) {
        unsigned char field[2];
        field[0] = (unsigned char)(templ_opts->tcp.mss>>8);
        field[1] = (unsigned char)(templ_opts->tcp.mss>>0);
        tcp_add_opt(&buf, &length, 2, 2, field);
    }

    /* --tcp-sackok
     * Sets option flag that permits selective acknowledgements */
    if (templ_opts->tcp.is_sackok == Remove) {
        tcp_remove_opt(&buf, &length, 4 /* sackok */);
    } else if (templ_opts->tcp.is_sackok == Add) {
        tcp_add_opt(&buf, &length, 4, 0, (const unsigned char*)"");
    }

    /* --tcp-wscale <num>
     * Sets window scale option  */
    if (templ_opts->tcp.is_wscale == Remove) {
        tcp_remove_opt(&buf, &length, 3 /* wscale */);
    } else if (templ_opts->tcp.is_wscale == Add) {
        unsigned char field[1];
        field[0] = (unsigned char)templ_opts->tcp.wscale;
        tcp_add_opt(&buf, &length, 3, 1, field);
    }

    /* --tcp-ts <num>
     * Timestamp */
    if (templ_opts->tcp.is_tsecho == Remove) {
        tcp_remove_opt(&buf, &length, 8 /* ts */);
    } else if (templ_opts->tcp.is_tsecho == Add) {
        unsigned char field[10] = {0};
        field[0] = (unsigned char)(templ_opts->tcp.tsecho>>24);
        field[1] = (unsigned char)(templ_opts->tcp.tsecho>>16);
        field[2] = (unsigned char)(templ_opts->tcp.tsecho>>8);
        field[2] = (unsigned char)(templ_opts->tcp.tsecho>>0);
        tcp_add_opt(&buf, &length, 8, 8, field);
    }


    *inout_buf = buf;
    *inout_length = length;
}

/***************************************************************************
 * Used during selftests in order to create a known options field as the
 * starting before before changing it somehow, followed by using
 * _compare_options() to test whether the change succeeded.
 ***************************************************************************/
static bool
_replace_options(unsigned char **inout_buf, size_t *inout_length,
                        const char *new_options, size_t new_length) {
    unsigned char *buf = *inout_buf;
    size_t length = *inout_length;
    struct tcp_hdr_t hdr;
    size_t offset;
    size_t old_length;
    char newnew_options[40] = {0};
    int adjust = 0;

    /* Maximum length of the options field is 40 bytes */
    if (new_length > 40)
        goto fail;

    /* Pad new options to 4 byte boundary */
    memcpy(newnew_options, new_options, new_length);
    while (new_length % 4)
        new_length++;

    /* find TCP header */
    hdr = _find_tcp_header(buf, length);
    if (!hdr.is_found)
        goto fail;

    /* Find start of options field */
    offset = _opt_begin(hdr);
    old_length = hdr.max - offset;

    /* Either increase or decrease the old length appropriately */
    //_HEXDUMPopt(buf, length, "resize before");
    adjust = (int)(new_length - old_length);
    if (adjust > 0) {
        length += adjust;
        buf = realloc(buf, length);
        safe_memmove(buf, length,
                        hdr.max + adjust,
                        hdr.max,
                        (length - adjust) - hdr.max);
    }
    if (adjust < 0) {
        safe_memmove(   buf, length,
                        hdr.max + adjust,
                        hdr.max,
                        length - hdr.max);
        length += adjust;
        buf = realloc(buf, length);
    }

    
    /* Now that we've resized the options field, overright
     * it with then new field */
    memcpy(buf + offset, newnew_options, new_length);

    /* fix the IP and TCP length fields */
    _adjust_length(buf, length, adjust, hdr);

    //_HEXDUMPopt(buf, length, "resize after");


    *inout_buf = buf;
    *inout_length = length;
    return true;
fail:
    *inout_buf = buf;
    *inout_length = length;
    return false;
}

/***************************************************************************
 ***************************************************************************/
enum {
    TST_NONE,
    TST_PADDING,
    TST_ADD,
    TST_REMOVE,
};

/***************************************************************************
 * This structure specifies test cases for the sefltest function. Each
 * test has a pre-condition <options-list>, and option to add/remove, and
 * a post-condition <options-list> that should match the result.
 ***************************************************************************/
struct mytests_t {
    struct {
        const char *options;
        size_t length;
    } pre;
    struct {
        int opcode;
        const char *data;
        size_t length;
    } test;
    struct {
        const char *options;
        size_t length;
    } post;
};

/***************************************************************************
 * The following tests add/remove options to a test packet. The goal of
 * these tests is code-coverage of all the conditions above, testing
 * all the boundary cases. Every code path that produces success is tested,
 * plus many code paths that produce failures.
 ***************************************************************************/
static struct mytests_t
tests[] = {
    /* A lot of these tests use 2-byte (\4\2) and 3-byte (\3\3\3) options.
     * The "\4\2" is "SACK permitted, kind=4, len=2, with no extra data.
     * The "\3\3\3" is "Window Scale, kind=3, len=3, data=3.
     * The "\2\4\5\6" is "Max Segment Size", kind=2, len=4, data=0x0506
     */

    /* Attempt removal of an option that doesn't exist. This is not
     * a failure, but a success, though nothing is changed*/

    {   {"\3\3\3\0", 4},
        {TST_REMOVE, "\x08", 1},
        {"\3\3\3\0", 4}
    },


    /* Test removal of an option. This will also involve removing
     the now unnecessary padding */
    {   {"\3\3\3\1\1\1\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00", 16},
        {TST_REMOVE, "\x08", 1},
        {"\3\3\3\0", 4}
    },

    /* Test when trying to add a big option that won't fit unless we get
     * rid of all the padding */
    {   {   "\x02\x04\x05\xb4"
            "\x01\x03\x03\x06"
            "\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
            "\x04\x02\x00\x00"
            "\0\0\0\0",
            28},
        {   TST_ADD,
            "\7\x14" "AAAAAAAAAAAAAAAAAAAA",
            20
        },
        {   "\x02\x04\x05\xb4"
            "\x03\x03\x06"
            "\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
            "\x04\x02"
            "\7\x14" "AAAAAAAAAAAAAAAAAA"
            "\0",
            40
        }
    },

    /* same as a bove, but field exists*/
    {{  "\x02\x04\x05\xb4"
        "\x01\x03\x03\x06"
        "\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
        "\7\4\1\1"
        "\x04\x02\x00\x00",
        28},
        {   TST_ADD,
            "\7\x14" "AAAAAAAAAAAAAAAAAAAA",
            20
        },
        {   "\x02\x04\x05\xb4"
            "\x03\x03\x06"
            "\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
            "\x04\x02"
            "\7\x14" "AAAAAAAAAAAAAAAAAA"
            "\0",
            40
        }
    },
    
    /* Add a new value to full packet  */
    {{"\3\3\3", 3}, {TST_ADD, "\4\2", 2}, {"\3\3\3\4\2\0\0\0", 8}},

    /* Change a 3 byte to 5 byte in middle of packet  */
    {{"\1\7\3\3\1\1\4\2", 8}, {TST_ADD, "\7\5\5\5\5", 5}, {"\7\5\5\5\5\1\4\2", 8}},

    /* Change 3 to 4 byte at start */
    {{"\7\3\3\1\2\4\5\6", 8}, {TST_ADD, "\7\4\4\4", 4}, {"\7\4\4\4\2\4\5\6", 8}},

    /* Change a 2-byte option */
    {{"\4\2", 2}, {TST_ADD, "\4\2", 2}, {"\4\2\0\0", 4}},

    /* Change a 3-byte option */
    {{"\3\3\2", 3}, {TST_ADD, "\3\3\3", 3}, {"\3\3\3\0", 4}},

    /* Change a 4-byte option */
    {{"\2\4\1\1", 4}, {TST_ADD, "\2\4\5\6", 4}, {"\2\4\5\6", 4}},

    /* Add a 2-byte option to empty packet*/
    {{"", 0}, {TST_ADD, "\4\2", 2}, {"\4\2\0\0", 4}},

    /* Add a 3-byte option to empty packet*/
    {{"", 0}, {TST_ADD, "\3\3\3", 3}, {"\3\3\3\0", 4}},

    /* Add a 4-byte option to empty packet*/
    {{"", 0}, {TST_ADD, "\2\4\5\6", 4}, {"\2\4\5\6", 4}},

    /* Empty packet: padding normalization should make no changes */
    {{"", 0}, {TST_PADDING,0,0}, {"", 0}},

    /* Empty packet plus 4 bytes of padding, should be removed */
    {{"\0", 1}, {TST_PADDING,0,0}, {"", 0}},

    /* 8 bytes of padding, should only remove all of them */
    {{"\0\0\0\0\0\0\0\0", 8}, {TST_PADDING,0,0}, {"", 0}},

    /* some padding is nops, should remove all  */
    {{"\1\1\0\0\0\0\0\0", 8}, {TST_PADDING,0,0}, {"", 0}},

    /* any trailing NOPs should be converted to EOLs  */
    {{"\3\3\3\1\0\0\0\0", 8}, {TST_PADDING,0,0}, {"\3\3\3\0", 4}},

    /* only NOPs should still be removed */
    {{"\3\3\3\1\1\1\1\1", 8}, {TST_PADDING,0,0}, {"\3\3\3\0", 4}},

    {{0}}
};


/***************************************************************************
 * This function runs through the tests in the [tests] array above. It
 * first creates a packet accoding to a pre-condition that may have
 * options already. We then call a function to manipulate the packet,
 * such as adding/changing an option. We then verify that that the
 * <option-list> field now matches the post-condition. Along the way,
 * we look for any errors are consistency failures.
 ***************************************************************************/
static int
_selftests_run(void) {
    static unsigned char templ[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Ethernet type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x48"      /* total length = 64 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x06"      /* TTL=255, proto=TCP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\0\0"          /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* sequence number */
    "\0\0\0\0"      /* ACK number */
    "\xB0"          /* header length */
    "\x02"          /* SYN */
    "\x04\x01"      /* window fixed to 1024 */
    "\xFF\xFF"      /* checksum */
    "\x00\x00"      /* urgent pointer */

    "\x02\x04\x05\xb4"
    "\x01\x03\x03\x06"
    "\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
    "\x04\x02\x00\x00"
    "DeadBeef"
    ;
    size_t i;

    /* execute all tests */
    for (i=0; tests[i].pre.options; i++) {
        unsigned char *buf;
        size_t length = sizeof(templ) - 1;
        bool success;
        struct tcp_hdr_t hdr;
        const unsigned char *field;
        size_t field_length;


        LOG(1, "[+] templ-tcp-hdr: run #%u\n", (unsigned)i);

        /* Each tests creates its own copy of the test packet, which it
         * will then alter according to the pre-conditions. */
        buf = malloc(length);
        memcpy(buf, templ, length);

        /* Set the pre-condition <option-list> field by replacing what
         * was there with a completely new field */
        success = _replace_options(&buf, &length,
                         tests[i].pre.options, tests[i].pre.length);
        if (!success)
            goto fail; /* this should never happen */
        if (_consistancy_check(buf, length, "DeadBeef", 8))
            goto fail; /* this shoiuld never happen*/


        //_HEXDUMPopt(buf, length, "[PRE]");

        /*
         * Run the desired test
         */
        switch (tests[i].test.opcode) {
            case TST_PADDING:
                /* We are testing the "normalize padding" function. This
                 * is called after ever 'add' or 'remove' to make sure that
                 * the padding at the end is consistent. Mostly, it means
                 * that when we remove a field, we'll probably have excess
                 * padding at the end, which needs to be trimmed to the
                 * minimum amount of padding */
                success = _normalize_padding(&buf, &length);
                if (!success)
                    goto fail;
                break;
            case TST_ADD:
                /* We are testing `tcp_add_opt()` function, which is called
                 * to either 'add' or 'change' an existing option. */
                field = (const unsigned char*)tests[i].test.data;
                field_length = tests[i].test.length;
                if (field_length < 2)
                    goto fail;
                else {
                    unsigned opt_kind = field[0];
                    unsigned opt_length = field[1];
                    const unsigned char *opt_data = field + 2;

                    if (field_length != opt_length)
                        goto fail;

                    /* skip the KIND and LENGTH fields, justa DATA length */
                    opt_length -= 2;

                    success = tcp_add_opt(&buf, &length,
                                          opt_kind,
                                          opt_length,
                                          opt_data);
                    if (!success)
                        goto fail;
                }
                break;
            case TST_REMOVE:
                /* We are testing `tcp_add_opt()` function, which is called
                 * to either 'add' or 'change' an existing option. */
                field = (const unsigned char*)tests[i].test.data;
                field_length = tests[i].test.length;
                if (field_length != 1)
                    goto fail;
                else {
                    unsigned opt_kind = field[0];

                    success = tcp_remove_opt(&buf, &length,
                                          opt_kind);

                    if (!success)
                        goto fail;
                }
                break;
            default:
                return 1; /* fail */
        }

        //_HEXDUMPopt(buf, length, "[POST]");

        if (_consistancy_check(buf, length, "DeadBeef", 8))
            goto fail;

        /*
         * Make sure output matches expected results
         */
        {
            size_t offset;
            int err;
            size_t post_length;

            /* Find the <options-list> field */
            hdr = _find_tcp_header(buf, length);
            if (!hdr.is_found)
                goto fail;
            offset = _opt_begin(hdr);

            /* Make sure the length matches the expected length */
            post_length = hdr.max - offset;
            if (tests[i].post.length != post_length)
                goto fail;

            /* makre sure the contents of the field match expected */
            err = memcmp(tests[i].post.options, buf+offset, (hdr.max-offset));
            if (err) {
                _HEXDUMPopt(buf, length, "[-] failed expectations");
                goto fail;
            }
        }

        free(buf);
    }

    return 0; /* success */
fail:
    fprintf(stderr, "[-] templ.tcp.selftest failed, test #%u\n",
            (unsigned)i);
    return 1;
};

/***************************************************************************
 * These self-tests manipulate a TCP header, adding and removing <option>
 * fields in various scenarios. We expose the `tcp_add_option()` function
 * to the end-user via the command-line, so we have to anticipate that
 * the option they want added is going to be corrupt. For example, the
 * end-user might try to add an option that overflows the <option-list>
 * field, which is rather small (only 40 bytes long).
 ***************************************************************************/
int
templ_tcp_selftest(void) {

    static unsigned char templ[] =
    "\0\1\2\3\4\5"  /* Ethernet: destination */
    "\6\7\x8\x9\xa\xb"  /* Ethernet: source */
    "\x08\x00"      /* Ethernet type: IPv4 */
    "\x45"          /* IP type */
    "\x00"
    "\x00\x48"      /* total length = 64 bytes */
    "\x00\x00"      /* identification */
    "\x00\x00"      /* fragmentation flags */
    "\xFF\x06"      /* TTL=255, proto=TCP */
    "\xFF\xFF"      /* checksum */
    "\0\0\0\0"      /* source address */
    "\0\0\0\0"      /* destination address */

    "\0\0"          /* source port */
    "\0\0"          /* destination port */
    "\0\0\0\0"      /* sequence number */
    "\0\0\0\0"      /* ACK number */
    "\xB0"          /* header length */
    "\x02"          /* SYN */
    "\x04\x01"      /* window fixed to 1024 */
    "\xFF\xFF"      /* checksum */
    "\x00\x00"      /* urgent pointer */

    "\x02\x04\x05\xb4"
    "\x01\x03\x03\x06"
    "\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"
    "\x04\x02\x00\x00"
    "DeadBeef"
    ;
    size_t length = sizeof(templ) - 1;
    unsigned char *buf;

    /* Execute planned selftests */
    if (_selftests_run())
        return 1;

    /* We need to make an allocated copy of the buffer, because the
     * size may change from `realloc()` */
    buf = malloc(length);
    memcpy(buf, templ, length);

    /*
     * Make sure we start wtih an un-corrupted test packet
     */
    if (_consistancy_check(buf, length, "DeadBeef", 8))
        goto fail;

    if (1460 != tcp_get_mss(buf, length, 0))
        goto fail;
    if (6 != tcp_get_wscale(buf, length, 0))
        goto fail;
    if (0 != tcp_get_sackperm(buf, length, 0))
        goto fail;

    tcp_add_opt(&buf, &length, 2, 2, (const unsigned char*)"\x12\x34");
    if (0x1234 != tcp_get_mss(buf, length, 0))
        goto fail;
    if (_consistancy_check(buf, length, "DeadBeef", 8))
        goto fail;

    tcp_remove_opt(&buf, &length, 3);
    if (0x1234 != tcp_get_mss(buf, length, 0))
        goto fail;
    if (0xFFFFffff != tcp_get_wscale(buf, length, 0))
        goto fail;
    if (_consistancy_check(buf, length, "DeadBeef", 8))
        goto fail;


    free(buf);
    return 0; /* success */
fail:
    free(buf);
    return 1; /* failure */
}
