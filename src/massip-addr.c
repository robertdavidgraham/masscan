#include "massip-addr.h"
#include <string.h>


/**
 * Holds the output string, so that we can append to it without
 * overflowing buffers. The _append_xxx() functions below append
 * to this string.
 */
typedef struct stream_t {
    char *buf;
    size_t offset;
    size_t length;
} stream_t;

/**
 * Append a character to the output string. All the other _append_xxx()
 * functions call this one, so this is the only one where a
 * buffer-overflow can occur.
 */
static void
_append_char(stream_t *out, char c)
{
    if (out->offset < out->length)
        out->buf[out->offset++] = c;

    /* keep the string nul terminated as we build it */
    if (out->offset < out->length)
        out->buf[out->offset] = '\0';
}

static void
_append_ipv6(stream_t *out, const unsigned char *ipv6)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    int is_ellision = 0;

    /* An IPv6 address is printed as a series of 2-byte hex words
     * separated by colons :, for a total of 16-bytes */
    for (i = 0; i < 16; i += 2) {
        unsigned n = ipv6[i] << 8 | ipv6[i + 1];

        /* Handle the ellision case. A series of words with a value
         * of 0 can be removed completely, replaced by an extra colon */
        if (n == 0 && !is_ellision) {
            is_ellision = 1;
            while (i < 13 && ipv6[i + 2] == 0 && ipv6[i + 3] == 0)
                i += 2;
            _append_char(out, ':');

            /* test for all-zero address, in which case the output
             * will be "::". */
            while (i == 14 && ipv6[i] == 0 && ipv6[i + 1] == 0){
                i=16;
                _append_char(out, ':');
            }
            continue;
        }

        /* Print the colon between numbers. Fence-post alert: only colons
         * between numbers are printed, not at the beginning or end of the
         * string */
        if (i)
            _append_char(out, ':');

        /* Print the digits. Leading zeroes are not printed */
        if (n >> 12)
            _append_char(out, hex[(n >> 12) & 0xF]);
        if (n >> 8)
            _append_char(out, hex[(n >> 8) & 0xF]);
        if (n >> 4)
            _append_char(out, hex[(n >> 4) & 0xF]);
        _append_char(out, hex[(n >> 0) & 0xF]);
    }
}

struct ipaddress_formatted ipv6address_fmt(ipv6address a)
{
    struct ipaddress_formatted out;
    unsigned char tmp[16];
    size_t i;
    stream_t s;

    /*
     * Convert address into a sequence of bytes. Our code
     * here represents an IPv6 address as two 64-bit numbers, but
     * the formatting code above that we copied from a different
     * project represents it as an array of bytes.
     */
    for (i=0; i<16; i++) {
        uint64_t x;
        if (i<8)
            x = a.hi;
        else
            x = a.lo;
        x >>= (7 - (i%8)) * 8;

        tmp[i] = (unsigned char)(x & 0xFF);
    }

    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);
    _append_ipv6(&s, tmp);

    return out;
}

/**
 * Append a decimal integer.
 */
static void
_append_decimal(stream_t *out, unsigned long long n)
{
    char tmp[64];
    size_t tmp_offset = 0;

    /* Create temporary string */
    while (n >= 10) {
        unsigned digit = n % 10;
        n /= 10;
        tmp[tmp_offset++] = (char)('0' + digit);
    }
    
    /* the final digit, may be zero */
    tmp[tmp_offset++] = (char)('0' + n);

    /* Copy the result backwards */
    while (tmp_offset)
        _append_char(out, tmp[--tmp_offset]);
}
static void
_append_hex2(stream_t *out, unsigned long long n)
{
    static const char hex[17] = "0123456789abcdef";
    
    _append_char(out, hex[(n>>4)&0xF]);
    _append_char(out, hex[(n>>0)&0xF]);
}

struct ipaddress_formatted ipv4address_fmt(ipv4address ip)
{
    struct ipaddress_formatted out;
    stream_t s;


    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_decimal(&s, (ip >> 24) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 16) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 8) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 0) & 0xFF);

    return out;
}

struct ipaddress_formatted macaddress_fmt(macaddress_t mac)
{
    struct ipaddress_formatted out;
    stream_t s;


    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_hex2(&s, mac.addr[0]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[1]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[2]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[3]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[4]);
    _append_char(&s, '-');
    _append_hex2(&s, mac.addr[5]);

    return out;
}

struct ipaddress_formatted ipaddress_fmt(ipaddress a)
{
    struct ipaddress_formatted out;
    stream_t s;
    ipv4address ip = a.ipv4;

    if (a.version == 6) {
        return ipv6address_fmt(a.ipv6);
    }


    /* Call the formatting function */
    s.buf = out.string;
    s.offset = 0;
    s.length = sizeof(out.string);

    _append_decimal(&s, (ip >> 24) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 16) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 8) & 0xFF);
    _append_char(&s, '.');
    _append_decimal(&s, (ip >> 0) & 0xFF);

    return out;
}


static unsigned _count_long(uint64_t number)
{
    unsigned i;
    unsigned count = 0;
    for (i=0; i<64; i++) {
        if ((number >> i) & 1)
            count = i + 1;
    }
    return count;
}

unsigned massint128_bitcount(massint128_t number)
{
    if (number.hi)
        return _count_long(number.hi) + 64;
    else
        return _count_long(number.lo);
}

int ipv6address_selftest(void)
{
    int x = 0;
    ipaddress ip;
    struct ipaddress_formatted fmt;

    ip.version = 4;
    ip.ipv4 = 0x01FF00A3;

    fmt = ipaddress_fmt(ip);
    if (strcmp(fmt.string, "1.255.0.163") != 0)
        x++;

    return x;
}

int ipv6address_is_equal_prefixed(ipv6address_t lhs, ipv6address_t rhs, unsigned prefix)
{
    ipv6address mask;
    
    /* If the prefix is bad, then the answer is 'no'. */
    if (prefix > 128) {
        return 0;
    }

    /* Create the mask from the prefix */
    if (prefix > 64)
        mask.hi = ~0ULL;
    else if (prefix == 0)
        mask.hi = 0;
    else
        mask.hi = ~0ULL << (64 - prefix);
    
    if (prefix > 64)
        mask.lo = ~0ULL << (128 - prefix);
    else
        mask.lo = 0;

    /* Mask off any non-zero bits from both addresses */
    lhs.hi &= mask.hi;
    lhs.lo &= mask.lo;
    rhs.hi &= mask.hi;
    rhs.lo &= mask.lo;

    /* Now do a normal compare */
    return ipv6address_is_equal(lhs, rhs);
}
