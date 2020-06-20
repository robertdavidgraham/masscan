/*
    Calculates Internet checksums for protocols like TCP/IP.

    Author: Robert David Graham
    Copyright: 2020
    License: The MIT License (MIT)
    Dependencies: none
*/
#include "util-checksum.h"

/**
 * Calculates the checksum over a buffer.
 * @param checksum
 *      The value of the pseudo-header checksum that this sum will be
 *      added to. This value must be calculated separately. This
 *      is the original value in 2s-complement. In other words,
 *      for TCP, which will be the integer value of the 
 *      IP addresses, protocol number, and length field added together.
 * @param buf
 *      The buffer that we are checksumming, such as all the
 *      payload after an IPv4 or IPv6 header.
 */
static unsigned
_checksum_calculate(const void *vbuf, size_t length)
{
    unsigned sum = 0;
    size_t i;
    const unsigned char *buf = (const unsigned char *)vbuf;
    int is_remainder;

    /* If there is an odd number of bytes, then we handle the 
     * last byte in a custom manner. */
    is_remainder = (length & 1);
    length &= (~1);

    /* Sum up all the 16-bit words in the packet */
    for (i=0; i<length; i += 2) {
        sum += buf[i]<<8 | buf[i+1];
    }

    /* If there is an odd number of bytes, then add the last
     * byte to the sum, in big-endian format as if there was
     * an additional trailing byte of zero. */
    if (is_remainder)
        sum += buf[length]<<8;

    /* Return the raw checksum. Note that this hasn't been
     * truncated to 16-bits yet or had the bits reversed. */
    return sum;
}


/**
 * After we sum up all the numbers involved, we must "fold" the upper
 * 16-bits back into the lower 16-bits. Since something like 0x1FFFF
 * will fold into 0x10000, we need to call a second fold operation
 * (obtaining 0x0001 in this example). In other words, we need to 
 * keep folding until the result is 16-bits, but that never takes
 * more than two folds. After this, we need to take the 1s-complement,
 * which means reversing the bits so that 0 becomes 1 and 1 becomes 0.
 */
static unsigned
_checksum_finish(unsigned sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return (~sum) & 0xFFFF;
}





unsigned 
checksum_ipv4(unsigned ip_src, unsigned ip_dst, unsigned ip_proto, size_t payload_length, const void *payload)
{
    unsigned sum;
    const unsigned char *buf = (const unsigned char *)payload;

    /* Calculate the sum of the pseudo-header. Note that all these fields
     * are assumed to be in host byte-order, not big-endian */
    sum = (ip_src>>16) & 0xFFFF;
    sum += (ip_src>> 0) & 0xFFFF;
    sum += (ip_dst>>16) & 0xFFFF;
    sum += (ip_dst>> 0) & 0xFFFF;
    sum += ip_proto;
    sum += (unsigned)payload_length;
    sum += _checksum_calculate(buf, payload_length);

    /* Remove the existing checksum field from the calculation. */
    switch (ip_proto) {
    case 0: /* IP header -- has no pseudo header */
        sum = _checksum_calculate(buf, payload_length);
        sum -= buf[10]<<8 | buf[11]; /* pretend the existing checksum field is zero */
        break;
    case 1:
        sum -= buf[2]<<8 | buf[3];
        break;
    case 2: /* IGMP - group message - has no pseudo header */
        sum = _checksum_calculate(payload, payload_length);
        sum -= buf[2]<<8 | buf[3];
        break;
    case 6:
        sum -= buf[16]<<8 | buf[17];
        break;
    case 17:
        sum -= buf[6]<<8 | buf[7];
        break;
    default:
        return 0xFFFFFFFF;
    }

    sum = _checksum_finish(sum);
    return sum;
}

unsigned 
checksum_ipv6(const unsigned char *ip_src, const unsigned char *ip_dst, unsigned ip_proto, size_t payload_length, const void *payload)
{
    const unsigned char *buf = (const unsigned char *)payload;
    unsigned sum;

    /* Calculate the pseudo-header */
    sum = _checksum_calculate(ip_src, 16);
    sum += _checksum_calculate(ip_dst, 16);
    sum += (unsigned)payload_length;
    sum += ip_proto;

    /* Calculate the remainder of the checksum */
    sum += _checksum_calculate(payload, payload_length);

    /* Remove the existing checksum field. */
    switch (ip_proto) {
    case 0:
        return 0;
    case 1:
    case 58:
        sum -= buf[2]<<8 | buf[3];
        break;
    case 6:
        sum -= buf[16]<<8 | buf[17];
        break;
    case 17:
        sum -= buf[6]<<8 | buf[7];
        break;
    default:
        return 0xFFFFFFFF;
    }

    /* fold and invert */
    sum = _checksum_finish(sum);
    return sum;
}

/*
 * Test cases for IPv4
 */
static struct {
    unsigned checksum;
    const char *buf;
    unsigned ip_src;
    unsigned ip_dst;
    size_t length;
    unsigned ip_proto;
} ipv4packets[] = {
    {
        0xee9b,
        "\x11\x64\xee\x9b\x00\x00\x00\x00",
        0x0a141e01, 0xe0000001, 8, 2 /* IGMP - Group Message protocol */
    }, {
        0x6042,
        "\xdc\x13\x01\xbb\x00\x29\x60\x42"
        "\x5b\xd6\x16\x3a\xb1\x78\x3d\x5d\xdd\x0e\x5a\x05\x35\x74\x92\x91"
        "\x57\x4c\xaa\xc1\x85\x76\xc0\x0f\x8d\x9e\x19\xa5\xcc\xa2\x81\x65\xbe",
        0x0a141ec9, 0xadc2900a, 41, 17 /* UDP */
    }, {
        0x84b2,
        "\x7e\x70\x69\x95\x1f\xb9\x77\xc6\xee\x09\x7b\x72\x50\x18\x03\xfd" 
        "\x84\xb2\x00\x00"
        "\x17\x03\x03\x00\x3a\x6c\x04\xe3\x0e\x25\x79\x8e\x1c\x98\xdd\x2c"
        "\x8d\x41\x39\x53\xfb\xd0\xd5\x3e\x14\xf8\xdf\xb9\xb8\x47\xe0\x43"
        "\xab\x09\x24\x58\x7c\x6a\xab\x91\xaf\x24\xc0\x5c\xc6\xaf\x56\x45"
        "\xed\xa3\xde\x06\xa2\xd1\x79\x0a\x21\xfe\x9c\x2e\x6e\x81\x19",
        0x0a141ec9, 0xa2fec14a, 83, 6 /* TCP */
    }, {0}
};

/*
 * Test cases for IPv6
 */
static struct {
    unsigned checksum;
    const char *buf;
    const char *ip_src;
    const char *ip_dst;
    size_t length;
    unsigned ip_proto;
} ipv6packets[] = {
    {
        0x09e3,
        "\x02\x22\x02\x23\x00\x32\x09\xe3"
        "\x0b\x15\x18\x54\x00\x06\x00\x0a\x00\x17\x00\x18\x00\x38\x00\x1f"
        "\x00\x0e\x00\x01\x00\x0e\x00\x02\x00\x00\xab\x11\xfd\xb3\xae\xbb"
        "\xe6\x57\x00\x5c\x00\x08\x00\x02\x00\x00",
        "\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x07\x32\xff\xfe\x42\x5e\x35",
        "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02",
        50, 17 /* UDP */
    }, {   0xbf3c,
        "\x8f\x00\xbf\x3c\x00\x00\x00\x04\x04\x00\x00\x00\xff\x02\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x01\xff\x03\x68\x4c\x04\x00\x00\x00"
        "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xd4\xa6\x80"
        "\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        "\xff\x06\xab\x72\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x01\xff\x2f\x65\x52",
        "\xfe\x80\x00\x00\x00\x00\x00\x00\x1c\x7b\x06\x42\x4e\x57\x19\xcc",
        "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16",
        88, 58 /* ICMPv6 */
    }, {   0x0d0e,
        "\x8d\x59\x01\xbb\xed\xb8\x70\x8b\x91\x6c\x8d\x68\x50\x10\x04\x01"
        "\x0d\x0e\x00\x00",
        "\x20\x02\x18\x62\x5d\xeb\x00\x00\xac\xc3\x59\xad\x84\x6b\x97\x80",
        "\x26\x02\xff\x52\x00\x00\x00\x6a\x00\x00\x00\x00\x1f\xd2\x94\x5a",
        20, 6 /* TCP */
    }, {0}
};



int checksum_selftest(void)
{
    unsigned sum;
    size_t i;

    /* Run through some IPv6 examples of TCP, UDP, and ICMP */
    for (i=0; ipv6packets[i].buf; i++) {
        sum = checksum_ipv6(
            (const unsigned char *)ipv6packets[i].ip_src, 
            (const unsigned char *)ipv6packets[i].ip_dst, 
            ipv6packets[i].ip_proto, 
            ipv6packets[i].length, 
            ipv6packets[i].buf);
        if (sum != ipv6packets[i].checksum)
            return 1; /* fail */
    }


    /* Run through some IPv4 examples of TCP, UDP, and ICMP */
    for (i=0; ipv4packets[i].buf; i++) {
        sum = checksum_ipv4(ipv4packets[i].ip_src, 
            ipv4packets[i].ip_dst, 
            ipv4packets[i].ip_proto, 
            ipv4packets[i].length, 
            ipv4packets[i].buf);
        if (sum != ipv4packets[i].checksum)
            return 1; /* fail */
    }

    return 0; /* success */
}
