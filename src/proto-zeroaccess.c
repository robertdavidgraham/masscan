/*
    ZeroAccess botnet

    This scans for the P2P ports on the "ZeroAccess" botnet.

    http://www.symantec.com/connect/blogs/grappling-zeroaccess-botnet
    http://www.sophos.com/en-us/medialibrary/PDFs/technical%20papers/Sophos_ZeroAccess_Botnet.pdf

*/
#include "proto-zeroaccess.h"
#include "proto-preprocess.h"
#include "output.h"
#include "proto-banner1.h"
#include "string_s.h"
#include <stdio.h>
#include <string.h>


/***************************************************************************
 * I hand-crafted this "getL" request packet. It has the ID set to "mass",
 * then has been CRCed and encrypted.
 ***************************************************************************/
const unsigned char zeroaccess_getL[] = {
    0x46, 0x5d, 0x49, 0x9e, 0x28, 0x94, 0x8d, 0xab,
    0xc9, 0xc0, 0xd1, 0x99, 0xe0, 0xf2, 0xc2, 0x5e,
};

/***************************************************************************
 * Table for the standard CRC32 algorithm used everywhere.
 ***************************************************************************/
static const unsigned crc32_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL
};


/***************************************************************************
 * Standard CRC32 calculation.
 ***************************************************************************/
static unsigned
crc_calc(const unsigned char *px, unsigned length)
{
    unsigned i;
    unsigned crc;

    crc = (unsigned)~0;
    for (i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ px[i]) & 0xff] ^ (crc >> 8);
    }
    crc = ~crc;

    return crc;
}

/***************************************************************************
 * Zero-Access encrypts packets with a simple encryption of starting
 * with the key "ftp2" XORed with each 4-byte word, then rotated left
 * by one bit after every XOR. Because it's XOR, encryption is also
 * decryption.
 ***************************************************************************/
static unsigned
zadecrypt(const unsigned char *src, size_t src_len, unsigned char *dst, size_t dst_len)
{
    unsigned key;
    size_t i;

    key = 'f'<<24 | 't'<<16 | 'p'<<8 | '2'<<0;

    for (i=0; i<dst_len && i<src_len; i+=4) {
        dst[i+0] = src[i+0] ^ (unsigned char)(key>> 0);
        dst[i+1] = src[i+1] ^ (unsigned char)(key>> 8);
        dst[i+2] = src[i+2] ^ (unsigned char)(key>>16);
        dst[i+3] = src[i+3] ^ (unsigned char)(key>>24);

        key = key<<1 | key>>31;
    }

    return (unsigned)src_len;
}

/***************************************************************************
 * Generate a "getL" request. I put this in the code, but I don't really
 * use it, because I ran it once to generate the hard-coded packet at
 * the top of this file.
 ***************************************************************************/
static unsigned
generate_getL(unsigned char *out_buf, size_t out_buf_len, unsigned xrand)
{
    unsigned char buf[16];
    unsigned crc;

    if (out_buf_len < 16)
        return 0;
    memset(buf, 0, 16);

    memcpy(&buf[4], "Lteg", 4); /* "getL" */

    buf[12] = (unsigned char)(xrand>>24);
    buf[13] = (unsigned char)(xrand>>16);
    buf[14] = (unsigned char)(xrand>> 8);
    buf[15] = (unsigned char)(xrand>> 0);

    crc = crc_calc(buf, 16);
    buf[3] = (unsigned char)(crc>>24);
    buf[2] = (unsigned char)(crc>>16);
    buf[1] = (unsigned char)(crc>> 8);
    buf[0] = (unsigned char)(crc>> 0);

    zadecrypt(buf, 16, out_buf, 16);

    return 16;
}

/***************************************************************************
 * Handles the response packet from our "getL" request, which is known
 * as a "retL". This contains a list of IP addresses of infected machines.
 * therefore, we want to parse the response and grab those IP addresses
 * so that we know about even more infected machines.
 ***************************************************************************/
unsigned
handle_zeroaccess(  struct Output *out, time_t timestamp,
                    const unsigned char *px, unsigned length,
                    struct PreprocessedInfo *parsed,
                    uint64_t entropy)
{
    unsigned char buf[2048];
    unsigned len;
    unsigned ip_them;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    struct BannerOutput banout[1];

    banout->length = 0;
    banout->next = 0;
    banout->protocol = PROTO_UDP_ZEROACCESS;

    UNUSEDPARM(entropy);
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(port_me);

    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    /*ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
            | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;*/

    /* Decrypt the response packet */
    buf[0] = '\0';
    len = zadecrypt(px + parsed->app_offset,
                    parsed->app_length,
                    buf, sizeof(buf));
    if (len != parsed->app_length) {
        return 0; /* is not zeroaccess botnet */
    }

    /* Validate the CRC */
    {
        unsigned old_crc;
        unsigned new_crc;

        old_crc = buf[0] | buf[1]<<8 | buf[2]<<16 | buf[3]<<24;
        memset(buf, 0, 4);
        new_crc = crc_calc(buf, len);
        if (old_crc != new_crc)
            return 0; /* not zeroaccess, or corrupted */
    }

    /* Make sure this is a "retl" packet */
    if (len < 16 || memcmp(buf+4, "Lter", 4) != 0)
        return 0; /* not "retL" */

    /* List IP addresses */
    banout_append(banout, PROTO_UDP_ZEROACCESS, "ZeroAccess:", 11);

    {
        unsigned i;
        unsigned ip_count = buf[12] | buf[13]<<8 | buf[14]<<16 | buf[15]<<24;
        if (ip_count > 256)
            return 0; /* too many addresses */
        if (16 + ip_count*8 > len)
            return 0; /* packet overflow */
        for (i=0; i<ip_count; i++) {
            unsigned ip_found;
            char szaddr[20];

            ip_found =  buf[16 + i*8 + 0] <<24
                      | buf[16 + i*8 + 1] <<16
                      | buf[16 + i*8 + 2] << 8
                      | buf[16 + i*8 + 3] << 0;

            sprintf_s(szaddr, sizeof(szaddr), "%u.%u.%u.%u ",
                    (unsigned char)(ip_found>>24),
                    (unsigned char)(ip_found>>16),
                    (unsigned char)(ip_found>> 8),
                    (unsigned char)(ip_found>> 0)
                    );
            banout_append(banout, PROTO_UDP_ZEROACCESS, szaddr, strlen(szaddr));
        }
    }





    output_report_banner(
            out, timestamp,
            ip_them, 17, port_them,
            PROTO_UDP_ZEROACCESS,
            parsed->ip_ttl,
            banout_string(banout, PROTO_UDP_ZEROACCESS),
            banout_string_length(banout, PROTO_UDP_ZEROACCESS));

    return 0; /* is zeroaccess botnet*/
}

/***************************************************************************
 ***************************************************************************/
static const unsigned char sample[] = {
    0xda, 0xbe, 0x6e, 0xce,
    0x28, 0x94, 0x8d, 0xab,
    0xc9, 0xc0, 0xd1, 0x99,
    0xec, 0xd6, 0xa9, 0x3c
};


/***************************************************************************
 ***************************************************************************/
int
zeroaccess_selftest(void)
{
    unsigned char buf[128];
    unsigned old_crc;
    unsigned new_crc;

    zadecrypt(sample, sizeof(sample), buf, sizeof(buf));

    old_crc = buf[0] | buf[1]<<8 | buf[2]<<16 | buf[3]<<24;


    memset(buf, 0, 4);

    new_crc = crc_calc(buf, sizeof(sample));

    generate_getL(buf, sizeof(buf), 0x7f570a0f);

    if (memcmp(buf, sample, 16) != 0)
        return 1; /*fail*/
    if (old_crc != new_crc)
        return 1; /*fail*/

    /*generate_getL(buf, sizeof(buf), *(unsigned*)"mass");
    {
        unsigned i;
        for (i=0; i<16; i++)
            printf("0x%02x, ", buf[i]);
    }*/

    return 0; /*success*/
}


