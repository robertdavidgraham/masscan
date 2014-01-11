#include "crypto-base64.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/****************************************************************************
 ****************************************************************************/
size_t
base64_encode(void *vdst, size_t sizeof_dst, const void *vsrc, size_t sizeof_src)
{
    static const char *b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";
    size_t i = 0;
    size_t d = 0;
    unsigned char *dst = (unsigned char *)vdst;
    const unsigned char *src = (const unsigned char *)vsrc;

    while (i + 3 <= sizeof_src) {
        unsigned n;
        
        /* make sure there is enough space */
        if (d + 4 > sizeof_dst)
            return d;

        /* conver the chars */
        n = src[i]<<16 | src[i+1]<<8 | src[i+2];
        dst[d+0] = b64[ (n>>18) & 0x3F ];
        dst[d+1] = b64[ (n>>12) & 0x3F ];
        dst[d+2] = b64[ (n>> 6) & 0x3F ];
        dst[d+3] = b64[ (n>> 0) & 0x3F ];

        i += 3;
        d += 4;
    }

    if (i + 2 <= sizeof_src && d + 4 <= sizeof_dst) {
        unsigned n = src[i]<<16 | src[i+1]<<8;
        dst[d+0] = b64[ (n>>18) & 0x3F ];
        dst[d+1] = b64[ (n>>12) & 0x3F ];
        dst[d+2] = b64[ (n>> 6) & 0x3F ];
        dst[d+3] = '=';
        d += 4;
    } else if (i + 1 <= sizeof_src && d + 4 <= sizeof_dst) {
        unsigned n = src[i]<<16 | src[i+1]<<8;
        dst[d+0] = b64[ (n>>18) & 0x3F ];
        dst[d+1] = b64[ (n>>12) & 0x3F ];
        dst[d+2] = '=';
        dst[d+3] = '=';
        d += 4;
    }

    return d;
}


/****************************************************************************
 ****************************************************************************/
size_t
base64_decode(void *vdst, size_t sizeof_dst, const void *vsrc, size_t sizeof_src)
{
	static const unsigned char rstr[] = {
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,	62,		0xFF,   0xFF,   0xFF,	63,
		52,		53,		54,		55,		56,		57,		58,		59,		60,		61,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0,		1,		2,		3,		4,		5,		6,		7,		8,		9,		10,		11,		12,		13,		14,
		15,		16,		17,		18,		19,		20,		21,		22,		23,		24,		25,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,	26,		27,		28,		29,		30,		31,		32,		33,		34,		35,		36,		37,		38,		39,		40,
		41,		42,		43,		44,		45,		46,		47,		48,		49,		50,		51,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
	};
    size_t i = 0;
    size_t d = 0;
    unsigned char *dst = (unsigned char *)vdst;
    const unsigned char *src = (const unsigned char *)vsrc;


	while (i < sizeof_src) {
        unsigned b;
		unsigned c=0;

		/* byte#1 */
		while (i<sizeof_src && (c = rstr[src[i]]) > 64)
			i++;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b = (c << 2) & 0xfc;
	
		while (i<sizeof_src && (c = rstr[src[i]]) > 64)
			i++;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= (c>>4) & 0x03;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;

		/* byte#2 */
		b = (c<<4) & 0xF0;
		while (i<sizeof_src && src[i] != '=' && (c = rstr[src[i]]) > 64)
			;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= (c>>2) & 0x0F;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;

		/* byte#3*/
		b = (c<<6) & 0xC0;
		while (i<sizeof_src && src[i] != '=' && (c = rstr[src[i]]) > 64)
			;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= c;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;
	}

	if (d<sizeof_dst)
		dst[d] = '\0';
	return d;
}


int
base64_selftest(void)
{
    char buf[100];
    char buf2[100];
    size_t buf_len;
    size_t buf2_len;

    buf_len = base64_encode(buf, sizeof(buf), "hello", 5);
    buf2_len = base64_decode(buf2, sizeof(buf2), buf, buf_len);
    if (buf2_len != 5 && memcmp(buf2, "hello", 5) != 0) {
        fprintf(stderr, "base64: selftest failed\n");
        return 1;
    }

    return 0;
}
