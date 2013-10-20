/*
    SSL parser

    This parses out the SSL "certificate" and "ephemeral keys", and
    any other information we want from SSL.

    BIZARRE CODE ALERT: This module uses "state-machines" to parse
    SSL. This has a number of advantages, such as handling TCP
    segmentation and SSL record fragmentation without having to 
    buffer any packets. But it's quite weird if you aren't used to
    it.
*/
#include "proto-ssl.h"
#include "unusedparm.h"

/**
 * Fugly macro for doing state-machine parsing
 */
#define DROPDOWN(i,length,state) (state)++;if (++(i)>=(length)) break


/***************************************************************************
       struct {
           ProtocolVersion server_version;
           Random random;
           SessionID session_id;
           CipherSuite cipher_suite;
           CompressionMethod compression_method;
       } ServerHello;
 ***************************************************************************/
static void
server_hello(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *pstate,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    struct SSL_SERVER_HELLO *hello = &pstate->sub.ssl.x.server_hello;
    unsigned state = hello->state;
    unsigned remaining = hello->remaining;
	unsigned i;
    enum {
        VERSION_MAJOR, VERSION_MINOR,
        TIME0, TIME1, TIME2, TIME3,
        RANDOM,
        SESSION_LENGTH, SESSION_ID,
        CIPHER0, CIPHER1,
        COMPRESSION,
        LENGTH0, LENGTH1,
        UNKNOWN,
    };

    UNUSEDPARM(banner1);
    UNUSEDPARM(banner);
    UNUSEDPARM(banner_offset);
    UNUSEDPARM(banner_max);
    UNUSEDPARM(banner1_private);

    for (i=0; i<length; i++) 
    switch (state) {
    case VERSION_MAJOR:
        hello->version_major = px[i];
        DROPDOWN(i,length,state);

    case VERSION_MINOR:
        hello->version_minor = px[i];
        if (hello->version_major > 3 || hello->version_minor > 4) {
            state = UNKNOWN;
            break;
        }
        hello->timestamp = 0;
        DROPDOWN(i,length,state);

    case TIME0:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME1:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME2:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME3:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        remaining = 28;
        DROPDOWN(i,length,state);
    case RANDOM:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;

            remaining -= len;
            i += len-1;

            if (remaining != 0) {
                break;
            }
        }
        DROPDOWN(i,length,state);

    case SESSION_LENGTH:
        remaining = px[i];
        DROPDOWN(i,length,state);

    case SESSION_ID:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;

            remaining -= len;
            i += len-1;

            if (remaining != 0) {
                break;
            }
        }
        hello->cipher_suite = 0;
        DROPDOWN(i,length,state);

    case CIPHER0:
        hello->cipher_suite <<= 8;
        hello->cipher_suite |= px[i];
        DROPDOWN(i,length,state);

    case CIPHER1:
        hello->cipher_suite <<= 8;
        hello->cipher_suite |= px[i]; /* cipher-suite recorded here */
        DROPDOWN(i,length,state);

    case COMPRESSION:
        hello->compression_method = px[i];
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i];
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);
        break;

    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    hello->state = state;
    hello->remaining = remaining;
}

enum {
    CERT_COPY_FINISH=0,
    CERT_COPY_START=1,
};



/***************************************************************************
 ***************************************************************************/
static void
out_b64(unsigned x, char *banner, unsigned *banner_offset, size_t banner_max)
{
    static const char *b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";
    if (*banner_offset < banner_max)
        banner[(*banner_offset)++] = b64[(x>>18)&0x3F];
    if (*banner_offset < banner_max)
        banner[(*banner_offset)++] = b64[(x>>12)&0x3F];
    if (*banner_offset < banner_max)
        banner[(*banner_offset)++] = b64[(x>> 6)&0x3F];
    if (*banner_offset < banner_max)
        banner[(*banner_offset)++] = b64[(x>> 0)&0x3F];
}

/***************************************************************************
 ***************************************************************************/
static void
server_cert_copy(   struct SSL_SERVER_CERT *data,
                    const unsigned char *px,
                    unsigned length, 
                    char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned state = data->state;
    unsigned b64x = data->b64x;
    unsigned i;

    /*
     * Initialize
     */
    if (px == 0 && length == CERT_COPY_START) {
        data->cert_state = 0;
        data->b64x = 0;
        data->banner_offset_start = *banner_offset;
        return;
    }

    /*
     * Convert to base64
     */
    if (px)
    for (i=0; i<length; i++)
    switch (state) {
    case 0:
        b64x = px[i];
        DROPDOWN(i,length,state);
    case 1:
        b64x = b64x * 256 + px[i];
        DROPDOWN(i,length,state);
    case 2:
        b64x = b64x * 256 + px[i];
        state = 0;
        out_b64(b64x, banner, banner_offset, banner_max);
    }

    /*
     * Finalize: we need to put the final touches on the
     * base64 encoding
     */
    if (px == 0) {
        unsigned zzz = (*banner_offset) - 1;
        switch (state) {
        case 0:
            break;
        case 1:
            b64x *= 256;
        case 2:
            b64x *= 256;
        }

        out_b64(b64x, banner, banner_offset, banner_max);

        switch (state) {
        case 0:
            break;
        case 1:
            banner[zzz--] = '=';
        case 2:
            banner[zzz--] = '=';
        }
    }

    data->state = state;
    data->b64x = b64x;
}

/***************************************************************************
 ***************************************************************************/
static void
server_cert(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *pstate,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    struct SSL_SERVER_CERT *data = &pstate->sub.ssl.x.server_cert;
    unsigned state = data->state;
    unsigned remaining = data->remaining;
    unsigned cert_remaining = data->cert_remaining;
	unsigned i;
    enum {
        LEN0, LEN1, LEN2,
        CLEN0, CLEN1, CLEN2,
        CERT,
        UNKNOWN,
    };

    UNUSEDPARM(banner1);
    UNUSEDPARM(banner1_private);

    for (i=0; i<length; i++) 
    switch (state) {
    case LEN0:
        remaining = px[i];
        DROPDOWN(i,length,state);
    case LEN1:
        remaining = remaining * 256 + px[i];
        DROPDOWN(i,length,state);
    case LEN2:
        remaining = remaining * 256 + px[i];
        DROPDOWN(i,length,state);

    case CLEN0:
        if (remaining < 3) {
            state = UNKNOWN;
            continue;
        }
        cert_remaining = px[i];
        remaining--;
        DROPDOWN(i,length,state);
    case CLEN1:
        cert_remaining = cert_remaining * 256 + px[i];
        remaining--;
        DROPDOWN(i,length,state);
    case CLEN2:
        cert_remaining = cert_remaining * 256 + px[i];
        remaining--;
        DROPDOWN(i,length,state);
        data->cert_state = 0;
        server_cert_copy(data,  0,CERT_COPY_START,  banner,banner_offset,banner_max);

    case CERT:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;
            if (len > cert_remaining)
                len = cert_remaining;

            /* parse the certificate */
            server_cert_copy(data, px+i, len, banner, banner_offset, banner_max);


            remaining -= len;
            cert_remaining -= len;
            i += len-1;

            if (cert_remaining == 0) {
                /* We've reached the end of the certificate, so make
                 * a record of it */
                server_cert_copy(data,  0, CERT_COPY_FINISH,  banner,banner_offset,banner_max);
                state = CLEN0;
            }
        }
        break;


    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    data->state = state;
    data->remaining = remaining;
    data->cert_remaining = cert_remaining;
}

/***************************************************************************
 ***************************************************************************/
static void
content_parse(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *pstate,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    struct SSLRECORD *ssl = &pstate->sub.ssl;
    unsigned state = ssl->record.state;
    unsigned remaining = ssl->record.remaining;
	unsigned i;
    enum {
        START,
        LENGTH0, LENGTH1, LENGTH2,
        CONTENTS,
        UNKNOWN,
    };

    for (i=0; i<length; i++) 
    switch (state) {
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        remaining = 0;
        ssl->record.type = px[i];
        ssl->x.all.state = 0;
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i];
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case LENGTH2:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case CONTENTS:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;

            switch (ssl->record.type) {
            case 0x02: /* server hello */
                server_hello(      banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banner, banner_offset, banner_max);
                break;
            case 0x0b: /* server certificate */
                server_cert(        banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banner, banner_offset, banner_max);
                break;
            }

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = START;
        }

        break;
    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    ssl->record.state = state;
    ssl->record.remaining = remaining;
}

/***************************************************************************
 * Parse just the outer record, then hands down the contents to the
 * a subparser at "content_parse()"
 ***************************************************************************/
static void
ssl_parse(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *pstate,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned state = pstate->state;
    unsigned remaining = pstate->remaining;
    struct SSLRECORD *ssl = &pstate->sub.ssl;
	unsigned i;
    enum {
        START,
        VERSION_MAJOR,
        VERSION_MINOR,
        LENGTH0, LENGTH1,
        CONTENTS,
        UNKNOWN,
    };
	
    for (i=0; i<length; i++) 
    switch (state) {
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        if (ssl->content_type != px[i]) {
            ssl->content_type = px[i];
            ssl->record.state = 0;
        }
        remaining = 0;
        DROPDOWN(i,length,state);

    case VERSION_MAJOR:
        ssl->version_major = px[i];
        DROPDOWN(i,length,state);

    case VERSION_MINOR:
        ssl->version_minor = px[i];
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i]<<8;
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining |= px[i];
        DROPDOWN(i,length,state);
        ssl->record.state = 0;

    case CONTENTS:
        {
            unsigned len = (unsigned)length - i;
            if (len > remaining)
                len = remaining;

            /*
             * Parse the contents of a record
             */
            content_parse(      banner1,
                                banner1_private,
                                pstate,
                                px+i, len,
                                banner, banner_offset, banner_max);

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = START;
        }

        break;
    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    pstate->state = state;
    pstate->remaining = remaining;
}

/***************************************************************************
 ***************************************************************************/
static void *
ssl_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static const char 
ssl_hello[] = 
"\x16\x03\x02\x01\x6f"          /* TLSv1.1 record layer */
"\x01" /* type = client-hello */
"\x00\x01\x6b" /* length = 363 */
"\x03\x02"      /* version = 3.02 (TLS 1.1) */

"\x52\x48\xc5\x1a\x23\xf7\x3a\x4e\xdf\xe2\xb4\x82\x2f\xff\x09\x54" /* random */
"\x9f\xa7\xc4\x79\xb0\x68\xc6\x13\x8c\xa4\x1c\x3d\x22\xe1\x1a\x98" /* TODO: re-randomize for each request, or at least on startup */

"\x20" /* session-id-length = 32 */
"\x84\xb4\x2c\x85\xaf\x6e\xe3\x59\xbb\x62\x68\x6c\xff\x28\x3d\x27"  /* random */
"\x3a\xa9\x82\xd9\x6f\xc8\xa2\xd7\x93\x98\xb4\xef\x80\xe5\xb9\x90"  /* TODO: re-randomize for each request, or at least on startup */

"\x00\x28" /* cipher suites length */
"\xc0\x0a\xc0\x14\x00\x39\x00\x6b\x00\x35\x00\x3d\xc0\x07\xc0\x09"
"\xc0\x23\xc0\x11\xc0\x13\xc0\x27\x00\x33\x00\x67\x00\x32\x00\x05"
"\x00\x04\x00\x2f\x00\x3c\x00\x0a"

"\x01" /* compression-methods-length = 1 */
"\x00" 

"\x00\xfa" /* extensions lkength */

/* server name */
"\xef\x00"
"\x00\x1a"
"\x00\x18\x00\x00\x15\x73\x79\x6e\x64\x69\x63\x61\x74\x69\x6f\x6e"
"\x2e\x74\x77\x69\x6d\x67\x2e\x63\x6f\x6d"

"\xff\x01"
"\x00\x01"
"\x00"

"\x00\x0a"
"\x00\x08"
"\x00\x06\x00\x17\x00\x18\x00\x19"

"\x00\x0b"
"\x00\x02"
"\x01\x00"

"\x00\x23"
"\x00\xb0"
"\x81\x01\x19\x67\x60\x1e\x04\x42\x9a\xf3\xe2\x3c\x86\x58\x4f\x87"
"\x69\x44\xb0\x1d\x8e\x01\xfa\xa5\x87\x3d\x5d\xdc\x16\x4c\xb4\x20"
"\xda\xd3\x42\xb0\x88\xec\x0a\x13\xc3\xc6\x4c\x44\x74\x7d\xf5\x83"
"\x93\xeb\x16\x60\x7e\x47\x07\x15\xae\x68\x3f\x32\xfc\x28\x71\xdd"
"\x8d\x2a\xe0\x9e\x03\xad\x28\xd9\x89\x2f\x0f\x07\xaf\xc1\x27\x8e"
"\xf1\x57\xfb\xc6\xc4\xd4\x56\x3a\xf6\xed\x59\x61\x4a\x17\x14\x0b"
"\xd7\x7c\xae\xfe\x55\xd9\x7a\xa6\xf6\xc6\x57\xb5\x3c\xed\x78\x9d"
"\xee\x39\xd8\x67\x02\x09\x92\xcb\xa5\x66\xa3\x48\x3d\x06\xed\xa5"
"\x02\x2e\x9b\x16\xf6\x2b\xe7\x3f\x79\x65\x1a\xcb\x6c\x5c\xbd\x6b"
"\xad\x11\xde\xbe\xdf\x35\xdb\x0b\xff\x2c\x90\x94\x32\xb5\x94\x57"
"\x3d\x5e\x25\xd2\x1b\xd2\x44\x85\x96\x31\x28\x69\xd7\x4a\x13\x0a"
"\x33\x74\x00\x00\x75\x4f\x00\x00\x00\x05\x00\x05\x01\x00\x00\x00"
"\x00"
;

/***************************************************************************
 ***************************************************************************/
static int
ssl_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
struct Banner1Stream banner_ssl = {
    "ssl", 443, ssl_hello, sizeof(ssl_hello)-1,
    ssl_selftest,
    ssl_init,
    ssl_parse,
};

