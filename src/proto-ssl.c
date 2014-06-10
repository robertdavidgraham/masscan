/*
    SSL parser
 
    This parses SSL packets from the server. It is built in multiple levels:
 
    RECORDS - ssl_parse_record()
      |
      +---> heartbeat
      |        |
      |        +---> banner grab
      |
      +---> handshake
               |
               +---> server hello
               |        |
               |        +---> banner grab
               |
               +---> certificate
                        |
                        +---> X.509 parser
                                 |
                                 +---> subject name (banner)
                                 |
                                 +---> certificate (banner)
 

    For "heartbeat", we grab the so-called "heartbleed" exploit info.
    For "server hello", we grab which cipher is used
    For "certificate", we grab the szubjectName of the server
 
 
    !!!!!!!!!!!!  BIZARRE CODE ALERT !!!!!!!!!!!!!!!
    
    This module uses a "streaming state-machine" to parse the SSL protocol.
    In other words, this does not "reasemble" fragments. Instead, it allows
    state to cross packet-boundaries. Thus, it supports both fragmentation
    at the TCP layer and the SSL record layer, but without reassembling
    things. Only in the output, in the gathered "banners", does reassembly
    happen -- in other words, reassembly happens after OSI Layer 7 rather
    than OSI Layer 4.
 
    As many are unfamiliar with this technique, they'll find it a little
    weird.
 
    The upshot of doing things this way is that we can support 10 million
    open TCP connections with minimal memory usage.
 */
#include "proto-ssl.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "string_s.h"
#include <string.h>
#include <ctype.h>
#include <assert.h>

/**
 * Fugly macro for doing state-machine parsing. I know it's bad, but
 * it makes stepping through the code in a debugger so much easier.
 */
#define DROPDOWN(i,length,state) (state)++;if (++(i)>=(length)) break


/*****************************************************************************
 * This parses the "Server Hello" packet, the response to our "ClientHello"
 * that we sent. We are looking for the following bits of information:
 *  - cipher chosen by the server
 *  - whether heartbeats are enabled
 *****************************************************************************/
static void
parse_server_hello(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
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
        EXT_TAG0, EXT_TAG1,
        EXT_LEN0, EXT_LEN1,
        EXT_DATA,
        EXT_DATA_HEARTBEAT,
        UNKNOWN,
    };

    UNUSEDPARM(banout);
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    UNUSEDPARM(more);

    /* What this structure looks like in ASN.1 format
       struct {
           ProtocolVersion server_version;
           Random random;
           SessionID session_id;
           CipherSuite cipher_suite;
           CompressionMethod compression_method;
       } ServerHello;
    */

    /* 'for all bytes in the packet...' */
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
            /* do our typical "skip" logic to skip this
             * 32 byte field */
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
        {
            char foo[64];
            sprintf_s(foo, sizeof(foo), "cipher:0x%x ", hello->cipher_suite);
            banout_append(banout, PROTO_SSL3, foo, strlen(foo));
        }
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
  
    case EXT_TAG0:
    ext_tag:
        if (remaining < 4) {
            state = UNKNOWN;
            continue;
        }
        hello->ext_tag = px[i]<<8;
        remaining--;
        DROPDOWN(i,length,state);
            
    case EXT_TAG1:
        hello->ext_tag |= px[i];
        remaining--;
        DROPDOWN(i,length,state);

    case EXT_LEN0:
        hello->ext_remaining = px[i]<<8;
        remaining--;
        DROPDOWN(i,length,state);
    case EXT_LEN1:
        hello->ext_remaining |= px[i];
        remaining--;
        switch (hello->ext_tag) {
            case 0x000f: /* heartbeat */
                state = EXT_DATA_HEARTBEAT;
                continue;
        }
        DROPDOWN(i,length,state);
        
    case EXT_DATA:
        if (hello->ext_remaining == 0) {
            state = EXT_TAG0;
            goto ext_tag;
        }
        if (remaining == 0) {
            state = UNKNOWN;
            continue;
        }
        remaining--;
        hello->ext_remaining--;
        continue;

    case EXT_DATA_HEARTBEAT:
        if (hello->ext_remaining == 0) {
            state = EXT_TAG0;
            goto ext_tag;
        }
        if (remaining == 0) {
            state = UNKNOWN;
            continue;
        }
        remaining--;
        hello->ext_remaining--;
        if (px[i]) {
            banout_append(  banout, PROTO_VULN, "SSL[heartbeat] ", 15);
        }
        state = EXT_DATA;
        continue;

    

    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    hello->state = state;
    hello->remaining = remaining;
}


/*****************************************************************************
 * This parses the certificates from the server. Thise contains an outer
 * length field for all certificates, and then uses a length field for
 * each certificate. The length fields are 3 bytes long.
 *
 * +--------+--------+--------+
 * |  length of all certs     |
 * +--------+--------+--------+
 *    +--------+--------+--------+
 *    |        cert length       |
 *    +--------+--------+--------+
 *    .                          .
 *    . . .    certificate   . . .
 *    .                          .
 *    +--------+--------+--------+
 *    |        cert length       |
 *    +--------+--------+--------+
 *    .                          .
 *    . . .    certificate   . . .
 *    .                          .
 *
 * This parser doesn't parse the certificates themselves, but initializes
 * and passes fragments to the X.509 parser.
 *
 * Called by ssl_parser_record()->parse_handshake()
 * Calls x509_decode() to parse the certificate
 * Calls banout_append_base64() to capture the certificate
 *****************************************************************************/
static void
parse_server_cert(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout)
{
    struct SSL_SERVER_CERT *data = &pstate->sub.ssl.x.server_cert;
    unsigned state = data->state;
    unsigned remaining = data->remaining;
    unsigned cert_remaining = data->sub.remaining;
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
        if (banner1->is_capture_cert) {
            banout_init_base64(&pstate->base64);
            //banout_append(  banout, PROTO_X509_CERT, "cert:", 5);
        }

        {
            unsigned count = data->x509.count;
            memset(&data->x509, 0, sizeof(data->x509));
            x509_decode_init(&data->x509, cert_remaining);
            data->x509.count = (unsigned char)count + 1;
        }
        DROPDOWN(i,length,state);

    case CERT:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;
            if (len > cert_remaining)
                len = cert_remaining;

            /* parse the certificate */
            if (banner1->is_capture_cert) {
                banout_append_base64(banout, 
                             PROTO_X509_CERT, 
                             px+i, len,
                             &pstate->base64);
            }

            x509_decode(&data->x509, px+i, len, banout);


            remaining -= len;
            cert_remaining -= len;
            i += len-1;

            if (cert_remaining == 0) {
                /* We've reached the end of the certificate, so make
                 * a record of it */
                if (banner1->is_capture_cert) {
                    banout_finalize_base64(banout, 
                                           PROTO_X509_CERT, 
                                           &pstate->base64);        
                    banout_end(banout, PROTO_X509_CERT);
                }
                state = CLEN0;
                if (remaining == 0) {
                    if (!banner1->is_heartbleed)
                        pstate->is_done = 1;
                }
            }
        }
        break;


    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    data->state = state;
    data->remaining = remaining;
    data->sub.remaining = cert_remaining;
}

/*****************************************************************************
 * Called from the SSL Record parser to parse the contents of
 * a handshake record. The way SSL handshaking works is that after we
 * have sent the "hello", the server then sends us a bunch of records,
 * including its certificate, then is done on their side with the handshake.
 * Then, the client sends a bunch of stuff, to complete their end of the
 * handshake (which we won't do). At that point, they then do a "change
 * cipher spec" to negotiate the encryption keys, which isn't technically
 * part of the handshaking.
 *
 * This is a four byte protocol:
 * +--------+
 * |  type  |
 * +--------+--------+--------+
 * |          length          |
 * +--------+--------+--------+
 * |  content ...
 * .
 * .
 *
 * Note that the "length" field is 3 bytes, supporting in theory 16-megs
 * of content, but the outer record that calls this uses only 2-byte length
 * fields. That's because records support fragmentation. This parser supports
 * this fragmentation -- the 'state' variable crosses fragment boundaries.
 *****************************************************************************/
static void
parse_handshake(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
{
    struct SSLRECORD *ssl = &pstate->sub.ssl;
    unsigned state = ssl->handshake.state;
    unsigned remaining = ssl->handshake.remaining;
    unsigned i;
    enum {
        START,
        LENGTH0, LENGTH1, LENGTH2,
        CONTENTS,
        UNKNOWN,
    };

    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (i=0; i<length; i++)
    switch (state) {
            
    /* There are 20 or so handshaking sub-messages, indicates by it's own
     * 'type' field, which we parse out here */
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        /* remember the 'type' field for use later in the CONTENT state */
        ssl->handshake.type = px[i];
        
        /* initialize the state variable that will be used by the inner
         * parsers */
        ssl->x.all.state = 0;
        DROPDOWN(i,length,state);

    /* This grabs the 'length' field. Note that unlike other length fields,
     * this one is 3 bytes long. That's because a single certificate 
     * packet can contain so many certificates in a chain that it exceeds
     * 64k kilobytes in size. */
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

        /* If we get a "server done" response, then it's a good time to
         * send the heartbleed request. Note that these are usually zero
         * length, so we can't process this below in the CONTENT state
         * but have to do it here at the end of the LENGTH2 state */
        if (ssl->handshake.type == 2) {
            static const char heartbleed_request[] = 
                "\x15\x03\x02\x00\x02\x01\x80"
                "\x18\x03\x02\x00\x03\x01" "\x40\x00";
            more->payload = heartbleed_request;
            more->length = sizeof(heartbleed_request)-1;
        }
        DROPDOWN(i,length,state);

    /* This parses the contents of the handshake. This parser just skips
     * the data, in the same way as explained in the "ssl_parse_record()"
     * function at its CONTENT state. We may pass the fragment to an inner
     * parser, but whatever the inner parser does is independent from this
     * parser, and has no effect on this parser
     */
    case CONTENTS:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;

            switch (ssl->handshake.type) {
                case 0: /* hello request*/
                case 1: /* client hello */
                case 3: /* DTLS hello verify request */
                case 4: /* new session ticket */
                case 12: /* server key exchange */
                case 13: /* certificate request */
                case 14: /* server done */
                case 15: /* certificate verify */
                case 16: /* client key exchange */
                case 20: /* finished */
                case 22: /* certificate status */
                default:
                    /* don't parse these types, just skip them */
                    break;
                    
                case 2: /* server hello */
                    parse_server_hello( banner1,
                                       banner1_private,
                                       pstate,
                                       px+i, len,
                                       banout,
                                       more);
                    break;
                case 11: /* server certificate */
                    parse_server_cert(  banner1,
                                      banner1_private,
                                      pstate,
                                      px+i, len,
                                      banout);
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

    ssl->handshake.state = state;
    ssl->handshake.remaining = remaining;
}


/*****************************************************************************
 * Called to parse the "hearbeat" data. This consists of the following 
 * structure:
 *
 * +--------+
 * |  type  | 1=request, 2=response
 * +--------+--------+
 * |      length     |
 * +--------+--------+
 *
 * This is followed by the echoed bytes, followed by some padding.
 *
 *****************************************************************************/
static void
parse_heartbeat(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
{
    struct SSLRECORD *ssl = &pstate->sub.ssl;
    unsigned state = ssl->handshake.state;
    unsigned remaining = ssl->handshake.remaining;
    unsigned i;
    enum {
        START,
        LENGTH0, LENGTH1,
        CONTENTS,
        UNKNOWN,
    };

    UNUSEDPARM(more);
    UNUSEDPARM(banner1_private);

    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (i=0; i<length; i++)
    switch (state) {
            
    /* this is the 'type' field for the hearbeat. There are only two
     * values, '1' for request and '2' for response. Anything else indicates
     * that either the data was corrupted, or else it is encrypted.
     */
    case START:
        if (px[i] < 1 || 2 < px[i]) {
            state = UNKNOWN;
            break;
        }
        ssl->handshake.type = px[i];
        DROPDOWN(i,length,state);

    /* Grab the two byte length field */
    case LENGTH0:
        remaining = px[i];
        DROPDOWN(i,length,state);
    case LENGTH1:
        remaining <<= 8;
        remaining |= px[i];
        
        /* `if heartbeat response ` */
        if (ssl->handshake.type == 2) {
            
            /* if we have a non-trivial amount of data in the response, then
             * it means the "bleed" attempt succeeded. */
            if (remaining >= 16)
                banout_append(  banout, PROTO_VULN, "SSL[HEARTBLEED] ", 16);
            
            /* if we've been configured to "capture" the heartbleed contents,
             * then initialize the BASE64 encoder */
            if (banner1->is_capture_heartbleed) {
                banout_init_base64(&pstate->base64);
                banout_append(banout, PROTO_HEARTBLEED, "", 0);
            }
        }
        DROPDOWN(i,length,state);

    /* Here is where we parse the contents of the heartbeat. This is the same
     * skipping logic as the CONTENTS state within the ssl_parse_record()
     * function.*/
    case CONTENTS:
        {
            unsigned len = (unsigned)length-i;
            if (len > remaining)
                len = remaining;

            /* If this is a RESPONSE, and we've been configured to CAPTURE
             * hearbleed responses, then we write the bleeding bytes in 
             * BASE64 into the banner system. The user will be able to 
             * then do research on those bleeding bytes */
            if (ssl->handshake.type == 2 && banner1->is_capture_heartbleed) {
                banout_append_base64(banout, 
                                     PROTO_HEARTBLEED, 
                                     px+i, len,
                                     &pstate->base64);
            }

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = UNKNOWN; /* padding */
        }

        break;
    
    /* We reach this state either because the hearbeat data is corrupted or
     * encrypted, or because we've reached the padding area after the 
     * heartbeat */
    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    /* not the handshake protocol, but we re-use their variables */
    ssl->handshake.state = state;
    ssl->handshake.remaining = remaining;
}

/*****************************************************************************
 * This is the main SSL parsing function.
 *
 * SSL is a multi-layered protocol, consisting of "Records" as the outer
 * protocol, with records containing data inside. The inner data is
 * unencrypted during the session handshake, but then encrypted from then on.
 *
 * The SSL Records are a simple 5 byte protocol:
 *
 * +--------+
 * |  type  |
 * +--------+--------+
 * |ver-mjr |ver-mnr |
 * +--------+--------+
 * |      length     |
 * +--------+--------+
 *
 * This allows simple state-machine parsing. We need only 6 states, one for
 * each byte, and then a "content" state tracking the contents of the recod
 * until we've parsed "length" bytes, then back to the initial state.
 *
 *****************************************************************************/
static void
ssl_parse_record(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
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

    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (i=0; i<length; i++)
    switch (state) {
            
    /* 
     * The initial state parses the "type" byte. There are only a few types
     * defined so far, the values 20-25, but more can be defined in the 
     * future. The standard explicity says that they must be lower than 128,
     * so if the high-order bit is set, we know that the byte is invalid,
     * and that something is wrong.
     */
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        if (ssl->type != px[i]) {
            ssl->type = px[i];
            
            /* this is for some minimal fragmentation/reassembly */
            ssl->handshake.state = 0;
        }
        DROPDOWN(i,length,state);

    /* This is the major version number, which must be the value '3',
     * which means both SSLv3 and TLSv1. This parser doesn't support
     * earlier versions of SSL. */
    case VERSION_MAJOR:
        if (px[i] != 3) {
            state = UNKNOWN;
            break;
        }
        ssl->version_major = px[i];
        DROPDOWN(i,length,state);

    /* This is the minor version number. It's a little weird:
     * 0 = SSLv3.0
     * 1 = TLSv1.0
     * 2 = TLSv1.1
     * 3 = TLSv1.2
     */
    case VERSION_MINOR:
        ssl->version_minor = px[i];
        DROPDOWN(i,length,state);

    /* This is the length field. In theory, it can be the full 64k bytes
     * in length, but typical implements limit it to 16k */
    case LENGTH0:
        remaining = px[i]<<8;
        DROPDOWN(i,length,state);
    case LENGTH1:
        remaining |= px[i];
        DROPDOWN(i,length,state);
        ssl->handshake.state = 0;
        
    /*
     * This state parses the "contents" of a record. What we do here is at
     * this level of the parser is that we calculate a sub-segment size,
     * which is bounded by either the number of bytes in this records (when
     * there are multiple records per packet), or the packet size (when the
     * record exceeds the size of the packet).
     * We then pass this sug-segment to the inner content parser. However, the
     * inner parser has no effect on what happens in this parser. It's wholy
     * indpedent, doing it's own thing.
     */
    case CONTENTS:
        {
            unsigned len;
            
            /* Size of this segment is either the bytes remaining in the 
             * current packet, or the bytes remaining in the record */
            len = (unsigned)length - i;
            if (len > remaining)
                len = remaining;

            /* Do an inner-parse of this segment. Note that the inner-parser
             * has no effect on this outer record parser */
            switch (ssl->type) {
                case 20: /* change cipher spec */
                    break;
                case 21: /* alert */
                    /* encrypted, usually */
                    break;
                case 22: /* handshake */
                    parse_handshake(banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banout,
                                    more);
                    break;
                case 23: /* application data */
                    /* encrypted, always*/
                    break;
                case 24: /* heartbeat */
                    /* enrypted, in theory, but not practice */
                    parse_heartbeat(banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banout,
                                    more);
                    break;
            }
            
            /* Skip ahead the number bytes in this segment. This makes the
             * parser very fast, because we aren't actually doing a single
             * byte at a time, but skipping forward large number of bytes
             * at a time -- except for the 5 byte headers */
            remaining -= len;
            i += len-1; /* if 'len' is zero, this still works */
            
            /* Once we've exhausted the contents of record, go back to the
             * start parsing the next record */
            if (remaining == 0)
                state = START;
        }
        break;
            
    /* We reach the state when the protocol has become corrupted, such as in
     * those cases where it's not SSL */
    case UNKNOWN:
    default:
        i = (unsigned)length;
    }

    pstate->state = state;
    pstate->remaining = remaining;
}


/*****************************************************************************
 * This is called at program startup to initialize any structures we need
 * for parsing. The SSL parser doesn't need anything in particular, so
 * we just ignore it. We have to implement the callback, however, which
 * is why this empty function exists.
 *****************************************************************************/
static void *
ssl_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}

/*****************************************************************************
 * This is the template "Client Hello" packet that is sent to the server
 * to initiate the SSL connection. Right now, it's statically just transmitted
 * on to the wire.
 * TODO: we need to make this dynamically generated, so that users can
 * select various options.
 *****************************************************************************/
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

"\x00\xfa" /* extensions length */

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


const char
ssl_hello_heartbeat_data[] =
/*0000*/ "\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02\x53\x43\x5b\x90\x9d"
/*0010*/ "\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc"
/*0020*/ "\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde\x00\x00\x66\xc0\x14"
/*0030*/ "\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f"
/*0040*/ "\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16"
/*0050*/ "\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e"
/*0060*/ "\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04"
/*0070*/ "\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05"
/*0080*/ "\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06"
/*0090*/ "\x00\x03\x00\xff\x01\x00\x00\x49\x00\x0b\x00\x04\x03\x00\x01\x02"
/*00a0*/ "\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c"
/*00b0*/ "\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07"
/*00c0*/ "\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02"
/*00d0*/ "\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00\x00\x0f\x00\x01"
/*00e0*/ "\x01";


unsigned ssl_hello_heartbeat_size = sizeof(ssl_hello_heartbeat_data)-1;
const char *ssl_hello_heartbeat = ssl_hello_heartbeat_data;



extern unsigned char ssl_test_case_1[];
extern size_t ssl_test_case_1_size;
extern unsigned char ssl_test_case_3[];
extern size_t ssl_test_case_3_size;
extern unsigned char google_cert[];
extern size_t google_cert_size;
extern unsigned char yahoo_cert[];
extern size_t yahoo_cert_size;


/*****************************************************************************
 *****************************************************************************/
static int
ssl_selftest(void)
{
    struct Banner1 *banner1;
    struct ProtocolState state[1];
    unsigned ii;
    struct BannerOutput banout1[1];
    struct BannerOutput banout2[1];
    struct InteractiveData more;
    unsigned x;

    /*
     * Yahoo cert
     */
    {
        struct CertDecode certstate[1];

        memset(certstate, 0, sizeof(certstate));
        x509_decode_init(certstate, yahoo_cert_size);

        banner1 = banner1_create();
        banner1->is_capture_cert = 1;
        banout_init(banout1);
        x509_decode(certstate, 
                    yahoo_cert,
                    yahoo_cert_size,
                    banout1);
        x = banout_is_contains(banout1, PROTO_SSL3,
                            ", fr.yahoo.com, ");
        if (!x) {
            printf("x.509 parser failure: google.com\n");
            return 1;
        }
        
        
        banner1_destroy(banner1);
        banout_release(banout1);
    }


    /*
     * Google cert
     */
    {
        struct CertDecode certstate[1];

        memset(certstate, 0, sizeof(certstate));
        x509_decode_init(certstate, google_cert_size);

        banner1 = banner1_create();
        banner1->is_capture_cert = 1;
        banout_init(banout1);
        x509_decode(certstate, 
                    google_cert,
                    google_cert_size,
                    banout1);
        x = banout_is_equal(banout1, PROTO_SSL3,
                            ", www.google.com, www.google.com");
        if (!x) {
            printf("x.509 parser failure: google.com\n");
            return 1;
        }
        banner1_destroy(banner1);
        banout_release(banout1);
    }


    /*
     * Do the normal parse
     */
    banner1 = banner1_create();
    banner1->is_capture_cert = 1;
    memset(state, 0, sizeof(state));
    banout_init(banout1);
    {
        size_t i;
        for (i=0; i<ssl_test_case_3_size; i++)
        ssl_parse_record(  banner1,
                         0,
                         state,
                         ssl_test_case_3+i,
                         1,
                         banout1,
                         &more
                         );
    }
    if (0) {
        const char *foo = (char*)banout_string(banout1, PROTO_X509_CERT);
        printf("-----BEGIN CERTIFICATE-----\n");
        for (;;) {
            if (strlen(foo) > 72) {
                printf("%.*s\n", 72, foo);
                foo += 72;
            } else {
                printf("%s\n", foo);
                break;
            }

        }
        printf("-----END CERTIFICATE-----\n");
    }
    banner1_destroy(banner1);
    banout_release(banout1);

    /*
     * Do the fragmented parse
     */
    banner1 = banner1_create();
    banner1->is_capture_cert = 1;
    memset(state, 0, sizeof(state));
    banout_init(banout2);
    for (ii=0; ii<ssl_test_case_3_size; ii++)
    ssl_parse_record(  banner1,
                0,
                state,
                (const unsigned char *)ssl_test_case_3+ii,
                1,
                banout2,
                &more
                );
    banner1_destroy(banner1);
    banout_release(banout2);

    /*
     * Do checking
     */
#if 0
    if (memcmp(banner, "cert:MIIGYjCCBUqgAwIBAgIIWQmqMKKz/PYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE", 65) != 0) {
        fprintf(stderr, "FAIL: ssl test\n");
        return 1;
    }

    if (banner_offset != bannerx_offset
        || memcmp(banner, bannerx, banner_offset) != 0)
        return 1;
#endif
#if 0
    {
        unsigned i = 0;

        while (i < banner_offset) {
            while (i < banner_offset && isspace(banner[i]))
                i++;
            if (memcmp(&banner[i], "cert:", 5) == 0)
                i += 5;

            printf("-----BEGIN CERTIFICATE-----\n");
            while (i < banner_offset && !isspace(banner[i])) {
                unsigned j;
                for (j=0; i+j<banner_offset && !isspace(banner[i+j]) && j < 64; j++)
                    ;
                printf("%.*s\n", j, banner+i);
                i += j;
            }
            printf("-----END CERTIFICATE-----\n");
        }
    }
#endif

    return 0;
}

/*****************************************************************************
 * This is the 'plugin' structure that registers callbacks for this parser in
 * the main system.
 *****************************************************************************/
struct ProtocolParserStream banner_ssl = {
    "ssl", 443, ssl_hello, sizeof(ssl_hello)-1, 0,
    ssl_selftest,
    ssl_init,
    ssl_parse_record,
};

