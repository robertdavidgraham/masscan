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
    For "certificate", we grab the subjectName of the server
 
 
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
#include "stack-tcp-api.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "crypto-siphash24.h"
#include "util-safefunc.h"
#include "util-malloc.h"
#include <string.h>
#include <ctype.h>
#include <assert.h>



/**
 * Fugly macro for doing state-machine parsing. I know it's bad, but
 * it makes stepping through the code in a debugger so much easier.
 */
#define DROPDOWN(i,length,state) (state)++;if (++(i)>=(length)) break


/*****************************************************************************
 *****************************************************************************/
static void
BANNER_CIPHER(struct BannerOutput *banout, unsigned cipher_suite)
{
    //const char *notes = "";
    char foo[64];
    snprintf(foo, sizeof(foo), "cipher:0x%x", cipher_suite);
    banout_append(banout, PROTO_SSL3, foo, AUTO_LEN);
    
    /*switch (cipher_suite) {
     case 0x0005: notes = "(_/RSA/RC4/SHA)"; break;
     case 0x0035: notes = "(_/RSA/AES-CBC/SHA)"; break;
     case 0x002f: notes = "(_/RSA/AES-CBC/SHA)"; break;
     case 0xc013: notes = "(ECDHE/RSA/AES-CBC/SHA)"; break;
     }
     banout_append(banout, PROTO_SSL3, notes, AUTO_LEN);*/
    
}
/*****************************************************************************
 *****************************************************************************/
static void
BANNER_VERSION(struct BannerOutput *banout, unsigned version_major,
               unsigned version_minor)
{
    char foo[64];

    switch (version_major<<8 | version_minor) {
        case 0x0300:
            banout_append(banout, PROTO_SSL3, "SSLv3 ", AUTO_LEN);
            banout_append(  banout, PROTO_VULN, "SSL[v3] ", AUTO_LEN);
            break;
        case 0x0301:
            banout_append(banout, PROTO_SSL3, "TLS/1.0 ", AUTO_LEN);
            break;
        case 0x0302:
            banout_append(banout, PROTO_SSL3, "TLS/1.1 ", AUTO_LEN);
            break;
        case 0x0303:
            banout_append(banout, PROTO_SSL3, "TLS/1.2 ", AUTO_LEN);
            break;
        case 0x0304:
            banout_append(banout, PROTO_SSL3, "TLS/1.3 ", AUTO_LEN);
            break;
        default:
            snprintf(foo, sizeof(foo), "SSLver[%u,%u] ", 
                      version_major,
                      version_minor);
            banout_append(banout, PROTO_SSL3, foo, strlen(foo));
    }
}


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
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
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
    UNUSEDPARM(socket);

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
        BANNER_VERSION(banout, hello->version_major, hello->version_minor);
        if (banner1->is_poodle_sslv3) {
            banout_append(banout, PROTO_VULN, " POODLE ", AUTO_LEN);
        }
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
		if (banner1->is_ticketbleed && remaining > 16) {
			banout_append(  banout, PROTO_VULN, "SSL[ticketbleed] ", 17);
		}
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
        BANNER_CIPHER(banout, hello->cipher_suite);
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
 * This parses the certificates from the server. This contains an outer
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
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
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
        CALEN0, CALEN1, CALEN2,
        CACERT,
        UNKNOWN,
    };

    UNUSEDPARM(banner1);
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(socket);

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
    case CALEN0:
        if (remaining < 3) {
            state = UNKNOWN;
            continue;
        }
        cert_remaining = px[i];
        remaining--;
        DROPDOWN(i,length,state);
    case CLEN1:
    case CALEN1:
        cert_remaining = cert_remaining * 256 + px[i];
        remaining--;
        DROPDOWN(i,length,state);
    case CLEN2:
    case CALEN2:
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
    case CACERT:
        {
            unsigned len = (unsigned)length-i;
	    unsigned proto = (state == CERT ? PROTO_X509_CERT : PROTO_X509_CACERT);
            if (len > remaining)
                len = remaining;
            if (len > cert_remaining)
                len = cert_remaining;

            /* parse the certificate */
            if (banner1->is_capture_cert) {
                banout_append_base64(banout, 
                             proto,
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
                                           proto,
                                           &pstate->base64);        
                    banout_end(banout, proto);
                }
                state = CALEN0;
                if (remaining == 0) {
                    /* FIXME: reduce this logic, it should only flush the
                     * FIXME: ertificate, not close the connection*/
                    if (!banner1->is_heartbleed) {
                        ; //tcpapi_close(socket);
                    }
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
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
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
        if (ssl->handshake.type == 2 && banner1->is_heartbleed) {
            static const char heartbleed_request[] = 
                "\x15\x03\x02\x00\x02\x01\x80"
                "\x18\x03\x02\x00\x03\x01" "\x40\x00";
            tcpapi_send(socket, heartbleed_request, sizeof(heartbleed_request)-1, 0);
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
                                       socket);
                    break;
                case 11: /* server certificate */
                    parse_server_cert(  banner1,
                                      banner1_private,
                                      pstate,
                                      px+i, len,
                                      banout,
                                      socket);
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
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
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

    UNUSEDPARM(socket);
    UNUSEDPARM(banner1_private);

    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (i=0; i<length; i++)
    switch (state) {
            
    /* this is the 'type' field for the heartbeat. There are only two
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
    
    /* We reach this state either because the heartbeat data is corrupted or
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
 * Called to parse the "hearbeat" data. This consists of the following 
 * structure:
 *
 * +--------+
 * | level  | 1=warning, 2=fatal
 * +--------+
 * | descr  |
 * +--------+
 *
 *****************************************************************************/
static void
parse_alert(
                const struct Banner1 *banner1,
                void *banner1_private,
                struct StreamState *pstate,
                const unsigned char *px, size_t length,
                struct BannerOutput *banout,
                struct stack_handle_t *socket)
{
    struct SSLRECORD *ssl = &pstate->sub.ssl;
    unsigned state = ssl->handshake.state;
    unsigned remaining = ssl->handshake.remaining;
    unsigned i;
    enum {
        START,
        DESCRIPTION,
        UNKNOWN,
    };
    
    UNUSEDPARM(socket);
    UNUSEDPARM(banner1_private);
    
    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (i=0; i<length; i++)
        switch (state) {
            case START:
                ssl->x.server_alert.level = px[i];
                DROPDOWN(i,length,state);
                
            case DESCRIPTION:
                ssl->x.server_alert.description = px[i];
                if (banner1->is_poodle_sslv3 && ssl->x.server_alert.level == 2) {
                    char foo[64];

                    /* fatal error */
                    switch (ssl->x.server_alert.description) {
                        case 86:
                            if (!banout_is_contains(banout, PROTO_SAFE, "TLS_FALLBACK_SCSV"))
                                banout_append(banout, PROTO_SAFE, 
                                      "poodle[TLS_FALLBACK_SCSV] ", AUTO_LEN);
                            break;
                        case 40:
                            if (!banout_is_contains(banout, PROTO_SAFE, "TLS_FALLBACK_SCSV"))
                                banout_append(banout, PROTO_SAFE, 
                                          "poodle[no-SSLv3] ", AUTO_LEN);
                            break;
                        default:
                            banout_append(banout, PROTO_SAFE, 
                                          "poodle[no-SSLv3] ", AUTO_LEN);
                            snprintf(foo, sizeof(foo), " ALERT(0x%02x%02x) ",
                                      ssl->x.server_alert.level,
                                      ssl->x.server_alert.description
                                      );
                            
                            banout_append(banout, PROTO_SSL3, foo, AUTO_LEN);
                            break;
                    }
                } else {
                    char foo[64];
                    snprintf(foo, sizeof(foo), " ALERT(0x%02x%02x) ",
                              ssl->x.server_alert.level,
                              ssl->x.server_alert.description
                              );
                
                    banout_append(banout, PROTO_SSL3, foo, AUTO_LEN);
                }
                DROPDOWN(i,length,state);
                
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
 * each byte, and then a "content" state tracking the contents of the record
 * until we've parsed "length" bytes, then back to the initial state.
 *
 *****************************************************************************/
static void
ssl_parse_record(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket)
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
     * defined so far, the values 20-25, but socket can be defined in the
     * future. The standard explicitly says that they must be lower than 128,
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
     * 4 = TLSv1.3
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
     * We then pass this sub-segment to the inner content parser. However, the
     * inner parser has no effect on what happens in this parser. It's wholly
     * independent, doing it's own thing.
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
                    /* encrypted, usually, but if we get one here, it won't
                     * be encrypted */
                    parse_alert(banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banout,
                                    socket);
                    break;
                case 22: /* handshake */
                    parse_handshake(banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banout,
                                    socket);
                    break;
                case 23: /* application data */
                    /* encrypted, always*/
                    break;
                case 24: /* heartbeat */
                    /* encrypted, in theory, but not practice */
                    parse_heartbeat(banner1,
                                    banner1_private,
                                    pstate,
                                    px+i, len,
                                    banout,
                                    socket);
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
ssl_hello_template[] =
"\x16\x03\x01\x00\xc1"          /* TLSv1.0 record layer */
"\x01" /* type = client-hello */
"\x00\x00\xbd" /* length = 193 */
"\x03\x03"      /* version = 3.03 (TLS 1.2) */

"\x97\xe5\x60\x50\xc4\xa5\x4a\xe0\xb9\x01\x75\x15\x31\x23\x27\x68" /* random */
"\x87\xdc\x3d\x66\xec\x07\xdc\xa0\xe5\x1f\x1f\xa1\x3f\x49\xf8\xfc" /* TODO: re-randomize for each request, or at least on startup */

"\x00"/* session-id-length = 0 */

"\x00\x3c" /* cipher suites length */
"\xc0\x2b\xcc\xa9\xc0\x2c\xc0\x09\xc0\x0a\xc0\x23\xc0\x24\xc0\x2f"
"\xcc\xa8\xc0\x30\xc0\x13\xc0\x14\xc0\x27\xc0\x28\x00\x9e\xcc\xaa"
"\x00\x9f\x00\x33\x00\x39\x00\x67\x00\x6b\x00\x9c\x00\x9d\x00\x3c"
"\x00\x3d\x00\x2f\x00\x35\x00\x0a\x00\x05\x00\xff"

"\x01" /* compression-methods-length = 1 */
"\x00"

"\x00\x58" /* extensions length = 88 */
/* extensions */
"\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0c\x00\x0a\x00\x1d"
"\x00\x17\x00\x1e\x00\x19\x00\x18\x00\x23\x00\x00\x00\x16\x00\x00"
"\x00\x17\x00\x00\x00\x0d\x00\x30\x00\x2e\x04\x03\x05\x03\x06\x03"
"\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06"
"\x04\x01\x05\x01\x06\x01\x03\x03\x02\x03\x03\x01\x02\x01\x03\x02"
"\x02\x02\x04\x02\x05\x02\x06\x02"
;

/*****************************************************************************
 * This is the template "Client Hello" packet that is sent to the server
 * to initiate the SSL connection. Right now, it's statically just transmitted
 * on to the wire.
 * TODO: we need to make this dynamically generated, so that users can
 * select various options.
 *****************************************************************************/
static const char
ssl_12_hello_template[] =
"\x16\x03\x01\x01\x1a"
"\x01"
"\x00\x01\x16"
"\x03\x03\x02\x58\x33\x79\x5f\x71\x03\xef\x07\xfe\x36\x61\xb0\x32\x81\xaa\x99\x10\x87\x6a\x8e\x5b\xf9\x03\x93\x44\x58\x4b\x19\xff\x42\x6a\x20\x64\x84\xcd\x28\x9c\xe9\xb1\x9d\xcd\x8a\x11\x4c\x3b\x40\x1c\x90\x02\xf2\xb5\x1a\xf1\x7e\x5d\xb8\x42\xc2\x1e\x17\x1e\x59\xa4\xac\x00\x3e\x13\x02\x13\x03\x13\x01\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff\x01\x00\x00\x8f\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0c\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x00\x23\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x2a\x00\x28\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x01\x03\x02\x04\x02\x05\x02\x06\x02\x00\x2b\x00\x09\x08\x03\x04\x03\x03\x03\x02\x03\x01\x00\x2d\x00\x02\x01\x01\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\xb6\x87\xb7\x72\xb9\xcb\x07\xe0\x14\x0a\x14\x81\x3f\x3f\x0a\xcc\xc4\x7d\x80\xf7\xe8\xaa\x1e\x73\xb0\xa9\xad\xb8\x3a\xa7\x3c\x64";
;
/*****************************************************************************
 *****************************************************************************/
static char *
ssl_add_cipherspec_sslv3(void *templ, unsigned cipher_spec, unsigned is_append)
{
    unsigned char *px;
    size_t len0 = ssl_hello_size(templ);
    size_t len1;
    size_t len1b;
    size_t len2;
    size_t offset;
    size_t offset2;
    
    /* Increase space by 2 for additional cipherspec */
    px = REALLOC(templ, ssl_hello_size(templ) + 2);
    
    /* parse the lengths */
    len1 = px[3] << 8 | px[4];
    len1b = px[6] << 16 | px[7] << 8 | px[8];
    
    
    /* skip session id field */
    offset = 43;
    offset += px[offset] + 1;
    
    /* do cipherspecs */
    len2 = px[offset] << 8 | px[offset+1];
    offset2 = offset+2;
    if (is_append) {
        /* append to end of list */
        memmove(px + offset2 + len2 + 2,
                px + offset2 + len2,
                len0 - (offset2 + len2));
        px[offset2 + len2    ] = (unsigned char)(cipher_spec>>8);
        px[offset2 + len2 + 1] = (unsigned char)(cipher_spec>>0);
    } else {
        /* prepend to start of list, making this the preferred cipherspec*/
        memmove(px + offset2 + 2,
                px + offset2,
                len0 - offset2);
        px[offset2    ] = (unsigned char)(cipher_spec>>8);
        px[offset2 + 1] = (unsigned char)(cipher_spec>>0);
    }
    
    /* fix length fields */
    len2 += 2;
    px[offset    ] = (unsigned char)(len2>>8);
    px[offset + 1] = (unsigned char)(len2>>0);
    len1b += 2;
    px[6] = (unsigned char)(len1b>>16);
    px[7] = (unsigned char)(len1b>> 8);
    px[8] = (unsigned char)(len1b>> 0);
    len1 += 2;
    px[3] = (unsigned char)(len1>>8);
    px[4] = (unsigned char)(len1>>0);
    
    return (char*)px;    
}

/*****************************************************************************
 *****************************************************************************/
char *
ssl_add_cipherspec(void *templ, unsigned cipher_spec, unsigned is_append)
{
    const unsigned char *px = (const unsigned char *)templ;
    unsigned version;
    
    /* ignore things that aren't "Hello" messages */
    if (px[0] != 0x16) {
        fprintf(stderr, "internal error\n");
        return templ;
    }

    /* figure out the proper version */
    version = px[1] << 8 | px[2];
    
    /* do different parsing depending on version */
    switch (version) {
        case 0x300:
            return ssl_add_cipherspec_sslv3(templ, cipher_spec, is_append);
        default:
            /*TODO:*/
            fprintf(stderr, "internal error\n");
            return templ;
    }
}

/*****************************************************************************
 * Figure out the Hello message size by parsing the data
 *****************************************************************************/
unsigned
ssl_hello_size(const void *templ)
{
    const unsigned char *px = (const unsigned char *)templ;
    size_t template_size;
    
    template_size = (px[3]<<8 | px[4]) + 5;
    
    return (unsigned)template_size;
}
    
/*****************************************************************************
 *****************************************************************************/
char *
ssl_hello(const void *templ)
{
    unsigned char *px = (unsigned char *)templ;
    unsigned now = (unsigned)time(0);
    unsigned i;
    
    /* parse existing template to figure out size */
    size_t template_size = (px[3]<<8 | px[4]) + 5;
    
    /* allocate memory for that size and copy */
    px = MALLOC(template_size);
    memcpy(px, templ, template_size);
    
    /* set the new timestamp and randomize buffer */
    px[11] = (unsigned char)(now>>24);
    px[12] = (unsigned char)(now>>16);
    px[13] = (unsigned char)(now>> 8);
    px[14] = (unsigned char)(now>> 0);
    
    /* create a pattern to make this detectable as specifically masscan */
    for (i=4; i<32; i++) {
        static const uint64_t key[2] = {0,0};
        unsigned val = i+now;
        unsigned char c = (unsigned char)siphash24(&val, sizeof(val), key);
        
        px[11+i] = c;
    }
    
    return (char*)px;
}


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
    struct StreamState state[1];
    unsigned ii;
    struct BannerOutput banout1[1];
    struct BannerOutput banout2[1];

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
                         0
                         );
    }
    /*if (0) {
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
    }*/
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
                0
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
struct ProtocolParserStream banner_ssl_12 = {
    "ssl", 443, ssl_12_hello_template, sizeof(ssl_12_hello_template)-1, 0,
    ssl_selftest,
    ssl_init,
    ssl_parse_record,
};

struct ProtocolParserStream banner_ssl = {
    "ssl", 443, ssl_hello_template, sizeof(ssl_hello_template)-1,
    SF__close, /* send FIN after the hello */
    ssl_selftest,
    ssl_init,
    ssl_parse_record,
    0,
    0,
    &banner_ssl_12,
};
