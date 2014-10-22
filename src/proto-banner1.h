#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>
#define STATE_DONE 0xFFFFFFFF
#include <stdio.h>
#include "proto-banout.h"
#include "proto-x509.h"

struct InteractiveData;

struct Banner1
{
    struct SMACK *smack;
    struct SMACK *http_fields;
    struct SMACK *html_fields;

    unsigned is_capture_html:1;
    unsigned is_capture_cert:1;
    unsigned is_capture_heartbleed:1;
    unsigned is_heartbleed:1;
    unsigned is_poodle_sslv3:1;

    struct ProtocolParserStream *tcp_payloads[65536];
};

struct BannerBase64
{
    unsigned state:2;
    unsigned temp:24;
};

struct SSL_SERVER_HELLO {
    unsigned state;
    unsigned remaining;
    unsigned timestamp;
    unsigned short cipher_suite;
    unsigned short ext_tag;
    unsigned short ext_remaining;
    unsigned char compression_method;
    unsigned char version_major;
    unsigned char version_minor;
};
struct SSL_SERVER_CERT {
    unsigned state;
    unsigned remaining;
    struct {
        unsigned remaining;
    } sub;
    struct CertDecode x509;
};
struct SSL_SERVER_ALERT {
    unsigned char level;
    unsigned char description;
};

struct SSLRECORD {
    unsigned char type;
    unsigned char version_major;
    unsigned char version_minor;

    struct {
        unsigned state;
        unsigned char type;
        unsigned remaining;
    } handshake;

    union {
        struct {
            /* all these structs should start with state */
            unsigned state;
        } all;
        struct SSL_SERVER_HELLO server_hello;
        struct SSL_SERVER_CERT server_cert;
        struct SSL_SERVER_ALERT server_alert;
    } x;

};

struct PIXEL_FORMAT {
    unsigned short red_max;
    unsigned short green_max;
    unsigned short blue_max;
    unsigned char red_shift;
    unsigned char green_shift;
    unsigned char blue_shift;
    unsigned char bits_per_pixel;
    unsigned char depth;
    unsigned big_endian_flag:1;
    unsigned true_colour_flag:1;
};
struct VNCSTUFF {
    unsigned sectype;
    unsigned char version;
    unsigned char len;
    
    unsigned short width;
    unsigned short height;
    
    struct PIXEL_FORMAT pixel;    
};

struct FTPSTUFF {
    unsigned code;
    unsigned is_last:1;
};


struct SMTPSTUFF {
    unsigned code;
    unsigned is_last:1;
};

struct POP3STUFF {
    unsigned code;
    unsigned is_last:1;
};

struct ProtocolState {
    unsigned state;
    unsigned remaining;
    unsigned short port;
    unsigned short app_proto;
    unsigned is_sent_sslhello:1;
    unsigned is_done:1;
    struct BannerBase64 base64;

    union {
        struct SSLRECORD ssl;
        struct VNCSTUFF vnc;
        struct FTPSTUFF ftp;
        struct SMTPSTUFF smtp;
        struct POP3STUFF pop3;
    } sub;
};

enum {
    CTRL_SMALL_WINDOW = 1,
};

/**
 * A registration structure for various TCP stream protocols
 * like HTTP, SSL, and SSH
 */
struct ProtocolParserStream {
    const char *name;
    unsigned port;
    const void *hello;
    size_t hello_length;
    unsigned ctrl_flags;
    int (*selftest)(void);
    void *(*init)(struct Banner1 *b);
    void (*parse)(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more);
};


struct Patterns {
    const char *pattern;
    unsigned pattern_length;
    unsigned id;
    unsigned is_anchored;
    unsigned extra;
};

struct Banner1 *
banner1_create(void);

void
banner1_destroy(struct Banner1 *b);

unsigned
banner1_parse(
        const struct Banner1 *banner1,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more);



/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
