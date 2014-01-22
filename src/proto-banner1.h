#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>
#define STATE_DONE 0xFFFFFFFF
#include <stdio.h>
#include "proto-banout.h"
#include "proto-x509.h"

struct Banner1
{
    struct SMACK *smack;
    struct SMACK *http_fields;
    struct SMACK *html_fields;

    unsigned is_capture_html:1;
    unsigned is_capture_cert:1;

    struct ProtocolParserStream *tcp_payloads[65536];
};

struct BanBase64
{
    unsigned state:2;
    unsigned temp:24;
};

struct SSL_SERVER_HELLO {
    unsigned state;
    unsigned remaining;
    unsigned timestamp;
    unsigned short cipher_suite;
    unsigned char compression_method;
    unsigned char version_major;
    unsigned char version_minor;
};
struct SSL_SERVER_CERT {
    unsigned state;
    unsigned remaining;
    struct {
        unsigned remaining;
        struct BanBase64 base64;
    } sub;
    struct CertDecode x509;
};

struct SSLRECORD {
    unsigned char content_type;
    unsigned char version_major;
    unsigned char version_minor;

    struct {
        unsigned state;
        unsigned char type;
        unsigned remaining;
    } record;

    union {
        struct {
            /* all these structs should start with state */
            unsigned state;
        } all;
        struct SSL_SERVER_HELLO server_hello;
        struct SSL_SERVER_CERT server_cert;
    } x;

};



struct ProtocolState {
    unsigned state;
    unsigned remaining;
    unsigned short port;
    unsigned short app_proto;
    unsigned is_sent_sslhello:1;
    union {
        struct SSLRECORD ssl;
    } sub;
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
    int (*selftest)(void);
    void *(*init)(struct Banner1 *b);
    void (*parse)(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout);
};


struct Patterns {
    const char *pattern;
    unsigned pattern_length;
    unsigned id;
    unsigned is_anchored;
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
        struct BannerOutput *banout);



/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
