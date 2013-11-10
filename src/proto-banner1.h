#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>
#define STATE_DONE 0xFFFFFFFF
#include <stdio.h>


struct Banner1
{
    struct SMACK *smack;
    struct SMACK *http_fields;
    struct SMACK *html_fields;

    unsigned char *http_header;
    unsigned http_header_length;
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
    unsigned banner_offset_start;
    struct {
        unsigned remaining;
        unsigned state;
        unsigned b64x;
    } sub;
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

struct Banner1State {
    unsigned state;
    unsigned remaining;
    unsigned short port;
    unsigned is_sent_sslhello:1;
    union {
        struct SSLRECORD ssl;
    } sub;
};

/**
 * A registration structure for various TCP stream protocols
 * like HTTP, SSL, and SSH
 */
struct Banner1Stream {
    const char *name;
    unsigned port;
    const void *hello;
    size_t hello_length;
    int (*selftest)(void);
    void *(*init)(struct Banner1 *b);
    void (*parse)(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *stream_state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);
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

void
banner1_parse(
        struct Banner1 *banner1,
        struct Banner1State *pstate,
        unsigned *proto,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);

void
banner_append(const void *src, size_t src_len, void *banner, unsigned *banner_offset, size_t banner_max);

void
banner_append_char(int c, void *banner, unsigned *banner_offset, size_t banner_max);

/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
