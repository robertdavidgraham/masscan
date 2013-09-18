#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>
#define STATE_DONE 0xFFFFFFFF
#include <stdio.h>

enum {
    PROTO_UNKNOWN,
    PROTO_SSH1,
    PROTO_SSH2,
    PROTO_HTTP,
    PROTO_FTP1,
    PROTO_FTP2,
    PROTO_DNS_VERSIONBIND,
    PROTO_SNMP,
};

struct Banner1
{
    struct SMACK *smack;
    struct SMACK *http_fields;
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
        struct Banner1 *banner1,
        unsigned state, unsigned *proto,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max);

/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
