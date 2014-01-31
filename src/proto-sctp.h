#ifndef PROTO_SCTP_H
#define PROTO_SCTP_H
#include <time.h>
#include <stdint.h>

struct PreprocessedInfo;
struct Output;

/**
 * Calculate the "CRC32c" checksum used in SCTP. This is a non-destructive
 * checksum that skips the checksum field itself.
 */
unsigned
sctp_checksum(const void *vbuffer, size_t length);

/**
 * Handle incoming SCTP response
 */
void
handle_sctp(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            unsigned cookie,
            struct PreprocessedInfo *parsed,
            uint64_t entropy);

int
sctp_selftest(void);


#endif
