#ifndef PROTO_ZEROACCESS_H
#define PROTO_ZEROACCESS_H
#include <time.h>
#include <stdint.h>
struct PreprocessedInfo;
struct Output;

unsigned
handle_zeroaccess(  struct Output *out, time_t timestamp,
                    const unsigned char *px, unsigned length,
                    struct PreprocessedInfo *parsed,
                    uint64_t entropy);

extern const unsigned char zeroaccess_getL[];
#define zeroaccess_getL_length 16


/**
 * Regression test this module.
 * @return
 *      0 on success, a positive integer otherwise.
 */
int
zeroaccess_selftest(void);

#endif
