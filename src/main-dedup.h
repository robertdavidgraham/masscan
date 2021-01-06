#ifndef MAIN_DEDUP_H
#define MAIN_DEDUP_H
#include "massip-addr.h"

struct DedupTable *
dedup_create(void);

void
dedup_destroy(struct DedupTable *table);

unsigned
dedup_is_duplicate(         struct DedupTable *dedup,
                            ipaddress ip_them, unsigned port_them,
                            ipaddress ip_me, unsigned port_me);

/**
 * Simple unit test
 * @return 0 on success, 1 on failure.
 */
int dedup_selftest(void);


#endif
