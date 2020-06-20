#ifndef MAIN_DEDUP_H
#define MAIN_DEDUP_H
#include "ipv6address.h"

struct DedupTable *
dedup_create(void);

void
dedup_destroy(struct DedupTable *table);

unsigned
dedup_is_duplicate(         struct DedupTable *dedup,
                            ipaddress ip_them, unsigned port_them,
                            ipaddress ip_me, unsigned port_me);


#endif
