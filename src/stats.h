#ifndef __src_stats_h
#define __src_stats_h

#include <stdatomic.h>

#define STATS_NAME "stats"

typedef struct stats_st {
    atomic_int_fast64_t sent;
    atomic_int_fast64_t recv;
} stats_t;

void init_stats(stats_t **, const char *);

#endif
