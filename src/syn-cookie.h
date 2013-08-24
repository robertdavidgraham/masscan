#ifndef SYN_COOKIE_H
#define SYN_COOKIE_H
#include <stdint.h>

unsigned syn_hash(unsigned ip, unsigned port);


void syn_set_entropy(uint64_t seed);


#endif
