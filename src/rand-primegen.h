#ifndef PRIMEGEN_H
#define PRIMEGEN_H

#include <stdint.h>

/**
 * This is B/32: the number of 32-bit words of space used in the primegen
 * inner loop. This should fit into the CPU's level-1 cache.
 *
 * 2048 works well on a Pentium-100.
 * 3600 works well on a Pentium II-350
 * 4004 works well on an UltraSPARC-I/167
 *
 * 2012-nov (Rob): This code was written 15 years ago. Processor caches
 * haven't really gotten any larger. A number like 8008 works slightly
 * better on an Ivy Bridge CPU, but works noticeably worse on an Atom
 * or ARM processor. The value 4004 seems to be a good compromise for
 * all these processors. In any case, modern CPUs will automatically
 * prefetch the buffers anyway, significantly lessoning the impact of
 * having a poor number defined here. I tried 16016, but it crashed, and
 * I don't know why, but I don't care because I'm not oing to use such a
 * large size.
 */
#define PRIMEGEN_WORDS 4004

typedef struct {
  uint32_t buf[16][PRIMEGEN_WORDS];
  uint64_t p[512]; /* p[num-1] ... p[0], in that order */
  int num;
  int pos; /* next entry to use in buf; WORDS to restart */
  uint64_t base;
  uint64_t L;
} primegen;

extern void primegen_sieve(primegen *);
extern void primegen_fill(primegen *);

extern void primegen_init(primegen *);
extern uint64_t primegen_next(primegen *);
extern uint64_t primegen_peek(primegen *);
extern uint64_t primegen_count(primegen *,uint64_t to);
extern void primegen_skipto(primegen *,uint64_t to);

#endif
