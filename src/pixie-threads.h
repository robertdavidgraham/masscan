#ifndef PORT_THREADS_H
#define PORT_THREADS_H
#include <stdio.h>
#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/**
 * Returns the number of CPUs in the system, including virtual CPUs.
 * On a single processor system, the number returned will be '1'.
 * On a dual socket, dual-core per socket, hyperthreaded system, the
 * count will be '8'.
 */
unsigned pixie_cpu_get_count(void);

/**
 * Launch a thread
 */
size_t pixie_begin_thread(void (*worker_thread)(void*),
                          unsigned flags,
                          void *worker_data);

void pixie_thread_join(size_t thread_handle);

void pixie_cpu_set_affinity(unsigned processor);
void pixie_cpu_raise_priority(void);

void pixie_locked_subtract_u32(unsigned *lhs, unsigned rhs);



#if defined(_MSC_VER)
#define pixie_locked_add_u32(dst, src) _InterlockedExchangeAdd((volatile long*)(dst), (src))
#define pixie_locked_CAS32(dst, src, expected) (_InterlockedCompareExchange((volatile long*)dst, src, expected) == (expected))
#define pixie_locked_CAS64(dst, src, expected) (_InterlockedCompareExchange64((volatile long long*)dst, src, expected) == (expected))
#define rte_atomic32_cmpset(dst, exp, src) (_InterlockedCompareExchange((volatile long *)dst, (long)src, (long)exp)==(long)(exp))

#elif defined(__GNUC__)
#define pixie_locked_add_u32(dst, src) __sync_add_and_fetch((volatile int*)(dst), (int)(src));
#define rte_atomic32_cmpset(dst, expected, src) __sync_bool_compare_and_swap((volatile int*)(dst),(int)expected,(int)src)
#define pixie_locked_CAS32(dst, src, expected) __sync_bool_compare_and_swap((volatile int*)(dst),(int)expected,(int)src);
#define pixie_locked_CAS64(dst, src, expected) __sync_bool_compare_and_swap((volatile long long int*)(dst),(long long int)expected,(long long int)src);

#if !defined(__x86_64__) && !defined(__i386__)
#define rte_wmb() __sync_synchronize()
#define rte_rmb() __sync_synchronize()
#define rte_pause()
#else
#define rte_wmb() asm volatile("sfence;" : : : "memory")
#define rte_rmb() asm volatile("lfence;" : : : "memory")
#define rte_pause()   asm volatile ("pause")
#endif
#else
unsigned pixie_locked_add_u32(volatile unsigned *lhs, unsigned rhs);
int pixie_locked_CAS32(volatile unsigned *dst, unsigned src, unsigned expected);
int pixie_locked_CAS64(volatile uint64_t *dst, uint64_t src, uint64_t expected);
#endif

#endif
