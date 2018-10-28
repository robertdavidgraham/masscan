#define _GNU_SOURCE
#include "pixie-threads.h"

#if defined(WIN32)
#include <Windows.h>
#include <process.h>
#endif
#if defined(__GNUC__)
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#ifndef UNUSEDPARM
#ifdef _MSC_VER
#define UNUSEDPARM(x) x
#else
#define UNUSEDPARM(x)
#endif
#endif

/****************************************************************************
 ****************************************************************************/
void
pixie_cpu_raise_priority(void)
{
#if defined WIN32
DWORD_PTR result;
    result = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    if (result == 0) {
        fprintf(stderr, "set_priority: returned error win32:%u\n", (unsigned)GetLastError());
    }
#elif defined(__linux__) && defined(__GNUC__)
    pthread_t thread = pthread_self();
    pthread_attr_t thAttr;
    int policy = 0;
    int max_prio_for_policy = 0;

    pthread_attr_init(&thAttr);
    pthread_attr_getschedpolicy(&thAttr, &policy);
    max_prio_for_policy = sched_get_priority_max(policy);


    pthread_setschedprio(thread, max_prio_for_policy);
    pthread_attr_destroy(&thAttr);
    return;

#endif
}

/****************************************************************************
 * Set the current thread (implicit) to run exclusively on the explicit
 * process.
 * http://en.wikipedia.org/wiki/Processor_affinity
 ****************************************************************************/
void
pixie_cpu_set_affinity(unsigned processor)
{
#if defined WIN32
    DWORD_PTR mask;
    DWORD_PTR result;
    if (processor > 0)
        processor--;
    mask = ((size_t)1)<<processor;

    //printf("mask(%u) = 0x%08x\n", processor, mask);
    result = SetThreadAffinityMask(GetCurrentThread(), mask);
    if (result == 0) {
        fprintf(stderr, "set_affinity: returned error win32:%u\n", (unsigned)GetLastError());
    }
#elif defined(__linux__) && defined(__GNUC__)
    int x;
    pthread_t thread = pthread_self();
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);

    CPU_SET(processor+1, &cpuset);

    x = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (x != 0) {
        fprintf(stderr, "set_affinity: returned error linux:%d\n", errno);
    }
#endif
}

/****************************************************************************
 ****************************************************************************/
unsigned
pixie_cpu_get_count(void)
{
#if defined WIN32
    /* WINDOWS - use GetProcessAffinityMask() function */
    size_t x;
#if defined _M_X64
    DWORD_PTR process_mask = 0;
    DWORD_PTR system_mask = 0;
#else
    unsigned long process_mask = 0;
    unsigned long system_mask = 0;
#endif
    unsigned count = 0;
    unsigned i;

    x = GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask);
    if (x == 0) {
        printf("GetProcessAffinityMask() returned error %u\n", (unsigned)GetLastError());
        return 1;
    }
    for (i=0; i<32; i++) {
        if (system_mask & 1)
            count++;
        system_mask >>= 1;
    }
    if (count == 0)
        return 1;
    else
        return count;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    /* BSD - use sysctl() function */
        int x;
        int mib[2];
        size_t ncpu_length;
        int ncpu = 1;

        mib[0] = CTL_HW;
        mib[1] = HW_NCPU;
        ncpu_length = sizeof(ncpu);
        x = sysctl(mib, 2, &ncpu, &ncpu_length, NULL, 0);
        if (x == -1) {
          perror("sysctl(HW_NCPU) failed");
          return 1;
        } else
          return (unsigned)ncpu;
#elif defined linux
    /* http://linux.die.net/man/2/sched_getaffinity */
    {
        pid_t pid;
        cpu_set_t mask;
        int err;

        /* Gegret our process ID */
        pid = getpid();

        /* Get list of available CPUs for our system */
        err = sched_getaffinity(pid, sizeof(mask), &mask);
        if (err) {
            perror("sched_getaffinity");
            return 1;
        } else {
#ifndef CPU_COUNT
            return 1;
#else
            return CPU_COUNT(&mask);
#endif
        }
    }
#else
#error need to find CPU count
    /* UNKNOWN - Well, we don't know the type of system which means we won't
     * be able to start multiple threads anyway, so just return '1' */
    return 1;
#endif
}

/****************************************************************************
 ****************************************************************************/
size_t
pixie_begin_thread(
    void (*worker_thread)(void*),
    unsigned flags,
    void *worker_data)
{
#if defined(WIN32)
    UNUSEDPARM(flags);
    return _beginthread(worker_thread, 0, worker_data);
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__kFreeBSD__) || defined(__OpenBSD__)

    typedef void *(*PTHREADFUNC)(void*);
    pthread_t thread_id = 0;
    pthread_create(
                          &thread_id,
                          NULL,
                          (PTHREADFUNC)worker_thread,
                          worker_data);
    return (size_t)thread_id;
#else
#error pixie_begin_thread undefined
#endif
}

/****************************************************************************
 ****************************************************************************/
void pixie_thread_join(size_t thread_handle)
{
#if defined(WIN32)
    WaitForSingleObject((HANDLE)thread_handle, INFINITE);
#else
    void *p;

    pthread_join((pthread_t)thread_handle, &p);
#endif
}
