#include "pixie-threads.h"

#if defined(WIN32)
#include <Windows.h>
#include <process.h>
#endif
#if defined(__GNUC__)
#include <unistd.h>
#include <pthread.h>
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
size_t
pixie_begin_thread(
    void (*worker_thread)(void*),
    unsigned flags,
    void *worker_data)
{
#if defined(WIN32)
    UNUSEDPARM(flags);
    return _beginthread(worker_thread, 0, worker_data);
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

    typedef void *(*PTHREADFUNC)(void*);
    pthread_t thread_id;
    return (size_t)pthread_create(
                          &thread_id,
                          NULL,
                          (PTHREADFUNC)worker_thread,
                          worker_data);

#else
#error pixie_begin_thread undefined
#endif
}
