/*
    portability: time

    Since this program runs on both Linux and Windows, I need a portable
    way to get a high-resolution timer.

    NOTE: The time I'm looking for is "elapsed time" not "wall clock"
    time. In other words, if you put the system to sleep and wake it
    up a day later, this function should see no change, since time
    wasn't elapsing while the system was asleep.
*/
#include "pixie-timer.h"

#include <time.h>
#include <stdio.h>
#include <errno.h>

#ifndef WIN32
#include <unistd.h>
#endif

#if defined(WIN32)
#include <Windows.h>

LARGE_INTEGER
getFILETIMEoffset()
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

int
clock_gettime(int X, struct timeval *tv)
{
    LARGE_INTEGER           t;
    FILETIME            f;
    double                  microseconds;
    static LARGE_INTEGER    offset;
    static double           frequencyToMicroseconds;
    static int              initialized = 0;
    static BOOL             usePerformanceCounter = 0;

    X=X;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
        } else {
            offset = getFILETIMEoffset();
            frequencyToMicroseconds = 10.;
        }
    }
    if (usePerformanceCounter) QueryPerformanceCounter(&t);
    else {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    microseconds = (double)t.QuadPart / frequencyToMicroseconds;
    t.QuadPart = (LONGLONG)microseconds;
    tv->tv_sec = (long)(t.QuadPart / 1000000);
    tv->tv_usec = t.QuadPart % 1000000;
    return (0);
}


uint64_t
port_gettime()
{
    //struct timeval tv;
    //clock_gettime(0, &tv);

    uint64_t time1 = 0, freq = 0;
    double seconds;

    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);

    seconds = (double)time1/(double)freq;

    return (uint64_t)(seconds * 1000000.0);

    //return (uint64_t)tv.tv_sec * 1000000UL + tv.tv_usec;
}

void
port_usleep(uint64_t waitTime)
{
    /*
    uint64_t time1 = 0, time2 = 0, freq = 0;

    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);

    do {
        QueryPerformanceCounter((LARGE_INTEGER *) &time2);
    } while((time2-time1) < waitTime);
    */

    uint64_t start;

    start = port_gettime();

    while (port_gettime() - start < waitTime)
        ;
}
#else
void port_usleep(uint64_t microseconds)
{
    usleep(microseconds);
}
uint64_t
port_gettime()
{
    int x;
    struct timespec tv;

    x = clock_gettime(CLOCK_MONOTONIC, &tv);
    if (x != 0) {
        printf("clock_gettime() err %d\n", errno);
    }

    return tv.tv_sec * 1000000 + tv.tv_nsec/1000;
}

#endif

int port_time_selftest()
{
    static const uint64_t duration = 123456;
    uint64_t start, stop, elapsed;
    

    start = port_gettime();
    port_usleep(duration);
    stop = port_gettime();
    elapsed = stop - start;

    if (elapsed < 0.9*duration || 1.1*duration < elapsed) {
        /* I wonder how often this will fail just because the process
         * gets swapped out, but I'm leaving it in to see if people notice */
        fprintf(stderr, "timing error, long delay\n");
        return 1;
    }
    
    return 0;
}
