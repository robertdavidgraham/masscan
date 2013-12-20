/*
    portability: time

    Since this program runs on both Linux and Windows, I need a portable
    way to get a high-resolution timer.

    NOTE: The time I'm looking for is "elapsed time" not "wall clock"
    time. In other words, if you put the system to sleep and wake it
    up a day later, this function should see no change, since time
    wasn't elapsing while the system was asleep.

    Reference:
    http://www.python.org/dev/peps/pep-0418/#monotonic-clocks
    http://www.brain-dump.org/blog/entry/107

*/
#include "pixie-timer.h"

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>


#if defined(WIN32)
#include <Windows.h>

LARGE_INTEGER
getFILETIMEoffset(void)
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
pixie_gettime(void)
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
uint64_t
pixie_nanotime(void)
{
    uint64_t time1 = 0, freq = 0;
    double seconds;
    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);
    seconds = (double)time1/(double)freq;
    return (uint64_t)(seconds * 1000000000.0);
}

void
pixie_mssleep(unsigned waitTime)
{
    Sleep(waitTime);
}

void
pixie_usleep(uint64_t waitTime)
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

    start = pixie_gettime();

    if (waitTime > 1000)
        Sleep((DWORD)(waitTime/1000));

    while (pixie_gettime() - start < waitTime)
        ;
}
#elif defined(CLOCK_MONOTONIC)
#include <unistd.h>

void
pixie_mssleep(unsigned milliseconds)
{
    pixie_usleep(milliseconds * 1000ULL);
}

void
pixie_usleep(uint64_t microseconds)
{
    struct timespec ts;
    struct timespec remaining;
    int err;

    ts.tv_sec  =  microseconds/1000000;
    ts.tv_nsec = (microseconds%1000000) * 1000;

again:
    err = nanosleep(&ts, &remaining);
    if (err == -1 && errno == EINTR) {
        memcpy(&ts, &remaining, sizeof(ts));
        goto again;
    }

    //usleep(microseconds);
}
uint64_t
pixie_gettime(void)
{
    int x;
    struct timespec tv;

#ifdef CLOCK_MONOTONIC_RAW
    x = clock_gettime(CLOCK_MONOTONIC_RAW, &tv);
#else
    x = clock_gettime(CLOCK_MONOTONIC, &tv);
#endif
    if (x != 0) {
        printf("clock_gettime() err %d\n", errno);
    }

    return tv.tv_sec * 1000000 + tv.tv_nsec/1000;
}
uint64_t
pixie_nanotime(void)
{
    int x;
    struct timespec tv;

#ifdef CLOCK_MONOTONIC_RAW
    x = clock_gettime(CLOCK_MONOTONIC_RAW, &tv);
#else
    x = clock_gettime(CLOCK_MONOTONIC, &tv);
#endif
    if (x != 0) {
        printf("clock_gettime() err %d\n", errno);
    }

    return tv.tv_sec * 1000000000 + tv.tv_nsec;
}
#elif defined(__MACH__) || defined(__FreeBSD__) /* works for Apple */
#include <unistd.h>
#include <mach/mach_time.h>

void pixie_usleep(uint64_t microseconds)
{
    struct timespec t;
    t.tv_nsec = microseconds * 1000;
    if (microseconds > 1000000)
        t.tv_sec = microseconds/1000000;
    else {
        t.tv_sec = 0;
    }

    nanosleep(&t, 0);
    //usleep(microseconds);
}
void
pixie_mssleep(unsigned milliseconds)
{
    pixie_usleep(milliseconds * 1000ULL);
}
uint64_t
pixie_gettime(void)
{
    return mach_absolute_time()/1000;
}
uint64_t
pixie_nanotime(void)
{
    return mach_absolute_time();
}
#endif

int pixie_time_selftest(void)
{
    static const uint64_t duration = 123456;
    uint64_t start, stop, elapsed;


    start = pixie_gettime();
    pixie_usleep(duration);
    stop = pixie_gettime();
    elapsed = stop - start;

    if (elapsed < 0.9*duration || 1.1*duration < elapsed) {
        /* I wonder how often this will fail just because the process
         * gets swapped out, but I'm leaving it in to see if people notice */
        fprintf(stderr, "timing error, long delay\n");
        return 1;
    }

    return 0;
}
