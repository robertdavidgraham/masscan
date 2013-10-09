/*
    safe C library functions

    This upgrades unsafe C functions like "strcpy()" to safer equivelents,
    like "strcpy_s()".

    NOTE: This is for maintaining a policy of "no unsafe functions"
*/
#include "string_s.h"
#include <errno.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

/**
 * fopen_s
 */
#if defined(__GNUC__) || _MSC_VER == 1200
errno_t fopen_s(FILE **pFile, const char *filename, const char *mode)
{
    if (pFile == NULL || filename == NULL || mode == NULL)
        return EINVAL;
    *pFile = fopen(filename, mode);
    if (*pFile != NULL)
        return 0;
    else
        return errno;
}
#endif

/**
 * Case-insensitive memcmp()
 */
#ifdef __GNUC__
int
memcasecmp(const void *lhs, const void *rhs, int length)
{
    int i;
    for (i=0; i<length; i++) {
        if (tolower(((char*)lhs)[i]) != tolower(((char*)rhs)[i]))
            return -1;
    }
    return 0;
}
#endif

/**
 * strcpy
 */
#ifdef __GNUC__
errno_t strcpy_s(char *dst, size_t sizeof_dst, const char *src)
{
    size_t i;

    if (sizeof_dst == 0)
        return ERANGE;

    if (dst == NULL)
        return EINVAL;

    if (src == NULL) {
        dst[0] = 0;
        return EINVAL;
    }

    for (i=0; src[i]; i++) {
        if (i >= sizeof_dst) {
            dst[0] = 0;
            return ERANGE;
        } else
            dst[i] = src[i];
    }
    if (i >= sizeof_dst) {
        dst[0] = 0;
        return ERANGE;
    } else
        dst[i] = src[i];

    return 0;
}

errno_t localtime_s(struct tm* _tm, const time_t *time)
{
    struct tm *x;

    x = localtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}
errno_t gmtime_s(struct tm* _tm, const time_t *time)
{
    struct tm *x;

    x = gmtime(time);
    if (x == NULL) {
        memset(_tm, 0, sizeof(*_tm));
        return -1;
    }
    memcpy(_tm, x, sizeof(*_tm));

    return 0;
}
#endif


/*
 * I don't understand why Microsoft says this function is unsafe, so
 * do it anyway
 */
const char *strerror_x(int x)
{
#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif
#undef strerror
    return strerror(x);
}
