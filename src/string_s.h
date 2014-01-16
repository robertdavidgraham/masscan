/*
    safe "string" functions, like Microsoft's

    This is for the "safe" clib functions, where things like "strcpy()" is
    replaced with a safer version of the function, like "strcpy_s()". Since
    these things are non-standard, compilers deal with them differently.

 Reference:
 http://msdn.microsoft.com/en-us/library/bb288454.aspx
*/
#ifndef STRCPY_S
#define STRCPY_S
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#undef strcpy
#define strcpy      STRCPY_FUNCTION_IS_BAD

#undef strncpy
#define strncpy     STRNCPY_FUNCTION_IS_BAD

#undef strcat
#define strcat      STRCAT_FUNCTION_IS_BAD

#undef strncat
#define strncat     STRNCAT_FUNCTION_IS_BAD

#undef sprintf
#define sprintf     SPRINTF_FUNCTION_IS_BAD

#undef vsprintf
#define vsprintf    VSPRINTF_FUNCTION_IS_BAD

#undef strtok
#define strtok      STRTOK_FUNCTION_IS_BAD

#undef gets
#define gets        GETS_FUNCTION_IS_BAD

#undef scanf
#define scanf       SCANF_FUNCTION_IS_BAD

#undef sscanf
#define sscanf      SSCANF_FUNCTION_IS_BAD

#undef itoa
#define itoa        ITOA_FUNCTION_IS_BAD

#undef strerror
#define strerror    STRERROR_FUNCTION_IS_BAD

const char *strerror_x(int x);

#if defined(_MSC_VER) && (_MSC_VER == 1600)
/*Visual Studio 2010*/
# include <stdio.h>
# include <string.h>
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# ifndef PRIu64
#  define PRIu64 "llu"
#  define PRId64 "lld"
#  define PRIx64 "llx"
# endif


#elif defined(_MSC_VER) && (_MSC_VER == 1200)
/* Visual Studio 6.0 */
# define sprintf_s      _snprintf
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# define vsprintf_s     _vsnprintf
 typedef int errno_t;
errno_t fopen_s(FILE **fp, const char *filename, const char *mode);

#elif defined(__GNUC__) && (__GNUC__ == 4)
#include <inttypes.h>
/* GCC 4 */
# define sprintf_s      snprintf
# define vsprintf_s     vsnprintf
 int memcasecmp(const void *lhs, const void *rhs, int length);
 typedef int errno_t;
errno_t fopen_s(FILE **fp, const char *filename, const char *mode);
errno_t strcpy_s(char *dst, size_t sizeof_dst, const char *src);
errno_t localtime_s(struct tm* _tm, const time_t *time);
errno_t gmtime_s(struct tm* _tm, const time_t *time);
#undef strerror

#else
# error unknown compiler
#endif




#endif
