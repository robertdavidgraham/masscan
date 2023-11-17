/*
    safe "string" functions

    This is for the "safe" clib functions, where things like "strcpy()" is
    replaced with a safer version of the function, like "safe_strcpy()".
 
    NOTE: I tried to based these on Microosft's `..._s()` functions proposed
    in Annex K, but it's become too hard trying to deal with both my own
    version and existing versions. Therefore, I've changed this code to
    use names not used by others.

 Reference:
 http://msdn.microsoft.com/en-us/library/bb288454.aspx
*/
#ifndef UTIL_SAFEFUNC_H
#define UTIL_SAFEFUNC_H
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif

#undef strcpy
#define strcpy      STRCPY_FUNCTION_IS_BAD

/*#undef strncpy
#define strncpy     STRNCPY_FUNCTION_IS_BAD*/

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

/**
 * A bounds checking version of strcpy, like `strcpy_s()` on Windows or
 * `strlcpy()` in glibc.
 */
void safe_strcpy(char *dst, size_t sizeof_dst, const char *src);
int safe_localtime(struct tm* _tm, const time_t *time);
int safe_gmtime(struct tm* _tm, const time_t *time);


#if defined(_MSC_VER) && (_MSC_VER >= 1900)
/*Visual Studio 2015 and 2017*/
# include <stdio.h>
# include <string.h>
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# ifndef PRIu64
#  define PRIu64 "llu"
#  define PRId64 "lld"
#  define PRIx64 "llx"
# endif

#elif defined(_MSC_VER) && (_MSC_VER == 1600)
/*Visual Studio 2010*/
# include <stdio.h>
# include <string.h>
#pragma warning(disable: 4996)
#define snprintf _snprintf
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# ifndef PRIu64
#  define PRIu64 "llu"
#  define PRId64 "lld"
#  define PRIx64 "llx"
# endif


#elif defined(_MSC_VER) && (_MSC_VER == 1200)
/* Visual Studio 6.0 */
# define snprintf      _snprintf
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# define vsnprintf     _vsnprintf

#elif defined(__GNUC__) && (__GNUC__ >= 4)
#include <inttypes.h>
 int memcasecmp(const void *lhs, const void *rhs, size_t length);;

#else
# warning unknown compiler
#endif




#endif
