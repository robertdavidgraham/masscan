#include "util-malloc.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAXNUM ((size_t)1 << (sizeof(size_t)*4))

/***************************************************************************
 ***************************************************************************/
void *
REALLOCARRAY(void *p, size_t count, size_t size)
{
    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX/size) {
            fprintf(stderr, "[-] alloc too large, aborting\n");
            abort();
        }
    }

    p = realloc(p, count * size);
    if (p == NULL && count * size != 0) {
        fprintf(stderr, "[-] out of memory, aborting\n");
        abort();
    }
    
    return p;
}

/***************************************************************************
 ***************************************************************************/
void *
CALLOC(size_t count, size_t size)
{
    void *p;
    
    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX/size) {
            fprintf(stderr, "[-] alloc too large, aborting\n");
            abort();
        }
    }
    
    p = calloc(count, size);
    if (p == NULL && count * size != 0) {
        fprintf(stderr, "[-] out of memory, aborting\n");
        abort();
    }
    
    return p;
}

/***************************************************************************
 * Wrap the standard 'malloc()' function.
 * - never returns a NULL pointer, aborts program instead
 * - if size is zero, still returns a valid pointer to one byte
 ***************************************************************************/
void *
MALLOC(size_t size)
{
    void *p;
    
    /* If 'size' is zero, then the behavior of 'malloc()' is undefined.
     * I'm not sure which behavior would be best, to either always abort
     * or always succeed. I'm choosing "always succeed" by bumping the
     * length by one byte */
    if (size == 0)
        size = 1;
    
    /* Do the original allocation */
    p = malloc(size);
    
    /* Abort the program if we've run out of memory */
    if (p == NULL) {
        fprintf(stderr, "[-] out of memory, aborting\n");
        abort();
    }
    
    /* At this point, we've either succeeded or aborted the program,
     * so this value is guaranteed to never be NULL */
    return p;
}

/***************************************************************************
 ***************************************************************************/
void *
REALLOC(void *p, size_t size)
{
    p = realloc(p, size);
    
    if (p == NULL) {
        fprintf(stderr, "[-] out of memory, aborting\n");
        abort();
    }
    
    return p;
}

/***************************************************************************
 ***************************************************************************/
char *
STRDUP(const char *str)
{
#if defined(WIN32)
    char *p = _strdup(str);
#else
    char *p = strdup(str);
#endif
    
    if (p == NULL && str != NULL) {
        fprintf(stderr, "[-] out of memory, aborting\n");
        abort();
    }
    
    return p;
}


