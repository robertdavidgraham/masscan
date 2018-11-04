#include "reallocarray_s.h"
#include <stdlib.h>
#include <stdint.h>

/***************************************************************************
 ***************************************************************************/
void *
reallocarray_s(void *p, size_t count, size_t size)
{
#define MAXNUM ((size_t)1 << (sizeof(size_t)*4)) 
    
    if (count >= MAXNUM || size >= MAXNUM) {
        if (size != 0 && count >= SIZE_MAX/size)
            return realloc(p, SIZE_MAX); /* should trigger error */
    }

    return realloc(p, count * size);
}
