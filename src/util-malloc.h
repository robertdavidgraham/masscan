/*
    Wrappers around the malloc()/heap functions to `abort()` the program in
    case of running out of memory.
 
    Also, defines a REALLOCARRAY() function that checks for integer
    overflow before trying to allocate memory.
*/
#ifndef UTIL_MALLOC_H
#define UTIL_MALLOC_H
#include <stdio.h>
#include <stdlib.h>

void *
REALLOCARRAY(void *p, size_t count, size_t size);

void *
CALLOC(size_t count, size_t size);

void *
MALLOC(size_t size);

void *
REALLOC(void *p, size_t size);

char *
STRDUP(const char *str);



#endif
