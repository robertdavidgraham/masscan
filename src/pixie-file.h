#ifndef PIXIE_FILE_H
#define PIXIE_FILE_H
#include <stdio.h>

#if defined(WIN32)
#include <io.h>
#define access _access
#else
#include <unistd.h>
#endif

/**
 * On Windows, files aren't shareable, so we need to have a portable function
 * to open files that can be shared and renamed while they are still open.
 */
int
pixie_fopen_shareable(FILE **in_fp, const char *filename, unsigned is_append);

#endif
