#include "pixie-file.h"

#if defined(WIN32)
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#define access _access
#else
#include <unistd.h>
#include <errno.h>
#endif

int
pixie_fopen_shareable(FILE **in_fp, const char *filename, unsigned is_append)
{
    FILE *fp = NULL;

    *in_fp = NULL;

#if defined(WIN32)
    /* PORTABILITY: WINDOWS
     *  This bit of code deals with the fact that on Windows, fopen() opens
     *  a file so that it can't be moved. This code opens it a different
     *  way so that we can move it.
     *
     * NOTE: this is probably overkill, it appears that there is a better
     * API _fsopen() that does what I want without all this nonsense.
     */
    {
    HANDLE hFile;
    int fd;

    /* The normal POSIX C functions lock the file */
    /* int fd = open(filename, O_RDWR | O_CREAT, _S_IREAD | _S_IWRITE); */ /* Fails */
    /* int fd = _sopen(filename, O_RDWR | O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE); */ /* Also fails */

    /* We need to use WINAPI + _open_osfhandle to be able to use
       file descriptors (instead of WINAPI handles) */
    hFile = CreateFileA(    filename,
                            GENERIC_WRITE | (is_append?FILE_APPEND_DATA:0),
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY,
                            NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_RDONLY | _O_TEMPORARY);
    if (fd == -1) {
        perror("_open_osfhandle");
        return -1;
    }

    fp = _fdopen(fd, "w");
    }

#else
    fp = fopen(filename, is_append?"a":"w");
    if (fp == NULL)
        return errno;
#endif

    *in_fp = fp;
    return 0;
}
