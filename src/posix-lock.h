#ifndef POSIX_LOCK_H
#define POSIX_LOCK_H

#if defined(__linux__) && defined(__GNUC__)
int acquire_posix_lock (const char *filename);
#endif

#endif