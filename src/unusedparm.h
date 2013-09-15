#ifndef UNUSEDPARM
#if defined(_MSC_VER)
#define UNUSEDPARM(x) x
#elif defined(__GNUC__)
#define UNUSEDPARM(x) (void) x
#endif
#endif
