/*
    When program crashes, print backtrace with line numbers
*/
#include "pixie-backtrace.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

char global_self[512] = "";


#if defined(__linux__)
#include <unistd.h>
#include <execinfo.h>
#include <dlfcn.h>




#define BACKTRACE_SIZE 256
static void
handle_segfault(int sig)
{
	void *func[BACKTRACE_SIZE];
	char **symb = NULL;
	int size;

	size = backtrace(func, BACKTRACE_SIZE);
	symb = backtrace_symbols(func, size);
	while (size > 0) {
        const char *symbol = symb[size - 1];
        char foo[1024];
		printf("%d: [%s]\n", size, symbol);
        if (strstr(symbol, "[0x")) {
            char *p = strstr(symbol, "[0x") + 1;
            char *pp = strchr(p, ']');

            snprintf(foo, sizeof(foo), "addr2line -p -i -f -e %s %.*s",
                global_self,
                (unsigned)(pp-p),
                p);
            system(foo);
        }
		size --;
	}
    exit(1);
    return;
}


/***************************************************************************
 ***************************************************************************/
void
pixie_backtrace_finish(void)
{
}

/***************************************************************************
 ***************************************************************************/
void
pixie_backtrace_init(const char *self)
{

    /* Need to get a handle to the currently executing program. On Linux,
     * we'll get this with /proc/self/exe, but on other platforms, we may
     * need to do other things */
    /* TODO: should we use readlink() to get the actual filename? */
#if defined(__linux__)
    readlink("/proc/self/exe", global_self, sizeof(global_self));
#elif defined(__FreeBSD__)
    readlink("/proc/curproc/file", global_self, sizeof(global_self));
#elif defined(__Solaris__)
    readlink("/proc/self/path/a.out", global_self, sizeof(global_self));
#else
    snprintf(global_self, sizeof(global_self), "%s", self);
#endif


	signal(SIGSEGV, handle_segfault);
}
#elif defined(WIN32)
#include <Windows.h>
void
pixie_backtrace_init(const char *self)
{

    GetModuleFileNameA(NULL, global_self, sizeof(global_self));

}
#else
void
pixie_backtrace_init(const char *self)
{
}
#endif