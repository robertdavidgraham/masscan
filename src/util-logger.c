/*
    log messages to console, depending on verbose level

    Use -d to get more verbose output. The more -v you add, the
    more verbose the output becomes.

    Details about the running of the program go to <stderr>.
    Details about scan results go to <stdout>, so that they can easily
    be redirected to a file.
*/
#include "util-logger.h"
#include "util-safefunc.h"
#include <stdarg.h>
#include <stdio.h>

static int global_debug_level = 0; /* yea! a global variable!! */
void LOG_add_level(int x)
{
    global_debug_level += x;
}

/***************************************************************************
 ***************************************************************************/
static void
vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= global_debug_level) {
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}


/***************************************************************************
 * Prints the message if the global "verbosity" flag exceeds this level.
 ***************************************************************************/
void
LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(level, fmt, marker);
    va_end(marker);
}

/***************************************************************************
 ***************************************************************************/
static void
vLOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, va_list marker)
{
    char sz_ip[64];
    ipaddress_formatted_t fmt1 = ipaddress_fmt(ip_them);

    snprintf(sz_ip, sizeof(sz_ip), "%s", fmt1.string);
    fprintf(stderr, "%u:%s: ", port_me, sz_ip);
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}
void
LOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOGnet(port_me, ip_them, fmt, marker);
    va_end(marker);
}



/***************************************************************************
 ***************************************************************************/
static void
vLOGip(int level, ipaddress ip, unsigned port, const char *fmt, va_list marker)
{
    if (level <= global_debug_level) {
        char sz_ip[64];
        ipaddress_formatted_t fmt1 = ipaddress_fmt(ip);

        snprintf(sz_ip, sizeof(sz_ip), "%s:%u: ", fmt1.string, port);
        fprintf(stderr, "%s ", sz_ip);
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}
void
LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOGip(level, ip, port, fmt, marker);
    va_end(marker);
}

