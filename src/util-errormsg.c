#include "util-errormsg.h"
#include "crypto-siphash24.h"
#include "massip-addr.h"
#include <stdarg.h>
#include <stdio.h>

#ifdef _MSC_VER
#pragma warning(disable: 4204)
#endif


static unsigned long long _entropy;

void errmsg_init(unsigned long long in_entropy) {
    _entropy = in_entropy;
}

static void
_errmsg(const char *fmt, va_list marker)
{
    fprintf(stderr, "[-] ERR: ");
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

static void
_errmsgip(ipaddress ip, unsigned port, const char *fmt, va_list marker)
{
    ipaddress_formatted_t fmted = ipaddress_fmt(ip);
    
    fprintf(stderr, "[-] %s:%u: ", fmted.string, port);
    vfprintf(stderr, fmt, marker);
    fflush(stderr);
}

/***************************************************************************
 * Prints the message if the global "verbosity" flag exceeds this level.
 ***************************************************************************/
void
ERRMSG(const char *fmt, ...)
{
    va_list marker;
    size_t index;
    uint64_t key[2] = {_entropy, _entropy};
    static size_t _table[1024] = {0};

    /* Hash the address of the format string */
    index = (size_t)siphash24(fmt, sizeof(fmt), key);
    index %= 1024;

    /* Filter out this error if we've seen it before */
    if (_table[index] == (size_t)fmt)
        return;
    else
        _table[index] = (size_t)fmt;

   
    va_start(marker, fmt);
    _errmsg(fmt, marker);
    va_end(marker);
}

void
ERRMSGip(ipaddress ip, unsigned port, const char *fmt, ...)
{
    va_list marker;
    size_t index;
    uint64_t key[2] = {_entropy, _entropy};
    static size_t _table[1024] = {0};

    /* Hash the address of the format string */
    index = (size_t)siphash24(fmt, sizeof(fmt), key);
    index %= 1024;

    /* Filter out this error if we've seen it before */
    if (_table[index] == (size_t)fmt)
        return;
    else
        _table[index] = (size_t)fmt;

   
    va_start(marker, fmt);
    _errmsgip(ip, port, fmt, marker);
    va_end(marker);
}

