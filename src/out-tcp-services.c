#include "out-tcp-services.h"
#include <string.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#else
#include <WinSock2.h>
#endif
#include <ctype.h>

/**
 * This is a stupid hack to avoid dependencies. I want to minimize the dependence
 * on network libraries. For example, I get a warning message on FreeBSD about
 * a missing `htons()`. I could just add a system header, but then this increases
 * dependencies on other things. Alternatively, I could just implement the
 * function myself. So I chose that route.
 */
static unsigned short my_htons(unsigned port)
{
    static const char test[2] = "\x11\x22";
    if (*(unsigned short*)test == 0x1122)
        return (unsigned short)(0xFFFF & port);
    else
        return (unsigned short)((port>>8)&0xFF) | ((port&0xFF)<<8);
}

#if _MSC_VER
#define strdup _strdup
#endif

static char *tcp_services[65536];
static char *udp_services[65536];
static char *oproto_services[256];


const char *
tcp_service_name(int port)
{
    if (tcp_services[port])
        return tcp_services[port];

#if defined(__linux__) && !defined(__TERMUX__)
    int r;
    struct servent result_buf;
    struct servent *result;
    char buf[2048];
    
    r = getservbyport_r(my_htons(port), "tcp", &result_buf,buf, sizeof(buf), &result);
    
    /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
    if (r != 0 || result == NULL)
        return "unknown";
    
    return tcp_services[port] = strdup(result_buf.s_name);
#else
    {
    struct servent *result;
    
    result = getservbyport(my_htons((unsigned short)port), "tcp");
    
    if (result == 0)
        return "unknown";
    
    return tcp_services[port] = strdup(result->s_name);
    }
#endif
}

const char *
udp_service_name(int port)
{
    if (udp_services[port])
        return udp_services[port];
#if defined(__linux__) && !defined(__TERMUX__)
    int r;
    struct servent result_buf;
    struct servent *result;
    char buf[2048];
    
    r = getservbyport_r(my_htons(port), "udp", &result_buf,buf, sizeof(buf), &result);
    
    /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
    if (r != 0 || result == NULL)
        return "unknown";
    
    return udp_services[port] = strdup(result_buf.s_name);
#else
    {
    struct servent *result;
    
    result = getservbyport(my_htons((unsigned short)port), "udp");
    
    if (result == 0)
        return "unknown";
    
    return udp_services[port] = strdup(result->s_name);
    }
#endif
}

const char *
oproto_service_name(int port)
{
    if (oproto_services[port])
        return oproto_services[port];
    {
        struct protoent *result;
        
        result = getprotobynumber(port);
        
        if (result == 0)
            return "unknown";
        
        return oproto_services[port] = strdup(result->p_name);
    }
}
