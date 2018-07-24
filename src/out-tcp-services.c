#include "out-tcp-services.h"
#include <string.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#else
#include <WinSock2.h>
#endif
#include <ctype.h>

#if _MSC_VER
#define strdup _strdup
#endif

static char *tcp_services[65536];
static char *udp_services[65536];



const char *
tcp_service_name(int port)
{
    if (tcp_services[port])
        return tcp_services[port];

#ifdef __linux__
    int r;
    struct servent result_buf;
    struct servent *result;
    char buf[2048];
    
    r = getservbyport_r(htons(port), "tcp", &result_buf,buf, sizeof(buf), &result);
    
    /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
    if (r != 0 || result == NULL)
        return "unknown";
    
    return tcp_services[port] = strdup(result_buf.s_name);
#else
    {
    struct servent *result;
    
    result = getservbyport(htons((unsigned short)port), "tcp");
    
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
#ifdef __linux__
    int r;
    struct servent result_buf;
    struct servent *result;
    char buf[2048];
    
    r = getservbyport_r(htons(port), "udp", &result_buf,buf, sizeof(buf), &result);
    
    /* ignore ERANGE - if the result can't fit in 2k, just return unknown */
    if (r != 0 || result == NULL)
        return "unknown";
    
    return udp_services[port] = strdup(result_buf.s_name);
#else
    {
    struct servent *result;
    
    result = getservbyport(htons((unsigned short)port), "udp");
    
    if (result == 0)
        return "unknown";
    
    return udp_services[port] = strdup(result->s_name);
    }
#endif
}
