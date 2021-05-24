/*
    retrieve IPv4 address of the named network interface/adapter
    like "eth0"


    This works on:
        - Windows
        - Linux
        - Apple
        - FreeBSD

 I think it'll work the same on any BSD system.
*/
#include "rawsock.h"
#include "string_s.h"
#include "massip-parse.h"

/*****************************************************************************
 *****************************************************************************/
#if defined(__linux__)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

ipv6address
rawsock_get_adapter_ipv6(const char *ifname)
{
    struct ifaddrs *list = NULL;
    struct ifaddrs *ifa;
    int err;
    ipv6address result = {0,0};

    /* Fetch the list of addresses */
    err = getifaddrs(&list);
    if (err == -1) {
        fprintf(stderr, "[-] getifaddrs(): %s\n", strerror(errno));
        return result;
    }

    for (ifa = list; ifa != NULL; ifa = ifa->ifa_next) {
        ipv6address addr;

        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_name == NULL)
            continue;
        if (strcmp(ifname, ifa->ifa_name) != 0)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        addr = ipv6address_from_bytes((const unsigned char *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr);
        
        if (addr.hi>>56ULL >= 0xFC)
            continue;
        if (addr.hi>>32ULL == 0x20010db8)
            continue;

        result = addr;
        break;
    }

    freeifaddrs(list);
    return result;
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif


ipv6address
rawsock_get_adapter_ipv6(const char *ifname)
{
    ULONG err;
    ipv6address result = {0,0};
    IP_ADAPTER_ADDRESSES *adapters = NULL;
    IP_ADAPTER_ADDRESSES *adapter;
    IP_ADAPTER_UNICAST_ADDRESS *addr;
    ULONG sizeof_addrs = 0;

    ifname = rawsock_win_name(ifname);

again:
    err = GetAdaptersAddresses(
                        AF_INET6, /* Get IPv6 addresses only */
                        0,
                        0,
                        adapters,
                        &sizeof_addrs);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(adapters);
        adapters = malloc(sizeof_addrs);
        if (adapters == NULL) {
            fprintf(stderr, "GetAdaptersAddresses():malloc(): failed: out of memory\n");
            return result;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersAddresses(): failed: %u\n", (unsigned)err);
        return result;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
        if (rawsock_is_adapter_names_equal(adapter->AdapterName, ifname))
            break;
    }

    /*
     * If our adapter isn't found, print an error.
     */
    if (adapters == NULL) {
        fprintf(stderr, "GetAdaptersInfo: adapter not found: %s\n", ifname);
        goto end;
    }


    /*
     * Search through the list of returned addresses looking for the first
     * that matches an IPv6 address.
     */
    for (addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr->Address.lpSockaddr;
        //char  buf[64];
        ipv6address ipv6;


        /* Ignore any address that isn't IPv6 */
        if (sa->sin6_family != AF_INET6)
            continue;

        /* Ignore transient cluster addresses */
        if (addr->Flags == IP_ADAPTER_ADDRESS_TRANSIENT)
            continue;

#if 0
/* My first attempt was to use the underlying approved operating system
 * APIs to format this, rather than making assumptions about the 
 * structure of how internals might hold an IPv6 address.
 * But it turns out, "inet_ntop()" has some portability
 * issues. Thus, I'm not going to follow this path */
        /* Format as a string */
        inet_ntop(sa->sin6_family, &sa->sin6_addr, buf, sizeof(buf));
        
        /* Convert to internal format */
        ipv6 = massip_parse_ipv6(buf);
        if (ipv6address_is_invalid(ipv6)) {
            fprintf(stderr, "[-] corrupt IPv6 address: %s\n", buf);
            continue;
        }
#else
        ipv6 = ipv6address_from_bytes((const unsigned char *)&sa->sin6_addr);
#endif

        if (addr->PrefixOrigin == IpPrefixOriginWellKnown) {
             /* This value applies to an IPv6 link-local address or an IPv6 loopback address */
            continue;
        }

        if (addr->PrefixOrigin == IpPrefixOriginRouterAdvertisement && addr->SuffixOrigin == IpSuffixOriginRandom) {
            /* This is a temporary IPv6 address
             * See: http://technet.microsoft.com/en-us/ff568768(v=vs.60).aspx */
            continue;
        }

        if (ipv6.hi>>56ULL >= 0xFC)
            continue;

        if (ipv6.hi>>32ULL == 0x20010db8)
            continue;

        result = ipv6;
    }

end:
    free(adapters);
    return result;
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || 1
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef AF_LINK
#   include <net/if_dl.h>
#endif
#ifdef AF_PACKET
#   include <netpacket/packet.h>
#endif

ipv6address
rawsock_get_adapter_ipv6(const char *ifname)
{
    struct ifaddrs *list = NULL;
    struct ifaddrs *ifa;
    int err;
    ipv6address result = {0,0};

    /* Fetch the list of addresses */
    err = getifaddrs(&list);
    if (err == -1) {
        fprintf(stderr, "[-] getifaddrs(): %s\n", strerror(errno));
        return result;
    }

    for (ifa = list; ifa != NULL; ifa = ifa->ifa_next) {
        ipv6address addr;

        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_name == NULL)
            continue;
        if (strcmp(ifname, ifa->ifa_name) != 0)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        addr = ipv6address_from_bytes((const unsigned char *)&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr);
        
        if (addr.hi>>56ULL >= 0xFC)
            continue;
        if (addr.hi>>32ULL == 0x20010db8)
            continue;

        result = addr;
        break;
    }

    freeifaddrs(list);
    return result;
}

#endif

