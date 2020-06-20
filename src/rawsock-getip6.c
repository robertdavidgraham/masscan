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
#include "ranges6.h" /*for parsing IPv6 addresses */

/*****************************************************************************
 *****************************************************************************/
#if defined(__linux__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
ipv6address
rawsock_get_adapter_ipv6(const char *ifname)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    int x;
    ipv6address result = {0,0};

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy_s(ifr.ifr_name, IFNAMSIZ, ifname);

    x = ioctl(fd, SIOCGIFADDR, &ifr);
    if (x < 0) {
        fprintf(stderr, "ERROR:'%s': %s\n", ifname, strerror(errno));
        //fprintf(stderr, "ERROR:'%s': couldn't discover IP address of network interface\n", ifname);
        close(fd);
        return result;
    }

    close(fd);

    sa = &ifr.ifr_addr;
    sin = (struct sockaddr_in *)sa;
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
        char  buf[64];
        struct Range6 range;


        /* Ignore any address that isn't IPv6 */
        if (sa->sin6_family != AF_INET6)
            continue;

        /* Ignore transient cluster addresses */
        if (addr->Flags == IP_ADAPTER_ADDRESS_TRANSIENT)
            continue;

        /* Format as a string */
        inet_ntop(sa->sin6_family, &sa->sin6_addr, buf, sizeof(buf));
        
        range = range6_parse(buf, 0, 0);

        if (addr->PrefixOrigin == IpPrefixOriginWellKnown) {
             /* This value applies to an IPv6 link-local address or an IPv6 loopback address */
            continue;
        }

        if (addr->PrefixOrigin == IpPrefixOriginRouterAdvertisement && addr->SuffixOrigin == IpSuffixOriginRandom) {
            /* This is a temporary IPv6 address
             * See: http://technet.microsoft.com/en-us/ff568768(v=vs.60).aspx */
            continue;
        }

        if (range.begin.hi>>56ULL >= 0xFC)
            continue;

        if (range.begin.hi>>32ULL == 0x20010db8)
            continue;

        result = range.begin;
        //printf("origin = %u %u\n", addr->PrefixOrigin, addr->SuffixOrigin);
        //printf("addr' = %s\n", buf);
        //printf("addr` = %s\n", ipv6address_fmt(range.begin).string);
    }

end:
    free(adapters);
    return result;
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(__APPLE__) || defined(__FreeBSD__) || 1
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

unsigned
rawsock_get_adapter_ip(const char *ifname)
{
    int err;
    struct ifaddrs *ifap;
    struct ifaddrs *p;
    unsigned ip;


    /* Get the list of all network adapters */
    err = getifaddrs(&ifap);
    if (err != 0) {
        perror("getifaddrs");
        return 0;
    }

    /* Look through the list until we get our adapter */
    for (p = ifap; p; p = p->ifa_next) {
        if (strcmp(ifname, p->ifa_name) == 0
            && p->ifa_addr
            && p->ifa_addr->sa_family == AF_INET)
            break;
    }
    if (p == NULL)
        goto error; /* not found */

    /* Return the address */
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;

        ip = ntohl(sin->sin_addr.s_addr);
    }

    freeifaddrs(ifap);
    return ip;
error:
    freeifaddrs(ifap);
    return 0;
}

#endif

