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
#include "ranges.h" /*for parsing IPv4 addresses */

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
unsigned
rawsock_get_adapter_ip(const char *ifname)
{
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    int x;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy_s(ifr.ifr_name, IFNAMSIZ, ifname);

    x = ioctl(fd, SIOCGIFADDR, &ifr);
    if (x < 0) {
        fprintf(stderr, "ERROR:'%s': %s\n", ifname, strerror(errno));
        //fprintf(stderr, "ERROR:'%s': couldn't discover IP address of network interface\n", ifname);
        close(fd);
        return 0;
    }

    close(fd);

    sa = &ifr.ifr_addr;
    sin = (struct sockaddr_in *)sa;
    return ntohl(sin->sin_addr.s_addr);
}

/*****************************************************************************
 *****************************************************************************/
#elif defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif

unsigned
rawsock_get_adapter_ip(const char *ifname)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

    ifname = rawsock_win_name(ifname);

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        fprintf(stderr, "error:malloc(): for GetAdaptersinfo\n");
        return 0;
    }

    /*
     * Query the adapter info. If the buffer is not big enough, loop around
     * and try again
     */
again:
    err = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (err == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            fprintf(stderr, "error:malloc(): for GetAdaptersinfo\n");
            return 0;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", (unsigned)err);
        return 0;
    }

    /*
     * loop through all adapters looking for ours
     */
    for (   pAdapter = pAdapterInfo;
            pAdapter;
            pAdapter = pAdapter->Next) {
        if (rawsock_is_adapter_names_equal(pAdapter->AdapterName, ifname))
            break;
    }

    if (pAdapter) {
        const IP_ADDR_STRING *addr;

        for (addr = &pAdapter->IpAddressList;
                addr;
                addr = addr->Next) {
            struct Range range;

            range = range_parse_ipv4(addr->IpAddress.String, 0, 0);
            if (range.begin != 0 && range.begin == range.end) {
                return range.begin;
            }
        }
    }

    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
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

