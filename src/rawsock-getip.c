/*
    retrieve IPv4 address of the named network interface/adapter
    like "eth0"

    This works on both Linux and Windows.
*/
#include "rawsock.h"
#include "string_s.h"
#include "ranges.h" /*for parsing IPv4 addresses */

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
        perror("ioctl");
        close(fd);
        return 0;
    } 

    close(fd);

    sa = &ifr.ifr_addr;
    sin = (struct sockaddr_in *)sa;
    return ntohl(sin->sin_addr.s_addr);
}
#endif

#if defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")



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
        fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
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
            fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
            return 0;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", err);
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
#endif

