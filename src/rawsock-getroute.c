/*
    get default route (gateway) IPv4 address of the named network
    interface/adapter (like "eth0").

    This works on both Linux and windows.
*/
#include "rawsock.h"
#include "string_s.h"

#include "ranges.h" /*for parsing IPv4 addresses */


#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <unistd.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <ctype.h>

#define ROUNDUP(a)                           \
((a) > 0 ? (1 + (((a) - 1) | (sizeof(int) - 1))) : sizeof(int))

static struct sockaddr *
get_rt_address(struct rt_msghdr *rtm, int desired)
{
    int i;
    int bitmask = rtm->rtm_addrs;
    struct sockaddr *sa = (struct sockaddr *)(rtm + 1);

    for (i = 0; i < RTAX_MAX; i++) {
        if (bitmask & (1 << i)) {
            if ((1<<i) == desired)
                return sa;
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else
            ;
    }
    return NULL;

}

static void
hexdump(const void *v, size_t len)
{
    const unsigned char *p = (const unsigned char *)v;
    size_t i;


    for (i=0; i<len; i += 16) {
        size_t j;

        for (j=i; j<i+16 && j<len; j++)
            printf("%02x ", p[j]);
        for (;j<i+16; j++)
            printf("   ");
        printf("  ");
        for (j=i; j<i+16 && j<len; j++)
            if (isprint(p[j]) && !isspace(p[j]))
                printf("%c", p[j]);
            else
                printf(".");
        printf("\n");
    }
}

#if 0
#define RTA_DST         0x1     /* destination sockaddr present */
#define RTA_GATEWAY     0x2     /* gateway sockaddr present */
#define RTA_NETMASK     0x4     /* netmask sockaddr present */
#define RTA_GENMASK     0x8     /* cloning mask sockaddr present */
#define RTA_IFP         0x10    /* interface name sockaddr present */
#define RTA_IFA         0x20    /* interface addr sockaddr present */
#define RTA_AUTHOR      0x40    /* sockaddr for author of redirect */
#define RTA_BRD         0x80    /* for NEWADDR, broadcast or p-p dest addr */
#endif

void
dump_rt_addresses(struct rt_msghdr *rtm);

void
dump_rt_addresses(struct rt_msghdr *rtm)
{
    int i;
    int bitmask = rtm->rtm_addrs;
    struct sockaddr *sa = (struct sockaddr *)(rtm + 1);

    for (i = 0; i < RTAX_MAX; i++) {
        if (bitmask & (1 << i)) {
            printf("b=%u fam=%u len=%u\n", (1<<i), sa->sa_family, sa->sa_len);
            hexdump(sa, sa->sa_len + sizeof(sa->sa_family));
            sa = (struct sockaddr *)(ROUNDUP(sa->sa_len) + (char *)sa);
        } else
            ;
    }
}

int
rawsock_get_default_gateway(const char *ifname, unsigned *ipv4)
{
    int fd;
    int seq = (int)time(0);
    size_t err;
    struct rt_msghdr *rtm;
    size_t sizeof_buffer;


    /*
     * Requests/responses from the kernel are done with an "rt_msghdr"
     * structure followed by an array of "sockaddr" structures.
     */
    sizeof_buffer = sizeof(*rtm) + sizeof(struct sockaddr_in)*16;
    rtm = (struct rt_msghdr *)malloc(sizeof_buffer);
    if (rtm == NULL)
        exit(1);


    /*
     * Create a socket for querying the kernel
     */
    fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) {
        perror("socket(PF_ROUTE)");
        free(rtm);
        return errno;
    }


    /*
     * Format and send request to kernel
     */
    memset(rtm, 0, sizeof_buffer);
    rtm->rtm_msglen = sizeof_buffer;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_flags = RTF_UP | RTF_GATEWAY;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = seq;
    rtm->rtm_addrs = RTA_DST | RTA_NETMASK | RTA_GATEWAY | RTA_IFP;

    err = write(fd, (char *)rtm, sizeof_buffer);
    if (err != sizeof_buffer) {
        perror("write(RTM_GET)");
        printf("----%u %u\n", (unsigned)err, (unsigned)sizeof_buffer);
        close(fd);
        free(rtm);
        return -1;
    }

    /*
     * Read responses until we find one that belongs to us
     */
    for (;;) {
        err = read(fd, (char *)rtm, sizeof_buffer);
        if (err <= 0)
            break;
        if (rtm->rtm_seq != seq) {
            printf("seq: %u %u\n", rtm->rtm_seq, seq);
            continue;
        }
        if (rtm->rtm_pid != getpid()) {
            printf("pid: %u %u\n", rtm->rtm_pid, getpid());
            continue;
        }
        break;
    }
    close(fd);

    //hexdump(rtm+1, err-sizeof(*rtm));
    //dump_rt_addresses(rtm);

    /*
     * Parse our data
     */
    {
        struct sockaddr_in *sin;
        struct sockaddr_dl *sdl;

        sdl = (struct sockaddr_dl *)get_rt_address(rtm, RTA_IFP);
        if (sdl) {
            //hexdump(sdl, sdl->sdl_len);
            //printf("%.*s\n", sdl->sdl_nlen, sdl->sdl_data);
            if (memcmp(ifname, sdl->sdl_data, sdl->sdl_nlen) != 0) {
                fprintf(stderr, "ERROR: ROUTE DOESN'T MATCH INTERFACE\n");
                fprintf(stderr, "YOU'LL HAVE TO SET --router-mac MANUALLY\n");
                exit(1);
            }
        }

        sin = (struct sockaddr_in *)get_rt_address(rtm, RTA_GATEWAY);
        if (sin) {
            *ipv4 = ntohl(sin->sin_addr.s_addr);
            free(rtm);
            return 0;
        }

    }

    free(rtm);
    return -1;
}

#elif defined(__linux__)
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>



struct route_info {
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

static int
read_netlink(int fd, char *bufPtr, size_t sizeof_buffer, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

 do {
        /* Recieve response from the kernel */
        if ((readLen = recv(fd, bufPtr, sizeof_buffer - msgLen, 0)) < 0) {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) bufPtr;

        /* Check if the header is valid */
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            perror("Error in received packet");
            return -1;
        }

        /* Check if the its the last message */
        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            /* return if its not */
            break;
        }
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* For parsing the route info returned */
static int
parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen = 0;

    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);

    /* This must be an IPv4 (AF_INET) route */
    if (rtMsg->rtm_family != AF_INET)
        return 1;

    /* This must be in main routing table */
    if (rtMsg->rtm_table != RT_TABLE_MAIN)
        return 1;

    /* Attributes field*/
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *) RTA_DATA(rtAttr), rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr .s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }

    return 0;
}


int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4)
{
    int fd;
    struct nlmsghdr *nlMsg;
    char msgBuf[16384];
    int len;
    int msgSeq = 0;

    /*
     * Set to zero, in case we cannot find it
     */
    *ipv4 = 0;

    /*
     * Create 'netlink' socket to query kernel
     */
    fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        fprintf(stderr, "%s:%d: socket(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * format the netlink buffer
     */
    memset(msgBuf, 0, sizeof(msgBuf));
    nlMsg = (struct nlmsghdr *)msgBuf;

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    /*
     * send first request to kernel
     */
    if (send(fd, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        fprintf(stderr, "%s:%d: send(NETLINK_ROUTE): %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }

    /*
     * Now read all the responses
     */
    len = read_netlink(fd, msgBuf, sizeof(msgBuf), msgSeq, getpid());
    if (len <= 0) {
        fprintf(stderr, "%s:%d: read_netlink: %d\n",
            __FILE__, __LINE__, errno);
        return errno;
    }


    /*
     * Parse the response
     */
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        struct route_info rtInfo[1];
        int err;

        memset(rtInfo, 0, sizeof(struct route_info));

        err = parseRoutes(nlMsg, rtInfo);
        if (err != 0)
            continue;

        /* make sure we match the desired network interface */
        if (ifname && strcmp(rtInfo->ifName, ifname) != 0)
            continue;

        /* make sure destination = 0.0.0.0 for "default route" */
        if (rtInfo->dstAddr.s_addr != 0)
            continue;

        /* found the gateway! */
        *ipv4 = ntohl(rtInfo->gateWay.s_addr);
    }

    close(fd);

    return 0;
}

#endif


#if defined(WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "IPHLPAPI.lib")
#endif



int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4)
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD err;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);

    /*
     * Translate numeric index (if it exists) to real name
     */
    ifname = rawsock_win_name(ifname);
    //printf("------ %s -----\n", ifname);

    /*
     * Allocate a proper sized buffer
     */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        fprintf(stderr, "Error allocating memory needed to call GetAdaptersinfo\n");
        return EFAULT;
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
            return EFAULT;
        }
        goto again;
    }
    if (err != NO_ERROR) {
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", 
                            (unsigned)err);
        return EFAULT;
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
        //printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
        //printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
        //printf("\tAdapter Desc: \t%s\n", pAdapter->Description);


        //printf("\tAdapter Addr: \t");
        /*for (i = 0; i < pAdapter->AddressLength; i++) {
            if (i == (pAdapter->AddressLength - 1))
                printf("%.2X\n", (int) pAdapter->Address[i]);
            else
                printf("%.2X-", (int) pAdapter->Address[i]);
        }*/
        //printf("\tIndex: \t%d\n", pAdapter->Index);
        //printf("\tType: \t");
        switch (pAdapter->Type) {
        case MIB_IF_TYPE_OTHER:
            //printf("Other\n");
            break;
        case MIB_IF_TYPE_ETHERNET:
            //printf("Ethernet\n");
            break;
        case MIB_IF_TYPE_TOKENRING:
            //printf("Token Ring\n");
            break;
        case MIB_IF_TYPE_FDDI:
            //printf("FDDI\n");
            break;
        case MIB_IF_TYPE_PPP:
            //printf("PPP\n");
            break;
        case MIB_IF_TYPE_LOOPBACK:
            //printf("Lookback\n");
            break;
        case MIB_IF_TYPE_SLIP:
            //printf("Slip\n");
            break;
        default:
            //printf("Unknown type %ld\n", pAdapter->Type);
            break;
        }

        //printf("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
        //printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

/*typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;*/

        {
            const IP_ADDR_STRING *addr;

            for (addr = &pAdapter->GatewayList;
                    addr;
                    addr = addr->Next) {
                struct Range range;

                range = range_parse_ipv4(addr->IpAddress.String, 0, 0);
                if (range.begin != 0 && range.begin == range.end) {
                    *ipv4 = range.begin;
                }


            }
        }


        //printf("\n");
    }
    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;
}

#endif
