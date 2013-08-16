#include "rawsock.h"
#include "string_s.h"

#include "ranges.h" /*for parsing IPv4 addresses */


#if defined(__linux__)
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

int read_netlink(int fd, char *bufPtr, size_t sizeof_buffer, int seqNum, int pId)
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
            perror("Error in recieved packet");
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
int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
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
#pragma comment(lib, "IPHLPAPI.lib")



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
        fprintf(stderr, "GetAdaptersInfo failed with error: %u\n", err);
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
