/*
    portable interface to "raw sockets"

    This uses both "libpcap" on systems, but on Linux, we try to use the 
    basic raw sockets, bypassing libpcap for better performance.
*/
#include "rawsock.h"
#include "tcpkt.h"
#include "logger.h"

#include "string_s.h"


#include <pcap.h>

#ifdef WIN32
#include <Win32-Extensions.h>
#include <iphlpapi.h>
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "IPHLPAPI.lib")

#elif defined(__linux__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

struct pcap_send_queue;
typedef struct pcap_send_queue pcap_send_queue;
pcap_send_queue *pcap_sendqueue_alloc(size_t size) {return 0;}
unsigned pcap_sendqueue_transmit(
    pcap_t *p, pcap_send_queue *queue, int sync) {return 0;}
void pcap_sendqueue_destroy(pcap_send_queue *queue) {;}
int pcap_sendqueue_queue(pcap_send_queue *queue,
    const struct pcap_pkthdr *pkt_header,
    const unsigned char *pkt_data) {return 0;}
#else
#endif

struct Adapter
{
	pcap_t *pcap;
	pcap_send_queue *sendq;
};


struct AdapterNames
{
	char *easy_name;
	char *hard_name;
};

struct AdapterNames adapter_names[64];
unsigned adapter_name_count = 0;

/***************************************************************************
 ***************************************************************************/
#ifdef WIN32
int pcap_setdirection(pcap_t *pcap, pcap_direction_t direction)
{
    static int (*real_setdirection)(pcap_t *, pcap_direction_t) = 0;

    if (real_setdirection == 0) {
        HMODULE h = LoadLibraryA("wpcap.dll");
        if (h == NULL) {
            fprintf(stderr, "couldn't load wpcap.dll: %u\n", GetLastError());
            return -1;
        }

        real_setdirection = (int (*)(pcap_t*,pcap_direction_t))GetProcAddress(h, "pcap_setdirection");
        if (real_setdirection == 0) {
            fprintf(stderr, "couldn't find pcap_setdirection(): %u\n", GetLastError());
            return -1;
        }
    }
#include <winerror.h>
    return real_setdirection(pcap, direction);
}

#endif

/***************************************************************************
 ***************************************************************************/
void
rawsock_init()
{
#ifdef WIN32
    /* Declare and initialize variables */

// It is possible for an adapter to have multiple
// IPv4 addresses, gateways, and secondary WINS servers
// assigned to the adapter. 
//
// Note that this sample code only prints out the 
// first entry for the IP address/mask, and gateway, and
// the primary and secondary WINS server for each adapter. 

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;

/* variables used to print DHCP time info */
    //struct tm newtime;
    //char buffer[32];
    //errno_t error;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return;
    }
// Make an initial call to GetAdaptersInfo to get
// the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
			if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
				continue;

            //printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
            //printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
			{
				size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
				char *name = (char*)malloc(name_len);
				size_t addr_len = pAdapter->AddressLength * 3 + 1;
				char *addr = (char*)malloc(addr_len);
				sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
				
				//printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
				//printf("\tAdapter Addr: \t");
				for (i = 0; i < pAdapter->AddressLength; i++) {
					if (i == (pAdapter->AddressLength - 1))
						sprintf_s(addr+i*3, addr_len-i*3, "%.2X", pAdapter->Address[i]);
					else
						sprintf_s(addr+i*3, addr_len-i*3, "%.2X-", pAdapter->Address[i]);
				}
				//printf("%s  ->  %s\n", addr, name);
				adapter_names[adapter_name_count].easy_name = addr;
				adapter_names[adapter_name_count].hard_name = name;
				adapter_name_count++;
			}

            //printf("\tIndex: \t%d\n", pAdapter->Index);
            
			{
				size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
				char *name = (char*)malloc(name_len);
				size_t addr_len = strlen(pAdapter->IpAddressList.IpAddress.String) + 1;
				char *addr = (char*)malloc(addr_len);
				sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
				sprintf_s(addr, addr_len, "%s", pAdapter->IpAddressList.IpAddress.String);				
				//printf("%s  ->  %s\n", addr, name);
				adapter_names[adapter_name_count].easy_name = addr;
				adapter_names[adapter_name_count].hard_name = name;
				adapter_name_count++;
			}

            //printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
            pAdapter = pAdapter->Next;
        }
    } else {
        printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

    }
    if (pAdapterInfo)
        free(pAdapterInfo);
#endif
    return;
}

/***************************************************************************
 ***************************************************************************/
void
rawsock_list_adapters()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) != -1) {
		int i;
		pcap_if_t *d;
		i=0;

		if (alldevs == NULL) {
			fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
		}
		/* Print the list */
		for(d=alldevs; d; d=d->next) {
			fprintf(stderr, " %d  %s \t", i++, d->name);
			if (d->description)
				fprintf(stderr, "(%s)\n", d->description);
			else
				fprintf(stderr, "(No description available)\n");
		}
		fprintf(stderr,"\n");
	} else {
		fprintf(stderr, "%s\n", errbuf);
	}
}

/***************************************************************************
 ***************************************************************************/
char *adapter_from_index(unsigned index)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
    int x;

    x = pcap_findalldevs(&alldevs, errbuf);
	if (x != -1) {
		pcap_if_t *d;

		if (alldevs == NULL) {
			fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
		}
		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			if (index-- == 0)
				return d->name;
		}
        return 0;
	} else {
        return 0;
	}
}

extern unsigned ip_checksum(struct TcpPacket *pkt);
extern unsigned tcp_checksum(struct TcpPacket *pkt);

/***************************************************************************
 * wrapper for libpcap's sendpacket
 ***************************************************************************/
int
rawsock_send_packet(
    struct Adapter *adapter,
    const unsigned char *packet,
    unsigned length)
{
    return pcap_sendpacket(adapter->pcap, packet, length);
}

/***************************************************************************
 ***************************************************************************/
int rawsock_recv_packet(
    struct Adapter *adapter,
    unsigned *length,
    unsigned *secs,
    unsigned *usecs,
    const unsigned char **packet)
{
    struct pcap_pkthdr hdr;
    
	*packet = pcap_next(adapter->pcap, &hdr);

    if (*packet == NULL)
        return 1;

    *length = hdr.caplen;
    *secs = hdr.ts.tv_sec;
    *usecs = hdr.ts.tv_usec;

    return 0;
}

/***************************************************************************
 ***************************************************************************/
void
rawsock_send_probe(
    struct Adapter *adapter,
    unsigned ip, unsigned port,
    struct TcpPacket *pkt)
{
    pcap_t *pcap;
    pcap_send_queue *sendq;
	int x;
	struct pcap_pkthdr hdr;

    if (adapter == NULL)
        return;
    else {
        pcap = adapter->pcap;
        sendq = adapter->sendq;
    }

	hdr.len = pkt->length;
	hdr.caplen = pkt->length;

    if (pkt->length < 60)
        pkt->length = 60;

	tcp_set_target(pkt, ip, port);
	if (sendq == 0)
		x = pcap_sendpacket(pcap, pkt->packet, pkt->length);
	else {
		x = pcap_sendqueue_queue(sendq, &hdr, pkt->packet);
		if (x != 0) {
			//printf("sendpacket() failed %d\n", x);
			//for (;;)
			x = pcap_sendqueue_transmit(pcap, sendq, 0);
			//printf("pcap_send_queue)() returned %u\n", x);
			pcap_sendqueue_destroy(sendq);
			adapter->sendq = sendq = pcap_sendqueue_alloc(65536);
			x = pcap_sendqueue_queue(sendq, &hdr, pkt->packet);
			//("sendpacket() returned %d\n", x);
			//exit(1);
		} else
			; //printf("+%u\n", count++);
	}
	if (ip_checksum(pkt) != 0xFFFF)
		printf("IP checksum bad 0x%04x\n", ip_checksum(pkt));
	if (tcp_checksum(pkt) != 0xFFFF)
		printf("TCP checksum bad 0x%04x\n", tcp_checksum(pkt));
}

/***************************************************************************
 ***************************************************************************/
static int
is_numeric_index(const char *ifname)
{
    int result = 1;
    int i;

    /* emptry strings aren't numbers */
    if (ifname[0] == '\0')
        return 0;

    /* 'true' if all digits */
    for (i=0; ifname[i]; i++) {
        char c = ifname[i];

        if (c < '0' || '9' < c)
            result = 0;
    }

    return result;
}

const char *rawsock_win_name(const char *ifname)
{
    if (is_numeric_index(ifname)) {
        const char *new_adapter_name;
        
        new_adapter_name = adapter_from_index(atoi(ifname));
        if (new_adapter_name)
            return new_adapter_name;
    }

    return ifname;
}

/***************************************************************************
 ***************************************************************************/
void rawsock_ignore_transmits(struct Adapter *adapter, const unsigned char *adapter_mac)
{
#ifndef WIN32
    int err;
      
    //printf("%u", PCAP_OPENFLAGS_NOCAPTURE_LOCAL);
    err = pcap_setdirection(adapter->pcap, PCAP_D_IN);
    if (err) {
        pcap_perror(adapter->pcap, "pcap_setdirection(IN)");
    }
#else
    int err;
    char filter[256];
    struct bpf_program prog;

    sprintf_s(filter, sizeof(filter), "not ether src %02x:%02X:%02X:%02X:%02X:%02X",
        adapter_mac[0], adapter_mac[1], adapter_mac[2], 
        adapter_mac[3], adapter_mac[4], adapter_mac[5]);

    err = pcap_compile(
                adapter->pcap,
                &prog,          /* object code, output of compile */
                filter,         /* source code */
                1,              /* optimize to go fast */
                0);

    if (err) {
        pcap_perror(adapter->pcap, "pcap_compile()");
        exit(1);
    }


    err = pcap_setfilter(adapter->pcap, &prog);
    if (err < 0) {
        pcap_perror(adapter->pcap, "pcap_setfilter");
        exit(1);
    }
#endif


}

/***************************************************************************
 ***************************************************************************/
struct Adapter *
rawsock_init_adapter(const char *adapter_name)
{
    struct Adapter *adapter;
	char errbuf[PCAP_ERRBUF_SIZE];

    adapter = (struct Adapter *)malloc(sizeof(*adapter));
    memset(adapter, 0, sizeof(*adapter));

    LOG(1, "pcap: %s\n", pcap_lib_version());

    /*
     * If is all digits index, then look in indexed list
     */
    if (is_numeric_index(adapter_name)) {
        const char *new_adapter_name;
        
        new_adapter_name = adapter_from_index(atoi(adapter_name));
        if (new_adapter_name == 0) {
            fprintf(stderr, "pcap_open_live(%s) error: bad index\n", adapter_name);
            return 0;
        } else
            adapter_name = new_adapter_name;
    }
    LOG(2, "RAWSOCK: opening adapter '%s'\n", adapter_name);

	/*
	 * Open the PCAP adapter
	 */
	adapter->pcap = pcap_open_live(
				adapter_name,	    	/* interface name */
				65536,					/* max packet size */
				8,						/* promiscuous mode */
				1000,					/* read timeout in milliseconds */
				errbuf);
	if (adapter->pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) error: %s\n", adapter_name, errbuf);
		return 0;
	}

 	/*
	 * Create a send queue for faster transmits
	 */
#if defined(WIN32)
	adapter->sendq = pcap_sendqueue_alloc(65536);
#else
    adapter->sendq = 0;
#endif

    return adapter;
}



/***************************************************************************
 * for testing when two Windows adapters have the same name. Sometimes
 * the \Device\NPF_ string is prepended, sometimes not.
 ***************************************************************************/
int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs)
{
    if (memcmp(lhs, "\\Device\\NPF_", 12) == 0)
        lhs += 12;
    if (memcmp(rhs, "\\Device\\NPF_", 12) == 0)
        rhs += 12;
    return strcmp(lhs, rhs) == 0;
}

/***************************************************************************
 ***************************************************************************/
int
rawsock_selftest_if(const char *ifname)
{
    int err;
    unsigned ipv4 = 0;
    unsigned router_ipv4 = 0;
    unsigned char mac[6] = {0,0,0,0,0,0};
    struct Adapter *adapter;
    char ifname2[246];

    if (ifname == NULL || ifname[0] == 0) {
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err) {
            fprintf(stderr, "get-default-if: returned err %d\n", err);
            return -1;
        }
        ifname = ifname2;
    }

    /* Name */
    printf("if = %s\n", ifname);

    /* IP address */
    ipv4 = rawsock_get_adapter_ip(ifname);
    if (ipv4 == 0) {
        fprintf(stderr, "get-ip: returned err\n");
    } else {
        printf("ip = %u.%u.%u.%u\n", 
            (unsigned char)(ipv4>>24),
            (unsigned char)(ipv4>>16),
            (unsigned char)(ipv4>>8),
            (unsigned char)(ipv4>>0));
    }

    /* MAC address */
    err = rawsock_get_adapter_mac(ifname, mac);
    if (err) {
        fprintf(stderr, "get-adapter-mac: returned err=%d\n", err);
    } else {
        printf("mac = %02x-%02x-%02x-%02x-%02x-%02x\n", 
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /* Gateway IP */
    err = rawsock_get_default_gateway(ifname, &router_ipv4);
    if (err) {
        fprintf(stderr, "get-default-gateway: returned err=%d\n", err);
    } else {
        unsigned char router_mac[6];

        printf("gateway = %u.%u.%u.%u\n", 
            (unsigned char)(router_ipv4>>24),
            (unsigned char)(router_ipv4>>16),
            (unsigned char)(router_ipv4>>8),
            (unsigned char)(router_ipv4>>0));


        adapter = rawsock_init_adapter(ifname);
        if (adapter == 0) {
            printf("adapter[%s]: failed\n", ifname);
            return -1;
        } else {
            printf("pcap = opened\n");
        }

        memset(router_mac, 0, 6);
        err = arp_resolve_sync(
                adapter,
                ipv4,
                mac,
                router_ipv4,
                router_mac);

        if (memcmp(router_mac, "\0\0\0\0\0\0", 6) != 0) {
            printf("gateway = %02x-%02x-%02x-%02x-%02x-%02x\n",
                router_mac[0],
                router_mac[1],
                router_mac[2],
                router_mac[3],
                router_mac[4],
                router_mac[5]
            );
        } else {
            printf("gateway = [failed to ARP address]\n");
        }
    }

    return 0;
}



/***************************************************************************
 ***************************************************************************/
int
rawsock_selftest()
{

    return 0;
}

