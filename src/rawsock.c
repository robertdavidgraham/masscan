#define _CRT_SECURE_NO_WARNINGS
#include "rawsock.h"
#include "tcpkt.h"
#include "logger.h"

#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#ifdef WIN32
#include <Win32-Extensions.h>
#include <iphlpapi.h>
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#define snprintf _snprintf
#else
struct pcap_send_queue;
typedef struct pcap_send_queue pcap_send_queue;
pcap_send_queue *pcap_sendqueue_alloc(size_t size) {return 0;}
unsigned pcap_sendqueue_transmit(
    pcap_t *p, pcap_send_queue *queue, int sync) {return 0;}
void pcap_sendqueue_destroy(pcap_send_queue *queue) {;}
int pcap_sendqueue_queue(pcap_send_queue *queue,
    const struct pcap_pkthdr *pkt_header,
    const unsigned char *pkt_data) {return 0;}
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

	/*
	 * Translate the adapter name into a raw adapter name
	 */
/*
	for (i=0; i<adapter_name_count; i++) {
		if (_stricmp(adapter_names[i].easy_name, masscan->ifname) == 0) {
			snprintf(masscan->ifname, sizeof(masscan->ifname), "%s", adapter_names[i].hard_name);
		}
	}
*/


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
				snprintf(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
				
				//printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
				//printf("\tAdapter Addr: \t");
				for (i = 0; i < pAdapter->AddressLength; i++) {
					if (i == (pAdapter->AddressLength - 1))
						snprintf(addr+i*3, addr_len-i*3, "%.2X", pAdapter->Address[i]);
					else
						snprintf(addr+i*3, addr_len-i*3, "%.2X-", pAdapter->Address[i]);
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
				snprintf(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
				snprintf(addr, addr_len, "%s", pAdapter->IpAddressList.IpAddress.String);				
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

/***************************************************************************
 ***************************************************************************/
struct Adapter *
rawsock_init_adapter(const char *adapter_name)
{
    struct Adapter *adapter;
	char errbuf[PCAP_ERRBUF_SIZE];

    adapter = (struct Adapter *)malloc(sizeof(*adapter));
    memset(adapter, 0, sizeof(*adapter));

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
	adapter->sendq = 0; //pcap_sendqueue_alloc(65536);

    return adapter;
}

/***************************************************************************
 ***************************************************************************/
int
rawsock_selftest()
{
    return 0;
}
