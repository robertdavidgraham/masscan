/*
    portable interface to "raw sockets"

    This uses both "libpcap" on systems, but on Linux, we try to use the
    basic raw sockets, bypassing libpcap for better performance.
*/
#include "rawsock.h"
#include "templ-pkt.h"
#include "logger.h"
#include "main-ptrace.h"
#include "string_s.h"
#include "stub-pcap.h"
#include "stub-pfring.h"
#include "pixie-timer.h"
#include "main-globals.h"

#include "unusedparm.h"
#include <assert.h>
#include <ctype.h>

static int is_pcap_file = 0;

#ifdef WIN32
#include <winsock.h>
#include <iphlpapi.h>

#if defined(_MSC_VER)
#pragma comment(lib, "IPHLPAPI.lib")
#endif

#elif defined(__GNUC__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#else
#endif

#include "rawsock-adapter.h"

#define SENDQ_SIZE 65536 * 8


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
        void* h = LoadLibraryA("wpcap.dll");
        if (h == NULL) {
            fprintf(stderr, "couldn't load wpcap.dll: %u\n", 
                                (unsigned)GetLastError());
            return -1;
        }

        real_setdirection = (int (*)(pcap_t*,pcap_direction_t))
                            GetProcAddress(h, "pcap_setdirection");
        if (real_setdirection == 0) {
            fprintf(stderr, "couldn't find pcap_setdirection(): %u\n", 
                                (unsigned)GetLastError());
            return -1;
        }
    }

    return real_setdirection(pcap, direction);
}
#endif

/***************************************************************************
 ***************************************************************************/
void
rawsock_init(void)
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
        for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
                continue;

            //printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
            //printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
            {
                size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
                char *name = (char*)malloc(name_len);
                size_t addr_len = pAdapter->AddressLength * 3 + 1;
                char *addr = (char*)malloc(addr_len);

                if (name == NULL || addr == NULL)
                    exit(1);

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
                if (name == NULL || addr == NULL)
                    exit(1);
                sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
                sprintf_s(addr, addr_len, "%s", pAdapter->IpAddressList.IpAddress.String);
                //printf("%s  ->  %s\n", addr, name);
                adapter_names[adapter_name_count].easy_name = addr;
                adapter_names[adapter_name_count].hard_name = name;
                adapter_name_count++;
            }

        }
    } else {
        printf("GetAdaptersInfo failed with error: %u\n", 
                                                    (unsigned)dwRetVal);

    }
    if (pAdapterInfo)
        free(pAdapterInfo);
#else
    PFRING_init();
#endif
    return;
}

/***************************************************************************
  * This function prints to the command line a list of all the network
  * intefaces/devices.
 ***************************************************************************/
void
rawsock_list_adapters(void)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (PCAP.findalldevs(&alldevs, errbuf) != -1) {
        int i;
        const pcap_if_t *d;
        i=0;
        
        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for(d=alldevs; d; d=PCAP.dev_next(d)) {
            fprintf(stderr, " %d  %s \t", i++, PCAP.dev_name(d));
            if (PCAP.dev_description(d))
                fprintf(stderr, "(%s)\n", PCAP.dev_description(d));
            else
                fprintf(stderr, "(No description available)\n");
        }
        fprintf(stderr,"\n");
        PCAP.freealldevs(alldevs);
    } else {
        fprintf(stderr, "%s\n", errbuf);
    }
}

/***************************************************************************
 ***************************************************************************/
static const char *
adapter_from_index(unsigned index)
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;

    x = PCAP.findalldevs(&alldevs, errbuf);
    if (x != -1) {
        const pcap_if_t *d;

        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for(d=alldevs; d; d=PCAP.dev_next(d)) {
            if (index-- == 0)
                return PCAP.dev_name(d);
        }
        return 0;
    } else {
        return 0;
    }
}

/***************************************************************************
 * Some methods of transmit queue multiple packets in a buffer then
 * send all queued packets at once. At the end of a scan, we might have
 * some pending packets that haven't been transmitted yet. Therefore,
 * we'll have to flush them.
 ***************************************************************************/
void
rawsock_flush(struct Adapter *adapter)
{
    if (adapter->sendq) {
        PCAP.sendqueue_transmit(adapter->pcap, adapter->sendq, 0);

        /* Dude, I totally forget why this step is necessary. I vaguely
         * remember there's a good reason for it though */
        PCAP.sendqueue_destroy(adapter->sendq);
        adapter->sendq =  PCAP.sendqueue_alloc(SENDQ_SIZE);
    }

}

/***************************************************************************
 * wrapper for libpcap's sendpacket
 *
 * PORTABILITY: WINDOWS and PF_RING
 * For performance, Windows and PF_RING can queue up multiple packets, then
 * transmit them all in a chunk. If we stop and wait for a bit, we need
 * to flush the queue to force packets to be transmitted immediately.
 ***************************************************************************/
int
rawsock_send_packet(
    struct Adapter *adapter,
    const unsigned char *packet,
    unsigned length,
    unsigned flush)
{
    if (adapter == 0)
        return 0;

    /* Print --packet-trace if debugging */
    if (adapter->is_packet_trace) {
        packet_trace(stdout, adapter->pt_start, packet, length, 1);
    }

    /* PF_RING */
    if (adapter->ring) {
        int err = PF_RING_ERROR_NO_TX_SLOT_AVAILABLE;

        while (err == PF_RING_ERROR_NO_TX_SLOT_AVAILABLE) {
            err = PFRING.send(adapter->ring, packet, length, (unsigned char)flush);
        }
        if (err < 0)
            LOG(1, "pfring:xmit: ERROR %d\n", err);
        return err;
    }

    /* WINDOWS PCAP */
    if (adapter->sendq) {
        int err;
        struct pcap_pkthdr hdr;
        hdr.len = length;
        hdr.caplen = length;

        err = PCAP.sendqueue_queue(adapter->sendq, &hdr, packet);
        if (err) {
            rawsock_flush(adapter);
            PCAP.sendqueue_queue(adapter->sendq, &hdr, packet);
        }

        if (flush) {
            rawsock_flush(adapter);
        }

        return 0;
    }

    /* LIBPCAP */
    if (adapter->pcap)
        return PCAP.sendpacket(adapter->pcap, packet, length);

    return 0;
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
    
    if (adapter->ring) {
        /* This is for doing libpfring instead of libpcap */
        struct pfring_pkthdr hdr;
        int err;

        again:
        err = PFRING.recv(adapter->ring,
                        (unsigned char**)packet,
                        0,  /* zero-copy */
                        &hdr,
                        0   /* return immediately */
                        );
        if (err == PF_RING_ERROR_NO_PKT_AVAILABLE || hdr.caplen == 0) {
            PFRING.poll(adapter->ring, 1);
            if (is_tx_done)
                return 1;
            goto again;
        }
        if (err)
            return 1;

        *length = hdr.caplen;
        *secs = (unsigned)hdr.ts.tv_sec;
        *usecs = (unsigned)hdr.ts.tv_usec;

    } else if (adapter->pcap) {
        struct pcap_pkthdr hdr;

        *packet = PCAP.next(adapter->pcap, &hdr);

        if (*packet == NULL) {
            if (is_pcap_file) {
                //pixie_time_set_offset(10*100000);
                is_tx_done = 1;
                is_rx_done = 1;
            }
            return 1;
        }

        *length = hdr.caplen;
        *secs = (unsigned)hdr.ts.tv_sec;
        *usecs = (unsigned)hdr.ts.tv_usec;
    }


    return 0;
}


/***************************************************************************
 * Sends the TCP SYN probe packet.
 *
 * Step 1: format the packet
 * Step 2: send it in a portable manner
 ***************************************************************************/
void
rawsock_send_probe(
    struct Adapter *adapter,
    unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    unsigned seqno, unsigned flush,
    struct TemplateSet *tmplset)
{
    unsigned char px[2048];
    size_t packet_length;

    /*
     * Construct the destination packet
     */
    template_set_target(tmplset, ip_them, port_them, ip_me, port_me, seqno,
        px, sizeof(px), &packet_length);
    
    /*
     * Send it
     */
    rawsock_send_packet(adapter, px, (unsigned)packet_length, flush);
}


/***************************************************************************
 * Used on Windows: network adapters have horrible names, so therefore we
 * use numeric indexes instead. You can which adapter you are looking for
 * by typing "--iflist" as an option.
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
 * Used on Windows: if the adpter name is a numeric index, convert it to
 * the full name.
 ***************************************************************************/
const char *
rawsock_win_name(const char *ifname)
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
 * Configure the socket to not capture transmitted packets. This is needed
 * because we transmit packets at a rate of millions per second, which will
 * overwhelm the receive thread.
 *
 * PORTABILITY: Windows doesn't seem to support this feature, so instead
 * what we do is apply a BPF filter to ignore the transmits, so that they
 * still get filtered at a low level.
 ***************************************************************************/
void
rawsock_ignore_transmits(struct Adapter *adapter, const unsigned char *adapter_mac)
{
    UNUSEDPARM(adapter_mac);
    if (adapter->ring) {
        /* PORTABILITY: don't do anything for PF_RING, because it's
         * actually done when we create the adapter, because we can't
         * reconfigure the adapter after it's been activated. */
        return;
    }

    if (adapter->pcap) {
        int err;

        err = PCAP.setdirection(adapter->pcap, PCAP_D_IN);
        if (err) {
            PCAP.perror(adapter->pcap, "pcap_setdirection(IN)");
        }
    }

#if !defined(WIN32)
    /* PORTABILITY: this is what we do on all systems except windows, because
     * Windows doesn't support this feature. */
    if (adapter->pcap) {
        int err;

        err = PCAP.setdirection(adapter->pcap, PCAP_D_IN);
        if (err) {
            PCAP.perror(adapter->pcap, "pcap_setdirection(IN)");
        }
    }
#elif defined(WIN32xxx)
    if (adapter->pcap) {
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
    }
#endif
}

/***************************************************************************
 ***************************************************************************/
static void
rawsock_close_adapter(struct Adapter *adapter)
{
    if (adapter->ring) {
        PFRING.close(adapter->ring);
    }
    if (adapter->pcap) {
        PCAP.close(adapter->pcap);
    }
    if (adapter->sendq) {
        PCAP.sendqueue_destroy(adapter->sendq);
    }

    free(adapter);
}

/***************************************************************************
 * Does the name look like a PF_RING DNA adapter? Common names are:
 * dna0
 * dna1
 * dna0@1
 *
 ***************************************************************************/
static int
is_pfring_dna(const char *name)
{
    if (strlen(name) < 4)
        return 0;
    if (memcmp(name, "zc:", 3) == 0)
        return 1;
    if (memcmp(name, "dna", 3) != 0)
        return 0;

    name +=3;

    if (!isdigit(name[0]&0xFF))
        return 0;
    while (isdigit(name[0]&0xFF))
        name++;

    if (name[0] == '\0')
        return 1;

    if (name[0] != '@')
        return 0;
    else
        name++;

    if (!isdigit(name[0]&0xFF))
        return 0;
    while (isdigit(name[0]&0xFF))
        name++;

    if (name[0] == '\0')
        return 1;
    else
        return 0;
}


/***************************************************************************
 ***************************************************************************/
int
rawsock_datalink(struct Adapter *adapter)
{
    if (adapter->ring)
        return 1; /* ethernet */
    else {
        return adapter->link_type;
    }
}

/***************************************************************************
 ***************************************************************************/
struct Adapter *
rawsock_init_adapter(const char *adapter_name,
                     unsigned is_pfring,
                     unsigned is_sendq,
                     unsigned is_packet_trace,
                     unsigned is_offline,
                     const char *bpf_filter,
                     unsigned is_vlan,
                     unsigned vlan_id)
{
    struct Adapter *adapter;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* BPF filter not supported on some platforms, so ignore this compiler
     * warning when unused */
    UNUSEDPARM(bpf_filter);

    adapter = (struct Adapter *)malloc(sizeof(*adapter));
    if (adapter == NULL)
        exit(1);
    memset(adapter, 0, sizeof(*adapter));
    adapter->is_packet_trace = is_packet_trace;
    adapter->pt_start = 1.0 * pixie_gettime() / 1000000.0;

    adapter->is_vlan = is_vlan;
    adapter->vlan_id = vlan_id;
    
    if (is_offline)
        return adapter;

    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     * If is all digits index, then look in indexed list
     *----------------------------------------------------------------*/
    if (is_numeric_index(adapter_name)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(adapter_name));
        if (new_adapter_name == 0) {
            fprintf(stderr, "pcap_open_live(%s) error: bad index\n",
                    adapter_name);
            return 0;
        } else
            adapter_name = new_adapter_name;
    }

    /*----------------------------------------------------------------
     * PORTABILITY: PF_RING
     *  If we've been told to use --pfring, then attempt to open the
     *  network adapter usign the PF_RING API rather than libpcap.
     *  Since a lot of things can go wrong, we do a lot of extra
     *  logging here.
     *----------------------------------------------------------------*/
    if(is_pfring && !is_pfring_dna(adapter_name)){ /*First ensure pfring dna adapter is available*/
        fprintf(stderr,"No pfring adapter available. Please install pfring or run masscan without the --pfring option.\n");
        return 0;
    }

    if (is_pfring_dna(adapter_name)) {
        int err;
        unsigned version;

        /*
         * Open
         *
         * TODO: Do we need the PF_RING_REENTRANT flag? We only have one
         * transmit and one receive thread, so I don't think we need it.
         * Also, this reduces performance in half, from 12-mpps to
         * 6-mpps.
         * NOTE: I don't think it needs the "re-entrant" flag, because it
         * transmit and receive are separate functions?
         */
        LOG(2, "pfring:'%s': opening...\n", adapter_name);
        adapter->ring = PFRING.open(adapter_name, 1500, 0);//PF_RING_REENTRANT);
        adapter->pcap = (pcap_t*)adapter->ring;
        adapter->link_type = 1;
        if (adapter->ring == NULL) {
            LOG(0, "pfring:'%s': OPEN ERROR: %s\n",
                adapter_name, strerror_x(errno));
            return 0;
        } else
            LOG(1, "pfring:'%s': successfully opened\n", adapter_name);

        /*
         * Housekeeping
         */
        PFRING.set_application_name(adapter->ring, "masscan");
        PFRING.version(adapter->ring, &version);
        LOG(1, "pfring: version %d.%d.%d\n",
                (version >> 16) & 0xFFFF,
                (version >> 8) & 0xFF,
                (version >> 0) & 0xFF);

        LOG(2, "pfring:'%s': setting direction\n", adapter_name);
        err = PFRING.set_direction(adapter->ring, rx_only_direction);
        if (err) {
            fprintf(stderr, "pfring:'%s': setdirection = %d\n",
                    adapter_name, err);
        } else
            LOG(2, "pfring:'%s': direction success\n", adapter_name);

        /*
         * Activate
         *
         * PF_RING requires a separate activation step.
         */
        LOG(2, "pfring:'%s': activating\n", adapter_name);
        err = PFRING.enable_ring(adapter->ring);
        if (err != 0) {
                LOG(0, "pfring: '%s': ENABLE ERROR: %s\n",
                    adapter_name, strerror_x(errno));
                PFRING.close(adapter->ring);
                adapter->ring = 0;
                return 0;
        } else
            LOG(1, "pfring:'%s': successfully enabled\n", adapter_name);

        return adapter;
    }

    
    /*----------------------------------------------------------------
     * PORTABILITY: LIBPCAP
     *
     * This is the stanard that should work everywhere.
     *----------------------------------------------------------------*/
    {
        LOG(1, "pcap: %s\n", PCAP.lib_version());
        LOG(2, "pcap:'%s': opening...\n", adapter_name);
     
        if (memcmp(adapter_name, "file:", 5) == 0) {
            LOG(1, "pcap: file: %s\n", adapter_name+5);
            is_pcap_file = 1;

            adapter->pcap = PCAP.open_offline(
                        adapter_name+5,         /* interface name */
                        errbuf);
        } else {
#if 0
            adapter->pcap = PCAP.open_live(
                        adapter_name,           /* interface name */
                        65536,                  /* max packet size */
                        8,                      /* promiscuous mode */
                        1000,                   /* read timeout in milliseconds */
                        errbuf);
#else
            /* We need to replace "pcap_open_live()" with "pcap_create()/pcap_set_XXX()/pcap_activate()" */
            adapter->pcap = PCAP.create(adapter_name, errbuf);
            if (adapter->pcap) {
                PCAP.set_snaplen(adapter->pcap, 65536);
                PCAP.set_promisc(adapter->pcap, 8);
                PCAP.set_timeout(adapter->pcap, 1000);
                PCAP.set_immediate_mode(adapter->pcap, 1);
                PCAP.activate(adapter->pcap);
            }

#endif
        }

        if (adapter->pcap == NULL) {
            LOG(0, "FAIL: %s\n", errbuf);
            if (strstr(errbuf, "perm")) {
                LOG(0, " [hint] need to sudo or run as root or something\n");
                LOG(0, " [hint] I've got some local priv escalation "
                        "0days that might work\n");
            }
#if defined(__APPLE__)
            if (strcmp(adapter_name, "vmnet1") == 0) {
                LOG(0, " [hint] VMware on Macintosh doesn't support masscan\n");
            }
#endif

            return 0;
        } else
            LOG(1, "pcap:'%s': successfully opened\n", adapter_name);
        

        /* Figure out the link-type. We suport Ethernet and IP */
        {
            int dl = PCAP.datalink(adapter->pcap);
            switch (dl) {
                case 1: /* Ethernet */
                    adapter->link_type = dl;
                    break;
                case 12: /* IP Raw */
                    adapter->link_type = dl;
                    break;
                default:
                    LOG(0, "unknown data link type: %u(%s)\n",
                        dl, PCAP.datalink_val_to_name(dl));
                    break;

            }
        }
        
#if 0
        /* Set any BPF filters the user might've set */
        if (bpf_filter) {
            int err;
            struct bpf_program prog;

            err = pcap_compile(
                        adapter->pcap,
                        &prog,          /* object code, output of compile */
                        bpf_filter,         /* source code */
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
        }
#endif
        

    }

    /*----------------------------------------------------------------
     * PORTABILITY: WINDOWS
     *
     * The transmit rate on Windows is really slow, like 40-kpps.
     * The speed can be increased by using the "sendqueue" feature
     * to roughly 300-kpps.
     *----------------------------------------------------------------*/
    adapter->sendq = 0;
#if defined(WIN32)
    if (is_sendq)
        adapter->sendq = PCAP.sendqueue_alloc(SENDQ_SIZE);
#endif


    return adapter;
}



/***************************************************************************
 * for testing when two Windows adapters have the same name. Sometimes
 * the \Device\NPF_ string is prepended, sometimes not.
 ***************************************************************************/
int
rawsock_is_adapter_names_equal(const char *lhs, const char *rhs)
{
    if (memcmp(lhs, "\\Device\\NPF_", 12) == 0)
        lhs += 12;
    if (memcmp(rhs, "\\Device\\NPF_", 12) == 0)
        rhs += 12;
    return strcmp(lhs, rhs) == 0;
}


/***************************************************************************
 * Runs some tests when the "--debug if" option is given on the
 * command-line. This is useful to figure out why the interface you
 * are accessing doesn't work.
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


        adapter = rawsock_init_adapter(ifname, 0, 0, 0, 0, 0, 0, 0);
        if (adapter == 0) {
            printf("adapter[%s]: failed\n", ifname);
            return -1;
        } else {
            printf("pcap = opened\n");
        }

        memset(router_mac, 0, 6);
        arp_resolve_sync(
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
        rawsock_close_adapter(adapter);
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

