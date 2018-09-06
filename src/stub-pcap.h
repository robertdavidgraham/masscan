/*
    Dynamically load libpcap at runtime
 
 This library optionally loads the 'libpcap' library at runtime, rather
 than statically linked at compile time. The advantage of this is that
 the user can build this project with no dependencies -- although they
 may require this dependency in order to run the program.
 
 As of 2017, libpcap shared libraries are standard on major Linux
 distributions (Debian, Readhat), FreeBSD, OpenBSD, and macOS. On
 Windows, "winpcap" must be downloaded. 
*/
#ifndef RAWSOCK_PCAP_H
#define RAWSOCK_PCAP_H
#include <stdio.h>



/* Including the right ".h" file to define "timeval" is difficult, so instead
 * so instead we are simply going to define our own structure. This should
 * match the binary definition within the operating system
 */
struct pcap_timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};

/* Forward reference of opaque 'pcap_t' structure */
struct pcap;
typedef struct pcap pcap_t;

/* Forward reference of opaque 'pcap_if_t' structure */
struct pcap_if;
typedef struct pcap_if pcap_if_t;

/* How many bytes to reserve for error messages. This is the number specified
 * in libpcap, smaller numbers can crash */
enum {
    PCAP_ERRBUF_SIZE=256,
};

/* used in pcap_setdirection() */
typedef enum {
    PCAP_D_INOUT    = 0,
    PCAP_D_IN       = 1,
    PCAP_D_OUT      = 2,
} pcap_direction_t;

/* The packet header for capturing packets. Apple macOS inexplicably adds
 * an extra comment-field onto the end of this, so the definition needs
 * to be careful to match the real definition */
struct pcap_pkthdr {
    struct pcap_timeval ts;
    unsigned caplen;
    unsigned len;
#ifdef __APPLE__
    char comment[256];
#endif
};


/*
 * This block is for function declarations. Consult the libpcap
 * documentation for what these functions really mean
 */
typedef void        (*PCAP_HANDLE_PACKET)(unsigned char *v_seap, const struct pcap_pkthdr *framehdr, const unsigned char *buf);
typedef void        (*PCAP_CLOSE)(void *hPcap);
typedef unsigned    (*PCAP_DATALINK)(void *hPcap);
typedef unsigned    (*PCAP_DISPATCH)(void *hPcap, unsigned how_many_packets, PCAP_HANDLE_PACKET handler, void *handle_data);
typedef int         (*PCAP_FINDALLDEVS)(pcap_if_t **alldevs, char *errbuf);
typedef const char *(*PCAP_LIB_VERSION)(void);
typedef char *      (*PCAP_LOOKUPDEV)(char *errbuf);
typedef int         (*PCAP_MAJOR_VERSION)(void *p);
typedef int         (*PCAP_MINOR_VERSION)(void *p);
typedef void *      (*PCAP_OPEN_LIVE)(const char *devicename, unsigned snap_length, unsigned is_promiscuous, unsigned read_timeout, char *errbuf);
typedef void        (*PCAP_FREEALLDEVS)(pcap_if_t *alldevs);
typedef pcap_t *    (*PCAP_OPEN_OFFLINE)(const char *fname, char *errbuf);
typedef int         (*PCAP_SENDPACKET)(pcap_t *p, const unsigned char *buf, int size);
typedef const unsigned char *(*PCAP_NEXT)(pcap_t *p, struct pcap_pkthdr *h);
typedef int         (*PCAP_SETDIRECTION)(pcap_t *, pcap_direction_t);
typedef const char *(*PCAP_DATALINK_VAL_TO_NAME)(int dlt);
typedef void        (*PCAP_PERROR)(pcap_t *p, char *prefix);
typedef const char *(*PCAP_DEV_NAME)(const pcap_if_t *dev);
typedef const char *(*PCAP_DEV_DESCRIPTION)(const pcap_if_t *dev);
typedef const pcap_if_t *(*PCAP_DEV_NEXT)(const pcap_if_t *dev);

/*
 pcap_open() replaced with a series of calls to:
  p = pcap_create(device, errbuf);
  pcap_set_snaplen(p, snaplen);
  pcap_set_promisc(p, promisc);
  pcap_set_timeout(p, to_ms);
  pcap_activate(p);
 */
typedef pcap_t *(*PCAP_CREATE)(const char *source, char *errbuf);
typedef int (*PCAP_SET_SNAPLEN)(pcap_t *p, int snaplen);
typedef int (*PCAP_SET_PROMISC)(pcap_t *p, int promisc);
typedef int (*PCAP_SET_TIMEOUT)(pcap_t *p, int to_ms);
typedef int (*PCAP_SET_IMMEDIATE_MODE)(pcap_t *p, int immediate_mode);
typedef int (*PCAP_SET_BUFFER_SIZE)(pcap_t *p, int buffer_size);
typedef int (*PCAP_SET_RFMON)(pcap_t *p, int rfmon);
typedef int (*PCAP_CAN_SET_RFMON)(pcap_t *p);
typedef int (*PCAP_ACTIVATE)(pcap_t *p);



/*
 * PORTABILITY: Windows supports the "sendq" feature, and is really slow
 * without this feature. It's not needed on Linux, so we just create
 * equivelent functions that do nothing
 */
struct pcap_send_queue;
typedef struct pcap_send_queue pcap_send_queue;

typedef pcap_send_queue *(*PCAP_SENDQUEUE_ALLOC)(size_t size);
typedef unsigned (*PCAP_SENDQUEUE_TRANSMIT)(pcap_t *p, pcap_send_queue *queue, int sync);
typedef void (*PCAP_SENDQUEUE_DESTROY)(pcap_send_queue *queue);
typedef int (*PCAP_SENDQUEUE_QUEUE)(pcap_send_queue *queue, const struct pcap_pkthdr *pkt_header, const unsigned char *pkt_data);





struct PcapFunctions {
    unsigned func_err:1;
    unsigned is_available:1;
    unsigned is_printing_debug:1;
    unsigned status;
    unsigned errcode;
    
    PCAP_CLOSE              close;
    PCAP_DATALINK           datalink;
    PCAP_DISPATCH           dispatch;
    PCAP_FINDALLDEVS        findalldevs;
    PCAP_FREEALLDEVS        freealldevs;
    PCAP_LOOKUPDEV          lookupdev;
    PCAP_LIB_VERSION        lib_version;
    PCAP_MAJOR_VERSION      major_version;
    PCAP_MINOR_VERSION      minor_version;
    PCAP_OPEN_LIVE          open_live;
    
    
    PCAP_OPEN_OFFLINE       open_offline;
    PCAP_SENDPACKET         sendpacket;
    PCAP_NEXT               next;
    PCAP_SETDIRECTION       setdirection;
    PCAP_DATALINK_VAL_TO_NAME datalink_val_to_name;
    PCAP_PERROR             perror;
    
    /* Accessor functions for opaque data structure, don't really
     * exist in libpcap */
    PCAP_DEV_NAME           dev_name;
    PCAP_DEV_DESCRIPTION    dev_description;
    PCAP_DEV_NEXT           dev_next;

    /* Windows-only functions */
	PCAP_SENDQUEUE_ALLOC	sendqueue_alloc;
	PCAP_SENDQUEUE_TRANSMIT	sendqueue_transmit;
	PCAP_SENDQUEUE_DESTROY	sendqueue_destroy;
	PCAP_SENDQUEUE_QUEUE	sendqueue_queue;

    PCAP_CREATE              create;
    PCAP_SET_SNAPLEN         set_snaplen;
    PCAP_SET_PROMISC         set_promisc;
    PCAP_SET_TIMEOUT         set_timeout;
    PCAP_SET_IMMEDIATE_MODE  set_immediate_mode;
    PCAP_SET_BUFFER_SIZE     set_buffer_size;
    PCAP_SET_RFMON           set_rfmon;
    PCAP_CAN_SET_RFMON       can_set_rfmon;
    PCAP_ACTIVATE            activate;

};

/**
 * This is global structure containing all the libpcap function pointers.
 * use in the form "PCAP.functionname()" rather than "pcap_functioname()".
 */
extern struct PcapFunctions PCAP;

/**
 * Dynamically loads the shared library (libpcap.so, libpcap.dynlib,
 * or libpcap.dll. Call this during program startup like main() in order
 * to load the libraries. Not thread safe, so call from the startup
 * thread, but not within threads.
 * @return
 *  0 on success or
 *  -1 on failure
 */
int pcap_init(void);


#endif
