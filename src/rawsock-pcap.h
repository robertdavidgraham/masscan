#ifndef RAWSOCK_PCAP_H
#define RAWSOCK_PCAP_H
#include <sys/time.h>

struct pcap;
typedef struct pcap pcap_t;
typedef struct pcap_if pcap_if_t;

enum {
    PCAP_ERRBUF_SIZE=256,
};

typedef enum {
    PCAP_D_INOUT = 0,
    PCAP_D_IN,
    PCAP_D_OUT
} pcap_direction_t;

struct pcap_pkthdr {
    struct timeval ts;
    unsigned caplen;
    unsigned len;
#ifdef __APPLE__
    char comment[256];
#endif
};

typedef void (*PCAP_HANDLE_PACKET)(unsigned char *v_seap, const struct pcap_pkthdr *framehdr, const unsigned char *buf);

typedef void (*PCAP_CLOSE)(void *hPcap);
typedef unsigned (*PCAP_DATALINK)(void *hPcap);
typedef unsigned (*PCAP_DISPATCH)(void *hPcap, unsigned how_many_packets, PCAP_HANDLE_PACKET handler, void *handle_data);
typedef int (*PCAP_FINDALLDEVS)(pcap_if_t **alldevs, char *errbuf);
typedef const char *(*PCAP_LIB_VERSION)(void);
typedef char *(*PCAP_LOOKUPDEV)(char *errbuf);
typedef int (*PCAP_MAJOR_VERSION)(void *p);
typedef int (*PCAP_MINOR_VERSION)(void *p);
typedef void * (*PCAP_OPEN_LIVE)(const char *devicename, unsigned snap_length, unsigned is_promiscuous, unsigned read_timeout, char *errbuf);
typedef void (*PCAP_FREEALLDEVS)(pcap_if_t *alldevs);
typedef void * (*PCAP_GET_AIRPCAP_HANDLE)(void *p);
typedef unsigned (*AIRPCAP_SET_DEVICE_CHANNEL)(void *p, unsigned channel);
typedef unsigned (*CAN_TRANSMIT)(const char *devicename);

typedef pcap_t *(*PCAP_OPEN_OFFLINE)(const char *fname, char *errbuf);
typedef int (*PCAP_SENDPACKET)(pcap_t *p, const unsigned char *buf, int size);
typedef const unsigned char *(*PCAP_NEXT)(pcap_t *p, struct pcap_pkthdr *h);
typedef int (*PCAP_SETDIRECTION)(pcap_t *, pcap_direction_t);
typedef const char *(*PCAP_DATALINK_VAL_TO_NAME)(int dlt);
typedef void (*PCAP_PERROR)(pcap_t *p, char *prefix);
typedef const char *(*PCAP_DEV_NAME)(const pcap_if_t *dev);
typedef const char *(*PCAP_DEV_DESCRIPTION)(const pcap_if_t *dev);
typedef const pcap_if_t *(*PCAP_DEV_NEXT)(const pcap_if_t *dev);



struct PcapFunctions {
    unsigned func_err:1;
    unsigned is_available:1;
    unsigned is_printing_debug:1;
    unsigned status;
    unsigned errcode;
    
    PCAP_CLOSE			close;
    PCAP_DATALINK		datalink;
    PCAP_DISPATCH		dispatch;
    PCAP_FINDALLDEVS	findalldevs;
    PCAP_FREEALLDEVS	freealldevs;
    PCAP_LOOKUPDEV		lookupdev;
    PCAP_LIB_VERSION	lib_version;
    PCAP_MAJOR_VERSION	major_version;
    PCAP_MINOR_VERSION	minor_version;
    PCAP_OPEN_LIVE		open_live;
    PCAP_GET_AIRPCAP_HANDLE get_airpcap_handle;
    AIRPCAP_SET_DEVICE_CHANNEL airpcap_set_device_channel;
    //AIRPCAP_SET_FCS_PRESENCE airpcap_set_fcs_presence;
    //BOOL AirpcapSetFcsPresence(PAirpcapHandle AdapterHandle, BOOL IsFcsPresent);
    
    CAN_TRANSMIT		can_transmit;
    
    PCAP_OPEN_OFFLINE   open_offline;
    PCAP_SENDPACKET     sendpacket;
    PCAP_NEXT           next;
    PCAP_SETDIRECTION   setdirection;
    PCAP_DATALINK_VAL_TO_NAME datalink_val_to_name;
    PCAP_PERROR         perror;
    
    PCAP_DEV_NAME dev_name;
    PCAP_DEV_DESCRIPTION dev_description;
    PCAP_DEV_NEXT dev_next;
    
};

extern struct PcapFunctions PCAP;
void pcap_init(void);

#endif
