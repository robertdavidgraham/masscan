/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Copyright (c) 2017 by Robert David Graham
 * Programer(s): Robert David Graham [rdg]
 */
/*
	LIBPCAP INTERFACE
 
 This VERY MESSY code is a hack to load the 'libpcap' library 
 at runtime rather than compile time.
 
 This reason for this mess is that it gets rid of a dependency
 when compiling this project. Otherwise, developers would have
 to download the 'libpcap-dev' dependency in order to build
 this project.
 
 Almost every platform these days (OpenBSD, FreeBSD, macOS,
 Debian, RedHat) comes with a "libpcap.so" library already
 installed by default with a known BINARY interface. Thus,
 we can include the data structures definitions directly
 in this project, then load the library dynamically.
 
 For those systems without libpcap.so already installed, the
 user can either install those on the system, or compile
 this project in "STATIC" mode, which will link to the 
 static libpcap.a library.
 
*/
#include "logger.h"

#if _MSC_VER==1200
#pragma warning(disable:4115 4201)
#include <winerror.h>
#endif
#include "stub-pcap.h"

#ifdef WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef UNUSEDPARM
#ifdef __GNUC__
#define UNUSEDPARM(x) x=(x)
#else
#define UNUSEDPARM(x) x=(x)
#endif
#endif

struct pcap_if {
    struct pcap_if *next;
    char *name;		/* name to hand to "pcap_open_live()" */
    char *description;	/* textual description of interface, or NULL */
    void  *addresses;
    unsigned flags;	/* PCAP_IF_ interface flags */
};

static void seterr(char *errbuf, const char *msg)
{
    size_t length = strlen(msg);
    
    if (length > PCAP_ERRBUF_SIZE-1)
    length = PCAP_ERRBUF_SIZE-1;
    memcpy(errbuf, msg, length);
    errbuf[length] = '\0';
}

static void null_PCAP_CLOSE(void *hPcap)
{
#ifdef STATICPCAP
    pcap_close(hPcap);
    return;
#endif
    UNUSEDPARM(hPcap);
}

#ifdef STATICPCAP
static pcap_t *(*null_PCAP_CREATE)(const char *source, char *errbuf);
static int (*null_PCAP_SET_SNAPLEN)(pcap_t *p, int snaplen);
static int (*null_PCAP_SET_PROMISC)(pcap_t *p, int promisc);
static int (*null_PCAP_SET_TIMEOUT)(pcap_t *p, int to_ms);
static int (*null_PCAP_SET_IMMEDIATE_MODE)(pcap_t *p, int immediate_mode);
static int (*null_PCAP_SET_BUFFER_SIZE)(pcap_t *p, int buffer_size);
static int (*null_PCAP_SET_RFMON)(pcap_t *p, int rfmon);
static int (*null_PCAP_CAN_SET_RFMON)(pcap_t *p);
static int (*null_PCAP_ACTIVATE)(pcap_t *p);
#else
static pcap_t *null_PCAP_CREATE(const char *source, char *errbuf) {return 0;}
static int null_PCAP_SET_SNAPLEN(pcap_t *p, int snaplen) {return 0;}
static int null_PCAP_SET_PROMISC(pcap_t *p, int promisc) {return 0;}
static int null_PCAP_SET_TIMEOUT(pcap_t *p, int to_ms) {return 0;}
static int null_PCAP_SET_IMMEDIATE_MODE(pcap_t *p, int immediate_mode)  {return 0;}
static int null_PCAP_SET_BUFFER_SIZE(pcap_t *p, int buffer_size) {return 0;}
static int null_PCAP_SET_RFMON(pcap_t *p, int rfmon) {return 0;}
static int null_PCAP_CAN_SET_RFMON(pcap_t *p) {return 0;}
static int null_PCAP_ACTIVATE(pcap_t *p) {return 0;}
#endif

static unsigned null_PCAP_DATALINK(void *hPcap)
{
#ifdef STATICPCAP
    return pcap_datalink(hPcap);
#endif
    UNUSEDPARM(hPcap);
    return 0;
}


static unsigned null_PCAP_DISPATCH(void *hPcap, unsigned how_many_packets, PCAP_HANDLE_PACKET handler, void *handle_data)
{
#ifdef STATICPCAP
    return pcap_dispatch(hPcap, how_many_packets, handler, handle_data);
#endif
    UNUSEDPARM(hPcap);UNUSEDPARM(how_many_packets);UNUSEDPARM(handler);UNUSEDPARM(handle_data);
    return 0;
}


static int null_PCAP_FINDALLDEVS(pcap_if_t **alldevs, char *errbuf)
{
#ifdef STATICPCAP
    return pcap_findalldevs(alldevs, errbuf);
#endif
    *alldevs = 0;
    seterr(errbuf, "libpcap not loaded");
    return -1;
}


static void null_PCAP_FREEALLDEVS(pcap_if_t *alldevs)
{
#ifdef STATICPCAP
    return pcap_freealldevs(alldevs);
#endif
    UNUSEDPARM(alldevs);
    return;
}


static char *null_PCAP_LOOKUPDEV(char *errbuf)
{
#ifdef STATICPCAP
    return pcap_lookupdev(errbuf);
#endif
    seterr(errbuf, "libpcap not loaded");
    return "";
}


static void * null_PCAP_OPEN_LIVE(const char *devicename, unsigned snap_length, unsigned is_promiscuous, unsigned read_timeout, char *errbuf)
{
#ifdef STATICPCAP
    return pcap_open_live(devicename, snap_length, is_promiscuous, read_timeout, errbuf);
#endif
    seterr(errbuf, "libpcap not loaded");
    UNUSEDPARM(devicename);UNUSEDPARM(snap_length);UNUSEDPARM(is_promiscuous);UNUSEDPARM(read_timeout);
    return NULL;
}

static int null_PCAP_MAJOR_VERSION(void *p)
{
#ifdef STATICPCAP
    return pcap_major_version(p);
#endif
    UNUSEDPARM(p);
    return 0;
}


static int null_PCAP_MINOR_VERSION(void *p)
{
#ifdef STATICPCAP
    return pcap_minor_version(p);
#endif
    UNUSEDPARM(p);
    return 0;
}

static const char *null_PCAP_LIB_VERSION(void)
{
#ifdef STATICPCAP
    return pcap_lib_version();
#endif
    
    return "stub/0.0";
}





struct PcapFunctions PCAP = {
    0,0,0,0,0,
    null_PCAP_CLOSE,
};


static void *my_null(int x, ...)
{
	UNUSEDPARM(x);
    return 0;
}
static pcap_t *null_PCAP_OPEN_OFFLINE(const char *fname, char *errbuf)
{
#ifdef STATICPCAP
    return pcap_open_offline(fname, errbuf);
#endif
    return my_null(2, fname, errbuf);
}
static int null_PCAP_SENDPACKET(pcap_t *p, const unsigned char *buf, int size)
{
#ifdef STATICPCAP
    return pcap_sendpacket(p, buf, size);
#endif
    my_null(3, p, buf, size);
	return 0;
}

static const unsigned char *null_PCAP_NEXT(pcap_t *p, struct pcap_pkthdr *h)
{
#ifdef STATICPCAP
    return pcap_next(p, h);
#endif
    my_null(3, p, h);
    return 0;
}
static int null_PCAP_SETDIRECTION(pcap_t *p, pcap_direction_t d)
{
#ifdef STATICPCAP
    return pcap_setdirection(p, d);
#endif
	my_null(2, p, d);
    return 0;
}
static const char *null_PCAP_DATALINK_VAL_TO_NAME(int dlt)
{
#ifdef STATICPCAP
    return pcap_datalink_val_toName(dlt);
#endif
	my_null(1, dlt);
    return 0;
}
static void null_PCAP_PERROR(pcap_t *p, char *prefix)
{
#ifdef STATICPCAP
    pcap_perror(p, prefix);
    return;
#endif
	UNUSEDPARM(p);
	fprintf(stderr, "%s\n", prefix);
    perror("pcap");
}
static const char *null_PCAP_DEV_NAME(const pcap_if_t *dev)
{
    return dev->name;
}
static const char *null_PCAP_DEV_DESCRIPTION(const pcap_if_t *dev)
{
    return dev->description;
}
static const pcap_if_t *null_PCAP_DEV_NEXT(const pcap_if_t *dev)
{
    return dev->next;
}

static pcap_send_queue *null_PCAP_SENDQUEUE_ALLOC(size_t size)
{
	UNUSEDPARM(size);
	return 0;
}
static unsigned null_PCAP_SENDQUEUE_TRANSMIT(pcap_t *p, pcap_send_queue *queue, int sync)
{
	my_null(3, p, queue, sync);
	return 0;
}
static void null_PCAP_SENDQUEUE_DESTROY(pcap_send_queue *queue) 
{
	my_null(1, queue);
	UNUSEDPARM(queue);
}
static int null_PCAP_SENDQUEUE_QUEUE(pcap_send_queue *queue,
    const struct pcap_pkthdr *pkt_header,
    const unsigned char *pkt_data)
{
	my_null(4, queue, pkt_header, pkt_data);
	return 0;
}

/**
 * Runtime-load the libpcap shared-object or the winpcap DLL. We
 * load at runtime rather than loadtime to allow this program to
 * be used to process offline content, and to provide more helpful
 * messages to people who don't realize they need to install PCAP.
 */
int pcap_init(void)
{
    struct PcapFunctions *pl = &PCAP;
#ifdef WIN32
    void * hPacket;
    void * hLibpcap;
    
    pl->is_available = 0;
    pl->is_printing_debug = 1;
    
    /* Look for the Packet.dll */
    hPacket = LoadLibraryA("NPcap\\Packet.dll");
    if (hPacket == NULL)
        hPacket = LoadLibraryA("Packet.dll");
    if (hPacket == NULL) {
        if (pl->is_printing_debug)
        switch (GetLastError()) {
            case ERROR_MOD_NOT_FOUND:
                fprintf(stderr, "%s: not found\n", "Packet.dll");
                fprintf(stderr, "  HINT: you must install either WinPcap or Npcap\n");
                return -1;
            default:
                fprintf(stderr, "%s: couldn't load %d\n", "Packet.dll", (int)GetLastError());
                return -1;
        }
    }
    
    /* Look for the winpcap.dll */
    hLibpcap = LoadLibraryA("Npcap\\wpcap.dll");
    if (hLibpcap == NULL)
        hLibpcap = LoadLibraryA("wpcap.dll");
    if (hLibpcap == NULL) {
        if (pl->is_printing_debug)
            fprintf(stderr, "%s: couldn't load %d\n", "wpcap.dll", (int)GetLastError());
        return -1;
    }
    
    
#define DOLINK(PCAP_DATALINK, datalink) \
pl->datalink = (PCAP_DATALINK)GetProcAddress(hLibpcap, "pcap_"#datalink); \
if (pl->datalink == NULL) pl->func_err=1, pl->datalink = null_##PCAP_DATALINK;
#endif
    
    
#ifndef WIN32
#ifndef STATICPCAP
    void *hLibpcap;
    
    pl->is_available = 0;
    pl->is_printing_debug = 1;
    
    {
        static const char *possible_names[] = {
            "libpcap.so",
            "libpcap.A.dylib",
            "libpcap.dylib",
            "libpcap.so.0.9.5",
            "libpcap.so.0.9.4",
            "libpcap.so.0.8",
            0
        };
        unsigned i;
        for (i=0; possible_names[i]; i++) {
            hLibpcap = dlopen(possible_names[i], RTLD_LAZY);
            if (hLibpcap) {
                LOG(1, "pcap: found library: %s\n", possible_names[i]);
                break;
            } else {
                LOG(2, "pcap: failed to load: %s\n", possible_names[i]);
            }
        }
     
        if (hLibpcap == NULL) {
            fprintf(stderr, "pcap: failed to load libpcap shared library\n");
            fprintf(stderr, "    HINT: you must install libpcap or WinPcap\n");
        }
    }
    
#define DOLINK(PCAP_DATALINK, datalink) \
pl->datalink = (PCAP_DATALINK)dlsym(hLibpcap, "pcap_"#datalink); \
    if (pl->datalink == NULL) LOG(1, "pcap: pcap_%s: failed\n", #datalink); \
    if (pl->datalink == NULL) pl->func_err=1, pl->datalink = null_##PCAP_DATALINK;
#else
#define DOLINK(PCAP_DATALINK, datalink) \
pl->func_err=0, pl->datalink = null_##PCAP_DATALINK;
#endif
#endif
    
    DOLINK(PCAP_CLOSE			, close);
    DOLINK(PCAP_DATALINK		, datalink);
    DOLINK(PCAP_DISPATCH		, dispatch);
    DOLINK(PCAP_FINDALLDEVS		, findalldevs);
    DOLINK(PCAP_FREEALLDEVS		, freealldevs);
    DOLINK(PCAP_LIB_VERSION		, lib_version);
    DOLINK(PCAP_LOOKUPDEV		, lookupdev);
    DOLINK(PCAP_MAJOR_VERSION	, major_version);
    DOLINK(PCAP_MINOR_VERSION	, minor_version);
    DOLINK(PCAP_OPEN_LIVE		, open_live);
    
    DOLINK(PCAP_OPEN_OFFLINE    , open_offline);
    DOLINK(PCAP_SENDPACKET      , sendpacket);
    DOLINK(PCAP_NEXT            , next);
    DOLINK(PCAP_SETDIRECTION    , setdirection);
    DOLINK(PCAP_DATALINK_VAL_TO_NAME , datalink_val_to_name);
    DOLINK(PCAP_PERROR          , perror);

    DOLINK(PCAP_DEV_NAME        , dev_name);
    DOLINK(PCAP_DEV_DESCRIPTION , dev_description);
    DOLINK(PCAP_DEV_NEXT        , dev_next);

	DOLINK(PCAP_SENDQUEUE_ALLOC		, sendqueue_alloc);
	DOLINK(PCAP_SENDQUEUE_TRANSMIT	, sendqueue_transmit);
	DOLINK(PCAP_SENDQUEUE_DESTROY	, sendqueue_destroy);
	DOLINK(PCAP_SENDQUEUE_QUEUE		, sendqueue_queue);

    DOLINK(PCAP_CREATE              , create);
    DOLINK(PCAP_SET_SNAPLEN         , set_snaplen);
    DOLINK(PCAP_SET_PROMISC         , set_promisc);
    DOLINK(PCAP_SET_TIMEOUT         , set_timeout);
    DOLINK(PCAP_SET_IMMEDIATE_MODE  , set_immediate_mode);
    DOLINK(PCAP_SET_BUFFER_SIZE     , set_buffer_size);
    DOLINK(PCAP_SET_RFMON           , set_rfmon);
    DOLINK(PCAP_CAN_SET_RFMON       , can_set_rfmon);
    DOLINK(PCAP_ACTIVATE            , activate);

    
    if (!pl->func_err)
        pl->is_available = 1;
    else
        pl->is_available = 0;
    
    return 0;
}

