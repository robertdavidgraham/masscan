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
#include "rawsock-pcap.h"

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

#ifdef WIN32
static void *null_PCAP_GET_AIRPCAP_HANDLE(void *p)
{
    UNUSEDPARM(p);
    return NULL;
}
#endif

#ifdef WIN32
static unsigned null_AIRPCAP_SET_DEVICE_CHANNEL(void *p, unsigned channel)
{
    UNUSEDPARM(p);UNUSEDPARM(channel);
    
    return 0; /*0=failure, 1=success*/
}
#endif


static unsigned null_CAN_TRANSMIT(const char *devicename)
{
#if WIN32
    struct DeviceCapabilities {
        unsigned AdapterId;		/* An Id that identifies the adapter model.*/
        char AdapterModelName;	/* String containing a printable adapter model.*/
        unsigned AdapterBus;	/* The type of bus the adapter is plugged to. */
        unsigned CanTransmit;	/* TRUE if the adapter is able to perform frame injection.*/
        unsigned CanSetTransmitPower; /* TRUE if the adapter's transmit power is can be specified by the user application.*/
        unsigned ExternalAntennaPlug; /* TRUE if the adapter supports plugging one or more external antennas.*/
        unsigned SupportedMedia;
        unsigned SupportedBands;
    } caps;
    void * (*myopen)(const char *devicename, char *errbuf);
    void (*myclose)(void *h);
    unsigned (*mycapabilities)(void *h, struct DeviceCapabilities *caps);
    
    unsigned result = 0;
    void *hAirpcap;
    
    
    hAirpcap = LoadLibraryA("airpcap.dll");
    if (hAirpcap == NULL)
    return 0;
    
    
    myopen = (void * (*)(const char *, char*))GetProcAddress(hAirpcap, "AirpcapOpen");
    myclose = (void (*)(void*))GetProcAddress(hAirpcap, "AirpcapClose");
    mycapabilities = (unsigned (*)(void*, struct DeviceCapabilities *))GetProcAddress(hAirpcap, "AirpcapGetDeviceCapabilities");
    if (myopen && mycapabilities && myclose ) {
        void *h = myopen(devicename, NULL);
        if (h) {
            if (mycapabilities(h, &caps)) {
                result = caps.CanTransmit;
            }
            myclose(h);
        }
    }
    
    FreeLibrary(hAirpcap);
    return result;
#elif defined(__linux__)
    return 1;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    return 1;
#else
#error unknown os
#endif
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
void pcap_init(void)
{
    struct PcapFunctions *pl = &PCAP;
#ifdef WIN32
    void * hPacket;
    void * hLibpcap;
    void * hAirpcap;
    
    pl->is_available = 0;
    pl->is_printing_debug = 1;
    
    /* Look for the Packet.dll */
    hPacket = LoadLibraryA("Packet.dll");
    if (hPacket == NULL) {
        if (pl->is_printing_debug)
        switch (GetLastError()) {
            case ERROR_MOD_NOT_FOUND:
            fprintf(stderr, "%s: not found\n", "Packet.dll");
            return;
            default:
            fprintf(stderr, "%s: couldn't load %d\n", "Packet.dll", (int)GetLastError());
            return;
        }
    }
    
    /* Look for the Packet.dll */
    hLibpcap = LoadLibraryA("wpcap.dll");
    if (hLibpcap == NULL) {
        if (pl->is_printing_debug)
        fprintf(stderr, "%s: couldn't load %d\n", "wpcap.dll", (int)GetLastError());
        return;
    }
    
    /* Look for the Packet.dll */
    hAirpcap = LoadLibraryA("airpcap.dll");
    if (hLibpcap == NULL) {
        if (pl->is_printing_debug)
        fprintf(stderr, "%s: couldn't load %d\n", "airpcap.dll", (int)GetLastError());
        return;
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
    
#ifdef WIN32
    DOLINK(PCAP_GET_AIRPCAP_HANDLE, get_airpcap_handle);
    if (pl->func_err) {
        pl->func_err = 0;
    }
    if (hAirpcap) {
        pl->airpcap_set_device_channel = (AIRPCAP_SET_DEVICE_CHANNEL)GetProcAddress(hAirpcap, "AirpcapSetDeviceChannel");
        if (pl->airpcap_set_device_channel == NULL)
        pl->airpcap_set_device_channel = null_AIRPCAP_SET_DEVICE_CHANNEL;
    }
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

    
    pl->can_transmit = null_CAN_TRANSMIT;
    
    if (!pl->func_err)
    pl->is_available = 1;
    else
    pl->is_available = 0;
}

