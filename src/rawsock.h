/*
    raw sockets stuff
*/
#ifndef RAWSOCK_H
#define RAWSOCK_H
#include <stdio.h>
struct Adapter;
struct TemplateSet;
#include "packet-queue.h"


/**
 * @return
 *      1 on failure
 *      0 on success
 */
int rawsock_selftest(void);
int rawsock_selftest_if(const char *ifname);

void rawsock_init(void);

/**
 * Does an "open" on the network adapter. What actually happens depends upon
 * the operating system and drivers that we are using, but usually this just
 * calls "pcap_open()"
 * @param adapter_name
 *      The name of the adapter, like "eth0" or "dna1".
 * @param is_pfring
 *      Whether we should attempt to use the PF_RING driver (Linux-only)
 * @param is_sendq
 *      Whether we should attempt to use a ring-buffer for sending packets.
 *      Currently Windows-only, but it'll be enabled for Linux soon. Big
 *      performance gains for Windows, but insignificant performance
 *      difference for Linux.
 * @param is_packet_trace
 *      Whether then Nmap --packet-trace option was set on the command-line
 * @param is_offline
 *      Whether the --offline parameter was set on the command-line. If so,
 *      then no network adapter will actually be opened.
 * @return
 *      a fully instantiated network adapter
 */
struct Adapter *
rawsock_init_adapter(const char *adapter_name,
                     unsigned is_pfring,
                     unsigned is_sendq,
                     unsigned is_packet_trace,
                     unsigned is_offline,
                     const char *bpf_filter);

/**
 * Retrieve the datalink type of the adapter
 *
 *  1 = Ethernet
 * 12 = Raw IP (no datalink)
 */
int
rawsock_datalink(struct Adapter *adapter);

/**
 * Print to the command-line the list of available adapters. It's called
 * when the "--iflist" option is specified on the command-line.
 */
void rawsock_list_adapters(void);

void
rawsock_send_probe(
    struct Adapter *adapter,
    unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    unsigned seqno, unsigned flush,
    struct TemplateSet *tmplset);

unsigned rawsock_get_adapter_ip(const char *ifname);
int rawsock_get_adapter_mac(const char *ifname, unsigned char *mac);

int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4);
int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname);

const char *rawsock_win_name(const char *ifname);

int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs);

/**
 * Transmit any queued (but not yet transmitted) packets. Useful only when
 * using a high-speed transmit mechanism. Since flushing happens automatically
 * whenever the transmit queue is full, this is only needed in boundary
 * cases, like when shutting down.
 */
void
rawsock_flush(struct Adapter *adapter);

int rawsock_send_packet(
    struct Adapter *adapter,
    const unsigned char *packet,
    unsigned length,
    unsigned flush);

/**
 * Called to read the next packet from the network.
 * @param adapter
 *      The network interface on which to receive packets.
 * @param length
 *      returns the length of the packet
 * @param secs
 *      returns the timestamp of the packet as a time_t value (the number
 *      of seconds since Jan 1 1970).
 * @param usecs
 *      returns part of the timestamp, the number of microseconds since the
 *      start of the current second
 * @param packet
 *      returns a pointer to the packet that was read from the netwrok.
 *      The contents of this pointer are good until the next call to this
 *      function.
 * @return
 *      0 for success, something else for failure
 *
 */
int rawsock_recv_packet(
    struct Adapter *adapter,
    unsigned *length,
    unsigned *secs,
    unsigned *usecs,
    const unsigned char **packet);

int arp_resolve_sync(struct Adapter *adapter,
    unsigned my_ipv4, const unsigned char *my_mac_address,
    unsigned your_ipv4, unsigned char *your_mac_address);


void rawsock_ignore_transmits(struct Adapter *adapter,
                              const unsigned char *adapter_mac);

#endif
