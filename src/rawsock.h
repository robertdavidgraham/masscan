/*
    raw sockets stuff
*/
#ifndef RAWSOCK_H
#define RAWSOCK_H
#include <stdio.h>
struct Adapter;
struct TcpPacket;


/**
 * @return
 *      1 on failure
 *      0 on success
 */
int rawsock_selftest();
int rawsock_selftest_if(const char *ifname);

void rawsock_init();

struct Adapter *rawsock_init_adapter(const char *adapter_name, unsigned is_pfring, unsigned is_sendq);

void rawsock_list_adapters();

void
rawsock_send_probe(
    struct Adapter *adapter,
    unsigned ip, unsigned port, unsigned seqno, unsigned flush,
    struct TcpPacket *pkt);

unsigned rawsock_get_adapter_ip(const char *ifname);
int rawsock_get_adapter_mac(const char *ifname, unsigned char *mac);

int rawsock_get_default_gateway(const char *ifname, unsigned *ipv4);
int rawsock_get_default_interface(char *ifname, size_t sizeof_ifname);

const char *rawsock_win_name(const char *ifname);

int rawsock_is_adapter_names_equal(const char *lhs, const char *rhs);

int rawsock_send_packet(
    struct Adapter *adapter,
    const unsigned char *packet,
    unsigned length,
    unsigned flush);

int rawsock_recv_packet(
    struct Adapter *adapter,
    unsigned *length,
    unsigned *secs,
    unsigned *usecs,
    const unsigned char **packet);

int arp_resolve_sync(struct Adapter *adapter, 
    unsigned my_ipv4, const unsigned char *my_mac_address,
    unsigned your_ipv4, unsigned char *your_mac_address);

int arp_response(struct Adapter *adapter, unsigned my_ip, const unsigned char *my_mac, const unsigned char *px, unsigned length);

void rawsock_ignore_transmits(struct Adapter *adapter, const unsigned char *adapter_mac);

#endif
