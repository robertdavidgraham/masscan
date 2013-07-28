/*
    raw sockets stuff
*/
#ifndef RAWSOCK_H
#define RAWSOCK_H
struct Adapter;
struct TcpPacket;

/**
 * @return
 *      1 on failure
 *      0 on success
 */
int rawsock_selftest();

void rawsock_init();

struct Adapter *rawsock_init_adapter(const char *adapter_name);

void rawsock_list_adapters();

void
rawsock_send_probe(
    struct Adapter *adapter,
    unsigned ip, unsigned port,
    struct TcpPacket *pkt);

#endif
