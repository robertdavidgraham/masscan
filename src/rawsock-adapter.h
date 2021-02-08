#ifndef RAWSOCK_ADAPTER_H
#define RAWSOCK_ADAPTER_H

struct Adapter
{
    struct pcap *pcap;
    struct pcap_send_queue *sendq;
    struct __pfring *ring;
    unsigned is_packet_trace:1; /* is --packet-trace option set? */
    unsigned is_vlan:1;
    unsigned vlan_id;
    double pt_start;
    int link_type;
};


/**
 * Retrieve the datalink type of the adapter
 *
 *  1 = Ethernet
 * 12 = Raw IP (no datalink)
 */
int
stack_if_datalink(struct Adapter *adapter);

#endif
