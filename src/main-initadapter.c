#include "masscan.h"
#include "logger.h"
#include "rawsock.h"


/***************************************************************************
 * Initialize the network adapter.
 *
 * This requires finding things like our IP address, MAC address, and router
 * MAC address. The user could configure these things manually instead.
 *
 * Note that we don't update the "static" configuration with the discovered
 * values, but instead return them as the "running" configuration. That's
 * so if we pause and resume a scan, auto discovered values don't get saved
 * in the configuration file.
 ***************************************************************************/
int
masscan_initialize_adapter(
    struct Masscan *masscan,
    unsigned index,
    unsigned char *adapter_mac,
    unsigned char *router_mac
    )
{
    char *ifname;
    char ifname2[256];
    unsigned adapter_ip = 0;

    LOG(1, "initializing adapter\n");

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (masscan->nic[index].ifname && masscan->nic[index].ifname[0])
        ifname = masscan->nic[index].ifname;
    else {
        /* no adapter specified, so find a default one */
        int err;
        ifname2[0] = '\0';
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return -1;
        } else {
            LOG(2, "auto-detected: interface=%s\n", ifname2);
        }
        ifname = ifname2;

    }

    /*
     * IP ADDRESS
     *
     * We need to figure out that IP address to send packets from. This
     * is done by querying the adapter (or configured by user). If the
     * adapter doesn't have one, then the user must configure one.
     */
    adapter_ip = masscan->nic[index].src.ip.first;
    if (adapter_ip == 0) {
        adapter_ip = rawsock_get_adapter_ip(ifname);
        LOG(2, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (adapter_ip>>24)&0xFF,
            (adapter_ip>>16)&0xFF,
            (adapter_ip>> 8)&0xFF,
            (adapter_ip>> 0)&0xFF
            );
        masscan->nic[index].src.ip.first = adapter_ip;
        masscan->nic[index].src.ip.last = adapter_ip;
        masscan->nic[index].src.ip.range = 1;
    }
    if (adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface \"%s\"\n",
                        ifname);
        fprintf(stderr, " [hint] did you spell the name correctly?\n");
        fprintf(stderr, " [hint] if it has no IP address, manually set with "
                        "\"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    memcpy(adapter_mac, masscan->nic[index].my_mac, 6);
    if (masscan->nic[index].my_mac_count == 0) {
        if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {

            rawsock_get_adapter_mac(ifname, adapter_mac);

            LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
                adapter_mac[0],
                adapter_mac[1],
                adapter_mac[2],
                adapter_mac[3],
                adapter_mac[4],
                adapter_mac[5]
                );
        }
        if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
            fprintf(stderr, "FAIL: failed to detect MAC address of interface:"
                    " \"%s\"\n", ifname);
            fprintf(stderr, " [hint] try something like "
                    "\"--adapter-mac 00-11-22-33-44-55\"\n");
            return -1;
        }
    }

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to
     * turn it on.
     */
    masscan->nic[index].adapter = rawsock_init_adapter(
                                            ifname,
                                            masscan->is_pfring,
                                            masscan->is_sendq,
                                            masscan->nmap.packet_trace,
                                            masscan->is_offline,
                                            masscan->bpf_filter);
    if (masscan->nic[index].adapter == 0) {
        fprintf(stderr, "adapter[%s].init: failed\n", ifname);
        return -1;
    }
    LOG(3, "rawsock: ignoring transmits\n");
    rawsock_ignore_transmits(masscan->nic[index].adapter, adapter_mac);
    LOG(3, "rawsock: initialization done\n");


    /*
     * ROUTER MAC ADDRESS
     *
     * NOTE: this is one of the least understood aspects of the code. We must
     * send packets to the local router, which means the MAC address (not
     * IP address) of the router.
     *
     * Note: in order to ARP the router, we need to first enable the libpcap
     * code above.
     */
    memcpy(router_mac, masscan->nic[index].router_mac, 6);
    if (masscan->is_offline) {
        memcpy(router_mac, "\x66\x55\x44\x33\x22\x11", 6);
    } else if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        unsigned router_ipv4 = masscan->nic[index].router_ip;
        int err = 0;


        LOG(1, "rawsock: looking for default gateway\n");
        if (router_ipv4 == 0)
            err = rawsock_get_default_gateway(ifname, &router_ipv4);
        if (err == 0) {
            LOG(2, "auto-detected: router-ip=%u.%u.%u.%u\n",
                (router_ipv4>>24)&0xFF,
                (router_ipv4>>16)&0xFF,
                (router_ipv4>> 8)&0xFF,
                (router_ipv4>> 0)&0xFF
                );

            arp_resolve_sync(
                    masscan->nic[index].adapter,
                    adapter_ip,
                    adapter_mac,
                    router_ipv4,
                    router_mac);

            if (memcmp(router_mac, "\0\0\0\0\0\0", 6) != 0) {
                LOG(2, "auto-detected: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
                    router_mac[0],
                    router_mac[1],
                    router_mac[2],
                    router_mac[3],
                    router_mac[4],
                    router_mac[5]
                    );
            }
        }
    }
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect router for interface: \"%s\"\n", ifname);
        fprintf(stderr, " [hint] try something like \"--router-mac 66-55-44-33-22-11\"\n");
        return -1;
    }


    LOG(1, "adapter initialization done.\n");
    return 0;
}
