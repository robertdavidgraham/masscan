#ifndef TCP_PACKET_H
#define TCP_PACKET_H
#include <stdio.h>
#include <stdint.h>
struct NmapPayloads;
struct MassScript;

/**
 * Does a regression test of this module.
 * @return
 *      1 on failure
 *      0 on success
 */
int template_selftest(void);

enum TemplateProtocol {
    Proto_TCP,
    Proto_UDP,
    Proto_SCTP,
    Proto_ICMP_ping,
    Proto_ICMP_timestamp,
    Proto_ARP,
    Proto_Script,
    //Proto_IP,
    //Proto_Custom,
    Proto_Count
};

struct TemplatePayload {
    unsigned length;
    unsigned checksum;
    unsigned char buf[1500];
};

unsigned
udp_checksum2(const unsigned char *px, unsigned offset_ip,
              unsigned offset_tcp, size_t tcp_length);

/**
 * Describes a packet template. The scan packets we transmit are based on a
 * a template containing most of the data, and we fill in just the necessary
 * bits, like the destination IP address and port
 */
struct TemplatePacket {
    unsigned length;
    unsigned offset_ip;
    unsigned offset_tcp;
    unsigned offset_app;
    unsigned char *packet;
    unsigned checksum_ip;
    unsigned checksum_tcp;
    unsigned ip_id;
    enum TemplateProtocol proto;
    struct NmapPayloads *payloads;
};

/**
 * We can run multiple types of scans (TCP, UDP, scripts, etc.) at the same
 * time. Therefore, instead of one packet prototype for all scans, we have
 * a set of prototypes/templates.
 */
struct TemplateSet
{
    unsigned count;
    struct TemplatePacket pkts[Proto_Count];
    struct MassScript *script;
    uint64_t entropy;
};

struct TemplateSet templ_copy(const struct TemplateSet *templ);

/**
 * Initialize the "template" packets. As we spew out probes, we simply make
 * minor adjustments to the template, such as changing the target IP
 * address or port number
 *
 * @param templset
 *      The template we are creating.
 * @param source_ip
 *      Our own IP address that we send packets from. The caller will have
 *      retrieved this automatically from the network interface/adapter, or
 *      the user will have set this with --source-ip parameter.
 * @param source_mac
 *      Our own MAC address. Gotten automatically from the network adapter,
 *      or on the commandline with --source-mac parameter
 * @param router_mac
 *      The MAC address of the local router/gateway, which will be placed in
 *      the Ethernet destination address field. This is gotten by ARPing
 *      the local router, or by --router-mac configuration parameter.
 * @param data_link
 *      The OSI layer 2 protocol, as defined in <pcap.h> standard.
 *       1 = Ethernet
 *      12 = Raw IP (no data link)
 */
void
template_packet_init(
    struct TemplateSet *templset,
    const unsigned char *source_mac,
    const unsigned char *router_mac,
    struct NmapPayloads *payloads,
    int data_link,
    uint64_t entropy);

/**
 * Sets the target/destination IP address of the packet, the destination port
 * number, and other bits of interest about the packet, such as a unique
 * sequence number. The template can contain things like IP or TCP options
 * with specific values. The program contains several built-in templates,
 * but they can also be read from a file.
 *
 * @param templset
 *      A template created by "template_packet_init()" and further modified
 *      by various configuration parameters.
 * @param ip
 *      The target/destination IPv4 address.
 * @param port
 *      The TCP port number, or port number from another protocol that will
 *      be shifted into the appropriate range. We actually build six base
 *      templates, one for each of these six protocols.
 *      [     0.. 65535] = TCP port number
 *      [ 65536..131071] = UDP port number
 *      [131072..196607] = SCTP port number
 *      [     196608   ] = ICMP
 *      [     196609   ] = ARP
 *      [     196610   ] = IP
 *      [      more    ] = custom
 * @param seqno
 *      On TCP, this will be the desired sequence number, which the caller
 *      will create from SYN-cookies. Other protocols may use this in a
 *      different manner. For example, if the UDP port is 161, then
 *      this will be the transaction ID of the SNMP request template.
 */
void
template_set_target(
    struct TemplateSet *templset,
    unsigned ip_them, unsigned port_them,
    unsigned ip_me, unsigned port_me,
    unsigned seqno,
    unsigned char *px, size_t sizeof_px, size_t *r_length);


/**
 * Create a TCP packet containing a payload, based on the original
 * template used for the SYN
 */
size_t
tcp_create_packet(
        struct TemplatePacket *pkt,
        unsigned ip_them, unsigned port_them,
        unsigned ip_me, unsigned port_me,
        unsigned seqno, unsigned ackno,
        unsigned flags,
        const unsigned char *payload, size_t payload_length,
        unsigned char *px, size_t px_length);

/**
 * Set's the TCP "window" field. The purpose is to cause the recipient
 * to fragment data on the response, thus evading IDS that triggers on
 * out going packets
 */
void
tcp_set_window(unsigned char *px, size_t px_length, unsigned window);

unsigned template_get_source_port(struct TemplateSet *tmplset);
unsigned template_get_source_ip(struct TemplateSet *tmplset);

void template_set_source_port(struct TemplateSet *tmplset, unsigned port);
void template_set_ttl(struct TemplateSet *tmplset, unsigned ttl);

#endif
