#ifndef TEMPL_PAYLOADS_H
#define TEMPL_PAYLOADS_H
#include <stdio.h>
#include <stdint.h>
struct RangeList;

/**
 * Regression test this module.
 * @return
 *      0 on success, or postivie integer on failure.
 */
int
payloads_udp_selftest(void);

/**
 * Create this module. Must be matched with the 'destroy()' function on exit
 */
struct PayloadsUDP *
payloads_udp_create(void);

struct PayloadsUDP *
payloads_oproto_create(void);

/**
 * Free the resources of an object created with a matching call to
 * 'payloads_create()'
 */
void
payloads_udp_destroy(struct PayloadsUDP *payloads);

void
payloads_oproto_destroy(struct PayloadsUDP *payloads);

/**
 * Read payloads from an "nmap-payloads" formatted file. The caller is
 * responsible for opening/closing the file, but should passin the
 * filename so that we can print helpful error messages.
 */
void
payloads_udp_readfile(FILE *fp, const char *filename,
                   struct PayloadsUDP *payloads);

/**
 * Read payloads from a libpcap formatted file.
 */
void
payloads_read_pcap(const char *filename, struct PayloadsUDP *payloads, struct PayloadsUDP *oproto_payloads);

/**
 * Called to remove any payloads that aren't be used in the scan. This makes
 * lookups faster when generating packets.
 */
void
payloads_udp_trim(struct PayloadsUDP *payloads, const struct RangeList *ports);

void
payloads_oproto_trim(struct PayloadsUDP *payloads, const struct RangeList *ports);


/**
 * The port scanner creates a "cookie" for every packet that it sends, which
 * will be a 64-bit value, whose low-order bits will be trimmed to fit whatever
 * size is available. For TCP, this becomes the 32-bit seqno of the SYN packet.
 * For UDP protocols, however, each application layer protocol will be
 * different. For example, SNMP can use a 32-bit transaction ID, whereas DNS
 * can use only a 16-bit transaction ID.
 */
typedef unsigned (*SET_COOKIE)(unsigned char *px, size_t length,
                               uint64_t seqno);


/**
 * Given a UDP port number, return the payload we have that is associated
 * with that port number.
 * @param payloads
 *      A table full over payloadsd.
 * @param port
 *      The input port number.
 * @param px
 *      The returned payload bytes.
 * @param length
 *      The returned count of payload bytes.
 * @param source_port
 *      The returned port that should be used when sending packets.
 * @param xsum
 *      The returned partial checksum of the payload bytes, so that it
 *      doesn't need to be recalculated for every packet.
 * @param set_cookie
 *      The returned function that will set the "cookie" field in the
 *      packet for each transmission
 */
int
payloads_udp_lookup(
                const struct PayloadsUDP *payloads,
                unsigned port,
                const unsigned char **px,
                unsigned *length,
                unsigned *source_port,
                uint64_t *xsum,
                SET_COOKIE *set_cookie);

int
payloads_oproto_lookup(
                    const struct PayloadsUDP *payloads,
                    unsigned port,
                    const unsigned char **px,
                    unsigned *length,
                    unsigned *source_port,
                    uint64_t *xsum,
                    SET_COOKIE *set_cookie);



#endif
