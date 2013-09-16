#ifndef TEMPL_PAYLOADS_H
#define TEMPL_PAYLOADS_H
#include <stdio.h>
#include <stdint.h>
struct RangeList;

int payloads_selftest();

struct NmapPayloads *
payloads_create();

void
payloads_destroy(struct NmapPayloads *payloads);

/**
 * Read payloads from an "nmap-payloads" formatted file
 */
void
payloads_read_file(FILE *fp, const char *filename, struct NmapPayloads *payloads);

/**
 * Read payloads from a libpcap formatted file.
 */
void
payloads_read_pcap(const char *filename, struct NmapPayloads *payloads);

/**
 * Called to remove any payloads that aren't be used in the scan. This makes
 * lookups faster when generating packets.
 */
void
payloads_trim(struct NmapPayloads *payloadsd, const struct RangeList *ports);

int
payloads_lookup(
                const struct NmapPayloads *payloads, 
                unsigned port, 
                const unsigned char **px, 
                unsigned *length, 
                unsigned *source_port, 
                uint64_t *xsum);



#endif
