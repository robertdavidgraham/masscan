#ifndef TEMPL_PAYLOADS_H
#define TEMPL_PAYLOADS_H
#include <stdio.h>
struct RangeList;

int payloads_selftest();

struct NmapPayloads *
payloads_create();

void
payloads_destroy(struct NmapPayloads *payloads);

void
payloads_read_file(FILE *fp, const char *filename, struct NmapPayloads *payloads);

/**
 * Called to remove any payloads that aren't be used in the scan. This makes
 * lookups faster when generating packets.
 */
void
payloads_trim(struct NmapPayloads *payloadsd, const struct RangeList *ports);

int
payloads_lookup(const struct NmapPayloads *payloads, unsigned port, const unsigned char **px, unsigned *length, unsigned *source_port, unsigned *xsum);



#endif
