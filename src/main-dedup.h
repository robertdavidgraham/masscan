#ifndef MAIN_DEDUP_H
#define MAIN_DEDUP_H

struct DedupTable *dedup_create();
void dedup_destroy(struct DedupTable *table);
unsigned dedup_is_duplicate(struct DedupTable *dedup, unsigned ip, unsigned port);


#endif
