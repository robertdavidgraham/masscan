/*
    This is for filtering input in the "--readscan" feature
*/
#ifndef IN_FILTER_H
#define IN_FILTER_H
struct RangeList;

/**
 * Filters readscan record by IP address, port number,
 * or banner-type.
 */
int
readscan_filter_pass(unsigned ip, unsigned port, unsigned type,
              const struct RangeList *ips,
              const struct RangeList *ports,
              const struct RangeList *btypes);



#endif
