/*
    This is for filtering input in the "--readscan" feature
*/
#ifndef IN_FILTER_H
#define IN_FILTER_H
#include "massip-addr.h"
struct RangeList;
struct Range6List;
struct MassIP;

/**
 * Filters readscan record by IP address, port number,
 * or banner-type.
 */
int
readscan_filter_pass(ipaddress ip, unsigned port, unsigned type,
              const struct MassIP *massip,
              const struct RangeList *btypes);



#endif
