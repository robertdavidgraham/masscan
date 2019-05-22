#ifndef RANGE_FILE_H
#define RANGE_FILE_H

/*
    range-file
 
    Reads IP addresses and ranges from a file. Optimized to
    read millions of addresses/ranges.
 */

struct RangeList;
struct Range6List;

int
rangefile_read(const char *filename, struct RangeList *targets_ipv4, struct Range6List *targets_ipv6);

int
rangefile_selftest(void);

#endif

