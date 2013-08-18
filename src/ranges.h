#ifndef RANGE_H
#define RANGE_H
#include <stdint.h>

/**
 * @return
 *      1 on failure
 *      0 on success
 */
int ranges_selftest();

struct Range
{
    unsigned begin;
    unsigned end;
};

struct RangeList
{
    struct Range *list;
	unsigned count;
	unsigned max;
};

void rangelist_add_range(struct RangeList *task, unsigned begin, unsigned end);
void rangelist_remove_range(struct RangeList *task, unsigned begin, unsigned end);
struct Range range_parse_ipv4(const char *line, unsigned *inout_offset, unsigned max);
uint64_t rangelist_count(struct RangeList *targets);
unsigned rangelist_pick(struct RangeList *targets, uint64_t i);

#endif
