#include "ranges.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUCKET_COUNT 16


/***************************************************************************
 * ???
 ***************************************************************************/
static void
todo_remove_at(struct RangeList *task, unsigned index)
{
    memmove(&task->list[index],
            &task->list[index+1],
            (task->count - index) * sizeof(task->list[index])
            );
    task->count--;
}


/***************************************************************************
 * Test if two ranges overlap
 ***************************************************************************/
static int
range_is_overlap(struct Range lhs, struct Range rhs)
{
    if (lhs.begin < rhs.begin) {
        if (lhs.end == 0xFFFFFFFF || lhs.end + 1 >= rhs.begin)
            return 1;
    }
    if (lhs.begin >= rhs.begin) {
        if (lhs.end <= rhs.end)
            return 1;
    }

    if (rhs.begin < lhs.begin) {
        if (rhs.end == 0xFFFFFFFF || rhs.end + 1 >= lhs.begin)
            return 1;
    }
    if (rhs.begin >= lhs.begin) {
        if (rhs.end <= lhs.end)
            return 1;
    }

    return 0;
}


/***************************************************************************
 * Combine two ranges, such as when they overlap.
 ***************************************************************************/
static void
range_combine(struct Range *lhs, struct Range rhs)
{
    if (lhs->begin > rhs.begin)
        lhs->begin = rhs.begin;
    if (lhs->end < rhs.end)
        lhs->end = rhs.end;
}


/***************************************************************************
 * Add the IPv4 range to our list of ranges.
 ***************************************************************************/
void
rangelist_add_range(struct RangeList *task, unsigned begin, unsigned end)
{
    unsigned i;
    struct Range range;

    range.begin = begin;
    range.end = end;

    /* auto-expand the list if necessary */
    if (task->count + 1 >= task->max) {
        unsigned new_max = task->max * 2 + 1;
        struct Range *new_list = (struct Range *)malloc(sizeof(*new_list) * new_max);
        memcpy(new_list, task->list, task->count * sizeof(*new_list));
        if (task->list)
            free(task->list);
        task->list = new_list;
        task->max = new_max;
    }

    /* See if the range overlaps any exist range already in the
     * list */
    for (i = 0; i < task->count; i++) {
        if (range_is_overlap(task->list[i], range)) {
            range_combine(&range, task->list[i]);
            todo_remove_at(task, i);
            rangelist_add_range(task, range.begin, range.end);
            return;
        }
    }

    /* Add to end of list */
    task->list[i].begin = begin;
    task->list[i].end = end;
    task->count++;
}

void
rangelist_add_range2(struct RangeList *task, struct Range range)
{
    rangelist_add_range(task, range.begin, range.end);
}


/***************************************************************************
 * Parse an IPv4 address from a line of text, moving the offset forward
 * to the first non-IPv4 character
 ***************************************************************************/
static unsigned
parse_ipv4(const char *line, unsigned *inout_offset, unsigned max)
{
    unsigned offset = *inout_offset;
    unsigned result = 0;
    unsigned i;

    for (i=0; i<4; i++) {
        unsigned x = 0;
        while (offset < max && isdigit(line[offset]&0xFF)) {
            x = x * 10 + (line[offset] - '0');
            offset++;
        }
        result = result * 256 + (x & 0xFF);
        if (offset >= max || line[offset] != '.')
            break;
        offset++; /* skip dot */
    }

    *inout_offset = offset;
    return result;
}

/****************************************************************************
 * Parse from text an IPv4 address range. This can be in one of several 
 * formats:
 * - '192.168.1.1" - a single address
 * - '192.168.1.0/24" - a CIDR spec
 * - '192.168.1.0-192.168.1.255' - a range
 * @param line
 *		Part of a line of text, probably read from a commandline or conf
 *		file.
 * @param inout_offset
 *		On input, the offset from the start of the line where the address
 *		starts. On output, the offset of the first character after the
 *		range, or equal to 'max' if the line prematurely ended.
 * @param max
 *		The maximum length of the line.
 * @return
 *		The first and last address of the range, inclusive.
 ****************************************************************************/
struct Range
range_parse_ipv4(const char *line, unsigned *inout_offset, unsigned max)
{
    unsigned offset;
    struct Range result;

    if (inout_offset == NULL) {
         inout_offset = &offset;
         offset = 0;
         max = (unsigned)strlen(line);
    } else
        offset = *inout_offset;


    /* trim whitespace */
    while (offset < max && isspace(line[offset]&0xFF))
        offset++;

    /* get the first IP address */
    result.begin = parse_ipv4(line, &offset, max);
    result.end = result.begin;

    /* trim whitespace */
    while (offset < max && isspace(line[offset]&0xFF))
        offset++;

	/* If onely one IP address, return that */
	if (offset >= max)
		goto end;

    /*
	 * Handle CIDR address of the form "10.0.0.0/8" 
	 */
    if (line[offset] == '/') {
        unsigned prefix = 0;
        uint64_t mask = 0;

		/* skip slash */
        offset++;

		/* parse decimal integer */
        while (offset<max && isdigit(line[offset]&0xFF))
            prefix = prefix * 10 + (line[offset++] - '0');

		/* Create the mask from the prefix */
        mask = 0xFFFFFFFF00000000UL >> prefix;
        
		/* Mask off any non-zero bits from the start
		 * TODO print warning */
		result.begin &= mask;

		/* Set all suffix bits to 1, so that 192.168.1.0/24 has
		 * an ending address of 192.168.1.255. */
        result.end = result.begin | (unsigned)~mask;
		goto end;
    }
	
	/*
	 * Handle a dashed range like "10.0.0.100-10.0.0.200"
	 */
	if (offset<max && line[offset] == '-') {
		unsigned ip;

        offset++;
		ip = parse_ipv4(line, &offset, max);
		if (ip < result.begin) {
            result.begin = 0xFFFFFFFF;
            result.end = 0x00000000;
			fprintf(stderr, "err: ending addr %u.%u.%u.%u cannot come before starting addr %u.%u.%u.%u\n",
				((ip>>24)&0xFF), ((ip>>16)&0xFF), ((ip>>8)&0xFF), ((ip>>0)&0xFF), 
				((result.begin>>24)&0xFF), ((result.begin>>16)&0xFF), ((result.begin>>8)&0xFF), ((result.begin>>0)&0xFF)
				);
        } else
            result.end = ip;
		goto end;
	}

end:
	*inout_offset = offset;
    return result;
}


/***************************************************************************
 ***************************************************************************/
uint64_t
rangelist_count(struct RangeList *targets)
{
	unsigned i;
	uint64_t result = 0;

	for (i=0; i<targets->count; i++) {
		result += (uint64_t)targets->list[i].end - (uint64_t)targets->list[i].begin + 1UL;
	}

	return result;
}


/***************************************************************************
 ***************************************************************************/
unsigned
rangelist_pick(struct RangeList *targets, uint64_t index)
{
	unsigned i;

	for (i=0; i<targets->count; i++) {
		uint64_t range = targets->list[i].end - targets->list[i].begin + 1;
		if (index < range)
			return (unsigned)(targets->list[i].begin + index);
		else
			index -= range;
	}

	assert(!"end of list");
	return 0;
}

/***************************************************************************
 ***************************************************************************/
int
ranges_selftest()
{
    struct Range r;
    struct RangeList task[1];

    memset(task, 0, sizeof(task[0]));


#define ERROR() fprintf(stderr, "selftest: failed %s:%u\n", __FILE__, __LINE__);

    r = range_parse_ipv4("192.168.1.3", 0, 0);
    if (r.begin != 0xc0a80103 || r.end != 0xc0a80103) {
        fprintf(stderr, "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }

    r = range_parse_ipv4("10.0.0.20-10.0.0.30", 0, 0);
    if (r.begin != 0x0A000000+20 || r.end != 0x0A000000+30) {
        fprintf(stderr, "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }

    r = range_parse_ipv4("10.0.1.2/16", 0, 0);
    if (r.begin != 0x0A000000 || r.end != 0x0A00FFFF) {
        fprintf(stderr, "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }


    rangelist_add_range2(task, range_parse_ipv4("10.0.0.0/24", 0, 0));
    rangelist_add_range2(task, range_parse_ipv4("10.0.1.10-10.0.1.19", 0, 0));
    rangelist_add_range2(task, range_parse_ipv4("10.0.1.20-10.0.1.30", 0, 0));
    rangelist_add_range2(task, range_parse_ipv4("10.0.0.0-10.0.1.12", 0, 0));

    if (task->count != 1) {
        fprintf(stderr, "count = %u\n", task->count);
        ERROR();
        return 1;
    }
    if (task->list[0].begin != 0x0a000000 || task->list[0].end != 0x0a000100+30) {
        fprintf(stderr, "r.begin = 0x%08x r.end = 0x%08x\n", task->list[0].begin, task->list[0].end);
        ERROR();
        return 1;
    }


    return 0;
}
