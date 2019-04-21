/*
    for tracking IP/port ranges
*/
#include "ranges6.h"
#include "util-malloc.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUCKET_COUNT 16

#define REGRESS(x) if (!(x)) return (fprintf(stderr, "regression failed %s:%d\n", __FILE__, __LINE__)|1)
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

static ipv6address ADD1(const ipv6address lhs, uint64_t rhs)
{
    ipv6address result = lhs;
    result.lo += rhs;
    if (result.lo < lhs.lo)
        result.hi++;
    return result;
}

static uint64_t DIFF(const ipv6address lhs, const ipv6address rhs)
{
    /* We don't allow larger ranges */
    assert(lhs.hi - rhs.hi < 2);

    if (lhs.hi > rhs.hi)
        return rhs.lo - lhs.lo;
    else
        return lhs.lo - rhs.lo;
}

static int
LESS(const ipv6address lhs, const ipv6address rhs)
{
    if (lhs.hi < rhs.hi)
        return 1;
    else if (lhs.hi == rhs.hi && lhs.lo < rhs.lo)
        return 1;
    else
        return 0;
}

static int
LESSEQ(const ipv6address lhs, const ipv6address rhs)
{
    if (lhs.hi <= rhs.hi)
        return 1;
    else if (lhs.hi == rhs.hi && lhs.lo <= rhs.lo)
        return 1;
    else
        return 0;
}

/*static int
EQUALS(const ipv6address lhs, const ipv6address rhs)
{
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}*/

static ipv6address
MINUS_ONE(const ipv6address ip)
{
    ipv6address result;
    
    if (ip.lo == 0) {
        result.hi = ip.hi - 1;
        result.lo = ~0ULL;
    } else {
        result.hi = ip.hi;
        result.lo = ip.lo - 1;
    }

    return result;
}

static ipv6address PLUS_ONE(const ipv6address ip)
{
    ipv6address result;
    
    if (ip.lo == ~0) {
        result.hi = ip.hi + 1;
        result.lo = 0;
    } else {
        result.hi = ip.hi;
        result.lo = ip.lo + 1;
    }

    return result;
}

/***************************************************************************
 ***************************************************************************/
int
range6list_is_contains(const struct Range6List *targets, const ipv6address ip)
{
    unsigned i;

    for (i=0; i<targets->count; i++) {
        struct Range6 *range = &targets->list[i];

        if (LESSEQ(range->begin, ip) && LESSEQ(ip, range->end))
            return 1;
    }
    return 0;
}

/***************************************************************************
 * ???
 ***************************************************************************/
static void
todo_remove_at(struct Range6List *targets, unsigned index)
{
    memmove(&targets->list[index],
            &targets->list[index+1],
            (targets->count - index) * sizeof(targets->list[index])
            );
    targets->count--;
}


/***************************************************************************
 * Test if two ranges overlap.
 * This is easiest done by testing that they don't overlap, and inverting
 * the result.
 * Note that adjacent addresses overlap.
 ***************************************************************************/
static int
range6_is_overlap(const struct Range6 lhs, const struct Range6 rhs)
{
    static const ipv6address zero = {0, 0};
    ipv6address lhs_endm = MINUS_ONE(lhs.end);
    ipv6address rhs_endm = MINUS_ONE(rhs.end);
    
    /* llll rrrr */
    if (LESS(zero, lhs.end) && LESS(lhs_endm, rhs.begin))
        return 0;

    /* rrrr llll */
    if (LESS(zero, rhs.end) && LESS(rhs_endm, lhs.begin))
        return 0;

    return 1;
}


/***************************************************************************
 * Combine two ranges, such as when they overlap.
 ***************************************************************************/
static void
range6_combine(struct Range6 *lhs, const struct Range6 rhs)
{
    if (LESSEQ(rhs.begin, lhs->begin))
        lhs->begin = rhs.begin;
    if (LESSEQ(lhs->end, rhs.end))
        lhs->end = rhs.end;
}


/***************************************************************************
 * Add the IPv6 range to our list of ranges.
 ***************************************************************************/
void
range6list_add_range(struct Range6List *targets, const ipv6address begin, const ipv6address end)
{
    struct Range6 range;

    range.begin = begin;
    range.end = end;

    /* auto-expand the list if necessary */
    if (targets->count + 1 >= targets->max) {

        /* double the size of the array */
        targets->max = targets->max * 2 + 1;

        targets->list = REALLOCARRAY(targets->list, targets->max, sizeof(targets->list[0]));
    }

    {
        size_t lo, hi, mid;
        
        lo = 0;
        hi = targets->count;
        while (lo < hi) {
            mid = lo + (hi - lo)/2;
            if (LESS(range.end, targets->list[mid].begin)) {
                /* This IP range comes BEFORE the current range */
                hi = mid;
            } else if (LESS(targets->list[mid].end, range.begin)) {
                /* this IP range comes AFTER the current range */
                lo = mid + 1;
            } else
                break;
        }
        
        /* No matching range was found, so insert at this location */
        mid = lo + (hi - lo)/2;
        
        /*
         * If overlap, then combine it with the range at this point. Otherwise,
         * insert it at this point.
         */
        if (mid < targets->count && range6_is_overlap(targets->list[mid], range)) {
            range6_combine(&targets->list[mid], range);
        } else {
            memmove(targets->list+mid+1, targets->list+mid, (targets->count - mid) * sizeof(targets->list[0]));
            targets->list[mid].begin = begin;
            targets->list[mid].end = end;
            targets->count++;
        }
        
        /*
         * If overlap with neighbors, then combine with neighbors
         */
        for (;;) {
            unsigned is_neighbor_overlapped = 0;
            if (mid > 0 && range6_is_overlap(targets->list[mid-1], targets->list[mid])) {
                range6_combine(&targets->list[mid-1], targets->list[mid]);
                memmove(targets->list+mid, targets->list+mid+1, (targets->count - mid) * sizeof(targets->list[0]));
                mid--;
                is_neighbor_overlapped = 1;
                targets->count--;
            }
            if (mid+1 < targets->count && range6_is_overlap(targets->list[mid], targets->list[mid+1])) {
                range6_combine(&targets->list[mid], targets->list[mid+1]);
                memmove(targets->list+mid, targets->list+mid+1, (targets->count - mid) * sizeof(targets->list[0]));
                is_neighbor_overlapped = 1;
                targets->count--;
            }
            if (!is_neighbor_overlapped)
                break;
        }
        return;
    }

}

/***************************************************************************
 ***************************************************************************/
void
range6list_remove_all(struct Range6List *targets)
{
    if (targets->list)
        free(targets->list);
    if (targets->picker)
        free(targets->picker);
    memset(targets, 0, sizeof(*targets));
}

/***************************************************************************
 ***************************************************************************/
void
range6list_merge(struct Range6List *list1, const struct Range6List *list2)
{
    unsigned i;
    
    for (i=0; i<list2->count; i++) {
        range6list_add_range(list1, list2->list[i].begin, list2->list[i].end);
    }
}

/***************************************************************************
 ***************************************************************************/
void
range6list_remove_range(struct Range6List *targets, const ipv6address begin, const ipv6address end)
{
    unsigned i;
    struct Range6 x;

    x.begin = begin;
    x.end = end;

    /* See if the range overlaps any exist range already in the
     * list */
    for (i = 0; i < targets->count; i++) {
        if (!range6_is_overlap(targets->list[i], x))
            continue;

        /* If the removal-range wholly covers the range, delete
         * it completely */
        if (LESSEQ(begin, targets->list[i].begin) && LESSEQ(targets->list[i].end, end)) {
            todo_remove_at(targets, i);
            i--;
            continue;
        }

        /* If the removal-range bisects the target-rage, truncate
         * the lower end and add a new high-end */
        if (LESSEQ(targets->list[i].begin, begin) && LESSEQ(end, targets->list[i].end)) {
            struct Range6 newrange;

            newrange.begin = PLUS_ONE(end);
            newrange.end = targets->list[i].end;


            targets->list[i].end = MINUS_ONE(begin);

            range6list_add_range(targets, newrange.begin, newrange.end);
            i--;
            continue;
        }

        /* If overlap on the lower side */
        if (LESSEQ(targets->list[i].begin, end) && LESSEQ(end, targets->list[i].end)) {
            targets->list[i].begin = PLUS_ONE(end);
        }

        /* If overlap on the upper side */
        if (LESSEQ(targets->list[i].begin, begin) && LESSEQ(begin, targets->list[i].end)) {
             targets->list[i].end = MINUS_ONE(begin);
        }
    }
}

/*void
range6list_add_range2(struct Range6List *targets, struct Range6 range)
{
    range6list_add_range(targets, range.begin, range.end);
}*/
void
range6list_remove_range2(struct Range6List *targets, struct Range6 range)
{
    range6list_remove_range(targets, range.begin, range.end);
}

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(int c)
{
	if ('0' <= c && c <= '9')
		return (unsigned)(c - '0');
	else if ('a' <= c && c <= 'f')
		return (unsigned)(c - 'a' + 10);
	else if ('A' <= c && c <= 'F')
		return (unsigned)(c - 'A' + 10);
	else
		return 0;
}

/***************************************************************************
 * Parse an IPv6 address from a line of text, moving the offset forward
 * to the first non-IPv6 character
 ***************************************************************************/
/****************************************************************************
 * Parse an IPv6 address
 *
 * Returns '0' if successful, some other value otherwise.
 *
 * Example:
 *  3ffe:ffff:101::230:6eff:fe04:d9ff
 * 
 * NOTE: The symbol :: is a special syntax that can be used as a 
 * shorthand way of representing multiple 16-bit groups of 
 * contiguous 0’s (zeros). The :: can appear anywhere in the address; 
 * however it can only appear once in the address.
 *
 ****************************************************************************/
static int
parse_ipv6(const char *buf, unsigned *offset, size_t length, ipv6address *ip)
{
	unsigned i = *offset;
	unsigned is_bracket_seen = 0;
	unsigned elision_offset = (unsigned)~0;
	unsigned d = 0;
    //unsigned prefix_length = 128;
    unsigned char address[16];

    /* If no /CIDR spec is found, assume 128-bits for IPv6 addresses */
    //prefix_length = 128;

	/* Remove leading whitespace */
	while (i < length && isspace(buf[i]))
		i++;

	/* If the address starts with a '[', then remove it */
	if (i < length && buf[i] == '[') {
		is_bracket_seen = 1;
		i++;

        /* remove more whitespace */
		while (i < length && isspace(buf[i]))
			i++;
	}

	/* Now parse all the numbers out of the stream */
	while (i < length) {
		unsigned j;
		unsigned number = 0;

		/* Have we found all 128-bits/16-bytes? */
		if (d >= 16)
			break;

		/* Is there an elision/compression of the address? */
		if (buf[i] == ':' && elision_offset < 16) {
			elision_offset = d;
			i++;
			continue;
		}

		/* Parse the hex digits into a 2-byte number */
		j=0;
		while (i < length) {
			if (j >= 4)
				break; /* max 4 hex digits at a time */
			if (buf[i] == ':')
				break; /* early exit due to leading nuls */
			if (!isxdigit(buf[i])) {
				break; /* error */
			}

			number <<= 4;
			number |= hexval(buf[i++]);
			j++;
		}

		/* If no hex digits were processed */
		if (j == 0)
			break;

		/* We have a 2-byte number */
		address[d+0] = (unsigned char)(number>>8);
		address[d+1] = (unsigned char)(number>>0);
		d += 2;

		/* See if we have the normal continuation */
		if (i < length && buf[i] == ':') {
			i++;
			continue;
		}

		/* Or, see if we have reached the trailing ']' character */
		if (i < length && is_bracket_seen && buf[i] == ']') {
			i++; /* skip ']' */
			//is_bracket_seen = false;
			break;
		}

		/* We have parsed all the address we are looking for. Therefore, stop
		 * parsing at this point */
		if (d == 16)
			break;

		/* Is there an ellision in this address? If so, break at this point */
		if (elision_offset != (unsigned)(~0))
			break;

		/* See if we have reached the end of the address. */
		if (i == length)
			break;

		/* Some unknown character is seen, therefore return an
		 * error */
		return -1;
	}

	/* Insert zeroes where numbers were removed */
	if (elision_offset != ~0) {
		if (d == 16) {
			/* oops, there was no elision, this is an error */
			return -1;
		}

		memmove(address + elision_offset + 16 - d, 
				address + elision_offset,
				d - elision_offset);
		memset(	address + elision_offset,
				0,
				16-d);
	}

#if 0
    /* Check for optional CIDR field */
    if (i < length && buf[i] == '/') {
        unsigned n = 0;
        
        i++;

        if (i >= length || !isdigit(buf[i]))
            return -1;

        n = buf[i] - '0';
        i++;

        if (i<length && isdigit(buf[i])) {
            n = n * 10 + buf[i] - '0';
            i++;
        }

        if (n > 128)
            return -1;
        else
            prefix_length = (unsigned char)n;
    }
#endif

    ip->hi =    (((uint64_t)address[0]) << 56ULL)
                    | ((uint64_t)address[1] << 48ULL)
                    | ((uint64_t)address[2] << 40ULL)
                    | ((uint64_t)address[3] << 32ULL)
                    | ((uint64_t)address[4] << 24ULL)
                    | ((uint64_t)address[5] << 16ULL)
                    | ((uint64_t)address[6] <<  8ULL)
                    | ((uint64_t)address[7] <<  0ULL);
    ip->lo =    ((uint64_t)address[ 8] << 56ULL)
                    | ((uint64_t)address[ 9] << 48ULL)
                    | ((uint64_t)address[10] << 40ULL)
                    | ((uint64_t)address[11] << 32ULL)
                    | ((uint64_t)address[12] << 24ULL)
                    | ((uint64_t)address[13] << 16ULL)
                    | ((uint64_t)address[14] <<  8ULL)
                    | ((uint64_t)address[15] <<  0ULL);
    
    *offset = i;

    /* Now convert the prefix into a begin/end */
    {
        //ip->hi = address[0]<<56ULL;

    }
    return true;
}

/****************************************************************************
 * Parse from text an IPv6 address range. This can be in one of several
 * formats:
 * - '192.168.1.1" - a single address
 * - '192.168.1.0/24" - a CIDR spec
 * - '192.168.1.0-192.168.1.255' - a range
 * @param line
 *      Part of a line of text, probably read from a commandline or conf
 *      file.
 * @param inout_offset
 *      On input, the offset from the start of the line where the address
 *      starts. On output, the offset of the first character after the
 *      range, or equal to 'max' if the line prematurely ended.
 * @param max
 *      The maximum length of the line.
 * @return
 *      The first and last address of the range, inclusive.
 ****************************************************************************/
struct Range6
range6_parse(const char *buf, unsigned *inout_offset, unsigned max)
{
    unsigned offset;
    struct Range6 result;
    static const struct Range6 badrange = {{~0ULL,~0ULL}, {0,0}};
    int err;

    if (buf == NULL)
        return badrange;

    if (inout_offset == NULL) {
         inout_offset = &offset;
         offset = 0;
         max = (unsigned)strlen(buf);
    } else
        offset = *inout_offset;


    /* trim whitespace */
    while (offset < max && isspace(buf[offset]&0xFF))
        offset++;

    /* get the first IP address */
    err = parse_ipv6(buf, &offset, max, &result.begin);
    if (err) {
        return badrange;
    }
    result.end = result.begin;

    /* trim whitespace */
    while (offset < max && isspace(buf[offset]&0xFF))
        offset++;

    /* If onely one IP address, return that */
    if (offset >= max)
        goto end;

    /*
     * Handle CIDR address of the form "::1/8"
     */
    if (buf[offset] == '/') {
        uint64_t prefix = 0;
        ipv6address mask = {0, 0};
        unsigned digits = 0;

        /* skip slash */
        offset++;

        if (!isdigit(buf[offset]&0xFF)) {
            return badrange;
        }

        /* strip leading zeroes */
        while (offset<max && buf[offset] == '0')
            offset++;

        /* parse decimal integer */
        while (offset<max && isdigit(buf[offset]&0xFF)) {
            prefix = prefix * 10 + (buf[offset++] - '0');
            if (++digits > 3)
                return badrange;
        }
        if (prefix > 128)
            return badrange;

        /* Create the mask from the prefix */
        if (prefix > 64)
            mask.hi = ~0ULL;
        else if (prefix == 0)
            mask.hi = 0;
        else
            mask.hi = ~0ULL << (64 - prefix);

        if (prefix > 64)
            mask.lo = ~0ULL << (128 - prefix);
        else
            mask.lo = 0;

        /* Mask off any non-zero bits from the start
         * TODO print warning */
        result.begin.hi &= mask.hi;
        result.begin.lo &= mask.lo;

        /* Set all suffix bits to 1, so that 192.168.1.0/24 has
         * an ending address of 192.168.1.255. */
        result.end.hi = result.begin.hi | ~mask.hi;
        result.end.lo = result.begin.lo | ~mask.lo;
        goto end;
    }

    /*
     * Handle a dashed range like "10.0.0.100-10.0.0.200"
     */
    if (offset<max && buf[offset] == '-') {
        ipv6address ip;

        offset++;
        err = parse_ipv6(buf, &offset, max, &ip);
        if (err)
            return badrange;
        if (LESS(ip, result.begin)) {
            ipv6address xx = result.begin;
            fprintf(stderr, "err: ending addr %4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x cannot come before starting addr %4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x\n",
                (unsigned)((ip.hi>>48ULL) & 0xFFFF),  (unsigned)((ip.hi>>32ULL) & 0xFFFF),
                (unsigned)((ip.hi>>16ULL) & 0xFFFF),  (unsigned)((ip.hi>> 0ULL) & 0xFFFF),
                (unsigned)((ip.lo>>48ULL) & 0xFFFF),  (unsigned)((ip.lo>>32ULL) & 0xFFFF),
                (unsigned)((ip.lo>>16ULL) & 0xFFFF),  (unsigned)((ip.lo>> 0ULL) & 0xFFFF),
                (unsigned)((xx.hi>>48ULL) & 0xFFFF),  (unsigned)((xx.hi>>32ULL) & 0xFFFF),
                (unsigned)((xx.hi>>16ULL) & 0xFFFF),  (unsigned)((xx.hi>> 0ULL) & 0xFFFF),
                (unsigned)((xx.lo>>48ULL) & 0xFFFF),  (unsigned)((xx.lo>>32ULL) & 0xFFFF),
                (unsigned)((xx.lo>>16ULL) & 0xFFFF),  (unsigned)((xx.lo>> 0ULL) & 0xFFFF)
                );
            result.begin.hi = ~0ULL;
            result.begin.lo = ~0ULL;
            result.end.hi = 0;
            result.end.lo = 0;
        } else
            result.end = ip;

        /* Make sure the size of the range fits with 64-bit integers */
        if (result.end.hi - result.begin.hi > 2 
            || (result.end.hi - result.begin.hi == 1 && result.end.lo >= result.begin.lo)) {
            ipv6address x1 = result.begin;
            ipv6address x2 = result.end;
            fprintf(stderr, "err: range %4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x - %4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x greater than 64-bits\n",
                (unsigned)((x1.hi>>48ULL) & 0xFFFF),  (unsigned)((x1.hi>>32ULL) & 0xFFFF),
                (unsigned)((x1.hi>>16ULL) & 0xFFFF),  (unsigned)((x1.hi>> 0ULL) & 0xFFFF),
                (unsigned)((x1.lo>>48ULL) & 0xFFFF),  (unsigned)((x1.lo>>32ULL) & 0xFFFF),
                (unsigned)((x1.lo>>16ULL) & 0xFFFF),  (unsigned)((x1.lo>> 0ULL) & 0xFFFF),
                (unsigned)((x2.hi>>48ULL) & 0xFFFF),  (unsigned)((x2.hi>>32ULL) & 0xFFFF),
                (unsigned)((x2.hi>>16ULL) & 0xFFFF),  (unsigned)((x2.hi>> 0ULL) & 0xFFFF),
                (unsigned)((x2.lo>>48ULL) & 0xFFFF),  (unsigned)((x2.lo>>32ULL) & 0xFFFF),
                (unsigned)((x2.lo>>16ULL) & 0xFFFF),  (unsigned)((x2.lo>> 0ULL) & 0xFFFF)
                );
            result.begin.hi = ~0ULL;
            result.begin.lo = ~0ULL;
            result.end.hi = 0;
            result.end.lo = 0;
        }
        goto end;
    }

end:
    *inout_offset = offset;
    return result;
}


/***************************************************************************
 ***************************************************************************/
uint64_t
range6list_exclude(  struct Range6List *targets,
                  const struct Range6List *excludes)
{
    uint64_t count = 0;
    unsigned i;
    
    for (i=0; i<excludes->count; i++) {
        struct Range6 range = excludes->list[i];
        count += DIFF(range.end, range.begin) + 1ULL;
        range6list_remove_range(targets, range.begin, range.end);
    }
    
    return count;
}


/***************************************************************************
 ***************************************************************************/
uint64_t
range6list_count(const struct Range6List *targets)
{
    unsigned i;
    uint64_t result = 0;

    for (i=0; i<targets->count; i++) {
        uint64_t result_old = result;

        result += DIFF(targets->list[i].end, targets->list[i].begin) + 1ULL;
        if (result < result_old) {
            /* integer overflow */
            fprintf(stderr, "targe range bigger than 64-bits\n");
            return ~0ULL;
        }
    }

    return result;
}


/***************************************************************************
 * Get's the indexed port/address.
 *
 * Note that this requires a search of all the ranges. Currently, this is
 * done by a learn search of the ranges. This needs to change, because
 * once we start adding in a lot of "exclude ranges", the address space
 * will get fragmented, and the linear search will take too long.
 ***************************************************************************/
static ipv6address
range6list_pick_linearsearch(const struct Range6List *targets, uint64_t index)
{
    static const ipv6address emptyaddress = {0,0};
    unsigned i;

    for (i=0; i<targets->count; i++) {
        uint64_t range = DIFF(targets->list[i].end, targets->list[i].begin) + 1ULL;
        if (index < range)
            return ADD1(targets->list[i].begin, index);
        else
            index -= range;
    }

    assert(!"end of list");
    return emptyaddress;
}

/***************************************************************************
 ***************************************************************************/
ipv6address
range6list_pick(const struct Range6List *targets, uint64_t index)
{
    size_t maxmax = targets->count;
    size_t min = 0;
    size_t max = targets->count;
    size_t mid;
    const uint64_t *picker = targets->picker;

    if (picker == NULL) {
        /* optimization wasn't done */
        return range6list_pick_linearsearch(targets, index);
    }


    for (;;) {
        mid = min + (max-min)/2;
        if (index < picker[mid]) {
            max = mid;
            continue;
        } if (index >= picker[mid]) {
            if (mid + 1 == maxmax)
                break;
            else if (index < picker[mid+1])
                break;
            else
                min = mid+1;
        }
    }

    return ADD1(targets->list[mid].begin, (index - picker[mid]));
}


/***************************************************************************
 * The normal "pick" function is a linear search, which is slow when there
 * are a lot of ranges. Therefore, the "pick2" creates sort of binary
 * search that'll be a lot faster. We choose "binary search" because
 * it's the most cache-efficient, having the least overhead to fit within
 * the cache.
 ***************************************************************************/
void
range6list_optimize(struct Range6List *targets)
{
    uint64_t *picker;
    size_t i;
    uint64_t total = 0;

    if (targets->picker)
        free(targets->picker);

    if (((size_t)targets->count) >= (size_t)(SIZE_MAX/sizeof(*picker)))
        exit(1); /* integer overflow */
    picker = malloc(targets->count * sizeof(*picker));
    if (picker == NULL)
        exit(1); /* out of memory */

    for (i=0; i<targets->count; i++) {
        picker[i] = total;
        total += DIFF(targets->list[i].end, targets->list[i].begin) + 1;
    }
    
    targets->picker = picker;
}



/***************************************************************************
 * Provide my own rand() simply to avoid static-analysis warning me that
 * 'rand()' is unrandom, when in fact we want the non-random properties of
 * rand() for regression testing.
 ***************************************************************************/
static unsigned
r_rand(unsigned *seed)
{
    static const unsigned a = 214013;
    static const unsigned c = 2531011;

    *seed = (*seed) * a + c;
    return (*seed)>>16 & 0x7fff;
}

/***************************************************************************
 ***************************************************************************/
static int
regress_pick2()
{
    unsigned i;
    unsigned seed = 0;

    /*
     * Run 100 randomized regression tests
     */
    for (i=0; i<100; i++) {
        unsigned j;
        unsigned num_targets;
        ipv6address begin = {0};
        ipv6address end = {0};
        struct Range6List targets[1];
        struct Range6List duplicate[1];
        unsigned range;


        /* Create a new target list */
        memset(targets, 0, sizeof(targets[0]));

        /* fill the target list with random ranges */
        num_targets = r_rand(&seed)%5 + 1;
        for (j=0; j<num_targets; j++) {
            begin.lo += r_rand(&seed)%10;
            end.lo = begin.lo + r_rand(&seed)%10;

            range6list_add_range(targets, begin, end);
        }
        range = (unsigned)range6list_count(targets);

        /* Optimize for faster 'picking' addresses from an index */
        range6list_optimize(targets);

        /* Duplicate the targetlist using the picker */
        memset(duplicate, 0, sizeof(duplicate[0]));
        for (j=0; j<range; j++) {
            ipv6address x;

            x = range6list_pick(targets, j);
            range6list_add_range(duplicate, x, x);
        }

        /* at this point, the two range lists shouild be identical */
        REGRESS(targets->count == duplicate->count);
        REGRESS(memcmp(targets->list, duplicate->list, targets->count*sizeof(targets->list[0])) == 0);

        range6list_remove_all(targets);
        range6list_remove_all(duplicate);
    }

    return 0;
}





/***************************************************************************
 * Called during "make regress" to run a regression test over this module.
 ***************************************************************************/
int
ranges6_selftest(void)
{
    struct Range6 r;
    struct Range6List targets[1];

    REGRESS(regress_pick2() == 0);

    memset(targets, 0, sizeof(targets[0]));
#define ERROR() fprintf(stderr, "selftest: failed %s:%u\n", __FILE__, __LINE__);

    /* test for the /0 CIDR block, since we'll be using that a lot to scan the entire
     * Internet */
    r = range6_parse("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 0, 0);
    if (r.begin.hi != 0x20010db885a30000)
        return 1;
    if (r.begin.lo != 0x00008a2e03707334)
        return 1;

    return 0;
}
