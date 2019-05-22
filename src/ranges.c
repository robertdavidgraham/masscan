/*
    IPv4 and port ranges
 
 This is one of the more integral concepts to how masscan works internally.
 We combine all the input addresses and address ranges into a sorted list
 of 'target' IP addresses. This allows us to enumerate all the addresses
 in order by incrementing a simple index. It is that index that we randomize
 in order to produce random output, but internally, everything is sorted.
 
 Sorting the list allows us to remove duplicates. It also allows us to
 apply the 'exludes' directly to the input list. In other words, other
 scanners typically work by selecting an IP address at random, then checking
 to see if it's been excluded, then skipping it. In this scanner, however,
 we remove all the excluded address from the targets list before we start
 scanning.
 
 This module has been tuned to support mass lists of millions of target
 IPv4 addresses and excludes. This has required:
    - a fast way to parse the address from a file (see range-file.c)
    - fast sort (just using qsort() from the standard C library)
    - fast application of exludes, using an optimal O(n + m) linear
      algorithm, where 'n' is the number of targets, and 'm' is the
      number of excluded ranges.
 Large lists can still take a bit to process. On a fast server with
 7-million input ranges/addresse and 5000 exclude ranges/addresses,
 it takes almost 3 seconds to process everything before starting.
 
*/
#include "ranges.h"
#include "logger.h"
#include "templ-port.h"
#include "util-bool.h"
#include "util-malloc.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUCKET_COUNT 16

#define REGRESS(x) if (!(x)) return (fprintf(stderr, "regression failed %s:%d\n", __FILE__, __LINE__)|1)

/* An invalid range, where begin comes after the end */
static struct Range INVALID_RANGE = {2,1};

/***************************************************************************
 * Does a linear search to see if the list contains the address/port.
 * FIXME: This should be upgraded to a binary search. However, we don't
 * really use it in any performance critical code, so it's okay
 * as a linear search.
 ***************************************************************************/
int
rangelist_is_contains(const struct RangeList *targets, unsigned addr)
{
    unsigned i;
    for (i=0; i<targets->count; i++) {
        struct Range *range = &targets->list[i];

        if (range->begin <= addr && addr <= range->end)
            return 1;
    }
    return 0;
}


/***************************************************************************
 * Test if two ranges overlap.
 * FIXME: I need to change this so that it (a) doesn't trigger on invalid
 * ranges (those where begin>end) and (b) use a simpler algorithm
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
 * Callback for qsort() for comparing two ranges
 ***************************************************************************/
static int
range_compare(const void *lhs, const void *rhs)
{
    struct Range *left = (struct Range *)lhs;
    struct Range *right = (struct Range *)rhs;

    if (left->begin < right->begin)
        return -1;
    else if (left->begin > right->begin)
        return 1;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
static void
rangelist_remove_at(struct RangeList *targets, size_t index)
{
    memmove(&targets->list[index],
            &targets->list[index+1],
            (targets->count - index) * sizeof(targets->list[index])
            );
    targets->count--;
}


/***************************************************************************
 ***************************************************************************/
void
rangelist_sort(struct RangeList *targets)
{
    size_t i;
    struct RangeList newlist = {0};
    unsigned original_count = targets->count;

    /* Empty lists are, of course, sorted. We need to set this
     * to avoid an error later on in the code which asserts that
     * the lists are sorted */
    if (targets->count == 0) {
        targets->is_sorted = 1;
        return;
    }
    
    /* If it's already sorted, then skip this */
    if (targets->is_sorted) {
        return;
    }
    
    
    /* First, sort the list */
    LOG(3, "[+] range:sort: sorting...\n");
    qsort(  targets->list,              /* the array to sort */
            targets->count,             /* number of elements to sort */
            sizeof(targets->list[0]),   /* size of element */
            range_compare);
    
    
    /* Second, combine all overlapping ranges. We do this by simply creating
     * a new list from a sorted list, so we don't have to remove things in the
     * middle when collapsing overlapping entries together, which is painfully
     * slow. */
    LOG(3, "[+] range:sort: combining...\n");
    for (i=0; i<targets->count; i++) {
        rangelist_add_range(&newlist, targets->list[i].begin, targets->list[i].end);
    }
    
    LOG(3, "[+] range:sort: combined from %u elements to %u elements\n", original_count, newlist.count);
    free(targets->list);
    targets->list = newlist.list;
    targets->count = newlist.count;
    newlist.list = 0;

    LOG(2, "[+] range:sort: done...\n");

    targets->is_sorted = 1;
}

/***************************************************************************
 * Add the IPv4 range to our list of ranges.
 ***************************************************************************/
void
rangelist_add_range(struct RangeList *targets, unsigned begin, unsigned end)
{
    struct Range range;

    range.begin = begin;
    range.end = end;

    /* auto-expand the list if necessary */
    if (targets->count + 1 >= targets->max) {
        targets->max = targets->max * 2 + 1;
        targets->list = REALLOCARRAY(targets->list, targets->max, sizeof(targets->list[0]));
    }

    /* If empty list, then add this one */
    if (targets->count == 0) {
        targets->list[0] = range;
        targets->count++;
        targets->is_sorted = 1;
        return;
    }

    /* If new range overlaps the last range in the list, then combine it
     * rather than appending it. This is an optimization for the fact that
     * we often read in sequential addresses */
    if (range_is_overlap(targets->list[targets->count - 1], range)) {
        range_combine(&targets->list[targets->count - 1], range);
        targets->is_sorted = 0;
        return;
    }

    /* append to the end of our list */
    targets->list[targets->count] = range;
    targets->count++;
    targets->is_sorted = 0;
}

/***************************************************************************
 * This is the "free" function for the list, freeing up any memory we've
 * allocated.
 ***************************************************************************/
void
rangelist_remove_all(struct RangeList *targets)
{
    free(targets->list);
    free(targets->picker);
    memset(targets, 0, sizeof(*targets));
}

/***************************************************************************
 ***************************************************************************/
void
rangelist_merge(struct RangeList *list1, const struct RangeList *list2)
{
    unsigned i;
    
    for (i=0; i<list2->count; i++) {
        rangelist_add_range(list1, list2->list[i].begin, list2->list[i].end);
    }
    rangelist_sort(list1);
}

/***************************************************************************
 * This searchs a range list and removes that range of IP addresses, if
 * they exist. Sicne the input range can overlap multiple entries, then
 * more than one entry can be removed, or truncated. Since the range
 * can be in the middle of an entry in the list, it can actually increase
 * the list size by one, as that entry is split into two entries.
 * DEPRECATED: this function is deprecated, and will be removed at some
 * point. It's only remaining in order to serve as a regression test for
 * its replacement.
 ***************************************************************************/
static void
rangelist_remove_range(struct RangeList *targets, unsigned begin, unsigned end)
{
    unsigned i;
    struct Range x;

    x.begin = begin;
    x.end = end;

    /* See if the range overlaps any exist range already in the
     * list */
    for (i = 0; i < targets->count; i++) {
        if (!range_is_overlap(targets->list[i], x))
            continue;

        /* If the removal-range wholly covers the range, delete
         * it completely */
        if (begin <= targets->list[i].begin && end >= targets->list[i].end) {
            rangelist_remove_at(targets, i);
            i--;
            continue;
        }

        /* If the removal-range bisects the target-rage, truncate
         * the lower end and add a new high-end */
        if (begin > targets->list[i].begin && end < targets->list[i].end) {
            struct Range newrange;

            newrange.begin = end+1;
            newrange.end = targets->list[i].end;


            targets->list[i].end = begin-1;

            rangelist_add_range(targets, newrange.begin, newrange.end);
            i--;
            continue;
        }

        /* If overlap on the lower side */
        if (end >= targets->list[i].begin && end < targets->list[i].end) {
            targets->list[i].begin = end+1;
        }

        /* If overlap on the upper side */
        if (begin > targets->list[i].begin && begin <= targets->list[i].end) {
             targets->list[i].end = begin-1;
        }

        //assert(!"impossible");
    }
}

static void
rangelist_add_range2(struct RangeList *targets, struct Range range)
{
    rangelist_add_range(targets, range.begin, range.end);
}
static void
rangelist_remove_range2(struct RangeList *targets, struct Range range)
{
    rangelist_remove_range(targets, range.begin, range.end);
}


/***************************************************************************
 * Parse an IPv4 address from a line of text, moving the offset forward
 * to the first non-IPv4 character
 ***************************************************************************/
static int
parse_ipv4(const char *line, unsigned *inout_offset, unsigned max, unsigned *ipv4)
{
    unsigned offset = *inout_offset;
    unsigned result = 0;
    unsigned i;

    for (i=0; i<4; i++) {
        unsigned x = 0;
        unsigned digits = 0;

        if (offset >= max)
            return -4;
        if (!isdigit(line[offset]&0xFF))
            return -1;

        /* clear leading zeros */
        while (offset < max && line[offset] == '0')
            offset++;

        /* parse maximum of 3 digits */
        while (offset < max && isdigit(line[offset]&0xFF)) {
            x = x * 10 + (line[offset] - '0');
            offset++;
            if (++digits > 3)
                return -2;
        }
        if (x > 255)
            return -5;
        result = result * 256 + (x & 0xFF);
        if (i == 3)
            break;

        if (line[offset] != '.')
            return -3;
        offset++; /* skip dot */
    }

    *inout_offset = offset;
    *ipv4 = result;

    return 0; /* parse ok */
}


/****************************************************************************
 * Parse from text an IPv4 address range. This can be in one of several
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
struct Range
range_parse_ipv4(const char *line, unsigned *inout_offset, unsigned max)
{
    unsigned offset;
    struct Range result;
    static const struct Range badrange = {0xFFFFFFFF, 0};
    int err;

    if (line == NULL)
        return badrange;

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
    err = parse_ipv4(line, &offset, max, &result.begin);
    if (err) {
        return badrange;
    }
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
        uint64_t prefix = 0;
        uint64_t mask = 0;
        unsigned digits = 0;

        /* skip slash */
        offset++;

        if (!isdigit(line[offset]&0xFF)) {
            return badrange;
        }

        /* strip leading zeroes */
        while (offset<max && line[offset] == '0')
            offset++;

        /* parse decimal integer */
        while (offset<max && isdigit(line[offset]&0xFF)) {
            prefix = prefix * 10 + (line[offset++] - '0');
            if (++digits > 2)
                return badrange;
        }
        if (prefix > 32)
            return badrange;

        /* Create the mask from the prefix */
        mask = 0xFFFFFFFF00000000ULL >> prefix;

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
        err = parse_ipv4(line, &offset, max, &ip);
        if (err)
            return badrange;
        if (ip < result.begin) {
            result.begin = 0xFFFFFFFF;
            result.end = 0x00000000;
            LOG(0, "err: ending addr %u.%u.%u.%u cannot come before starting addr %u.%u.%u.%u\n",
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
 * This is the old algorithm for applying exclude ranges, very slow
 * for large lists. We keep it around for verifying correctness of the
 * new replacement algorithm.
 ***************************************************************************/
static void
rangelist_exclude2(  struct RangeList *targets,
                  const struct RangeList *excludes)
{
    unsigned i;
    
    for (i=0; i<excludes->count; i++) {
        struct Range range = excludes->list[i];
        rangelist_remove_range(targets, range.begin, range.end);
    }
    
    /* Since chopping up large ranges can split ranges, this can
     * grow the list so we need to re-sort it */
    rangelist_sort(targets);

}

/**
 * Applies the (presumably overlapping) exclude range to the target. This can have
 * four outcomes:
 *  - there is no overlap, in which case 'target' is unchanged, and 'split'
 *    is set to INVALID.
 *  - the entire target is excluded, in which case it's set to INVALID.
 *  - the overlap is at the beginning, in which case the 'begin' is increased.
 *  - the overlap is at the end, in which case 'end' is reduced.
 *  - the overlap is in the middle, in which case the target is split
 *    in two, with 'target' becoming the low addresses, and 'split' becoming
 *    the high addresses.
 */
static void
range_apply_exclude(const struct Range exclude, struct Range *target, struct Range *split)
{
    /* Set 'split' to invalid to start with */
    split->begin = 2;
    split->end = 1;

    /* Case 1: no overlap */
    if (target->begin > exclude.end || target->end < exclude.begin) {
        return;
    }
    
    /* Case 2: complete overlap, mark target as invalid and return */
    if (target->begin >= exclude.begin && target->end <= exclude.end) {
        target->begin = 2;
        target->end = 1;
        return;
    }
    
    /* Case 3: overlap at start */
    if (target->begin >= exclude.begin && target->end > exclude.end) {
        target->begin = exclude.end + 1;
        return;
    }
    
    /* Case 4: overlap at end */
    if (target->begin < exclude.begin && target->end <= exclude.end) {
        target->end = exclude.begin - 1;
        return;
    }
    
    /* Case 5: this range needs to be split */
    if (target->begin < exclude.begin && target->end > exclude.end) {
        split->end = target->end;
        split->begin = exclude.end + 1;
        target->end = exclude.begin - 1;
        return;
    }
    
    /* No other condition should be possible */
    assert(!"possible");
}

/***************************************************************************
 ***************************************************************************/
int
range_is_valid(struct Range range)
{
    return range.begin <= range.end;
}

/***************************************************************************
 * Apply the exclude ranges, which means removing everything from "targets"
 * that's also in "exclude". This can make the target list even bigger
 * as individually excluded address chop up large ranges.
 ***************************************************************************/
void
rangelist_exclude(  struct RangeList *targets,
                  const struct RangeList *excludes)
{
    unsigned i;
    unsigned x;
    struct RangeList newlist = {0};
    
    /* Both lists must be sorted */
    rangelist_sort(targets);
    assert(excludes->is_sorted);
    
    /* Go through all target ranges, apply excludes to them
     * (which may split into two ranges), and add them to the
     * the new target list */
    x = 0;
    for (i=0; i<targets->count; i++) {
        struct Range range = targets->list[i];
        
        /* Move the exclude forward until we find a potentially
         * overlapping candidate */
        while (x < excludes->count && excludes->list[x].end < range.begin)
            x++;
        
        /* Keep applying excludes to this range as long as there are overlaps */
        while (x < excludes->count && excludes->list[x].begin <= range.end) {
            struct Range split = INVALID_RANGE;
            
            range_apply_exclude(excludes->list[x], &range, &split);
            
            /* If there is a split, then add the original range to our list
             * and then set that range to the splitted portion */
            if (range_is_valid(split)) {
                rangelist_add_range(&newlist, range.begin, range.end);
                memcpy(&range, &split, sizeof(range));
            }
            
            if (excludes->list[x].begin > range.end)
                break;
            
            x++;
        }
        
        /* If the range hasn't been completely excluded, then add the remnants */
        if (range_is_valid(range)) {
            rangelist_add_range(&newlist, range.begin, range.end);
        }
    }

    /* Now free the old list and move over the new list */
    free(targets->list);
    targets->list = newlist.list;
    targets->count = newlist.count;
    newlist.list = NULL;
    newlist.count = 0;
    
    /* Since chopping up large ranges can split ranges, this can
     * grow the list so we need to re-sort it */
    rangelist_sort(targets);
}


/***************************************************************************
 * Counts the total number of addresses in all the ranges combined.
 * For 0.0.0.0/0, this will be 0x100000000, which means we have to use a
 * larger number than 32-bit to return the result. This assumes that
 * all overlaps have been resolved in the list (i.e. it's been sorted).
 ***************************************************************************/
uint64_t
rangelist_count(const struct RangeList *targets)
{
    unsigned i;
    uint64_t result = 0;

    for (i=0; i<targets->count; i++) {
        result += (uint64_t)targets->list[i].end - (uint64_t)targets->list[i].begin + 1UL;
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
static unsigned
rangelist_pick_linearsearch(const struct RangeList *targets, uint64_t index)
{
    unsigned i;

    for (i=0; i<targets->count; i++) {
        uint64_t range = (uint64_t)targets->list[i].end - (uint64_t)targets->list[i].begin + 1UL;
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
unsigned
rangelist_pick(const struct RangeList *targets, uint64_t index)
{
    unsigned maxmax = targets->count;
    unsigned min = 0;
    unsigned max = targets->count;
    unsigned mid;
    const unsigned *picker = targets->picker;

    if (!targets->is_sorted)
        rangelist_sort((struct RangeList *)targets);
    assert(targets->is_sorted);

    if (picker == NULL) {
        /* optimization wasn't done */
        return rangelist_pick_linearsearch(targets, index);
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

    return (unsigned)(targets->list[mid].begin + (index - picker[mid]));
}


/***************************************************************************
 * The normal "pick" function is a linear search, which is slow when there
 * are a lot of ranges. Therefore, the "pick2" creates sort of binary
 * search that'll be a lot faster. We choose "binary search" because
 * it's the most cache-efficient, having the least overhead to fit within
 * the cache.
 ***************************************************************************/
void
rangelist_optimize(struct RangeList *targets)
{
    unsigned *picker;
    unsigned i;
    unsigned total = 0;
    unsigned bit_count = 0;
    size_t count = targets->count;

    if (!targets->is_sorted)
        rangelist_sort(targets);

    if (targets->picker)
        free(targets->picker);

    picker = REALLOCARRAY(NULL, targets->count, sizeof(*picker));

    for (i=0; i<targets->count; i++) {
        picker[i] = total;
        total += targets->list[i].end - targets->list[i].begin + 1;
    }
    targets->picker = picker;


    for (;;) {
        count >>= 1;
        bit_count++;
        if (count == 0)
            break;
    }

    targets->picker_mask = (1 << bit_count) - 1;

    
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
        unsigned begin = 0;
        unsigned end;
        struct RangeList targets[1] = {{0}};
        struct RangeList duplicate[1] = {{0}};
        unsigned range;


        /* Create a new target list */
        memset(targets, 0, sizeof(targets[0]));

        /* fill the target list with random ranges */
        num_targets = r_rand(&seed)%5 + 1;
        for (j=0; j<num_targets; j++) {
            begin += r_rand(&seed)%10;
            end = begin + r_rand(&seed)%10;

            rangelist_add_range(targets, begin, end);
        }
        rangelist_sort(targets);
        range = (unsigned)rangelist_count(targets);

        /* Optimize for faster 'picking' addresses from an index */
        rangelist_optimize(targets);

        /* Duplicate the targetlist using the picker */
        memset(duplicate, 0, sizeof(duplicate[0]));
        for (j=0; j<range; j++) {
            unsigned x;

            x = rangelist_pick(targets, j);
            rangelist_add_range(duplicate, x, x);
        }
        rangelist_sort(duplicate);

        /* at this point, the two range lists shouild be identical */
        REGRESS(targets->count == duplicate->count);
        REGRESS(memcmp(targets->list, duplicate->list, targets->count*sizeof(targets->list[0])) == 0);

        rangelist_remove_all(targets);
        rangelist_remove_all(duplicate);
    }

    return 0;
}


/***************************************************************************
 * This returns a character pointer where parsing ends so that it can
 * handle multiple stuff on the same line
 ***************************************************************************/
const char *
rangelist_parse_ports(struct RangeList *ports, const char *string, unsigned *is_error, unsigned proto_offset)
{
    char *p = (char*)string;
    
    *is_error = 0;
    while (*p) {
        unsigned port;
        unsigned end;

        /* skip whitespace */
        while (*p && isspace(*p & 0xFF))
            p++;

        /* end at comment */
        if (*p == 0 || *p == '#')
            break;

        /* special processing. Nmap allows ports to be prefixed with a
         * characters to clarify TCP, UDP, or SCTP */
        if (isalpha(*p&0xFF) && p[1] == ':') {
            switch (*p) {
                case 'T': case 't':
                    proto_offset = 0;
                    break;
                case 'U': case 'u':
                    proto_offset = Templ_UDP;
                    break;
                case 'S': case 's':
                    proto_offset = Templ_SCTP;
                    break;
                case 'O': case 'o':
                    proto_offset = Templ_Oproto_first;
                    break;
                case 'I': case 'i':
                    proto_offset = Templ_ICMP_echo;
                    break;
                default:
                    LOG(0, "bad port charactern = %c\n", p[0]);
                    *is_error = 1;
                    return p;
            }
            p += 2;
        }

        if (!isdigit(p[0] & 0xFF))
            break;

        port = (unsigned)strtoul(p, &p, 0);
        end = port;
        if (*p == '-') {
            p++;
            end = (unsigned)strtoul(p, &p, 0);
        }

        if (port > 0xFF && proto_offset == Templ_Oproto_first) {
            LOG(0, "bad ports: %u-%u\n", port, end);
            *is_error = 2;
            return p;
        } else if (port > 0xFFFF || end > 0xFFFF || end < port) {
            LOG(0, "bad ports: %u-%u\n", port, end);
            *is_error = 2;
            return p;
        } else {
            rangelist_add_range(ports, port+proto_offset, end+proto_offset);
        }
        if (*p == ',')
            p++;
        else
            break;
    }

    return p;
}

/***************************************************************************
 * Deterministic random number generator for repeatable tests.
 ***************************************************************************/
static unsigned
lcgrand(unsigned *state)
{
    *state = 1103515245 * (*state) + 12345;
    return *state;
}

/***************************************************************************
 * Create an exact duplicate range.
 ***************************************************************************/
static void
rangelist_copy(struct RangeList *dst, const struct RangeList *src)
{
    free(dst->list);
    free(dst->picker);
    memset(dst, 0, sizeof(*dst));
    dst->list = CALLOC(src->count, sizeof(src->list[0]));
    memcpy(dst->list, src->list, src->count * sizeof(src->list[0]));
    dst->count = src->count;
    dst->max = dst->count;
    dst->is_sorted = src->is_sorted;
}

/***************************************************************************
 * Test if two ranges are exact duplicates
 * @return true if equal, false if not equal
 ***************************************************************************/
static bool
rangelist_is_equal(const struct RangeList *lhs, const struct RangeList *rhs)
{
    unsigned i;
    
    if (lhs->count != rhs->count)
        return false;
    for (i=0; i<lhs->count; i++) {
        if (lhs->list[i].begin != rhs->list[i].begin) {
            return false;
        }
        if (lhs->list[i].end != rhs->list[i].end) {
            return false;
        }
    }
    
    return true;
}

/***************************************************************************
 * The old way of excuding addresses assume unsorted lists, so had to
 * search the entire exclude list for each included address, which is
 * O(n * m), and fails when we have millions of excludes and includes,
 * because it takes forever to apply.
 * This was revamped with a new version that sorts both lists first,
 * the applies the excludes sequentially in an O(n + m) operation.
 * This selftest simply creates random lists and runs the new code
 * against the old code, and make sure the results match.
 ***************************************************************************/
static int
exclude_selftest(void)
{
    unsigned seed = 0;
    struct RangeList includes1 = {0};
    struct RangeList includes2 = {0};
    struct RangeList excludes = {0};
    unsigned addr = 0;
    size_t i;
    
    /* In my initial tests, simply using 10 as the count seems to
     * catch all the combinations. On the other hand, 100,000 takes
     * a long time to complete, because it's O(n2) quadratic time.
     * Therefore, I pick a thousand as a compromise, likely to catch
     * any possibility, yet fast enough to complete quickly even on
     * a Raspberry Pi */
    static const unsigned MAXCOUNT = 1000;
    
    /* Fill the include list. This is designed to make short ranges
     * that are a short distance apart. We'll do the same for the
     * same for the excludes, using a different random seed. This
     * should create two lists that have lots and lots of overlapping
     * and non-overlapping ranges.
     */
    seed = 0;
    addr = 0;
    for (i=0; i<MAXCOUNT; i++) {
        unsigned begin;
        unsigned end;
        
        addr += lcgrand(&seed) & 0xF;
        begin = addr;
        addr += lcgrand(&seed) & 0xF;
        end = addr;
        
        rangelist_add_range(&includes1, begin, end);
    }
    rangelist_sort(&includes1);
    
    /* Fill the exlcude list, using the same algorithm as above for
     * includes, but now with a different seed. This creates lots of
     * conflicts. */
    seed = 1;
    addr = 0;
    for (i=0; i<MAXCOUNT; i++) {
        unsigned begin;
        unsigned end;
        
        addr += lcgrand(&seed) & 0xF;
        begin = addr;
        addr += lcgrand(&seed) & 0xF;
        end = addr;
        
        rangelist_add_range(&excludes, begin, end);
    }
    rangelist_sort(&excludes);
    
    /* Now create a copy of the include list, because we want to
     * apply excludes using two different algorithms to see if the
     * results match */
    rangelist_copy(&includes2, &includes1);
    if (!rangelist_is_equal(&includes1, &includes2))
        return 1;

    
    /* Now apply the exclude alogirthms, both new and old, to the
     * the include lists. */
    rangelist_exclude(&includes1, &excludes);
    rangelist_exclude2(&includes2, &excludes);
    if (!rangelist_is_equal(&includes1, &includes2))
        return 1; /* fail */
    
    /* If we reach this point, the selftest has succeeded */
    return 0;

}

/***************************************************************************
 * Called during "make test" to run a regression test over this module.
 ***************************************************************************/
int
ranges_selftest(void)
{
    struct Range r;
    struct RangeList targets[1] = {{0}};

    REGRESS(regress_pick2() == 0);

    /* Do a spearate test of the 'exclude' feature */
    if (exclude_selftest())
        return 1;
    
    memset(targets, 0, sizeof(targets[0]));
#define ERROR() LOG(0, "selftest: failed %s:%u\n", __FILE__, __LINE__);

    /* test for the /0 CIDR block, since we'll be using that a lot to scan the entire
     * Internet */
    r = range_parse_ipv4("0.0.0.0/0", 0, 0);
    REGRESS(r.begin == 0 && r.end == 0xFFFFFFFF);

    r = range_parse_ipv4("0.0.0./0", 0, 0);
    REGRESS(r.begin > r.end);

    r = range_parse_ipv4("75.748.86.91", 0, 0);
    REGRESS(r.begin > r.end);

    r = range_parse_ipv4("23.75.345.200", 0, 0);
    REGRESS(r.begin > r.end);

    r = range_parse_ipv4("192.1083.0.1", 0, 0);
    REGRESS(r.begin > r.end);

    r = range_parse_ipv4("192.168.1.3", 0, 0);
    if (r.begin != 0xc0a80103 || r.end != 0xc0a80103) {
        LOG(0, "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }

    r = range_parse_ipv4("10.0.0.20-10.0.0.30", 0, 0);
    if (r.begin != 0x0A000000+20 || r.end != 0x0A000000+30) {
        LOG(0,  "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }

    r = range_parse_ipv4("10.0.1.2/16", 0, 0);
    if (r.begin != 0x0A000000 || r.end != 0x0A00FFFF) {
        LOG(0, "r.begin = 0x%08x r.end = 0x%08x\n", r.begin, r.end);
        ERROR();
        return 1;
    }


    rangelist_add_range2(targets, range_parse_ipv4("10.0.0.0/24", 0, 0));
    rangelist_add_range2(targets, range_parse_ipv4("10.0.1.10-10.0.1.19", 0, 0));
    rangelist_add_range2(targets, range_parse_ipv4("10.0.1.20-10.0.1.30", 0, 0));
    rangelist_add_range2(targets, range_parse_ipv4("10.0.0.0-10.0.1.12", 0, 0));
    rangelist_sort(targets);

    if (targets->count != 1) {
        LOG(0, "count = %u\n", targets->count);
        ERROR();
        return 1;
    }
    if (targets->list[0].begin != 0x0a000000 || targets->list[0].end != 0x0a000100+30) {
        LOG(0, "r.begin = 0x%08x r.end = 0x%08x\n", targets->list[0].begin, targets->list[0].end);
        ERROR();
        return 1;
    }

    rangelist_remove_all(targets);

    /*
     * Test removal
     */
    memset(targets, 0, sizeof(targets[0]));

    rangelist_add_range2(targets, range_parse_ipv4("10.0.0.0/8", 0, 0));
    rangelist_sort(targets);

    /* These removals shouldn't change anything */
    rangelist_remove_range2(targets, range_parse_ipv4("9.255.255.255", 0, 0));
    rangelist_remove_range2(targets, range_parse_ipv4("11.0.0.0/16", 0, 0));
    rangelist_remove_range2(targets, range_parse_ipv4("192.168.0.0/16", 0, 0));
    rangelist_sort(targets);

    if (targets->count != 1
        || targets->list->begin != 0x0a000000
        || targets->list->end != 0x0aFFFFFF) {
        ERROR();
        return 1;
    }

    /* These removals should remove a bit from the edges */
    rangelist_remove_range2(targets, range_parse_ipv4("1.0.0.0-10.0.0.0", 0, 0));
    rangelist_remove_range2(targets, range_parse_ipv4("10.255.255.255-11.0.0.0", 0, 0));
    rangelist_sort(targets);
    if (targets->count != 1
        || targets->list->begin != 0x0a000001
        || targets->list->end != 0x0aFFFFFE) {
        ERROR();
        return 1;
    }


    /* remove things from the middle */
    rangelist_remove_range2(targets, range_parse_ipv4("10.10.0.0/16", 0, 0));
    rangelist_remove_range2(targets, range_parse_ipv4("10.20.0.0/16", 0, 0));
    rangelist_sort(targets);
    if (targets->count != 3) {
        ERROR();
        return 1;
    }

    rangelist_remove_range2(targets, range_parse_ipv4("10.12.0.0/16", 0, 0));
    rangelist_sort(targets);
    if (targets->count != 4) {
        ERROR();
        return 1;
    }

    rangelist_remove_range2(targets, range_parse_ipv4("10.10.10.10-10.12.12.12", 0, 0));
    rangelist_sort(targets);
    if (targets->count != 3) {
        ERROR();
        return 1;
    }
    rangelist_remove_all(targets);

    /* test ports */
    {
        unsigned is_error = 0;
        memset(targets, 0, sizeof(targets[0]));

        rangelist_parse_ports(targets, "80,1000-2000,1234,4444", &is_error, 0);
        rangelist_sort(targets);
        if (targets->count != 3 || is_error) {
            ERROR();
            return 1;
        }

        if (targets->list[0].begin != 80 || targets->list[0].end != 80 ||
            targets->list[1].begin != 1000 || targets->list[1].end != 2000 ||
            targets->list[2].begin != 4444 || targets->list[2].end != 4444) {
            ERROR();
            return 1;
        }
    }

    return 0;
}
