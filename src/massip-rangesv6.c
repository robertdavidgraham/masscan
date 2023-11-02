/*
    for tracking IP/port ranges
*/
#include "massip-rangesv6.h"
#include "massip-rangesv4.h"
#include "util-malloc.h"
#include "logger.h"
#include "massip.h"
#include "massip-parse.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUCKET_COUNT 16

#define REGRESS(i,x) if (!(x)) return (fprintf(stderr, "[-] %u: regression failed %s:%d\n", (unsigned)i, __FILE__, __LINE__)|1)
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#define EQUAL(x,y) ipv6address_is_equal(x,y)

static inline ipv6address
_int128_add(ipv6address x, ipv6address y)
{
  ipv6address result;
  result.lo = x.lo + y.lo;
  result.hi = x.hi + y.hi + (result.lo < x.lo);
  return result;
}

static inline ipv6address
_int128_subtract(ipv6address x, ipv6address y)
{
  ipv6address result;
  result.lo = x.lo - y.lo;
  result.hi = x.hi - y.hi - (result.lo > x.lo);
  return result;
}

static ipv6address 
_int128_add64(const ipv6address lhs, uint64_t rhs)
{
    ipv6address result = lhs;
    result.lo += rhs;
    if (result.lo < lhs.lo)
        result.hi++;
    return result;
}

static inline massint128_t
_int128_mult64(massint128_t lhs, uint64_t rhs)
{
    massint128_t result = {0,0};
    uint64_t x;
    uint64_t b;
    uint64_t a;
    
    /* low-order 32 */
    a = (rhs>>0) & 0xFFFFFFFFULL;
    b = (lhs.lo>>0) & 0xFFFFFFFFULL;
    x = (a * b);
    result.lo += x;
    
    b = (lhs.lo>>32ULL) & 0xFFFFFFFFULL;
    x =  (a * b);
    result.lo += x<<32ULL;
    result.hi += x>>32ULL;

    b = lhs.hi;
    x = (a * b);
    result.hi += x;

    /* next 32 */
    a = (rhs>>32ULL) & 0xFFFFFFFFULL;
    b = (lhs.lo>>0ULL) & 0xFFFFFFFFULL;
    x = (a * b);
    result.lo += x<<32ULL;
    result.hi += (x>>32ULL) + (result.lo < (x<<32ULL));

    b = (lhs.lo>>32ULL) & 0xFFFFFFFFULL;
    x =  (a * b);
    result.hi += x;

    b = lhs.hi;
    x =  (a * b);
    result.hi += x<<32ULL;

    return result;
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
#define GREATEREQ(x,y) (!LESS(x,y))

static int
LESSEQ(const ipv6address lhs, const ipv6address rhs)
{
    if (lhs.hi < rhs.hi)
        return 1;
    if (lhs.hi > rhs.hi)
        return 0;
    
    if (lhs.lo <= rhs.lo)
        return 1;
    else
        return 0;
}

int range6_is_bad_address(const struct Range6 *range)
{
    return LESS(range->end, range->begin);
}

static int
_int128_is_equals(const ipv6address lhs, const ipv6address rhs)
{
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

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
massint128_t 
massip_range(struct MassIP *massip)
{
    massint128_t result;


    result = range6list_count(&massip->ipv6);
    result = _int128_add64(result, rangelist_count(&massip->ipv4));
    result = _int128_mult64(result, rangelist_count(&massip->ports));

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
    static const ipv6address FFFF = {~0ULL, ~0ULL};

    if (LESS(lhs.begin, rhs.begin)) {
        if (EQUAL(lhs.end, FFFF) || GREATEREQ(PLUS_ONE(lhs.end), rhs.begin))
            return 1;
    }
    if (GREATEREQ(lhs.begin, rhs.begin)) {
        if (LESSEQ(lhs.end, rhs.end))
            return 1;
    }

    if (LESS(rhs.begin, lhs.begin)) {
        if (EQUAL(rhs.end, FFFF) || GREATEREQ(PLUS_ONE(rhs.end), lhs.begin))
            return 1;
    }
    if (GREATEREQ(rhs.begin, lhs.begin)) {
        if (LESSEQ(rhs.end, lhs.end))
            return 1;
    }

    return 0;
#if 0
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
#endif
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
 * Callback for qsort() for comparing two ranges
 ***************************************************************************/
static int
range6_compare(const void *lhs, const void *rhs)
{
    struct Range6 *left = (struct Range6 *)lhs;
    struct Range6 *right = (struct Range6 *)rhs;

    if (ipv6address_is_equal(left->begin, right->begin))
        return 0;
    else if (LESS(left->begin, right->begin))
        return -1;
    else 
        return 1;
}


/***************************************************************************
 ***************************************************************************/
void
range6list_sort(struct Range6List *targets)
{
    size_t i;
    struct Range6List newlist = {0};
    size_t original_count = targets->count;

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
    LOG(3, "[+] range6:sort: sorting...\n");
    qsort(  targets->list,              /* the array to sort */
            targets->count,             /* number of elements to sort */
            sizeof(targets->list[0]),   /* size of element */
            range6_compare);
    
    
    /* Second, combine all overlapping ranges. We do this by simply creating
     * a new list from a sorted list, so we don't have to remove things in the
     * middle when collapsing overlapping entries together, which is painfully
     * slow. */
    LOG(3, "[+] range:sort: combining...\n");
    for (i=0; i<targets->count; i++) {
        range6list_add_range(&newlist, targets->list[i].begin, targets->list[i].end);
    }
    
    LOG(3, "[+] range:sort: combined from %u elements to %u elements\n", original_count, newlist.count);
    free(targets->list);
    targets->list = newlist.list;
    targets->count = newlist.count;
    newlist.list = 0;

    LOG(2, "[+] range:sort: done...\n");

    targets->is_sorted = 1;
}



void
range6list_add_range(struct Range6List *targets, ipv6address begin, ipv6address end)
{
    struct Range6 range;

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
    if (range6_is_overlap(targets->list[targets->count - 1], range)) {
        range6_combine(&targets->list[targets->count - 1], range);
        targets->is_sorted = 0;
        return;
    }

    /* append to the end of our list */
    targets->list[targets->count] = range;
    targets->count++;
    targets->is_sorted = 0;
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

void
range6list_remove_range2(struct Range6List *targets, struct Range6 range)
{
    range6list_remove_range(targets, range.begin, range.end);
}

/***************************************************************************
 ***************************************************************************/
ipv6address
range6list_exclude(  struct Range6List *targets,
                  const struct Range6List *excludes)
{
    ipv6address count = {0,0};
    unsigned i;
    
    for (i=0; i<excludes->count; i++) {
        struct Range6 range = excludes->list[i];
        ipv6address x;
        
        x = _int128_subtract(range.end, range.begin);
        x = _int128_add64(x, 1);

        count = _int128_add(count, x);
        range6list_remove_range(targets, range.begin, range.end);
    }
    
    return count;
}


/***************************************************************************
 ***************************************************************************/
massint128_t
range6list_count(const struct Range6List *targets)
{
    unsigned i;
    ipv6address result = {0,0};

    for (i=0; i<targets->count; i++) {
        ipv6address x;

        x = _int128_subtract(targets->list[i].end, targets->list[i].begin);
        if (x.hi == ~0ULL && x.lo == ~0ULL)
            return x; /* overflow */
        x = _int128_add64(x, 1);
        result = _int128_add(result, x);
    }

    return result;
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
    const size_t *picker = targets->picker;

    if (picker == NULL) {
        fprintf(stderr, "[-] ipv6 picker is null\n");
        exit(1);
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

    return _int128_add64(targets->list[mid].begin, (index - picker[mid]));
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
    size_t *picker;
    size_t i;
    ipv6address total = {0,0};

    if (targets->count == 0)
        return;

    /* This technique only works when the targets are in
     * ascending order */
    if (!targets->is_sorted)
        range6list_sort(targets);

    if (targets->picker)
        free(targets->picker);

    picker = REALLOCARRAY(NULL, targets->count, sizeof(*picker));

    for (i=0; i<targets->count; i++) {
        ipv6address x;
        picker[i] = total.lo;
        x = _int128_subtract(targets->list[i].end, targets->list[i].begin);
        x = _int128_add64(x, 1);
        total = _int128_add(total, x);
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
    */
    for (i=0; i<65536; i++)
    {
        ipv6address a;
        ipv6address b;
        ipv6address c;
        ipv6address d;

        a.hi = r_rand(&seed);
        a.lo = (unsigned long long)r_rand(&seed)<<49ULL;
        b.hi = r_rand(&seed);
        b.lo = 0x8765432100000000ULL;

        c = _int128_add(a, b);
        d = _int128_subtract(c, b);

        if (!_int128_is_equals(a, d)) {
            fprintf(stderr, "[-] %s:%d: test failed (%u)\n", __FILE__, __LINE__, (unsigned)i);
            return 1;
        }
    }

    /*
     * Run 100 randomized regression tests
     */
    for (i=3; i<100; i++) {
        unsigned j;
        unsigned num_targets;
        ipv6address begin = {0};
        ipv6address end = {0};
        struct Range6List targets[1];
        struct Range6List duplicate[1];
        uint64_t range;
        ipv6address x;

        seed = i;

        /* Create a new target list */
        memset(targets, 0, sizeof(targets[0]));

        /* fill the target list with random ranges */
        num_targets = r_rand(&seed)%5 + 1;
        for (j=0; j<num_targets; j++) {
            begin.lo += r_rand(&seed)%10;
            end.lo = begin.lo + r_rand(&seed)%10;

            range6list_add_range(targets, begin, end);
        }

        /* Optimize for faster 'picking' addresses from an index */
        range6list_optimize(targets);


        /* Duplicate the targetlist using the picker */
        memset(duplicate, 0, sizeof(duplicate[0]));
        x = range6list_count(targets);
        if (x.hi) {
            fprintf(stderr, "[-] range6: range too big\n");
            return 1;
        }
        range = x.lo;
        for (j=0; j<range; j++) {
            ipv6address addr;

            addr = range6list_pick(targets, j);
            range6list_add_range(duplicate, addr, addr);
        }

        /* at this point, the two range lists should be identical */
        REGRESS(i, targets->count == duplicate->count);
        REGRESS(i, memcmp(targets->list, duplicate->list, targets->count*sizeof(targets->list[0])) == 0);

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
    int err;

    REGRESS(0, regress_pick2() == 0);

    memset(targets, 0, sizeof(targets[0]));
#define ERROR() fprintf(stderr, "selftest: failed %s:%u\n", __FILE__, __LINE__);

    err = massip_parse_range("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 0, 0, 0, &r);
    if (err != Ipv6_Address)
        ERROR();
    
    /* test for the /0 CIDR block, since we'll be using that a lot to scan the entire
     * Internet */
    if (r.begin.hi != 0x20010db885a30000ULL)
        return 1;
    if (r.begin.lo != 0x00008a2e03707334ULL)
        return 1;

    return 0;
}

