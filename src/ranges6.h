/*
    List of IPv6 ranges.

    Sames as the "ranges.h" module, but for IPv6 instead of IPv4.
*/
#ifndef RANGES6_H
#define RANGES6_H
#include <stdio.h>
#include <stdint.h>

typedef struct {uint64_t hi; uint64_t lo;} ipv6address;

/**
 * A range of IPv6 ranges.
 * Inclusive, so [n..m] includes both 'n' and 'm'.
 */
struct Range6
{
    ipv6address begin;
    ipv6address end; 
};

/**
 * An array of ranges in sorted order
 */
struct Range6List
{
    struct Range6 *list;
    size_t count;
    size_t max;
    uint64_t *picker;
};

/**
 * Adds the given range to the targets list. The given range can be a duplicate
 * or overlap with an existing range, which will get combined with existing
 * ranges. 
 * @param targets
 *      A list of IPv6 ranges.
 * @param begin
 *      The first address of the range that'll be added.
 * @param end
 *      The last address (inclusive) of the range that'll be added.
 */
void
range6list_add_range(struct Range6List *targets, const ipv6address begin, const ipv6address end);

/**
 * Removes the given range from the target list. The input range doesn't
 * have to exist, or can partial overlap with existing ranges.
 * @param targets
 *      A list of IPv6 ranges.
 * @param begin
 *      The first address of the range that'll be removed.
 * @param end
 *      The last address of the range that'll be removed (inclusive).
 */
void
range6list_remove_range(struct Range6List *targets, const ipv6address begin, const ipv6address end);

/**
 * Same as 'rangelist_remove_range()', except the input is a range
 * structure instead of a start/stop numbers.
 */
void
range6list_remove_range2(struct Range6List *targets, struct Range6 range);

/**
 * Returns 'true' if the indicated IPv6 address is in one of the target
 * ranges.
 * @param targets
 *      A list of IPv6 ranges
 * @param ip
 *      An IPv6 address that might in be in the list of ranges
 * @return 
 *      'true' if the ranges contain the item, or 'false' otherwise
 */
int
range6list_is_contains(const struct Range6List *targets, const ipv6address ip);


/**
 * Parses IPv6 addresses out of a string. A number of formats are allowed,
 * either an individual IPv6 address, a CIDR spec, or a start/stop address.
 * @param line
 *      A line of text, probably read from a configuration file, or a string
 *      probably input from the command line. It doesn't need to be nul
 *      terminated.
 * @param inout_offset
 *      The offset into the line were we are parsing. This integer will be
 *      be incremented by the number of bytes we've parsed from the string.
 * @param max
 *      The length of the line, in other words, the max value of inout_offset.
 */
struct Range6 
range6_parse(const char *line, unsigned *inout_offset, unsigned max);


/**
 * Remove things from the target list. The primary use of this is the
 * "exclude-file" containing a list of IP addresses that we should
 * not scan
 * @param targets
 *      Our array of target IP address (or port) ranges that we'll be
 *      scanning.
 * @param excludes
 *      A list, probably read in from --excludefile, of things that we
 *      should not be scanning, that will override anything we otherwise
 *      try to scan.
 * @return
 *      the total number of IP addresses or ports removed.
 */
uint64_t
range6list_exclude( struct Range6List *targets,
                    const struct Range6List *excludes);


/**
 * Counts the total number of IPv6 addresses in the target list. This
 * iterates over all the ranges in the table, summing up the count within
 * each range.
 * @param targets
 *      A list of IP address or port ranges.
 * @return
 *      The total number of address or ports.
 */
uint64_t
range6list_count(const struct Range6List *targets);

/**
 * Given an index in a continous range of [0...count], pick a corresponding
 * number (IP address or port) from a list of non-continuous ranges (not
 * necessarily starting from 0). In other words, given the two ranges
 *    10-19 50-69
 * we'll have a total of 30 possible numbers. Thus, the index goes from
 * [0..29], with the values 0..9 picking the corresponding values from the
 * first range, and the values 10..29 picking the corresponding values
 * from the second range.
 *
 * NOTE: This is a fundamental part of this program's design, that the user
 * can specify non-contiguous IP and port ranges, but yet we iterate over
 * them using a monotonicly increasing index variable.
 *
 * @param targets
 *      A list of IP address ranges, or a list of port ranges (one or the
 *      other, but not both).
 * @param index
 *      An integer starting at 0 up to (but not including) the value returned
 *      by 'rangelist_count()' for this target list.
 * @return
 *      an IP address or port corresponding to this index.
 */
ipv6address
range6list_pick(const struct Range6List *targets, uint64_t index);



/**
 * Remove all the ranges in the range list.
 */
void
range6list_remove_all(struct Range6List *list);

/**
 * Merge two range lists
 */
void
range6list_merge(struct Range6List *list1, const struct Range6List *list2);


/**
 * Optimizes the target list, so that when we call "rangelist_pick()"
 * from an index, it runs faster. It currently configures this for 
 * a binary-search, though in the future some more efficient
 * algorithm may be chosen.
 */
void
range6list_optimize(struct Range6List *targets);

/**
 * Does a regression test of this module
 * @return
 *      0 if the regression test succeeds, or a positive value on failure
 */
int
ranges6_selftest(void);


#endif
