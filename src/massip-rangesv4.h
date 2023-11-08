#ifndef RANGES_H
#define RANGES_H
#include <stdint.h>
#include <stdio.h>
#include "util-bool.h" /*<stdbool.h>*/

/**
 * A range of either IP addresses or ports
 */
struct Range
{
    unsigned begin;
    unsigned end; /* inclusive, so [n..m] includes both 'n' and 'm' */
};


/**
 * Find the first CIDR range (one that can be specified with a /prefix)
 * inside the current range. If the current range can already be
 * specified with a CIDR /prefix, then the entire range is returned.
 * Examples:
 *  [10.0.0.0->10.0.0.255] returns [10.0.0.0->10.0.0.255] (no change)
 *  [10.0.0.1->10.0.0.255] returns [10.0.0.1->10.0.0.1]
 *  [10.0.0.2->10.0.0.255] returns [10.0.0.2->10.0.0.3]
 *  [10.0.0.4->10.0.0.255] returns [10.0.0.4->10.0.0.7]
 *  [10.0.0.248->10.0.0.254] returns [10.0.0.248->10.0.0.251]
 *  [10.0.0.252->10.0.0.254] returns [10.0.0.252->10.0.0.253]
 *  [10.0.0.254->10.0.0.254] returns [10.0.0.254->10.0.0.254]
 *  @param range
 *      A range specified by a starting IPv4 address and an ending
 *      IPv4 address, like [10.0.0.4->10.0.0.255].
 *  @param prefix_length
 *      An out-only parameter that receives the CIDR prefix length
 *      (number of bits) of the resulting range. This parameter is
 *      optional (may be NULL).
 *  @return the smaller range, and the number of prefix bits in the range.
 */
struct Range
range_first_cidr(const struct Range range, unsigned *prefix_length /*out*/);

/**
 * Test if the range can instead be expressed using a CIDR /prefix.
 * In other words, [10.0.0.0-10.0.0.255] can be expressed as [10.0.0.0/24].
 * @param range to be tested
 * @param prefix_length receivesoutput of the number of prefix bits if
 *  successful, otherwise set to 0xFFFFFFFF. This is optional, may
 *  be NULL and receive no output.
 * @return True if the range can be expressed in CIDR notation, in
 *  which case `prefix_length` is set to the number of bits in the prefix
 *  for printing in that notation. False otherwise, in which case
 *  `prefix_length` is set to 0xFFFFFFFF (an invalid value).
 */
bool range_is_cidr(const struct Range range, unsigned *prefix_length /*out*/);




/**
 * An array of ranges in sorted order
 */
struct RangeList
{
    struct Range *list;
    unsigned count;
    unsigned max;
    unsigned *picker;
    unsigned is_sorted:1;
};

/**
 * Adds the given range to the task list. The given range can be a duplicate
 * or overlap with an existing range, which will get combined with existing
 * ranges. 
 * @param task
 *      A list of ranges of either IPv4 addresses or port numbers.
 * @param begin
 *      The first address of the range that'll be added.
 * @param end
 *      The last address (inclusive) of the range that'll be added.
 */
void
rangelist_add_range(struct RangeList *task, unsigned begin, unsigned end);

void
rangelist_add_range_tcp(struct RangeList *targets, unsigned begin, unsigned end);
void
rangelist_add_range_udp(struct RangeList *targets, unsigned begin, unsigned end);


/**
 * Returns 'true' is the indicated port or IP address is in one of the task
 * ranges.
 * @param task
 *      A list of ranges of either IPv4 addresses or port numbers.
 * @param number
 *      Either an IPv4 address or a TCP/UDP port number.
 * @return 
 *      'true' if the ranges contain the item, or 'false' otherwise
 */
int
rangelist_is_contains(const struct RangeList *task, unsigned number);


/**
 * Returns 'true' if the indicate range is valid, which is simple the
 * fact that 'begin' comes before 'end'. We mark invalid ranges
 * by putting 'begin' after the 'end'
 */
int
range_is_valid(struct Range range);

/**
 * Parses IPv4 addresses out of a string. A number of formats are allowed,
 * either an individual IPv4 address, a CIDR spec, or a start/stop address.
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
struct Range 
range_parse_ipv4(const char *line, unsigned *inout_offset, unsigned max);


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
 */
void
rangelist_exclude(  struct RangeList *targets,
                    struct RangeList *excludes);


/**
 * Counts the total number of IP addresses or ports in the target list. This
 * iterates over all the ranges in the table, summing up the count within
 * each range.
 * @param targets
 *      A list of IP address or port ranges.
 * @return
 *      The total number of address or ports.
 */
uint64_t
rangelist_count(const struct RangeList *targets);

/**
 * Given an index in a continuous range of [0...count], pick a corresponding
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
 * them using a monotonically increasing index variable.
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
unsigned
rangelist_pick(const struct RangeList *targets, uint64_t i);


/**
 * Given a string like "80,8080,20-25,U:161", parse it into a structure
 * containing a list of port ranges.
 *
 * @param ports
 *      The array of port ranges that's produced by this parsing function.
 *      This structure will be used by the transmit thread when sending
 *      probes to a target IP address.
 * @param string
 *      A string from either the command-line or configuration file
 *      in the nmap "ports" format.
 * @param is_error
 *      Set to zero is no error occurred while parsing the string, or
 *      set to a non-zero value if an error was found.
 * @return
 *      the pointer in the string where the parsing ended, so that additional
 *      things can be contained in the string, such as comments
 */
const char *
rangelist_parse_ports(  struct RangeList *ports,
                        const char *string,
                        unsigned *is_error,
                        unsigned proto_offset
                      );


/**
 * Remove all the ranges in the range list.
 */
void
rangelist_remove_all(struct RangeList *list);

/**
 * Merge two range lists
 */
void
rangelist_merge(struct RangeList *list1, const struct RangeList *list2);


/**
 * Optimizes the target list, so that when we call "rangelist_pick()"
 * from an index, it runs faster. It currently configures this for 
 * a binary-search, though in the future some more efficient
 * algorithm may be chosen.
 */
void
rangelist_optimize(struct RangeList *targets);


/**
 * Sorts the list of target. We maintain the list of targets in sorted
 * order internally even though we scan the targets in random order
 * externally.
 */
void
rangelist_sort(struct RangeList *targets);


/**
 * Does a regression test of this module
 * @return
 *      0 if the regression test succeeds, or a positive value on failure
 */
int
ranges_selftest(void);


#endif
