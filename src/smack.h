#ifndef _SMACK_H
#define _SMACK_H
#include <stdio.h>

#define SMACK_NOT_FOUND ((size_t)(~0))

/**
 * "Anchor" flags are specified only for patterns that must
 * match at the start of input, at the end, or both.
 * These are equivalent to the regex specifiers "^" and "$"
 * respectively.
 */
enum {
    SMACK_ANCHOR_BEGIN  = 0x01,
    SMACK_ANCHOR_END    = 0x02,
    SMACK_SNMP_HACK     = 0x04,
    SMACK_WILDCARDS     = 0x08,
};

enum {
    SMACK_CASE_SENSITIVE = 0,
    SMACK_CASE_INSENSITIVE = 1,
};


/**
 * This is the function that will be called whenever SMACK
 * finds a pattern.
 */
typedef int (*FOUND_CALLBACK)(size_t id, int offset, void *data);


/**
 * Create the Aho-Corasick search object. After creation, you can start
 * adding patterns, but you cannot use it for searching until you've
 * compiled the patterns.
 */
struct SMACK *
smack_create(const char *name, unsigned nocase);


/**
 * Cleans up and frees an object created with smack_create().
 */
void
smack_destroy(struct SMACK *smack);


/**
 * Registers a pattern with the search engine. The 'smack' object
 * must have been created with 'smack_create()', but you must not
 * have yet called 'smack_compile()' to compile the patterns. The
 * "id" field can contain a pointer (size_t is 64-bit on 64-bit
 * systems).
 */
void
smack_add_pattern(        struct SMACK *  smack,
                        const void *    pattern,
                        unsigned        pattern_length,
                        size_t          id,
                        unsigned        flags);

/**
 * You call this function after you have registered all the patterns
 * using 'smack_add_pattern()' in order to compile the state-machine.
 * Don't use the state-machine with 'smack_search()' until you have
 * compiled all the patterns with this function.
 */
void
smack_compile(struct SMACK *smack);


/**
 * Run the state-machine, searching for the compiled patterns within
 * a block of data/text. This can only be called after "smack_compile()"
 * has created the state-machine.
 *
 * If the input is fragmented, this function can be called repeatedly
 * for each fragment. Patterns that cross fragments will still be
 * detected.
 *
 * The caller must initialize "*state" to zero "0" before running this
 * function on the first fragment, but must thereafter leave it
 * unchanged between fragments. (If the caller resets the *state variable
 * to zero between each fragment, then patterns that cross fragment
 * boundaries cannot be detected).
 */
unsigned
smack_search(           struct SMACK *  smack,
                        const void *    px,
                        unsigned        length,
                        FOUND_CALLBACK  cb_found,
                        void *          cb_data,
                        unsigned *      state);

size_t
smack_search_next(      struct SMACK *  smack,
                        unsigned *      state,
                        const void *    px,
                        unsigned *       offset,
                        unsigned        length
                        );

/**
 * If there are multiple matches at the current state, returns the next
 * one. Otherwise, returns NOT_FOUND. Used with "smack_search_next()".
 */
size_t
smack_next_match(      struct SMACK *  smack,
                        unsigned *      state);

/**
 * Call this after search is done. This is not generally necessary.
 * It's only purpose is to detect patterns that have the
 * SMACK_ANCHOR_END flag set. If no pattern has that flag, then
 * this function will do nothing.
 */
unsigned
smack_search_end(       struct SMACK *  smack,
                        FOUND_CALLBACK  cb_found,
                        void *          cb_data,
                        unsigned *      state);



/**
 * Runs a regression test on the module to make sure it's compiled
 * correctly for the current platform.
 *
 * @return
 *      zero if regression test succeeds, non-zero on failure
 */
int
smack_selftest(void);

int
smack_benchmark(void);

#endif /*_SMACK_H*/
