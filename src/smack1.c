/****************************************************************************

          SMACK1 - an Aho-Corasick search engine

  This creates a state-machine out of patterns, like a DFA implementation
  of a regex. This can be used for intrusion-detection "signature" matching
  to search network traffic for a lot of signatures. This can also be used
  for protocol parsers, where fields are "matched" using a state-machine
  rather than buffered and compared. In other words, instead of extracting
  the "method" from HTTP and later comparing against GET, PUT, POST, etc.,
  we create an Aho-Corasick pattern matcher for those patterns, match all
  known ones, and otherwise generate an error for unknown methods.


  In addition to normal and nocase patterns, SMACK also supports "anchored"
  patterns. This is like the (^) and ($) symbols in regex patterns,
  although we use flags in this code when adding patterns.

  THE ALGORITHM

  The basic engine is TEXTBOOK "Aho-Corasic". I've used macros to capture
  the flavor of the textbook example pseudo-code. Therefore, you see code
  that looks like the following:

    while (queue_has_more_items(queue)) {
        r = dequeue(queue);
        for (a=0; a<ALPHABET_SIZE; a++) {
            if (GOTO(r,a) == FAIL)
                GOTO(r,a) = GOTO(GOTO_FAIL(r),a);
            else
                enqueue(queue, GOTO(r,a));
        }
    }

  You aren't supposed to understand the code so much that you are supposed
  to be able to confirm the code matches the textbook pseudo-code.


  COMPRESSION

  Bytes/characters in the patterns are converted to "symbols". This is done
  for two reasons.

  The first is for case-insensitive pattern-matches. Both upper and lower
  case letters in incoming bytes will map to the same symbol (both for
  patterns as well as the searched text).

  The second reason is to shrink the table size. Normally, rows would be
  256 elements wide. When only a few patterns are being matched, the table
  can be as small as 16-characters wide. Even when searching for a 100
  patterns, the table is still often only 64 elements wide.

  The row width is done as a power-of-2, which means widths of 2, 4, 8, 16,
  32, 64, 128, and 256. When doing the calculation table[row][column], we
  have to multiple the "row" index by row width. Because it's a power-of-2,
  we convert that into a shift for performance reasons.

  Ideally, we should do even more optimizations, like a shift-add, allowing
  half widths (3, 6, 24, 48, 96, 192) that would more closely match the
  table width to the number of characters. Maybe I'll get around to adding
  that.


  COMPILATION

  Once the patterns have been entered and compiled into a typical state
  machine, I've added one more compilation step. I create a block of
  memory that contains all the transitions.

  I then DISCARD all the original pattern information. The only memory
  used is that one block.

  This reflects how the fast-SMACK works, where the simple Aho-Corasick
  state tables are compiled into a complicated memory structure. In this
  case, the primary optimization is simply that row-transitions, being
  powers-of-2, are faster.

  However, the main reason I discard the original state is one of purity.
  Like compiling source into machine language, state-machines are supposed
  to be purely compiled states, with no reference to the original set of
  patterns that created them.


  16-BIT STATE

  While the engine compiles using 32-bit states, the last compilation
  step reduces this to 16-bits states. This can be trivially changed
  by redefining the type "transition_t".


  64-BIT COMPILATION

  The "id" that triggers for a pattern is declared as "size_t". This allows
  it to hold a pointer as well as an integer. On most 64-bit systems
  (Windows 7, Linux, Mac OS X), the 'size_t' will be a 64-bit value, while
  'unsigned' will be a 32-bit value. The 'unsigned short' type will still
  be 16-bits, which means the tables will still be small.


  TODO
  Make it so that the longest match triggers first.

 ****************************************************************************/
#include "smack.h"
#include "smackqueue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>


#ifndef NOBENCHMARK
#include "pixie-timer.h"
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <machine/cpufunc.h>
#define __rdtsc rdtsc
#if (__ARM_ARCH >= 6)  // V6 is the earliest arch that has a standard cyclecount
unsigned long long rdtsc(void)
{
  uint32_t pmccntr;
  uint32_t pmuseren;
  uint32_t pmcntenset;
  // Read the user mode perf monitor counter access permissions.
  asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r"(pmuseren));
  if (pmuseren & 1) {  // Allows reading perfmon counters for user mode code.
    asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r"(pmcntenset));
    if (pmcntenset & 0x80000000ul) {  // Is it counting?
      asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
      // The counter is set up to count every 64th cycle
      return (unsigned long long)(pmccntr) * 64ULL; 
    }
  }
  return 0;
}
#endif
#elif defined (__llvm__)
#if defined(i386) || defined(__i386__)
#include <x86intrin.h>
#else
#define __rdtsc() 0
#endif
#elif defined(__GNUC__) || defined(__llvm__)
static __inline__ unsigned long long __rdtsc(void)
{
#if defined(i386) || defined(__i386__)
    unsigned long hi = 0, lo = 0;
    __asm__ __volatile__ ("lfence\n\trdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
#else
    return 0;
#endif
}
#endif
#endif

/**
 * By default, the table holds only 64k states using 2-byte
 * integers. If you want more states, simply change this to
 * a 4-byte or 8-byte integer
 */
typedef unsigned short transition_t;


/**
 * These constants represent the anchor-start (^) and anchor-end ($) symbols.
 * Since we use all 256 combinations of a byte, these values are set to
 * 0x100 and 0x101, so they don't collide with bytes that might otherwise
 * be used
 */
enum {
    CHAR_ANCHOR_START=256,
    CHAR_ANCHOR_END=257,
};

/**
 * The alphabet consists of all combinations for a byte PLUS two special
 * symbols: the anchor-start (^) and anchor-end ($) symbol.
 */
#define ALPHABET_SIZE  (256+2)


/**
 * During the initial phases of compilation, the "FAIL" state points to
 * an impossible state. Later phases of compilation then figure out a
 * better fail state (one that shares many of the same trailing
 * characters of the current prefix).
 */
#define FAIL (unsigned)(-1)


static const unsigned BASE_STATE = 0;
static const unsigned UNANCHORED_STATE = 1;
#define GOTO(r, a)      smack->m_state_table[r].m_next_state[a]
#define GOTO_FAIL(r)   smack->m_state_table[r].m_fail_state



/**
 * This variable can be used to visualize transitions while debugging
 */
#ifdef _DEBUG
#define DEBUG
#endif
#ifdef DEBUG
unsigned print_transitions = 0;
#endif

/****************************************************************************
 ****************************************************************************/
struct SmackPattern
{
    /** The 'id' is what's reported back when the pattern matches.
     * This value can be either an integer, or a pointer to some
     * private data structure */
    size_t                    id;

    /** This holds a malloc-ed copy of the pattern the caller gave us.
     * If the engine is running "nocase", then this is converted to
     * lower case */
    unsigned char *          pattern;

    /** The number of characters in the pattern */
    unsigned                pattern_length;

    /** Whether this pattern is "anchored" (^) at the start of the
     * input. This means the pattern will only trigger when it's at the
     * very start, but not when it's in the middle */
    unsigned                is_anchor_begin:1;

    /** Whether this pattern is "anchored" ($) at the END of the
     * input. This means the pattern will only trigger when it's
     * the last characters of the input, and the caller also calls
     * "smack_search_end()" */
    unsigned                is_anchor_end:1;

    unsigned                is_snmp_hack:1;
    
    unsigned                is_wildcards:1;
};


/****************************************************************************
 * This is an INTERMEDIATE structure created and freed during compilation.
 * It holds the expanded state-table before it is compressed.
 ****************************************************************************/
struct SmackRow
{
    unsigned                m_next_state[ALPHABET_SIZE];
    unsigned                m_fail_state;
};


/****************************************************************************
 * This table indicates which states are matches. A state may have more than
 * one match. If we are debugging this, this table will also have a name
 * for the state, based on the pattern.
 ****************************************************************************/
struct SmackMatches {
    size_t *               m_ids;
    unsigned                m_count;

#ifdef DEBUG
    char *DEBUG_name;
#endif
};

/****************************************************************************
 * This is the master structure for the SMACK engine.
 ****************************************************************************/
struct SMACK {
    /**
     * Since a typical application may have multiple instances of this
     * structure for different pattern sets, we allow the application to
     * give a helpful name to this table
     */
    char *              name;

    /**
     * Whether or not this table is case-sensitive or case-insensitive
     */
    unsigned            is_nocase:1;

    /**
     * Whether one of the patterns contains an anchor (^) at the beginning
     * of the pattern. If so, we need to add a symbol in our symbol table
     * for the anchor.
     */
    unsigned            is_anchor_begin:1;


    /**
     * Whether one of the patterns contains an anchor ($) at the end
     * of the pattern. If so, we need to add a symbol in our symbol table
     * for the anchor.
     */
    unsigned            is_anchor_end:1;


    /**
     * Temporary pattern list. Patterns are added here at the beginning.
     * However, after the patterns have been compiled, this structure can
     * be freed.
     */
    struct SmackPattern **m_pattern_list;
    unsigned            m_pattern_count;
    unsigned            m_pattern_max;

    /**
     * Temporary place holder for DFA state transitions. After we
     * compress the table, this is thrown away */
    struct SmackRow *  m_state_table;
    unsigned            m_state_count;
    unsigned            m_state_max;
    struct SmackMatches *m_match;
    unsigned            m_match_limit;


    /**
     * The opposite of "char_to_symbol", this table takes a symbol and
     * converts it back to a  character. This can be useful in debugging,
     * but it's real purpose is just during compilation in order to
     * count the number of characters used in patterns, and consequently,
     * how wide 'rows' need to be. */
    unsigned            symbol_to_char[ALPHABET_SIZE];

    /**
     * The "symbol compression dictionary". As we parse incoming bytes,
     * they are first translated to a symbol. This is useful for two reasons.
     * The first reason is that this allows us to create "case-insensitive"
     * pattern-matches, where upper-case is converted to lower-case. The
     * second reason is that it allows us to compress the table. If only
     * 32 different characters are used in the patterns, then rows only
     * have to be 32 symbols wide, instead of 256 characters wide.
     */
    unsigned char       char_to_symbol[ALPHABET_SIZE];

    /**
     * The number different characters used in all the patterns we are
     * looking for. See "char_to_symbol" for more information.
     */
    unsigned            symbol_count;

    /**
     * This is the row width, log2. Rows are expanded to the nearest
     * power-of-2. Thus, if we have 26 different characters used in
     * patterns, then we'll use row sizes of 32 elements. This allows
     * use to optimize row lookups using the fast "shift" operation
     * rather than the slow "multiplication" operation.
     */
    unsigned            row_shift;

    /**
     * This is the final compressed table. It contains one row for each
     * sub-pattern, and each row is wide enough to hold all the symbols
     * (must be a power of two) */
    transition_t *       table;
};


/****************************************************************************
 * Given a row-width, figure out the nearest power-of-two (16,32,64,128,etc.)
 * that can hold that row. Return the number of bits needed to left-shift
 * in order to multiple by that number (shifts are faster than multiply).
 ****************************************************************************/
static unsigned
row_shift_from_symbol_count(unsigned symbol_count)
{
    unsigned row_shift = 1;

    symbol_count++;

    while ((unsigned)(1 << row_shift) < symbol_count)
        row_shift++;

    return row_shift;
}


/****************************************************************************
 * Creates this engine, use "smack_destroy()" to free all the resources
 ****************************************************************************/
struct SMACK *
smack_create(const char *name, unsigned nocase)
{
    struct SMACK *smack;

    smack = (struct SMACK *)malloc(sizeof (struct SMACK));
    if (smack == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memset (smack, 0, sizeof (struct SMACK));

    smack->is_nocase = nocase;
    smack->name = (char*)malloc(strlen(name)+1);
    if (smack->name == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memcpy(smack->name, name, strlen(name)+1);
    return smack;
}


/****************************************************************************
 ****************************************************************************/
static void
create_intermediate_table(struct SMACK *smack, unsigned size)
{
    struct SmackRow *x;

    x = (struct SmackRow *)malloc(sizeof(*x) * size);
    if (x == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memset(x, 0, sizeof(*x) * size);
    smack->m_state_table = x;
}

/****************************************************************************
 ****************************************************************************/
static void
destroy_intermediate_table(struct SMACK *smack)
{
    if (smack->m_state_table) {
        free(smack->m_state_table);
        smack->m_state_table = 0;
    }
}


/****************************************************************************
 ****************************************************************************/
static void
create_matches_table(struct SMACK *smack, unsigned size)
{
    struct SmackMatches *x;

    x = (struct SmackMatches *)malloc(sizeof(*x) * size);
    if (x == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memset(x, 0, sizeof(*x) * size);

    smack->m_match = x;
}

/****************************************************************************
 ****************************************************************************/
static void
destroy_matches_table(struct SMACK *smack)
{
    unsigned i;

    if (!smack->m_match)
        return;


    for (i=0; i<smack->m_state_count; i++) {
        struct SmackMatches *match;
        match = &smack->m_match[i];

        if (match->m_count) {
            free(match->m_ids);
        } else {
            assert(match->m_ids == NULL);
        }
#ifdef DEBUG
        if (match->DEBUG_name)
            free(match->DEBUG_name);
#endif
    }

    free(smack->m_match);
    smack->m_match = 0;
}


/****************************************************************************
 * Destroy the patterns that were registered by the caller. This will be
 * called during the compilation process to free the memory, since we no
 * longer need the original patterns during searching.
 ****************************************************************************/
static void
destroy_pattern_table(struct SMACK *smack)
{
    unsigned i;

    if (!smack->m_pattern_list)
        return;

    for (i=0; i<smack->m_pattern_count; i++) {
        struct SmackPattern *pat;
        pat = smack->m_pattern_list[i];
        free(pat->pattern);
        free(pat);
    }

    free(smack->m_pattern_list);
    smack->m_pattern_list = 0;
}


/****************************************************************************
 * Frees everything allocated by "smack_create()", and further allocated
 * during compilation.
 ****************************************************************************/
void
smack_destroy(struct SMACK *smack)
{
    destroy_intermediate_table(smack);
    destroy_matches_table(smack);
    destroy_pattern_table(smack);

    if (smack->table)
        free(smack->table);

    free(smack);
}

/****************************************************************************
 * In the function "smack_copy_matches()", this tests to see if the match
 * already exists in the old list, in which case it won't copy a duplicate
 * from the new list.
 ****************************************************************************/
static unsigned
id_already_exists(const size_t *ids, unsigned count, size_t new_id)
{
    unsigned i;

    for (i=0; i<count; i++) {
        if (ids[i] == new_id)
            return 1;
    }
    return 0;
}

/****************************************************************************
 * When combining two match lists (when two patterns overlap, like the
 * pattern "BERT" and "ROBERT"), we need to merge the two lists of matches.
 ****************************************************************************/
static void
smack_copy_matches(
    struct SmackMatches *row,
    const size_t *new_ids,
    unsigned new_count)
{
    size_t *total_ids;
    unsigned total_count;
    size_t *old_ids = row->m_ids;
    unsigned old_count = row->m_count;
    unsigned i;

    /* Allocate space for both lists */
    total_ids = (size_t *)malloc((old_count + new_count)*sizeof(*total_ids));
    if (total_ids == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }

    /* Copy existing matches */
    for (i=0; i<old_count; i++)
        total_ids[i] = old_ids[i];
    total_count = old_count;

    /* Copy new matches, if needed */
    for (i=0; i<new_count; i++) {
        if (!id_already_exists(old_ids, old_count, new_ids[i]))
            total_ids[total_count++] = new_ids[i];
    }

    /* Free the old list */
    if (row->m_ids) {
        free(row->m_ids);
    }

    /* Replace old list with total combined list */
    row->m_ids = total_ids;
    row->m_count = total_count;
}


/****************************************************************************
 * In order to compress the size of the table, and to do case-insensitive
 * pattern-matches, we convert characters into symbols. We need to create
 * a new symbol for different type of character in a pattern. Note that this
 * function will be called with the pseudo-characters representing anchors,
 * which have a value of 256 and 257.
 ****************************************************************************/
static unsigned
smack_add_symbol(struct SMACK *smack, unsigned c)
{
    unsigned i;
    unsigned symbol;

    /* See if we already know the symbol */
    for (i=1; i<=smack->symbol_count; i++) {
        if (smack->symbol_to_char[i] == c)
            return i;
    }

    /* Add the symbol to our list */
    smack->symbol_count++;
    symbol = smack->symbol_count;

    /* Map it in both directions */
    smack->symbol_to_char[symbol] = c;
    smack->char_to_symbol[c] = (unsigned char)symbol;

    return symbol;
}


/****************************************************************************
 * Add all the symbols in a pattern.
 ****************************************************************************/
static void
smack_add_symbols(struct SMACK *smack, const unsigned char *pattern, unsigned pattern_length)
{
    unsigned i;

    /* Add all the bytes in this pattern to the symbol table */
    for (i=0; i<pattern_length; i++) {
        if (smack->is_nocase)
            smack_add_symbol(smack, tolower(pattern[i]));
        else
            smack_add_symbol(smack, pattern[i]);
    }
}


/****************************************************************************
 * Make a copy of the pattern. We need to do this for two reasons. The first
 * is that the caller may immediately release th memory in the pattern
 * he gave us. Therefore, we have to allocate our own memory to hold it.
 * The second is if it's a case-insensitive pattern. In that case, we are
 * going to normalize it to all lower case.
 ****************************************************************************/
static unsigned char *
make_copy_of_pattern(   const unsigned char *pattern,
                        unsigned pattern_length,
                        unsigned is_nocase)
{
    unsigned char *result;

    /* allocate space */
    result = (unsigned char *)malloc(pattern_length+1);
    if (result == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }

    /* copy, removing case if necessary */
    if (is_nocase) {
        unsigned i;
        for (i=0; i<pattern_length; i++) {
            result[i] = (unsigned char)(tolower(pattern[i]));
        }
    } else
        memcpy(result, pattern, pattern_length);

    /* NUL terminate the string. This makes debugging easier when patterns
     * are text. However, the NUL terminator is never used by the program
     * to end the string -- we always use the length instead. */
    result[pattern_length] = '\0';

    return result;
}


/****************************************************************************
 * Called to register a pattern with SMACK.
 ****************************************************************************/
void
smack_add_pattern(
    struct SMACK *  smack,
    const void *    v_pattern,
    unsigned        pattern_length,
    size_t          id,
    unsigned        flags)
{
    const unsigned char *pattern = (const unsigned char*)v_pattern;
    struct SmackPattern *pat;


    /*
     * Create a pattern structure based on the input
     */
    pat = (struct SmackPattern *)malloc(sizeof (struct SmackPattern));
    if (pat == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    pat->pattern_length = pattern_length;
    pat->is_anchor_begin = ((flags & SMACK_ANCHOR_BEGIN) > 0);
    pat->is_anchor_end = ((flags & SMACK_ANCHOR_END) > 0);
    pat->is_snmp_hack = ((flags & SMACK_SNMP_HACK) > 0);
    pat->is_wildcards = ((flags & SMACK_WILDCARDS) > 0);
    pat->id = id;
    pat->pattern = make_copy_of_pattern(pattern, pattern_length, smack->is_nocase);
    if (pat->is_anchor_begin)
        smack->is_anchor_begin = 1;
    if (pat->is_anchor_end)
        smack->is_anchor_end = 1;


    /*
     * Register the symbols used in the pattern. Hopefully, not all 256
     * possible combinations will be used, allowing us to shrink the
     * size of the rows in the final table
     */
    smack_add_symbols(smack, pattern, pattern_length);
    if (pat->is_snmp_hack)
        smack_add_symbols(smack, (const unsigned char *)"\x80", 1);


    /*
     * Automatically expand the table in order to hold more patterns,
     * as the caller keeps adding more.
     */
    if (smack->m_pattern_count + 1 >= smack->m_pattern_max) {
        struct SmackPattern **new_list;
        unsigned new_max;

        new_max = smack->m_pattern_max * 2 + 1;
        new_list = (struct SmackPattern **)malloc(sizeof(*new_list)*new_max);
        if (new_list == NULL) {
            fprintf(stderr, "%s: out of memory error\n", "smack");
            exit(1);
        }

        if (smack->m_pattern_list) {
            memcpy(    new_list,
                    smack->m_pattern_list,
                    sizeof(*new_list) * smack->m_pattern_count);
            free(smack->m_pattern_list);
        }

        smack->m_pattern_list = new_list;
        smack->m_pattern_max = new_max;
    }


    /*
     * Put this pattern onto the end of our list
     */
    smack->m_pattern_list[smack->m_pattern_count] = pat;
    smack->m_pattern_count++;
}


/****************************************************************************
 ****************************************************************************/
#ifdef DEBUG
static void
DEBUG_set_name(struct SMACK *smack, const void *pattern,
               unsigned length, unsigned state)
{
    char *name = (char*)malloc(length+1);
    if (name == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memcpy(name, pattern, length);
    name[length] = '\0';
    smack->m_match[state].DEBUG_name = name;
}
#else
#define DEBUG_set_name(a,b,c,d);
#endif


/****************************************************************************
 ****************************************************************************/
static void
smack_add_prefixes(struct SMACK *smack, struct SmackPattern *pat)
{
    unsigned i;
    unsigned pattern_length;
    unsigned char *pattern;
    int state=0;

    pattern_length = pat->pattern_length;
    pattern = pat->pattern;

    /*
     * If we anchor at the beginning, then start with that
     */
    if (pat->is_anchor_begin)
        state = GOTO(state, CHAR_ANCHOR_START);

    /*
     * Match the existing prefix patterns. For example, if we add all the
     * prefixes for "football", then add "foobar", there will already be
     * prefixes for 'f', 'fo', and 'foo'. We won't start adding new states
     * until we reach 'foob', 'fooba', and 'foobar'.
     */
    for (i=0; i<pattern_length && GOTO(state,pattern[i]) != FAIL; i++)
        state = GOTO(state,pattern[i]);

    /*
     * Now that we've matched existing states, start creating new states to
     * complete this pattern.
     */
    for ( ; i<pattern_length; i++) {
        unsigned new_state = smack->m_state_count++;
        if (pat->is_snmp_hack)
            GOTO(state, 0x80) = state; /* snmp_hack, space_hack */
        GOTO(state, pattern[i]) = new_state;
        state = new_state;
        DEBUG_set_name(smack, pattern, i+1, new_state);
    }

    /*
     * If there is an anchor at the end, then create one more state
     */
    if (pat->is_anchor_end) {
        unsigned new_state = smack->m_state_count++;
        GOTO(state, CHAR_ANCHOR_END) = new_state;
        state = new_state;
#ifdef DEBUG
        DEBUG_set_name(smack, pattern, i+1, new_state);
        smack->m_match[new_state].DEBUG_name[i] = '$';
#endif
    }

    /*
     * Now mark the final state as a "match" state.
     */
    smack_copy_matches(&smack->m_match[state], &pat->id, 1);
}



/****************************************************************************
 ****************************************************************************/
static void
smack_stage0_compile_prefixes(struct SMACK *smack)
{
    unsigned s;
    unsigned a;

    /*
     * Initialize the base-state.
     */
    smack->m_state_count = 1;
    for (s=0; s<smack->m_state_max; s++) {
        for (a=0; a<ALPHABET_SIZE; a++)
            GOTO(s,a) = FAIL;
    }
    DEBUG_set_name(smack, "*", 1, 0);

    /*
     * Initialize the anchor-state
     */
    if (smack->is_anchor_begin) {
        unsigned anchor_begin = smack->m_state_count++;
        GOTO(BASE_STATE, CHAR_ANCHOR_START) = anchor_begin;
        DEBUG_set_name(smack, "^", 1, anchor_begin);
    }

    /*
     * Split a pattern into its sub patterns and add each of them
     * to the table.
     */
    for (a=0; a<(int)smack->m_pattern_count; a++)
        smack_add_prefixes(smack, smack->m_pattern_list[a]);

    /* Set all failed state transitions to return to the 0'th state */
    for (a=0; a<ALPHABET_SIZE; a++) {
        if (GOTO(BASE_STATE,a) == FAIL)
            GOTO(BASE_STATE,a) = BASE_STATE;
    }
}


/****************************************************************************
 ****************************************************************************/
static void
smack_stage1_generate_fails(struct SMACK * smack)
{
    unsigned s;
    unsigned a;
    struct Queue *queue;

    /* Create a queue for breadth-first enumeration of the patterns*/
    queue = queue_create();

    /* Do the base-state first */
    for (a=0; a<ALPHABET_SIZE; a++) {
        s = GOTO(BASE_STATE,a);
        if (s != BASE_STATE) {
            enqueue(queue, s);
            GOTO_FAIL(s) = BASE_STATE;
        }
    }

    /* Build the fail state transitions for each valid state */
    while (queue_has_more_items(queue)) {
        unsigned r;

        r = dequeue(queue);

        /* Find Final States for any Failure */
        for (a=0; a<ALPHABET_SIZE; a++) {
            unsigned f;

            s = GOTO(r, a);
            if (s == FAIL)
                continue;
            if (s == r)
                continue; /* snmp_hack, space_hack */

            enqueue(queue, s); /* Breadth first search on states */

            f = GOTO_FAIL(r);

            while (GOTO(f,a) == FAIL)
                f = GOTO_FAIL(f);

            GOTO_FAIL(s) = GOTO(f,a);

            if (smack->m_match[GOTO(f,a)].m_count)
                smack_copy_matches(
                    &smack->m_match[s],
                    smack->m_match[GOTO(f,a)].m_ids,
                    smack->m_match[GOTO(f,a)].m_count
                    );
        }
    }

    queue_destroy(queue);
}



/****************************************************************************
 ****************************************************************************/
static void
smack_stage2_link_fails(struct SMACK * smack)
{
    unsigned a;
    struct Queue *queue;

    queue = queue_create();

    for (a=0; a<ALPHABET_SIZE; a++) {
        if (GOTO(BASE_STATE, a) != BASE_STATE)
            enqueue(queue, GOTO(BASE_STATE, a));
    }

    while (queue_has_more_items(queue)) {
        unsigned r;

        r = dequeue(queue);

        for (a=0; a<ALPHABET_SIZE; a++) {
            if (GOTO(r,a) == FAIL)
                GOTO(r,a) = GOTO(GOTO_FAIL(r),a);
            else if (GOTO(r,a) == r)
                ; /* snmp_hack, space_hack */
            else
                enqueue(queue, GOTO(r,a));
        }
    }

    queue_destroy(queue);
}



/****************************************************************************
 ****************************************************************************/
static void
smack_stage4_make_final_table(struct SMACK *smack)
{
    unsigned row;
    unsigned row_count = smack->m_state_count;
    unsigned column_count;
    transition_t *table;
    unsigned char *char_to_symbol = smack->char_to_symbol;

    /*
     * Figure out the row-size-shift. Instead of doing a multiply by the
     * row-width, we expand it out to the nearest pattern of two, and
     * then use shifts instead of multiplies.
     */
    smack->row_shift = row_shift_from_symbol_count(smack->symbol_count);
    column_count = 1 << smack->row_shift;

    /*
     * Allocate table:
     * rows*columns
     */
    table = malloc(sizeof(transition_t) * row_count * column_count);
    if (table == NULL) {
        fprintf(stderr, "%s: out of memory error\n", "smack");
        exit(1);
    }
    memset(table, 0, sizeof(transition_t) * row_count * column_count);


    for (row=0; row<row_count; row++) {
        unsigned col;

        for (col=0; col<ALPHABET_SIZE; col++) {
            unsigned transition;
            unsigned symbol = char_to_symbol[col];

            transition = GOTO(row,col);

            *(table + row*column_count + symbol) = (transition_t)transition;
        }
    }

    smack->table = table;
}


/****************************************************************************
 ****************************************************************************/
static void
swap_rows(struct SMACK *smack, unsigned row0, unsigned row1)
{
    struct SmackRow swap;
    struct SmackMatches swapm;
    unsigned s;

    /* Swap the first two states */
    memcpy(&swap,                       &smack->m_state_table[row0],   sizeof(swap));
    memcpy(&smack->m_state_table[row0], &smack->m_state_table[row1],   sizeof(swap));
    memcpy(&smack->m_state_table[row1], &swap,                         sizeof(swap));

    /* Swap the 'match' info */
    memcpy(&swapm,                      &smack->m_match[row0],         sizeof(swapm));
    memcpy(&smack->m_match[row0],       &smack->m_match[row1],         sizeof(swapm));
    memcpy(&smack->m_match[row1],       &swapm,                        sizeof(swapm));


    /* Now reset any pointers to the swapped states in exisitng states */
    for (s=0; s<smack->m_state_count; s++) {
        unsigned a;
        for (a=0; a<ALPHABET_SIZE; a++) {
            if (GOTO(s,a) == row0)
                GOTO(s,a) = row1;
            else if (GOTO(s,a) == row1)
                GOTO(s,a) = row0;
        }
    }
}

/****************************************************************************
 * Sort the states so that all MATCHES are at the end
 ****************************************************************************/
static void
smack_stage3_sort(struct SMACK *smack)
{
    unsigned start = 0;
    unsigned end = smack->m_state_count;

    for (;;) {

        while (start < end && smack->m_match[start].m_count == 0)
            start++;
        while (start < end && smack->m_match[end-1].m_count != 0)
            end--;

        if (start >= end)
            break;

        swap_rows(smack, start, end-1);
    }

    smack->m_match_limit = start;
}

/****************************************************************************
 *
 * KLUDGE KLUDGE KLUDGE KLUDGE KLUDGE
 *
 * This function currently only works in a very narrow case, for the SMB
 * parser, where all the patterns are "anchored" and none overlap with the
 * the SMB patterns. This allows us to modify existing states with the
 * the wildcards, without adding new states. Do do this right we need
 * to duplicate states in order to track wildcards
 ****************************************************************************/
static void
smack_fixup_wildcards(struct SMACK *smack)
{
    size_t i;
    
    for (i=0; i<smack->m_pattern_count; i++) {
        size_t j;
        struct SmackPattern *pat = smack->m_pattern_list[i];
        
        /* skip patterns that aren't wildcards */
        if (!pat->is_wildcards)
            continue;
        
        /* find the state leading up to the wilcard * character */
        for (j=0; j<pat->pattern_length; j++) {
            unsigned row = 0;
            unsigned offset = 0;
            size_t row_size = ((size_t)1 << smack->row_shift);
            transition_t *table;
            transition_t next_pattern;
            transition_t base_state = (smack->is_anchor_begin?1:0);
            size_t k;
            
            /* Skip non-wildcard characters */
            if (pat->pattern[j] != '*')
                continue;
            
            /* find the current 'row' */
            while (offset < j)
                smack_search_next(smack, &row, pat->pattern, &offset, (unsigned)j);
            
            row = row & 0xFFFFFF;
            table = smack->table + (row << smack->row_shift);
            next_pattern = table[smack->char_to_symbol['*']];
            
            for (k=0; k<row_size; k++) {
                if (table[k] == base_state)
                    table[k] = next_pattern;
            }
        }
    }

}
/****************************************************************************
 ****************************************************************************/
void
smack_compile(struct SMACK *smack)
{
    unsigned i;

    /*
     * Fix up the symbol table to handle "anchors" and "nocase" conditions.
     */
    if (smack->is_anchor_begin)
        smack_add_symbol(smack, CHAR_ANCHOR_START);
    if (smack->is_anchor_end)
        smack_add_symbol(smack, CHAR_ANCHOR_END);
    if (smack->is_nocase) {
        for (i='A'; i<='Z'; i++) {
            smack->char_to_symbol[i] = smack->char_to_symbol[tolower(i)];
        }
    }


    /*
     * Calculate the maximum possible number of states. This will be somewhat
     * larger than the number of states we'll actually use because there can
     * be overlaps
     */
    smack->m_state_max = 1;
    for (i=0; i<(int)smack->m_pattern_count; i++) {
        struct SmackPattern *pat = smack->m_pattern_list[i];

        smack->m_state_max += pat->pattern_length;
        smack->m_state_max += pat->is_anchor_begin;
        smack->m_state_max += pat->is_anchor_end;
    }

    /*
     * Allocate a state-table that can hold that number of states
     */
    create_intermediate_table(smack, smack->m_state_max);
    create_matches_table(smack, smack->m_state_max);


    /*
     * Go through the various compilation stages
     */
    smack_stage0_compile_prefixes(smack);
    smack_stage1_generate_fails(smack);
    smack_stage2_link_fails(smack);


    /* If we have an anchor pattern, then swap
     * the first two states. */
    if (smack->is_anchor_begin) {
        swap_rows(smack, BASE_STATE, UNANCHORED_STATE);
    }

    /* prettify table for debugging */
    smack_stage3_sort(smack);

    /*
     * Build the final table we use for evaluation
     */
    smack_stage4_make_final_table(smack);
    
    /*
     * Fixup the wildcard states
     */
    smack_fixup_wildcards(smack);

    /*
     * Get rid of the original pattern tables, since we no longer need them.
     * However, if this is a debug build, keep the tables around to make
     * debugging easier
     */
#ifndef DEBUG
    destroy_pattern_table(smack);
    destroy_intermediate_table(smack);
#endif
}


/****************************************************************************
 * Found!
 *
 * We found one or more patterns in the input stream. Go through the list
 * and notify the caller of "smack_search()" which ones we found.
 ****************************************************************************/
static unsigned
handle_match(    struct SMACK * smack,
                unsigned index,
                int (*callback_function)(size_t id, int index, void *callback_data),
                void *callback_data,
                unsigned state)
{
    unsigned i;
    struct SmackMatches *match = &smack->m_match[state];

    /*
     * Notify caller of all possible matches.
     */
    for (i=0; i<match->m_count; i++) {
        size_t id = match->m_ids[i];
        callback_function(id, index, callback_data);
    }

    return match->m_count;
}







/****************************************************************************
 ****************************************************************************/
unsigned
smack_search(    struct SMACK * smack,
                const void *v_px,
                unsigned length,
                FOUND_CALLBACK cb_found,
                void *callback_data,
                unsigned *current_state)
{
    const unsigned char *px = (const unsigned char*)v_px;
    unsigned row;
    unsigned i;
    const unsigned char *char_to_symbol = smack->char_to_symbol;
    transition_t *table = smack->table;
    unsigned row_shift = smack->row_shift;
    unsigned found_count = 0;
    const struct SmackMatches *match = smack->m_match;

    /* Get the row. This is encoded as the lower 24-bits of the state
     * variable */
    row = *current_state & 0xFFFFFF;

    /* 'for all bytes in this block' */
    for (i=0; i<length; i++) {
        unsigned char column;
        unsigned char c;

        /* Get the next character of input */
        c = px[i];

        /* Convert that character into a symbol. This compresses the table.
         * Even though there are 256 possible combinations for a byte, we
         * are probably using fewer than 32 individual characters in the
         * patterns we are looking for. This step allows us to create tables
         * that are only 32 elements wide, instead of 256 elements wide */
        column = char_to_symbol[c];

        /*
         * If debugging, and the variable is set, then print out the
         * transition to the command line. This is a good way of visualizing
         * how they work.
         */
#ifdef DEBUG
        if (print_transitions) {
            printf("%s+%c = %s%s\n",
                    smack->m_match[row].DEBUG_name,
                    c,
                    smack->m_match[*(table + (row<<row_shift) + column)].DEBUG_name,
                    smack->m_match[*(table + (row<<row_shift) + column)].m_count?"$$":"");
            print_transitions--;
        }
#endif

        /*
         * STATE TRANSITION
         * Given the current row, lookup the symbol, and find the next row.
         * Logically, this is the following  calculation:
         *    row = table[row][column]
         * However, since row can have a variable width (depending on the
         * number of characters in a pattern), we have to do the calculation
         * manually.
         */
        row = *(table + (row<<row_shift) + column);

        /* Test to see if we have one (or more) matches, and if so, call
         * the callback function */
        if (match[row].m_count)
            found_count = handle_match(smack, i, cb_found, callback_data, row);
    }
    *current_state = row;
    return found_count;
}

/*****************************************************************************
 *****************************************************************************/
static size_t
inner_match(    const unsigned char *px, 
                size_t length,
                const unsigned char *char_to_symbol,
                const transition_t *table, 
                unsigned *state, 
                unsigned match_limit,
                unsigned row_shift) 
{
    const unsigned char *px_start = px;
    const unsigned char *px_end = px + length;
    unsigned row = *state;
    
    for ( ; px<px_end; px++) {
        unsigned char column;
        
        /* Convert that character into a symbol. This compresses the table.
         * Even though there are 256 possible combinations for a byte, we
         * are probably using fewer than 32 individual characters in the
         * patterns we are looking for. This step allows us to create tables
         * that are only 32 elements wide, instead of 256 elements wide */
        column = char_to_symbol[*px];
        
        /*
         * STATE TRANSITION
         * Given the current row, lookup the symbol, and find the next row.
         * Logically, this is the following  calculation:
         *    row = table[row][column]
         * However, since row can have a variable width (depending on the
         * number of characters in a pattern), we have to do the calculation
         * manually.
         */
        row = *(table + (row<<row_shift) + column);
        
        if (row >= match_limit)
            break;
        
    }

    *state = row;
    return px - px_start;
}
/*****************************************************************************
 *****************************************************************************/
static size_t
inner_match_shift7(    const unsigned char *px, 
            size_t length,
            const unsigned char *char_to_symbol,
            const transition_t *table, 
            unsigned *state, 
            unsigned match_limit) 
{
    const unsigned char *px_start = px;
    const unsigned char *px_end = px + length;
    unsigned row = *state;
    
    for ( ; px<px_end; px++) {
        unsigned char column;
        column = char_to_symbol[*px];
        row = *(table + (row<<7) + column);
        if (row >= match_limit)
            break;
    }
    
    *state = row;
    return px - px_start;
}

/*****************************************************************************
 *****************************************************************************/
size_t
smack_search_next(      struct SMACK *  smack,
                        unsigned *      current_state,
                        const void *    v_px,
                        unsigned *       offset,
                        unsigned        length
                        )
{
    const unsigned char *px = (const unsigned char*)v_px;
    unsigned row;
    register size_t i = *offset;
    const unsigned char *char_to_symbol = smack->char_to_symbol;
    const transition_t *table = smack->table;
    register unsigned row_shift = smack->row_shift;
    const struct SmackMatches *match = smack->m_match;
    unsigned current_matches = 0;
    size_t id = (size_t)-1;
    register unsigned match_limit = smack->m_match_limit;

    /* Get the row. This is encoded as the lower 24-bits of the state
     * variable */
    row = *current_state & 0xFFFFFF;

    /* See if there are current matches we are processing */
    current_matches = (*current_state)>>24;
 
    /* 'for all bytes in this block' */
    if (!current_matches) {
        /*if ((length-i) & 1)
            i += inner_match(px + i, 
                             length - i,
                             char_to_symbol,
                             table, 
                             &row, 
                             match_limit,
                             row_shift);
        if (row < match_limit && i < length)*/
        switch (row_shift) {
            case 7:
                i += inner_match_shift7(px + i, 
                                 length - i,
                                 char_to_symbol,
                                 table, 
                                 &row, 
                                 match_limit);
                break;
            default:
                i += inner_match(px + i, 
                                 length - i,
                                 char_to_symbol,
                                 table, 
                                 &row, 
                                 match_limit,
                                 row_shift);
                break;

        }

        //printf("*** row=%u, i=%u, limit=%u\n", row, i, match_limit);

        /* Test to see if we have one (or more) matches, and if so, call
         * the callback function */
        if (match[row].m_count) {
            i++; /* points to first byte after match */
            current_matches = match[row].m_count;
        }
    }

    *offset = (unsigned)i;

    /* If we broke early because we found a match, return that match */
    if (current_matches) {
        id = match[row].m_ids[current_matches-1];
        current_matches--;
    }

    *current_state = row | (current_matches<<24);
    return id;
}


/****************************************************************************
 ****************************************************************************/
size_t
smack_next_match(struct SMACK *smack, unsigned *current_state)
{
    unsigned row, current_matches;
    size_t id = SMACK_NOT_FOUND;

    /* split the state variable */
    row = *current_state & 0xFFFFFF;
    current_matches = (*current_state)>>24;

    /* If we broke early because we found a match, return that match */
    if (current_matches) {
        const struct SmackMatches *match = smack->m_match;
        id = match[row].m_ids[current_matches-1];
        current_matches--;
    }

    /* Recombine the state */
    *current_state = row | (current_matches<<24);

    return id;
}


/****************************************************************************
 ****************************************************************************/
unsigned
smack_search_end(       struct SMACK *  smack,
                        FOUND_CALLBACK  cb_found,
                        void *          callback_data,
                        unsigned *      current_state)
{
    unsigned found_count = 0;
    transition_t *table = smack->table;
    unsigned row_shift = smack->row_shift;
    unsigned row = *current_state;
    const struct SmackMatches *match = smack->m_match;
    unsigned column = smack->char_to_symbol[CHAR_ANCHOR_END];

    /*
     * This is the same logic as for "smack_search()", except there is
     * only one byte of input -- the virtual character ($) that represents
     * the anchor at the end of some patterns.
     */
    row = *(table + (row<<row_shift) + column);
    if (match[row].m_count)
        found_count = handle_match(smack, 0, cb_found, callback_data, row);

    *current_state = row;
    return found_count;
}

/*****************************************************************************
 * Provide my own rand() simply to avoid static-analysis warning me that
 * 'rand()' is unrandom, when in fact we want the non-random properties of
 * rand() for regression testing.
 *****************************************************************************/
static unsigned
r_rand(unsigned *seed)
{
    static const unsigned a = 214013;
    static const unsigned c = 2531011;
    
    *seed = (*seed) * a + c;
    return (*seed)>>16 & 0x7fff;
}

/****************************************************************************
 ****************************************************************************/
int
smack_benchmark(void)
{
    char *buf;
    unsigned seed = 0;
    static unsigned BUF_SIZE = 1024*1024;
    static uint64_t ITERATIONS = 30;
    unsigned i;
    struct SMACK *s;
    uint64_t start, stop;
    uint64_t result = 0;
    uint64_t cycle1, cycle2;

    printf("-- smack-1 -- \n");
    
    s = smack_create("benchmark1", 1);

    /* Fill a buffer full of junk */
    buf = (char*)malloc(BUF_SIZE);
    for (i=0; i<BUF_SIZE; i++)
        buf[i] = (char)r_rand(&seed)&0x7F;


    /* Create 20 patterns */
    for (i=0; i<20; i++) {
        unsigned pattern_length = r_rand(&seed)%3 + r_rand(&seed)%4 + 4;
        char pattern[20];
        unsigned j;

        for (j=0; j<pattern_length; j++)
            pattern[j] = (char)(r_rand(&seed)&0x7F) | 0x80;
        
        smack_add_pattern(s, pattern, pattern_length, i, 0);
    }

    smack_compile(s);

    start = pixie_nanotime();
    cycle1 = __rdtsc();
    for (i=0; i<ITERATIONS; i++) {
        unsigned state = 0;
        unsigned offset = 0;

        while (offset < BUF_SIZE)
            result += smack_search_next(s, &state, buf, &offset, BUF_SIZE);
    }
    cycle2 = __rdtsc();
    stop = pixie_nanotime();

    if (result) {
        double elapsed = ((double)(stop - start))/(1000000000.0);
        double rate = (BUF_SIZE*ITERATIONS*8ULL)/elapsed;
        double cycles = (BUF_SIZE*ITERATIONS*1.0)/(1.0*(cycle2-cycle1));

        rate /= 1000000.0;

        printf("bits/second = %5.3f-million\n", rate);
        printf("clocks/byte = %5.3f\n", (1.0/cycles));
        printf("clockrate = %5.3f-GHz\n", ((cycle2-cycle1)*1.0/elapsed)/1000000000.0);

        
    }

    return 0;
}

/****************************************************************************
 ****************************************************************************/
int
smack_selftest(void)
{
    struct SMACK *s;

    
        const char *patterns[] = {
            "GET",      "PUT",      "POST",     "OPTIONS",
            "HEAD",     "DELETE",   "TRACE",    "CONNECT",
            "PROPFIND", "PROPPATCH","MKCOL",    "MKWORKSPACE",
            "MOVE",     "LOCK",     "UNLOCK",   "VERSION-CONTROL",
            "REPORT",   "CHECKOUT", "CHECKIN",  "UNCHECKOUT",
            "COPY",     "UPDATE",   "LABEL",    "BASELINE-CONTROL",
            "MERGE",    "SEARCH",   "ACL",      "ORDERPATCH",
            "PATCH",    "MKACTIVITY", 0};
        unsigned i;
        const char *text = "ahpropfinddf;orderpatchposearchmoversion-controlockasldhf";
        unsigned text_length = (unsigned)strlen(text);
        size_t id;
        unsigned state = 0;

        /*
         * using SMACK is 5 steps:
         * #1 create an instance at program startup
         * #2 add patterns to it
         * #3 compile the patterns
         * #4 do your searches while running the program
         * #5 destroy the instance at program exit
         */
        s = smack_create("test1", 1);

        for (i=0; patterns[i]; i++)
            smack_add_pattern(s, patterns[i], (unsigned)strlen(patterns[i]), i, 0);

        smack_compile(s);

        i = 0;
#define TEST(pat, offset, str) if (pat != id || offset != i) return 1 + fprintf(stderr, "smack: fail %s\n", str)
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST(  8,  10, "PROPFIND");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 28,  23, "PATCH");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 27,  23, "ORDERPATCH");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 25,  31, "SEARCH");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 12,  35, "MOVE");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 15,  48, "VERSION-CONTROL");
        id = smack_search_next(s,&state,text, &i,text_length);
        TEST( 13,  51, "LOCK");

        /*{
            unsigned i;
            for (i=0; i<s->m_state_count; i++) {
                if (s->m_match[i].m_count)
                    printf("*");
                else
                    printf(".");
            }
            printf("\n");
        }*/
        smack_destroy(s);

    


    return 0;
}
