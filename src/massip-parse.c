/*
    massip-parse

    This module parses IPv4 and IPv6 addresses.

    It's not a typical parser. It's optimized around parsing large
    files containing millions of addresses and ranges using a 
    "state-machine parser".
*/
#include "massip.h"
#include "massip-parse.h"
#include "massip-rangesv4.h"
#include "massip-rangesv6.h"
#include "logger.h"
#include "util-bool.h"
#include "util-malloc.h"
#include "string_s.h"
#include "unusedparm.h"

#include <string.h>

struct massip_parser
{
    unsigned long long line_number;
    unsigned long long char_number;
    unsigned state;
    unsigned tmp;
    unsigned char digit_count;
    unsigned addr;
    unsigned begin;
    unsigned end;
    struct {
        ipv6address _begin;
        ipv6address _end;
        unsigned short tmp[8];
        unsigned char index;
        unsigned char ellision_index;
        unsigned is_bracket:1;
        unsigned is_second:1;
    } ipv6;
};

/***************************************************************************
 ***************************************************************************/
static struct massip_parser *
_parser_init(struct massip_parser *p)
{
    memset(p, 0, sizeof(*p));
    p->line_number = 1;
    p->ipv6.ellision_index = 8;
    return p;
}

/***************************************************************************
 ***************************************************************************/
static void
_parser_destroy(struct massip_parser *p)
{
    UNUSEDPARM(p);
}

/***************************************************************************
 ***************************************************************************/
static void
_parser_err(struct massip_parser *p, unsigned long long *line_number, unsigned long long *charindex)
{
    *line_number = p->line_number;
    *charindex = p->char_number;
}

/** 
 * Called before parsing the first address in a pair, and also
 * after the first address, to prepare for parsing the next
 * address
 */
static void
_init_next_address(struct massip_parser *p, int is_second)
{
    p->tmp = 0;
    p->ipv6.ellision_index = 8;
    p->ipv6.index = 0;
    p->ipv6.is_bracket = 0;
    p->digit_count = 0;
    p->ipv6.is_second = is_second;
}



static unsigned
_parser_finish_ipv6(struct massip_parser *p)
{
    unsigned index = p->ipv6.index;
    unsigned ellision = p->ipv6.ellision_index;
    

    /* We must have seen 8 numbers, or an ellision */
    if (index < 8 && ellision >= 8)
        return 1;
    
    /* Handle ellision */
    memmove(
        &p->ipv6.tmp[8-(index-ellision)],
        &p->ipv6.tmp[ellision],
        sizeof(p->ipv6.tmp[0]) * (index-ellision)
        );
    memset(
        &p->ipv6.tmp[ellision],
        0,
        sizeof(p->ipv6.tmp[0]) * (8 - index)
    );
    
    /* Copy over to begin/end. We parse the address as a series of 16-bit
     * integers, but return the result as two 64-bit integers */
    {
        ipv6address a;
        a.hi = (uint64_t)p->ipv6.tmp[0] << 48ULL
                | (uint64_t)p->ipv6.tmp[1] << 32ULL
                | (uint64_t)p->ipv6.tmp[2] << 16ULL
                | (uint64_t)p->ipv6.tmp[3] << 0ULL;
        a.lo = (uint64_t)p->ipv6.tmp[4] << 48ULL
                | (uint64_t)p->ipv6.tmp[5] << 32ULL
                | (uint64_t)p->ipv6.tmp[6] << 16ULL
                | (uint64_t)p->ipv6.tmp[7] << 0ULL;
        if (p->ipv6.is_second)
            p->ipv6._end = a;
        else {
            p->ipv6._begin = a;

            /* Set this here in case there is no 'end' address */
            p->ipv6._end = a;
        }
    }

    /* Reset the parser to start parsing the next address */
    _init_next_address(p, 1);

    return 0;
}

/***************************************************************************
 * We store the IPv6 addresses that we are building inside the 'state'
 * of the state-machine. This function copies them out of the opaque
 * state into discrete values.
 ***************************************************************************/
static void
_parser_get_ipv6(struct massip_parser *state, ipv6address *begin, ipv6address *end)
{
    *begin = state->ipv6._begin;
    *end = state->ipv6._end;
}

enum parser_state_t {
    LINE_START, ADDR_START,
    COMMENT,
    NUMBER0, NUMBER1, NUMBER2, NUMBER3, NUMBER_ERR,
    SECOND0, SECOND1, SECOND2, SECOND3, SECOND_ERR,
    IPV4_CIDR_NUM,
    UNIDASH1, UNIDASH2,
    IPV6_BEGIN, IPV6_COLON, IPV6_CIDR, IPV6_CIDR_NUM,
    IPV6_NEXT,
    IPV6_END,
    ERROR
};

/***************************************************************************
 * When we start parsing an address, we don't know whether it's going to 
 * be IPv4 or IPv6. We assume IPv4, but when we hit a condition indicating
 * that it's IPv6 instead, we need change the temporary number we 
 * are working on from decimal to hex, then move from the middle of 
 * parsing an IPv4 address to the middle of parsing an IPv6 address.
 ***************************************************************************/
static int
_switch_to_ipv6(struct massip_parser *p, int old_state)
{
    unsigned num = p->tmp;

    num = ((num/1000)%10) * 16 * 16 * 16
        + ((num/100)%10) * 16 * 16
        + ((num/10)%10) * 16
        + (num % 10);
    
    //printf("%u -> 0x%x\n", p->tmp, num);
    p->tmp = num;
    return old_state;
}


enum {
    IPV4_n, IPV4_nn, IPV4_nnn, IPV4_nnn_, 
    IPV4_nnn_n, IPV4_nnn_nn, IPV4_nnn_nnn, IPV4_nnn_nnn_, 
    IPV4_nnn_nnn_n, IPV4_nnn_nnn_nn, IPV4_nnn_nnn_nnn, IPV4_nnn_nnn_nnn_,
    IPV4_nnn_nnn_nnn_n, IPV4_nnn_nnn_nnn_nn, IPV4_nnn_nnn_nnn_nnn, IPV4_nnn_nnn_nnn_nnn_,
    IPV4e_n, IPV4e_nn, IPV4e_nnn, IPV4e_nnn_, 
    IPV4e_nnn_n, IPV4e_nnn_nn, IPV4e_nnn_nnn, IPV4e_nnn_nnn_, 
    IPV4e_nnn_nnn_n, IPV4e_nnn_nnn_nn, IPV4e_nnn_nnn_nnn, IPV4e_nnn_nnn_nnn_,
    IPV4e_nnn_nnn_nnn_n, IPV4e_nnn_nnn_nnn_nn, IPV4e_nnn_nnn_nnn_nnn, IPV4e_nnn_nnn_nnn_nnn_,


};


/**
 * Applies a CIDR mask to an IPv4 address to create a begin/end address.
 */
static void
_ipv4_apply_cidr(unsigned *begin, unsigned *end, unsigned bitcount)
{
    unsigned long long mask = 0xFFFFFFFF00000000ULL >> bitcount;
    
    /* mask off low-order bits */
    *begin &= (unsigned)mask;

    /* Set all suffix bits to 1, so that 192.168.1.0/24 has
     * an ending address of 192.168.1.255. */
    *end = *begin | (unsigned)~mask;
}

/**
 * Given an address 'being' and a 'prefix', return the 'begin' and 'end' address of the range.
 * @param begin
 *      An in/out parameter. This may have some extra bits somewhere in the range.
 *      These will be masked off and set to zero when the function returns.
 * @param end
 *      An out parameter. This will be set to the last address of the range, meaning
 *      that all the trailing bits will be set to '1'.
 * @parame prefix
 *      The number of bits of the prefix, from [0..128]. If the value is 0,
 *      then the 'begin' address will be set to all zeroes and the 'end'
 *      address will be set to all ones. If the value is 128,
 *      the 'begin' address is unchanged and the 'end' address
 *      is set to the same as 'begin'.
 */
static void
_ipv6_apply_cidr(ipv6address *begin, ipv6address *end, unsigned prefix)
{
    ipv6address mask;
    
    /* For bad prefixes, make sure we return an invalid address */
    if (prefix > 128) {
        static const ipv6address invalid = {~0ULL, ~0ULL};
        *begin = invalid;
        *end = invalid;
        return;
    };

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
    begin->hi &= mask.hi;
    begin->lo &= mask.lo;
    
    /* Set all suffix bits to 1, so that 192.168.1.0/24 has
     * an ending address of 192.168.1.255. */
    end->hi = begin->hi | ~mask.hi;
    end->lo = begin->lo | ~mask.lo;
}

/***************************************************************************
 * Parse the next IPv4/IPv6 address from a text stream, using a
 * 'state-machine parser'.
 ***************************************************************************/
static enum {Still_Working, Found_Error, Found_IPv4, Found_IPv6}
_parser_next(struct massip_parser *p, const char *buf, size_t *r_offset, size_t length,
                unsigned *r_begin, unsigned *r_end)
{ 
    size_t i;
    enum parser_state_t state = p->state;
    int result = Still_Working;

    /* The 'offset' parameter is optional. If NULL, then set it to zero */
    if (r_offset)
        i = *r_offset;
    else
        i = 0;

    /* For all bytes in this chunk. This loop will exit early once
     * we've found a complete IP address. */
    while (i < length) {
        unsigned char c = buf[i++];

        p->char_number++;
        switch (state) {
            case LINE_START:
            case ADDR_START:
                _init_next_address(p, 0);
                switch (c) {
                    case ' ': case '\t': case '\r':
                        /* ignore leading whitespace */
                        continue;
                    case '\n':
                        p->line_number++;
                        p->char_number = 0;
                        continue;
                    case '#': case ';': case '/': case '-':
                        state = COMMENT;
                        continue;
                        
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        p->tmp = (c - '0');
                        p->digit_count = 1;
                        state = NUMBER0;
                        break;
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        p->tmp = (c - 'a' + 10);
                        p->digit_count = 1;
                        state = IPV6_BEGIN;
                        break;
                    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        p->tmp = (c - 'A' + 10);
                        p->digit_count = 1;
                        state = IPV6_BEGIN;
                        break;
                    case ':':
                        p->ipv6.tmp[p->ipv6.index++] = 0;
                        state = IPV6_COLON;
                        break;
                    case '[':
                        p->ipv6.is_bracket = 1;
                        state = IPV6_BEGIN;
                        break;
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;
            case IPV6_CIDR:
                p->digit_count = 0;
                p->tmp = 0;
                switch (c) {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        p->tmp = (c - '0');
                        p->digit_count = 1;
                        state = IPV6_CIDR_NUM;
                        break;
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;
                
            case IPV6_COLON:
                p->digit_count = 0;
                p->tmp = 0;
                if (c == ':') {
                    if (p->ipv6.ellision_index < 8) {
                        state = ERROR;
                        length = i;
                    } else {
                        p->ipv6.ellision_index = p->ipv6.index;
                        state = IPV6_COLON;
                    }
                    break;
                }
                state = IPV6_BEGIN;

                /* drop down */
            case IPV6_BEGIN:
            case IPV6_NEXT:
                switch (c) {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        if (p->digit_count >= 4) {
                            state = ERROR;
                            length = i;
                        } else {
                            p->tmp = p->tmp * 16 + (c - '0');
                            p->digit_count++;
                        }
                        break;
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        if (p->digit_count >= 4) {
                            state = ERROR;
                            length = i;
                        } else {
                            p->tmp = p->tmp * 16 + (c - 'a' + 10);
                            p->digit_count++;
                        }
                        break;
                    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        if (p->digit_count >= 4) {
                            state = ERROR;
                            length = i;
                        } else {
                            p->tmp = p->tmp * 16 + (c - 'A' + 10);
                            p->digit_count++;
                        }
                        break;
                    case ':':
                        if (p->ipv6.index >= 8) {
                            state = ERROR;
                            length = i;
                        } else {
                            p->ipv6.tmp[p->ipv6.index++] = (unsigned short)p->tmp;
                            state = IPV6_COLON;
                        }
                        break;
                    case ']':
                        if (!p->ipv6.is_bracket) {
                            state = ERROR;
                            length = i;
                        } else {
                            state = IPV6_END;
                        }
                        break;
                    case '[':
                        if (p->ipv6.is_bracket) {
                            state = ERROR;
                            length = i;
                        } else {
                            p->ipv6.is_bracket = 1;
                        }
                        break;
                    case '/':
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                    case ',':
                    case '-':
                        i--; /* push back */
                        state = IPV6_END;
                        continue;
                    default:
                        state = ERROR;
                        length = i;
                        break;
                }
                break;

            case IPV6_END:
                /* Finish off the trailing number */
                p->ipv6.tmp[p->ipv6.index++] = (unsigned short)p->tmp;

                /* Do the final processing of this IPv6 address and
                 * prepare for the next one */
                if (_parser_finish_ipv6(p) != 0) {
                    state = ERROR;
                    length = i;
                    continue;
                }

                /* Now decide the next state, whether this is a single
                 * address, an address range, or a CIDR address */
                switch (c) {
                    case '/':
                        result = Still_Working;
                        state = IPV6_CIDR;
                        break;
                    case '-':
                        result = Still_Working;
                        state = IPV6_NEXT;
                        break;
                    case '\n':
                        p->line_number++;
                        p->char_number = 0;
                        /* drop down */
                    case ' ':
                    case '\t':
                    case '\r':
                    case ',':
                        result = Found_IPv6;
                        state = 0;
                        length = i; /* shorten the end to break out of loop */
                        break;
                    default:
                        state = ERROR;
                        length = i;
                        break;
                }
                break;
            case COMMENT:
                if (c == '\n') {
                    state = LINE_START;
                    p->line_number++;
                    p->char_number = 0;
                } else
                    state = COMMENT;
                break;
            case IPV6_CIDR_NUM:
                switch (c) {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        if (p->digit_count == 4) {
                            state = ERROR;
                            length = i; /* break out of loop */
                        } else {
                            p->digit_count++;
                            p->tmp = p->tmp * 10 + (c - '0');
                            if (p->tmp > 128) {
                                state = ERROR;
                                length = i;
                            }
                            continue;
                        }
                        break;
                    case ':':
                    case ',':
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                        {
                            _ipv6_apply_cidr(&p->ipv6._begin, &p->ipv6._end, p->tmp);

                            state = ADDR_START;
                            length = i; /* break out of loop */
                            if (c == '\n') {
                                p->line_number++;
                                p->char_number = 0;
                            }
                            *r_begin = p->begin;
                            *r_end = p->end;
                            result = Found_IPv6;
                        }
                        break;
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;
            case IPV4_CIDR_NUM:
                switch (c) {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        if (p->digit_count == 3) {
                            state = ERROR;
                            length = i; /* break out of loop */
                        } else {
                            p->digit_count++;
                            p->tmp = p->tmp * 10 + (c - '0');
                            if (p->tmp > 32) {
                                state = ERROR;
                                length = i;
                            }
                            continue;
                        }
                        break;
                    case ':':
                    case ',':
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                        {
                            _ipv4_apply_cidr(&p->begin, &p->end, p->tmp);
                            state = ADDR_START;
                            length = i; /* break out of loop */
                            if (c == '\n') {
                                p->line_number++;
                                p->char_number = 0;
                            }
                            *r_begin = p->begin;
                            *r_end = p->end;
                            result = Found_IPv4;
                        }
                        break;
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;

            case UNIDASH1:
                if (c == 0x80)
                    state = UNIDASH2;
                else {
                    state = ERROR;
                    length = i; /* break out of loop */
                }
                break;
            case UNIDASH2:
                /* This covers:
                 * U+2010 HYPHEN
                 * U+2011 NON-BREAKING HYPHEN
                 * U+2012 FIGURE DASH
                 * U+2013 EN DASH
                 * U+2014 EM DASH
                 * U+2015 HORIZONTAL BAR
                 */
                if (c < 0x90 || 0x95 < c) {
                    state = ERROR;
                    length = i; /* break out of loop */
                } else {
                    c = '-';
                    state = NUMBER3;
                    /* drop down */
                }


            case NUMBER0:
            case NUMBER1:
            case NUMBER2:
            case NUMBER3:
            case SECOND0:
            case SECOND1:
            case SECOND2:
            case SECOND3:
                switch (c) {
                    case '.':
                        p->addr = (p->addr << 8) | p->tmp;
                        p->tmp = 0;
                        p->digit_count = 0;
                        if (state == NUMBER3 || state == SECOND3) {
                            length = i;
                            state = ERROR;
                        } else
                            state++;
                        break;
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        p->digit_count++;
                        p->tmp = p->tmp * 10 + (c - '0');
                        if (p->tmp > 255 || p->digit_count > 3) {
                            if (state == NUMBER0) {
                                /* Assume that we've actually got an
                                 * IPv6 number */
                                _switch_to_ipv6(p, state);
                                state = IPV6_BEGIN;
                            } else {
                                state = ERROR;
                                length = i;
                            }
                        }
                        continue;
                        break;
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        if (state == NUMBER0 || state == SECOND0) {
                            /* Assume that we've actually got an
                             * IPv6 number */
                            _switch_to_ipv6(p, state);
                            state = IPV6_BEGIN;
                            i--; /* go back one character */
                        } else {
                            state = ERROR;
                            length = i; /* break out of loop */
                        }
                        break;
                    case 0xe2:
                        if (state == NUMBER3) {
                            state = UNIDASH1;
                        } else {
                            state = ERROR;
                            length = i; /* break out of loop */
                        }
                        break;
                    case '-':
                    case 0x96: /* long dash, comes from copy/pasting into exclude files */
                        if (state == NUMBER3) {
                            p->begin = (p->addr << 8) | p->tmp;
                            p->tmp = 0;
                            p->digit_count = 0;
                            p->addr = 0;
                            state = SECOND0;
                        } else {
                            state = NUMBER_ERR;
                            length = i;
                        }
                        break;
                    case '/':
                        if (state == NUMBER3) {
                            p->begin = (p->addr << 8) | p->tmp;
                            p->tmp = 0;
                            p->digit_count = 0;
                            p->addr = 0;
                            state = IPV4_CIDR_NUM;
                        } else {
                            state = NUMBER_ERR;
                            length = i; /* break out of loop */
                        }
                        break;
                    case ':':
                        if (state == NUMBER0) {
                            /* Assume this is an IPv6 address instead of an IPv4 address */
                            _switch_to_ipv6(p, state);
                            state = IPV6_BEGIN;
                            i--;
                            break;
                        }
                    case ',':
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                        if (state == NUMBER3) {
                            p->begin = (p->addr << 8) | p->tmp;
                            p->end = p->begin;
                            p->tmp = 0;
                            p->digit_count = 0;
                            p->addr = 0;
                            state = ADDR_START;
                            length = i; /* break out of loop */
                            if (c == '\n') {
                                p->line_number++;
                                p->char_number = 0;
                            }
                            *r_begin = p->begin;
                            *r_end = p->end;
                            result = Found_IPv4;
                        } else if (state == SECOND3) {
                            p->end = (p->addr << 8) | p->tmp;
                            p->tmp = 0;
                            p->digit_count = 0;
                            p->addr = 0;
                            state = ADDR_START;
                            length = i; /* break out of loop */
                            if (c == '\n') {
                                p->line_number++;
                                p->char_number = 0;
                            }
                            *r_begin = p->begin;
                            *r_end = p->end;
                            result = Found_IPv4;
                        } else {
                            state = NUMBER_ERR;
                            length = i;
                        }
                        break;
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;
                
            default:
            case ERROR:
            case NUMBER_ERR:
            case SECOND_ERR:
                state = ERROR;
                length = i; /* break */
                break;
        }
    }

    /* The 'offset' parameter is optional. If NULL, then 
     * we don't return a value */
    if (r_offset)
        *r_offset = i;

    p->state = state;
    if (state == ERROR || state == NUMBER_ERR || state == SECOND_ERR)
        result = Found_Error;
    return result;
}


/***************************************************************************
 * Test errors. We should get exactly which line-number and which character
 * in the line caused the error
 ***************************************************************************/
static int
rangefile_test_error(const char *buf, unsigned long long in_line_number, unsigned long long in_char_number, unsigned which_test)
{
    size_t length = strlen(buf);
    size_t offset = 0;
    struct massip_parser p[1];
    unsigned out_begin = 0xa3a3a3a3;
    unsigned out_end  = 0xa3a3a3a3;
    unsigned long long out_line_number;
    unsigned long long out_char_number;
    int x;

    /* test the entire buffer */
    _parser_init(p);
    x = _parser_next(p, buf, &offset, length, &out_begin, &out_end);
    if (x != Found_Error)
        goto fail;
    _parser_err(p, &out_line_number, &out_char_number);
    if (in_line_number != out_line_number || in_char_number != out_char_number)
        goto fail;

    /* test one byte at a time */
    _parser_destroy(p);
    _parser_init(p);
    offset = 0;
    out_begin = 0xa3a3a3a3;
    out_end  = 0xa3a3a3a3;
    
    x = 0;
    while (offset < length) {
        x = _parser_next(p, buf, &offset, offset+1, &out_begin, &out_end);
        if (x == Found_Error)
            break;
    }
    if (x != Found_Error)
        goto fail;
    _parser_err(p, &out_line_number, &out_char_number);

    if (in_line_number != out_line_number || in_char_number != out_char_number)
        goto fail;

    _parser_destroy(p);
    return 0;
fail:
    _parser_destroy(p);
    fprintf(stderr, "[-] rangefile test fail, line=%u\n", which_test);
    return 1;
}

/***************************************************************************
 ***************************************************************************/
int
massip_parse_file(struct MassIP *massip, const char *filename)
{
    struct RangeList *targets_ipv4 = &massip->ipv4;
    struct Range6List *targets_ipv6 = &massip->ipv6;
    struct massip_parser p[1];
    char buf[65536];
    FILE *fp = NULL;
    int err;
    bool is_error = false;
    unsigned addr_count = 0;
    unsigned long long line_number, char_number;

    /*
     * Open the file containing IP addresses, which can potentially be
     * many megabytes in size
     */
    if (strcmp(filename, "-") == 0) {
        fp = stdin;
        err = 0;
    } else {
        err = fopen_s(&fp, filename, "rb");
        if (err || fp == NULL) {
            perror(filename);
            exit(1);
        }
    }

    /*
     * Create a parser for reading in the IP addresses using a state
     * machine parser
     */
    _parser_init(p);

    /*
     * Read in the data a block at a time, parsing according to the state
     * machine.
     */
    while (!is_error) {
        size_t count;
        size_t offset;

        count = fread(buf, 1, sizeof(buf), fp);
        if (count <= 0)
            break;

        offset = 0;
        while (offset < count) {
            unsigned begin, end;

            err = _parser_next(p, buf, &offset, count, &begin, &end);
            switch (err) {
            case Still_Working:
                if (offset < count) {
                    /* We reached this somehow in the middle of the buffer, but
                     * this return is only possible at the end of the buffer */
                    fprintf(stderr, "[-] rangeparse_next(): unknown coding failure\n");
                }
                break;
            case Found_Error:
            default:
                _parser_err(p, &line_number, &char_number);
                fprintf(stderr, "[-] %s:%llu:%llu: invalid IP address on line #%llu\n", filename, line_number, char_number, line_number);
                is_error = true;
                count = offset;
                break;
            case Found_IPv4:
                rangelist_add_range(targets_ipv4, begin, end);
                addr_count++;
                break;
            case Found_IPv6:
                {
                    ipv6address found_begin, found_end;
                    _parser_get_ipv6(p, &found_begin, &found_end);
                    range6list_add_range(targets_ipv6, found_begin, found_end);
                    addr_count++;
                }
                break;
            }
        }
    }
    
    /* Close the file, unless we are reading from <stdin> */
    if (fp != stdin && fp != NULL)
        fclose(fp);

    /* In case the file doesn't end with a newline '\n', then artificially
     * add one to the end. This is just a repeat of the code above */
    if (!is_error) {
        size_t offset = 0;
        unsigned begin, end;
        err = _parser_next(p, "\n", &offset, 1, &begin, &end);
        switch (err) {
        case Still_Working:
                break;
        case Found_Error:
        default:
            _parser_err(p, &line_number, &char_number);
            fprintf(stderr, "[-] %s:%llu:%llu: invalid IP address on line #%llu\n", filename, line_number, char_number, line_number);
            is_error = true;
            break;
        case Found_IPv4:
            rangelist_add_range(targets_ipv4, begin, end);
            addr_count++;
            break;
        case Found_IPv6:
            {
                ipv6address found_begin, found_end;
                _parser_get_ipv6(p, &found_begin, &found_end);
                range6list_add_range(targets_ipv6, found_begin, found_end);
                addr_count++;
            }
            break;
        }
    }

    LOG(1, "[+] %s: %u addresses read\n", filename, addr_count);

    /* Target list must be sorted every time it's been changed, 
     * before it can be used */
    rangelist_sort(targets_ipv4);

    if (is_error)
        return -1;  /* fail */
    else
        return 0; /* success*/
}


ipv6address
massip_parse_ipv6(const char *line)
{
    struct massip_parser p[1];
    size_t count = strlen(line);
    size_t offset = 0;
    int err;
    unsigned begin, end;
    ipv6address result;
    ipv6address range;

    _parser_init(p);
    err = _parser_next(p, line, &offset, count, &begin, &end);
again:
    switch (err) {
        case Still_Working:
            if (offset < count) {
                /* We reached this somehow in the middle of the buffer, but
                 * this return is only possible at the end of the buffer */
                fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                goto fail;
            } else {
                err = _parser_next(p, "\n", 0, 1, &begin, &end);
                if (err == Still_Working) {
                    fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                    goto fail;
                } else {
                    goto again;
                }
            }
            break;
        case Found_Error:
        default:
            goto fail;
        case Found_IPv4:
            goto fail;
        case Found_IPv6:
            _parser_get_ipv6(p, &result, &range);
            if (!ipv6address_is_equal(result, range))
                goto fail;
            return result;
    }
fail:
    result.hi = ~0ULL;
    result.lo = ~0ULL;
    return result;
}

unsigned
massip_parse_ipv4(const char *line)
{
    struct massip_parser p[1];
    size_t count = strlen(line);
    size_t offset = 0;
    int err;
    unsigned begin, end;


    _parser_init(p);
    err = _parser_next(p, line, &offset, count, &begin, &end);
again:
    switch (err) {
        case Still_Working:
            if (offset < count) {
                /* We reached this somehow in the middle of the buffer, but
                 * this return is only possible at the end of the buffer */
                fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                goto fail;
            } else {
                err = _parser_next(p, "\n", 0, 1, &begin, &end);
                if (err == Still_Working) {
                    fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                    goto fail;
                } else {
                    goto again;
                }
            }
            break;
        case Found_Error:
        default:
            goto fail;
        case Found_IPv6:
            goto fail;
        case Found_IPv4:
            if (begin != end)
                goto fail;
            return begin;
    }
fail:
    return 0xFFFFFFFF;
}

enum RangeParseResult
massip_parse_range(const char *line, size_t *offset, size_t count, struct Range *ipv4, struct Range6 *ipv6)
{
    struct massip_parser p[1];
    int err;
    unsigned begin, end;
    size_t tmp_offset = 0;
    
    /* The 'count' (length of the string) is an optional parameter. If
     * zero, and also the offset is NULL, then set it to the string length */
    if (count == 0 && offset == NULL)
        count = strlen(line);

    /* The offset is an optional parameter. If NULL, then we set
     * it to point to a value on the stack instead */
    if (offset == NULL)
        offset = &tmp_offset;
    
    /* Create e parser object */
    _parser_init(p);

    /* Parse the next range from the input */
    err = _parser_next(p, line, offset, count, &begin, &end);
again:
    switch (err) {
        case Still_Working:
            if (*offset < count) {
                /* We reached this somehow in the middle of the buffer, but
                 * this return is only possible at the end of the buffer */
                fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                return Bad_Address;
            } else {
                err = _parser_next(p, "\n", 0, 1, &begin, &end);
                if (err == Still_Working) {
                    fprintf(stderr, "[-] _parser_next(): unknown coding failure\n");
                    return Bad_Address;
                } else {
                    goto again;
                }
            }
            break;
        case Found_Error:
        default:
            return Bad_Address;
        case Found_IPv4:
            ipv4->begin = begin;
            ipv4->end = end;
            return Ipv4_Address;
        case Found_IPv6:
            _parser_get_ipv6(p, &ipv6->begin, &ipv6->end);
            return Ipv6_Address;
    }
}

/**
 * This tests  parsing when addresses/ranges are specified on the command-line
 * or configuration files, rather than the other test-cases which test parsing
 * when the IP addresses are specified in a file. The thing we are looking for
 * here is specifically when users separate addresses with things like
 * commas and spaces.
 */
static int
selftest_massip_parse_range(void)
{
    struct testcases {
        const char *line;
        union {
            struct Range ipv4;
            struct Range6 ipv6;
        } list[4];
    } cases[] = {
        {"0.0.1.0/24,0.0.3.0-0.0.4.0", {{{0x100,0x1ff}}, {{0x300,0x400}}}},
        {"0.0.1.0-0.0.1.255,0.0.3.0-0.0.4.0", {{{0x100,0x1ff}}, {{0x300,0x400}}}},
        {"0.0.1.0/24 0.0.3.0-0.0.4.0", {{{0x100,0x1ff}}, {{0x300,0x400}}}},
        {0}
    };
    size_t i;
    
    for (i=0; cases[i].line; i++) {
        size_t length = strlen(cases[i].line);
        size_t offset = 0;
        size_t j = 0;
        struct Range6 range6;
        struct Range range4;
        
        while (offset < length) {
            int x;
            x = massip_parse_range(cases[i].line, &offset, length, &range4, &range6);
            switch (x) {
                default:
                case Bad_Address:
                    fprintf(stdout, "[-] selftest_massip_parse_range[%u] fail\n", (unsigned)i);
                    return 1;
                case Ipv4_Address:
                    if (cases[i].list[j].ipv4.begin != range4.begin
                        || cases[i].list[j].ipv4.end != range4.end) {
                        fprintf(stdout, "[-] %u.%u.%u.%u - %u.%u.%u.%u\n",
                                (unsigned char)(range4.begin>>24),
                                (unsigned char)(range4.begin>>16),
                                (unsigned char)(range4.begin>> 8),
                                (unsigned char)(range4.begin>> 0),
                                (unsigned char)(range4.end>>24),
                                (unsigned char)(range4.end>>16),
                                (unsigned char)(range4.end>> 8),
                                (unsigned char)(range4.end>> 0)
                                );
                        fprintf(stdout, "[-] selftest_massip_parse_range[%u] fail\n", (unsigned)i);
                        return 1;
                    }
                    break;
            }
            j++;
        }
        
        /* Make sure we have found all the expected cases */
        if (cases[i].list[j].ipv4.begin != 0) {
            fprintf(stdout, "[-] selftest_massip_parse_range[%u] fail\n", (unsigned)i);
            return 1;
        }
    }
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
rangefile6_test_buffer(struct massip_parser *parser,
                       const char *buf,
                       ipv6address expected_begin,
                       ipv6address expected_end)
{
    size_t length = strlen(buf);
    size_t offset = 0;
    ipv6address found_begin = {1,2};
    ipv6address found_end = {1,2};
    unsigned tmp1, tmp2;
    int err;
    
    /* test the entire buffer */
    err = _parser_next(parser, buf, &offset, length, &tmp1, &tmp2);
    if (err == Still_Working)
        err = _parser_next(parser, "\n", 0, 1, &tmp1, &tmp2);
    switch (err) {
    case Found_IPv6:
        /* Extract the resulting IPv6 address from the state structure */
        _parser_get_ipv6(parser, &found_begin, &found_end);
    
        /* Test to see if the parsed address equals the expected address */
        if (!ipv6address_is_equal(found_begin, expected_begin)) {
            ipaddress_formatted_t fmt1 = ipv6address_fmt(found_begin);
            ipaddress_formatted_t fmt2 = ipv6address_fmt(expected_begin);
            fprintf(stderr, "[-] begin mismatch: found=[%s], expected=[%s]\n", fmt1.string, fmt2.string);
            goto fail;
        }
        if (!ipv6address_is_equal(found_end, expected_end)) {
            ipaddress_formatted_t fmt1 = ipv6address_fmt(found_end);
            ipaddress_formatted_t fmt2 = ipv6address_fmt(expected_end);
            fprintf(stderr, "[-] end mismatch: found=[%s], expected=[%s]\n", fmt1.string, fmt2.string);
            goto fail;
        }
        break;
    case Found_IPv4:
        if (expected_begin.hi != 0 || expected_end.hi != 0)
            goto fail;
        if (tmp1 != expected_begin.lo || tmp2 != expected_end.lo)
            goto fail;
        break;
    case Still_Working:
        /* Found a partial address, which is a normal result in the 
         * real world at buffer boundaries, but which is an error
         * here */
        goto fail;
    case Found_Error:
    default:
        goto fail;
    }

    return 0; /* success */
fail:
    return 1; /* failure */
}

/***************************************************************************
 * List of test cases. Each test case contains three parts:
 * - the string representation of an address, as read from a file, meaning
 *   that it can contain additional things like comment strings
 * - the first address of a range, which in the case of IPv6 addresses
 *   will be two 64-bit numbers, but an IPv4 address have a high-order
 *   number set to zero and the low-order number set to the IPv4 address
 * - the second address of a range, which in the case of individual
 *   addresses, will be equal to the first number
 ***************************************************************************/
struct {
    const char *string;
    ipv6address begin;
    ipv6address end;
} test_cases[] = {
    {"[1::1]/126", {0x0001000000000000ULL, 0ULL}, {0x0001000000000000ULL, 3ULL}},
    {"1::1/126", {0x0001000000000000ULL, 0ULL}, {0x0001000000000000ULL, 3ULL}},
    {"[1::1]-[2::3]", {0x0001000000000000ULL, 1ULL}, {0x0002000000000000ULL, 3ULL}},
    {"1::1-2::3", {0x0001000000000000ULL, 1ULL}, {0x0002000000000000ULL, 3ULL}},
    {"[1234:5678:9abc:def0:0fed:cba9:8765:4321]", {0x123456789abcdef0ULL, 0x0fedcba987654321ULL}, {0x123456789abcdef0ULL, 0x0fedcba987654321ULL}},
    {"22ab::1", {0x22ab000000000000ULL, 1ULL}, {0x22ab000000000000ULL, 1ULL}},
    {"240e:33c:2:c080:d08:d0e:b53:e74e", {0x240e033c0002c080ULL, 0x0d080d0e0b53e74eULL}, {0x240e033c0002c080ULL, 0x0d080d0e0b53e74eULL}},
    {"2a03:90c0:105::9", {0x2a0390c001050000ULL, 9ULL}, {0x2a0390c001050000ULL, 9ULL}},
    {"2a03:9060:0:400::2", {0x2a03906000000400ULL, 2ULL}, {0x2a03906000000400ULL, 2ULL}},
    {"2c0f:ff00:0:a:face:b00c:0:a7", {0x2c0fff000000000aULL, 0xfaceb00c000000a7ULL}, {0x2c0fff000000000aULL, 0xfaceb00c000000a7ULL}},
    {"2a01:5b40:0:4a01:0:e21d:789f:59b1", {0x2a015b4000004a01ULL, 0x0000e21d789f59b1ULL}, {0x2a015b4000004a01ULL, 0x0000e21d789f59b1ULL}},
    {"2001:1200:10::1", {0x2001120000100000ULL, 1ULL}, {0x2001120000100000ULL, 1ULL}},
    {"fec0:0:0:ffff::1", {0xfec000000000ffffULL, 1ULL}, {0xfec000000000ffffULL, 1ULL}},
    {"1234:5678:9abc:def0:0fed:cba9:8765:4321", {0x123456789abcdef0ULL, 0x0fedcba987654321ULL}, {0x123456789abcdef0ULL, 0x0fedcba987654321ULL}},
    {"[1111:2222:3333:4444:5555:6666:7777:8888]", {0x1111222233334444ULL, 0x5555666677778888ULL}, {0x1111222233334444ULL, 0x5555666677778888ULL}},
    {"1::1", {0x0001000000000000ULL, 1ULL}, {0x0001000000000000ULL, 1ULL}},
    {"1.2.3.4", {0, 0x01020304}, {0, 0x01020304}},
    {"#test\n  97.86.162.161" "\x96" "97.86.162.175\n", {0, 0x6156a2a1}, {0, 0x6156a2af}},
    {"1.2.3.4/24\n", {0, 0x01020300}, {0, 0x010203ff}},
    {" 1.2.3.4-1.2.3.5\n", {0, 0x01020304}, {0, 0x01020305}},
    {0,{0,0},{0,0}}
};

/***************************************************************************
 * Called during "make test" to run a regression test over this module.
 ***************************************************************************/
int
massip_parse_selftest(void)
{
    int x = 0;
    size_t i;
    struct massip_parser parser[1];

    
    /* Run through the test cases, stopping at the first failure */
    _parser_init(parser);
    for (i=0; test_cases[i].string; i++) {
        x += rangefile6_test_buffer(parser,
                                    test_cases[i].string, 
                                    test_cases[i].begin,
                                    test_cases[i].end);
        if (x) {
            fprintf(stderr, "[-] failed: %u: %s\n", (unsigned)i, test_cases[i].string);
            break;
        }
    }
    _parser_destroy(parser);

    
    /* First, do the single line test */
    x += selftest_massip_parse_range();
    if (x)
        return x;
    

    x += rangefile_test_error("#bad ipv4\n 257.1.1.1\n", 2, 5, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.257.1.1.1\n", 2, 6, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.257.1.1.1\n", 2, 9, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.255.256.1.1.1\n", 2, 13, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.1.1.1.1\n", 2, 9, __LINE__);

    if (x)
       LOG(0, "[-] rangefile_selftest: fail\n");
    return x;
}

