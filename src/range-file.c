#include "range-file.h"
#include "ranges.h"
#include "ranges6.h"
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

    /* Reset the parser */
    p->ipv6.ellision_index = 8;
    p->ipv6.index = 0;
    p->ipv6.is_second = 1;

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
    CIDR,
    UNIDASH1, UNIDASH2,
    IPV6_BEGIN, IPV6_COLON, IPV6_CIDR, IPV6_ENDBRACKET, 
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
                p->ipv6.ellision_index = 8;
                p->ipv6.index = 0;
                p->ipv6.is_bracket = 0;
                p->ipv6.is_second = 0;
                p->digit_count = 0;
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
            case IPV6_END:
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
                    case '/':
                    case ']':
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                    case ',':
                    case '-':
                        /* All the things that end an IPv6 address */
                        p->ipv6.tmp[p->ipv6.index++] = (unsigned short)p->tmp;
                        if (_parser_finish_ipv6(p) != 0) {
                            state = ERROR;
                            length = i;
                            break;
                        } else {
                            state = IPV6_END;
                            result = Found_Error;
                            length = i;
                        }

                        switch (c) {
                            case '/':
                                result = Still_Working;
                                state = IPV6_CIDR;
                                break;
                            case ']':
                                if (!p->ipv6.is_bracket) {
                                    result = Found_Error;
                                    state = ERROR;
                                    length = i;
                                } else {
                                    state = IPV6_ENDBRACKET;
                                    result = Still_Working;
                                    length = i; /* break out of loop */
                                }
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
                                /* Return the address */
                                length = i; /* break out of loop */
                                break;

                            case '-':
                                result = Still_Working;
                                /* Continue parsing the next IPv6 address */
                                break;
                        }
                        break;
                    default:
                        state = ERROR;
                        length = i;
                        break;
                }
                break;
            case IPV6_ENDBRACKET:
                switch (c) {
                    case '/':
                        result = Found_IPv6;
                        state = IPV6_CIDR;
                        break;
                    case '\n':
                        p->line_number++;
                        p->char_number = 0;
                        /* drop down */
                    case ' ':
                    case '\t':
                    case '\r':
                    case ',':
                        /* We have found a single address, so return that address */
                        result = Found_IPv6;
                        state = 0;
                        length = i;
                        break;
                    case '-':
                        result = Still_Working;
                        state = IPV6_END;
                        break;
                    default:
                    case ']':
                        result = Found_Error;
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
            case CIDR:
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
                            unsigned long long prefix = p->tmp;
                            unsigned long long mask = 0xFFFFFFFF00000000ULL >> prefix;
                            
                            /* mask off low-order bits */
                            p->begin &= (unsigned)mask;

                            /* Set all suffix bits to 1, so that 192.168.1.0/24 has
                             * an ending address of 192.168.1.255. */
                            p->end = p->begin | (unsigned)~mask;


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
                            state = CIDR;
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
massip_parse_file(const char *filename, struct RangeList *targets_ipv4, struct Range6List *targets_ipv6)
{
    struct massip_parser p[1];
    char buf[65536];
    FILE *fp = NULL;
    int err;
    bool is_error = false;
    unsigned addr_count = 0;

    /*
     * Open the file containing IP addresses, which can potentially be
     * many megabytes in size
     */
    err = fopen_s(&fp, filename, "rb");
    if (err || fp == NULL) {
        perror(filename);
        exit(1);
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
        unsigned long long line_number, char_number;

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
                fprintf(stderr, "%s:%llu:%llu: parse err\n", filename, line_number, char_number);
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
    fclose(fp);

    /* In case the file doesn't end with a newline '\n', then artificially
     * add one to the end */
    if (!is_error) {
        int x;
        size_t offset = 0;
        unsigned begin, end;
        x = _parser_next(p, "\n", &offset, 1, &begin, &end);
        if (x < 0) {
            unsigned long long line_number, char_number;
            _parser_err(p, &line_number, &char_number);
            fprintf(stderr, "%s:%llu:%llu: parse err\n", filename, line_number, char_number);
            is_error = true;
        } else if (x == 1) {
            rangelist_add_range(targets_ipv4, begin, end);
            addr_count++;
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
    
    /* Creat e parser object */
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
                       uint64_t expected_begin_hi,
                       uint64_t expected_begin_lo,
                       uint64_t expected_end_hi,
                       uint64_t expected_end_lo)
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
        if (found_begin.hi != expected_begin_hi || found_begin.lo != expected_begin_lo)
            goto fail;
        if (found_end.hi != expected_end_hi || found_end.lo != expected_end_lo)
            goto fail;
        break;
    case Found_IPv4:
        if (expected_begin_hi != 0 || expected_end_hi != 0)
            goto fail;
        if (tmp1 != expected_begin_lo || tmp2 != expected_end_lo)
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
    uint64_t begin_hi;
    uint64_t begin_lo;
    uint64_t end_hi;
    uint64_t end_lo;
} test_cases[] = {
    {"22ab::1", 0x22ab000000000000ULL, 1ULL, 0x22ab000000000000ULL, 1ULL},
    {"240e:33c:2:c080:d08:d0e:b53:e74e", 0x240e033c0002c080ULL, 0x0d080d0e0b53e74e, 0x240e033c0002c080, 0x0d080d0e0b53e74e},
    {"2a03:90c0:105::9", 0x2a0390c001050000ULL, 9ULL, 0x2a0390c001050000ULL, 9ULL},
    {"2a03:9060:0:400::2", 0x2a03906000000400ULL, 2ULL, 0x2a03906000000400, 2ULL},
    {"2c0f:ff00:0:a:face:b00c:0:a7", 0x2c0fff000000000aULL, 0xfaceb00c000000a7ULL, 0x2c0fff000000000aULL, 0xfaceb00c000000a7ULL, },
    {"2a01:5b40:0:4a01:0:e21d:789f:59b1", 0x2a015b4000004a01ULL, 0x0000e21d789f59b1, 0x2a015b4000004a01ULL, 0x0000e21d789f59b1},
    {"2001:1200:10::1", 0x2001120000100000ULL, 1ULL, 0x2001120000100000ULL, 1ULL},
    {"fec0:0:0:ffff::1", 0xfec000000000ffffULL, 1ULL, 0xfec000000000ffffULL, 1ULL},
    {"1234:5678:9abc:def0:0fed:cba9:8765:4321", 0x123456789abcdef0ULL, 0x0fedcba987654321ULL, 0x123456789abcdef0ULL, 0x0fedcba987654321ULL},
    {"[1234:5678:9abc:def0:0fed:cba9:8765:4321]", 0x123456789abcdef0ULL, 0x0fedcba987654321ULL, 0x123456789abcdef0ULL, 0x0fedcba987654321ULL},
    {"[1111:2222:3333:4444:5555:6666:7777:8888]", 0x1111222233334444ULL, 0x5555666677778888ULL, 0x1111222233334444ULL, 0x5555666677778888ULL},
    {"1::1", 0x0001000000000000ULL, 1ULL, 0x0001000000000000ULL, 1ULL},
    {"1.2.3.4", 0, 0x01020304, 0, 0x01020304},
    {"#test\n  97.86.162.161" "\x96" "97.86.162.175\n", 0, 0x6156a2a1, 0, 0x6156a2af},
    {"1.2.3.4/24\n", 0, 0x01020300, 0, 0x010203ff},
    {" 1.2.3.4-1.2.3.5\n", 0, 0x01020304, 0, 0x01020305},
    {0,0,0,0,0}
};

/***************************************************************************
 * Called during "make test" to run a regression test over this module.
 ***************************************************************************/
int
massip_selftest(void)
{
    int x = 0;
    size_t i;
    struct massip_parser parser[1];

    /* First, do the sginle line test */
    x = selftest_massip_parse_range();
    if (x)
        return x;
    
    /* Run through the test cases, stopping at the first failure */
    _parser_init(parser);
    for (i=0; test_cases[i].string; i++) {
        x += rangefile6_test_buffer(parser,
                                    test_cases[i].string, 
                                    test_cases[i].begin_hi,
                                    test_cases[i].begin_lo,
                                    test_cases[i].end_hi,
                                    test_cases[i].end_lo);
        if (x) {
            fprintf(stderr, "[-] parse IP address: test failed on string: %s\n", test_cases[i].string);
            break;
        }
    }
    _parser_destroy(parser);

    
    

    x += rangefile_test_error("#bad ipv4\n 257.1.1.1\n", 2, 5, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.257.1.1.1\n", 2, 6, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.257.1.1.1\n", 2, 9, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.255.256.1.1.1\n", 2, 13, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.1.1.1.1\n", 2, 9, __LINE__);

    if (x)
       LOG(0, "[-] rangefile_selftest: fail\n");
    return x;
}

