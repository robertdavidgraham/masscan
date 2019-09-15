#include "range-file.h"
#include "ranges.h"
#include "ranges6.h"
#include "logger.h"
#include "util-bool.h"
#include "util-malloc.h"
#include "string_s.h"

#include <string.h>

struct RangeParser
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
        unsigned char begin[16];
        unsigned char end[16];
        unsigned short tmp[8];
        unsigned char index;
        unsigned char ellision_index;
        unsigned is_bracket:1;
        unsigned is_second:1;
    } ipv6;
};

/***************************************************************************
 ***************************************************************************/
static struct RangeParser *
rangeparse_create(void)
{
    struct RangeParser *result;
    
    result = CALLOC(1, sizeof(*result));
    result->line_number = 1;    
    return result;
}

/***************************************************************************
 ***************************************************************************/
static void
rangeparse_destroy(struct RangeParser *p)
{
    free(p);
}

/***************************************************************************
 ***************************************************************************/
static void
rangeparse_err(struct RangeParser *p, unsigned long long *line_number, unsigned long long *charindex)
{
    *line_number = p->line_number;
    *charindex = p->char_number;
}

static void
ipv6_init(struct RangeParser *p)
{
    memset(&p->ipv6, 0, sizeof(p->ipv6));
}


static unsigned
ipv6_finish_number(struct RangeParser *p, unsigned char c)
{
    unsigned index = p->ipv6.index;
    unsigned ellision = p->ipv6.ellision_index;
    
    /* We must have seen 8 numbers, or an ellision */
    if (index < 7 && ellision >= 8)
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
        sizeof(p->ipv6.tmp[0]) * (7 - index)
    );
    
    /* Copy over to begin/end */
    if (p->ipv6.is_second)
        memcpy(p->ipv6.end, p->ipv6.tmp, sizeof(p->ipv6.end));
    else
        memcpy(p->ipv6.begin, p->ipv6.tmp, sizeof(p->ipv6.begin));

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static void
rangeparse_getipv6(struct RangeParser *p, ipv6address *begin, ipv6address *end)
{
    const unsigned char *address;
    
    address = p->ipv6.begin;
    begin->hi =    (((uint64_t)address[0]) << 56ULL)
    | ((uint64_t)address[1] << 48ULL)
    | ((uint64_t)address[2] << 40ULL)
    | ((uint64_t)address[3] << 32ULL)
    | ((uint64_t)address[4] << 24ULL)
    | ((uint64_t)address[5] << 16ULL)
    | ((uint64_t)address[6] <<  8ULL)
    | ((uint64_t)address[7] <<  0ULL);
    begin->lo =    ((uint64_t)address[ 8] << 56ULL)
    | ((uint64_t)address[ 9] << 48ULL)
    | ((uint64_t)address[10] << 40ULL)
    | ((uint64_t)address[11] << 32ULL)
    | ((uint64_t)address[12] << 24ULL)
    | ((uint64_t)address[13] << 16ULL)
    | ((uint64_t)address[14] <<  8ULL)
    | ((uint64_t)address[15] <<  0ULL);
    
    memcpy(end, begin, sizeof(*begin));
}

/***************************************************************************
 ***************************************************************************/
static int
rangeparse_next(struct RangeParser *p, const unsigned char *buf, size_t *r_offset, size_t length,
                unsigned *r_begin, unsigned *r_end)
{
    size_t i = *r_offset;
    enum RangeState {
        LINE_START, ADDR_START,
        COMMENT,
        NUMBER0, NUMBER1, NUMBER2, NUMBER3, NUMBER_ERR,
        SECOND0, SECOND1, SECOND2, SECOND3, SECOND_ERR,
        CIDR,
        UNIDASH1, UNIDASH2,
        IPV6_NUM, IPV6_COLON, IPV6_CIDR, IPV6_ENDBRACKET,
        ERROR
    } state = p->state;
    int result = 0;
    
    while (i < length) {
        unsigned char c = buf[i++];
        p->char_number++;
        switch (state) {
            case LINE_START:
            case ADDR_START:
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
                        ipv6_init(p);
                        p->tmp = (c - 'a' + 10);
                        p->digit_count = 1;
                        state = IPV6_NUM;
                        break;
                    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        ipv6_init(p);
                        p->tmp = (c - 'A' + 10);
                        p->digit_count = 1;
                        state = IPV6_NUM;
                        break;
                    case '[':
                        ipv6_init(p);
                        p->ipv6.is_bracket = 1;
                        state = IPV6_NUM;
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
                /* drop down */
            case IPV6_NUM:
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
                            p->ipv6.tmp[p->ipv6.index++] = p->tmp;
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
                        p->ipv6.tmp[p->ipv6.index++] = p->tmp;
                        if (ipv6_finish_number(p, c) != 0) {
                            state = ERROR;
                            length = i;
                            break;
                        }
                        switch (c) {
                            case '/':
                                state = IPV6_CIDR;
                                break;
                            case ']':
                                if (!p->ipv6.is_bracket) {
                                    state = ERROR;
                                    length = i;
                                } else {
                                    state = IPV6_ENDBRACKET;
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
                                /* Return the address */
                            case '-':
                                break;
                        }
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
                            result = 1;
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
                        if (p->digit_count == 3) {
                            state = ERROR;
                            length = i; /* break out of loop */
                        } else {
                            p->digit_count++;
                            p->tmp = p->tmp * 10 + (c - '0');
                            if (p->tmp > 255) {
                                state = ERROR;
                                length = i;
                            }
                            continue;
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
                            result = 1;
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
                            result = 1;
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
    
    *r_offset = i;
    p->state = state;
    if (state == ERROR || state == NUMBER_ERR || state == SECOND_ERR)
        result = -1;
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
    struct RangeParser *p;
    unsigned out_begin = 0xa3a3a3a3;
    unsigned out_end  = 0xa3a3a3a3;
    unsigned long long out_line_number;
    unsigned long long out_char_number;
    int x;
    bool is_found = false;

    /* test the entire buffer */
    p = rangeparse_create();
    x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &out_begin, &out_end);
    if (!(x < 0))
        goto fail;
    rangeparse_err(p, &out_line_number, &out_char_number);
    rangeparse_destroy(p);
    if (in_line_number != out_line_number || in_char_number != out_char_number)
        goto fail;

    /* test one byte at a time */
    p = rangeparse_create();
    offset = 0;
    out_begin = 0xa3a3a3a3;
    out_end  = 0xa3a3a3a3;
    is_found = false;
    while (offset < length) {
        x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &out_begin, &out_end);
        if (x == 0 || x > 1)
            continue;
        is_found = true;
        rangeparse_err(p, &out_line_number, &out_char_number);
        if (in_line_number != out_line_number || in_char_number != out_char_number)
            goto fail;
        else
            break;
    }
    rangeparse_destroy(p);
    if (!is_found)
        goto fail;

    return 0;
fail:
    fprintf(stderr, "[-] rangefile test fail, line=%u\n", which_test);
    return 1;
}

/***************************************************************************
 ***************************************************************************/
int
rangefile_read(const char *filename, struct RangeList *targets_ipv4, struct Range6List *targets_ipv6)
{
    struct RangeParser *p;
    unsigned char buf[65536];
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
    p = rangeparse_create();

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
            int x;
            unsigned begin, end;

            x = rangeparse_next(p, buf, &offset, count, &begin, &end);
            if (x < 0) {
                unsigned long long line_number, char_number;
                rangeparse_err(p, &line_number, &char_number);
                fprintf(stderr, "%s:%llu:%llu: parse err\n", filename, line_number, char_number);
                is_error = true;
                break;
            } else if (x == 1) {
                rangelist_add_range(targets_ipv4, begin, end);
                addr_count++;
            } else if (x == 0) {
                if (offset < count)
                    fprintf(stderr, "[-] fail\n");
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
        x = rangeparse_next(p, (const unsigned char *)"\n", &offset, 1, &begin, &end);
        if (x < 0) {
            unsigned long long line_number, char_number;
            rangeparse_err(p, &line_number, &char_number);
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


/***************************************************************************
 ***************************************************************************/
static int
rangefile_test_buffer(const char *buf, unsigned in_begin, unsigned in_end)
{
    size_t length = strlen(buf);
    size_t offset = 0;
    struct RangeParser *p;
    unsigned out_begin = 0xa3a3a3a3;
    unsigned out_end  = 0xa3a3a3a3;
    int x;
    bool is_found = false;

    /* test the entire buffer */
    p = rangeparse_create();
    x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &out_begin, &out_end);
    if (x != 1)
        return 1; /*fail*/
    if (in_begin != out_begin || in_end != out_end)
        return 1; /*fail*/
    rangeparse_destroy(p);

    /* test one byte at a time */
    p = rangeparse_create();
    offset = 0;
    out_begin = 0xa3a3a3a3;
    out_end  = 0xa3a3a3a3;
    is_found = false;
    while (offset < length) {
        x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &out_begin, &out_end);
        if (x == 0)
            continue;
        if (x < 0)
            return 1; /*fail*/
        is_found = true;    
        if (in_begin != out_begin || in_end != out_end)
            return 1; /*fail*/
    }
    rangeparse_destroy(p);
    if (!is_found)
        return 1; /*fail*/

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int
rangefile6_test_buffer(const char *buf,
                       uint64_t in_begin_hi,
                       uint64_t in_begin_lo,
                       uint64_t in_end_hi,
                       uint64_t in_end_lo)
{
    size_t length = strlen(buf);
    size_t offset = 0;
    struct RangeParser *p;
    ipv6address out_begin = {1,2};
    ipv6address out_end = {1,2};
    unsigned tmp1, tmp2;
    int x;
    bool is_found = false;
    
    /* test the entire buffer */
    p = rangeparse_create();
    x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &tmp1, &tmp2);
    if (x != 2)
        return 1; /*fail*/
    rangeparse_getipv6(p, &out_begin, &out_end);
    if (out_begin.hi != in_begin_hi || out_begin.lo != in_begin_lo)
        return 1; /*fail*/
    if (out_end.hi != in_end_hi || out_end.lo != in_end_lo)
        return 1; /*fail*/
    rangeparse_destroy(p);
    
    /* test one byte at a time */
    p = rangeparse_create();
    offset = 0;
    out_begin.hi = 1;
    out_begin.lo = 2;
    out_end.hi = 1;
    out_end.lo = 2;
    is_found = false;
    while (offset < length) {
        x = rangeparse_next(p, (const unsigned char *)buf, &offset, length, &tmp1, &tmp2);
        if (x == 0)
            continue;
        if (x != 2)
            return 1; /*fail*/
        is_found = true;
        rangeparse_getipv6(p, &out_begin, &out_end);
        if (out_begin.hi != in_begin_hi || out_begin.lo != in_begin_lo)
            return 1; /*fail*/
        if (out_end.hi != in_end_hi || out_end.lo != in_end_lo)
            return 1; /*fail*/
    }
    rangeparse_destroy(p);
    if (!is_found)
        return 1; /*fail*/
    
    return 0;
}

/***************************************************************************
 * Called during "make test" to run a regression test over this module.
 ***************************************************************************/
int
rangefile_selftest(void)
{
    int x = 0;

    /*x += rangefile6_test_buffer("#test\n  1111:2222:3333:4444:5555:6666:7777:8888\n",
                               0x1111222233334444ULL,
                               0x5555666677778888ULL,
                               0x1111222233334444ULL,
                               0x5555666677778888ULL
                               );*/

    x += rangefile_test_buffer("#test\n  97.86.162.161" "\x96" "97.86.162.175\n", 0x6156a2a1, 0x6156a2af);
    x += rangefile_test_buffer("#test\n  1.2.3.4\n", 0x01020304, 0x01020304);
    x += rangefile_test_buffer("#test\n  1.2.3.4/24\n", 0x01020300, 0x010203ff);
    x += rangefile_test_buffer("#test\n  1.2.3.4-1.2.3.5\n", 0x01020304, 0x01020305);



    x += rangefile_test_error("#bad ipv4\n 257.1.1.1\n", 2, 4, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.257.1.1.1\n", 2, 6, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.257.1.1.1\n", 2, 9, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.10.255.256.1.1.1\n", 2, 13, __LINE__);
    x += rangefile_test_error("#bad ipv4\n 1.1.1.1.1\n", 2, 9, __LINE__);

    //test_file("../ips.txt");
    if (x)
       LOG(0, "[-] rangefile_selftest: fail\n");
    return x;
}

