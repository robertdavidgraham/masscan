#include "range-file.h"
#include "ranges.h"
#include "ranges6.h"
#include "util-malloc.h"

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
};

static struct RangeParser *
rangeparse_create(void)
{
    struct RangeParser *result;
    
    result = CALLOC(1, sizeof(*result));
    
    return result;
}
static void
rangeparse_destroy(struct RangeParser *p)
{
    free(p);
}

static void
rangeparse_err(struct RangeParser *p, unsigned long long *line_number, unsigned long long *charindex)
{
    *line_number = p->line_number;
    *charindex = p->char_number;
}

static int
rangeparse_next(struct RangeParser *p, const unsigned char *buf, size_t *r_offset, size_t length,
                unsigned *r_begin, unsigned *r_end)
{
    size_t i = *r_offset;
    unsigned state = p->state;
    enum {
        LINE_START, ADDR_START,
        COMMENT,
        NUMBER0, NUMBER1, NUMBER2, NUMBER3, NUMBER_ERR,
        SECOND0, SECOND1, SECOND2, SECOND3, SECOND_ERR,
        CIDR,
        ERROR
    };
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
                    default:
                        state = ERROR;
                        length = i; /* break out of loop */
                        break;
                }
                break;
            case COMMENT:
                if (c == '\n') {
                    state = LINE_START;
                    p->line_number++;
                    p->char_number = 0;
                }
                break;
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
                            continue;
                        }
                        break;
                    case '-':
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
                                p->char_number++;
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
                                p->char_number++;
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
 ***************************************************************************/
/***************************************************************************
 ***************************************************************************/
int
rangefile_test_buffer(const char *buf)
{
    return 0;
}

/***************************************************************************
 * Called during "make test" to run a regression test over this module.
 ***************************************************************************/
int
rangefile_test(void)
{
    return 0;

    
}

