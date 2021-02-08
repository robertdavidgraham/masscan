#include "main-readrange.h"
#include "masscan.h"
#include <assert.h>

/***************************************************************************
 ***************************************************************************/
static unsigned
count_cidr_bits(struct Range range)
{
    unsigned i;

    for (i=0; i<32; i++) {
        unsigned mask = 0xFFFFFFFF >> i;

        if ((range.begin & ~mask) == (range.end & ~mask)) {
            if ((range.begin & mask) == 0 && (range.end & mask) == mask)
                return i;
        }
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static unsigned
count_cidr6_bits(struct Range6 range)
{
    uint64_t i;

    /* Kludge: can't handle more than 64-bits of CIDR ranges */
    if (range.begin.hi != range.begin.lo)
        return 0;

    for (i=0; i<64; i++) {
        uint64_t mask = 0xFFFFFFFFffffffffull >> i;

        if ((range.begin.lo & ~mask) == (range.end.lo & ~mask)) {
            if ((range.begin.lo & mask) == 0 && (range.end.lo & mask) == mask)
                return (unsigned)i;
        }
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
void
main_readrange(struct Masscan *masscan)
{
    struct RangeList *list4 = &masscan->targets.ipv4;
    struct Range6List *list6 = &masscan->targets.ipv6;
    unsigned i;
    FILE *fp = stdout;

    for (i=0; i<list4->count; i++) {
        struct Range range = list4->list[i];
        fprintf(fp, "%u.%u.%u.%u",
            (range.begin>>24)&0xFF,
            (range.begin>>16)&0xFF,
            (range.begin>> 8)&0xFF,
            (range.begin>> 0)&0xFF
            );
        if (range.begin != range.end) {
            unsigned cidr_bits = count_cidr_bits(range);

            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else {
                fprintf(fp, "-%u.%u.%u.%u",
                    (range.end>>24)&0xFF,
                    (range.end>>16)&0xFF,
                    (range.end>> 8)&0xFF,
                    (range.end>> 0)&0xFF
                    );
            }
        }
        fprintf(fp, "\n");
    }

    for (i=0; i<list6->count; i++) {
        struct Range6 range = list6->list[i];
        ipaddress_formatted_t fmt = ipv6address_fmt(range.begin);
        fprintf(fp, "%s", fmt.string);
        if (!ipv6address_is_equal(range.begin, range.end)) {
            unsigned cidr_bits = count_cidr6_bits(range);
            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else {
                fmt = ipv6address_fmt(range.end);
                fprintf(fp, "-%s", fmt.string);
            }
        }
        fprintf(fp, "\n");
    }

}
