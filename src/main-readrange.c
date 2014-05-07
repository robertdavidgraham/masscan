#include "main-readrange.h"
#include "ranges.h"
#include "masscan.h"

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
void
main_readrange(struct Masscan *masscan)
{
    struct RangeList *list = &masscan->targets;
    unsigned i;
    FILE *fp = stdout;

    for (i=0; i<list->count; i++) {
        struct Range range = list->list[i];
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
            } else
            fprintf(fp, "-%u.%u.%u.%u",
                (range.end>>24)&0xFF,
                (range.end>>16)&0xFF,
                (range.end>> 8)&0xFF,
                (range.end>> 0)&0xFF
                );
        }
        fprintf(fp, "\n");
    }


}
