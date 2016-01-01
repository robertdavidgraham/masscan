#include "in-filter.h"
#include "ranges.h"

int
readscan_filter_pass(unsigned ip, unsigned port, unsigned type,
              const struct RangeList *ips,
              const struct RangeList *ports,
              const struct RangeList *btypes)
{
    if (ips && ips->count) {
        if (!rangelist_is_contains(ips, ip))
            return 0;
    }
    if (ports && ports->count) {
        if (!rangelist_is_contains(ports, port))
            return 0;
    }
    if (btypes && btypes->count) {
        if (!rangelist_is_contains(btypes, type))
            return 0;
    }

    return 1;
}
