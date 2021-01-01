#include "in-filter.h"
#include "massip.h"


int
readscan_filter_pass(ipaddress ip, unsigned port, unsigned type,
              const struct MassIP *filter,
              const struct RangeList *btypes)
{
    if (filter && filter->count_ipv4s) {
        if (!massip_has_ip(filter, ip))
            return 0;
    }
    if (filter && filter->count_ports) {
        if (!massip_has_port(filter, port))
            return 0;
    }
    if (btypes && btypes->count) {
        if (!rangelist_is_contains(btypes, type))
            return 0;
    }

    return 1;
}
