#include "masscan.h"
#include "logger.h"
#include "rand-blackrock.h"


void
main_listscan(struct Masscan *masscan)
{
    uint64_t i;
    uint64_t range;
    uint64_t start;
    uint64_t end;
    struct BlackRock blackrock;
    unsigned increment = masscan->shard.of;
    uint64_t seed = masscan->seed;

    /* If called with no ports, then create a pseudo-port needed
     * for the internal algorithm. */
    if (!massip_has_target_ports(&masscan->targets))
        rangelist_add_range(&masscan->targets.ports, 80, 80);
    massip_optimize(&masscan->targets);

    /* The "range" is the total number of IP/port combinations that
     * the scan can produce */
    range = massip_range(&masscan->targets).lo;


infinite:
    blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

    start = masscan->resume.index + (masscan->shard.one-1);
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += (uint64_t)(masscan->retries * masscan->max_rate);

    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned port;
        ipaddress addr;

        xXx = blackrock_shuffle(&blackrock,  i);

        massip_pick(&masscan->targets, xXx, &addr, &port);
        

        if (masscan->is_test_csv) {
            /* [KLUDGE] [TEST]
             * For testing randomness output, prints last two bytes of
             * IP address as CSV format for import into spreadsheet
             */
            printf("%u,%u\n",(addr.ipv4>>8)&0xFF, (addr.ipv4>>0)&0xFF);
        } else if (masscan->targets.count_ports == 1) {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            /* This is the normal case */
            printf("%s\n", fmt.string);
        } else {
            ipaddress_formatted_t fmt = ipaddress_fmt(addr);
            if (addr.version == 6)
                printf("[%s]:%u\n", fmt.string, port);
            else
                printf("%s:%u\n", fmt.string, port);
        }

        i += increment; /* <------ increment by 1 normally, more with shards/NICs */
    }

    if (masscan->is_infinite) {
        seed++;
        goto infinite;
    }
}
