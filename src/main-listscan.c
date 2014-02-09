#include "masscan.h"
#include "logger.h"
#include "rand-blackrock.h"

void
main_listscan(struct Masscan *masscan)
{
    uint64_t count_ips;
    uint64_t count_ports;
    uint64_t i;
    uint64_t range;
    uint64_t start;
    uint64_t end;
    struct BlackRock blackrock;
    unsigned increment = masscan->shard.of;
    uint64_t seed = masscan->seed;

    count_ports = rangelist_count(&masscan->ports);
    if (count_ports == 0)
        rangelist_add_range(&masscan->ports, 80, 80);
    count_ports = rangelist_count(&masscan->ports);

    count_ips = rangelist_count(&masscan->targets);
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return;
    }

    range = count_ips * count_ports;

infinite:
    blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

    start = masscan->resume.index + (masscan->shard.one-1);
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += (uint64_t)(masscan->retries * masscan->max_rate);

//printf("start=%llu, end=%llu\n", start, end);
    for (i=start; i<end; ) {
        uint64_t xXx;
        unsigned ip;
        unsigned port;

        xXx = blackrock_shuffle(&blackrock,  i);

        ip = rangelist_pick(&masscan->targets, xXx % count_ips);
        port = rangelist_pick(&masscan->ports, xXx / count_ips);

        if (count_ports == 1) {
            if (masscan->is_test_csv) {
                /* [KLUDGE] [TEST]
                 * For testing randomness output, prints last two bytes of
                 * IP address as CSV format for import into spreadsheet
                 */
                printf("%u,%u\n",
                       (ip>>8)&0xFF, (ip>>0)&0xFF
                       );
            } else {
                printf("%u.%u.%u.%u\n",
                       (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF
                       );
            }
        } else
            printf("%u.%u.%u.%u:%u\n",
                   (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF,
                   port
                   );

        i += increment; /* <------ increment by 1 normally, more with shards/nics */
    }

    if (masscan->is_infinite) {
        seed++;
        goto infinite;
    }
}
