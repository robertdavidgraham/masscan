/*
    TCP connection table
*/
#include <stdio.h>
#include <stdint.h>

#define is_power_of_2(x) ((((x)-1) & (x)) == 0)

struct TCP_ConnectionTable {
    int x;
};


struct TCP_ConnectionTable *
tcpcon_create(size_t entry_count)
{
    struct TCP_ConnectionTable *tcpcon;

    return 0;
}


