#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "stats.h"

void
init_stats(stats_t **s, const char *filename)
{
    int stats_fd;
    void *addr;

    if ((stats_fd = open(name, O_RDWR, S_IRUSR | S_IWUSR)) == -1) {
        perror("open");
        exit(1);
    }

    if ((addr = mmap(NULL, sizeof(stats_t), PROT_WRITE, MAP_FILE | MAP_SHARED, stats_fd, 0)) == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    *s = addr;
}
