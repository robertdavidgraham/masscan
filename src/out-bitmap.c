#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"
#include "stats.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <sys/mman.h>

#define BITMAP_SIZE 512 * 1024 * 1024

static atomic_uint_fast64_t *g_bmp;
static stats_t *g_stats;

/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_open(struct Output *out, FILE *fp)
{
    void *addr;
    if ((addr = mmap(NULL, BITMAP_SIZE, PROT_WRITE, MAP_FILE | MAP_SHARED, fileno(fp), 0)) == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    g_bmp = (atomic_uint_fast64_t *)addr;

    init_stats(&g_stats, STATS_NAME);

    out->rotate.bytes_written += 0;
}


/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(status);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

    uint64_t idx = ip / 64;
    uint64_t pos = 1ULL << (ip % 64);

    atomic_fetch_or(&g_bmp[idx], pos);
    atomic_fetch_add(&stats->recv, 1);

    out->rotate.bytes_written += 0;
}


/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(proto);
    UNUSEDPARM(ttl);
    UNUSEDPARM(px);
    UNUSEDPARM(length);

    // Not used for bitmap so far
    out->rotate.bytes_written += 0;
}


/****************************************************************************
 ****************************************************************************/
const struct OutputType bitmap_output = {
    "bitmap",
    0,
    bitmap_out_open,
    bitmap_out_close,
    bitmap_out_status,
    bitmap_out_banner,
};


