#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"

static size_t bitmap_buffer_size = 0x100000000 / 8;
static uint64_t * bitmap_buffer;

/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    bitmap_buffer = (uint64_t *) malloc(bitmap_buffer_size);
    if (bitmap_buffer == NULL) {
      perror("malloc");
      exit(1);
    }
    memset(bitmap_buffer, 0, bitmap_buffer_size);
    out->rotate.bytes_written += 0;
}


/****************************************************************************
 ****************************************************************************/
static void
bitmap_out_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    if (fp) {
      if (fwrite(bitmap_buffer, bitmap_buffer_size, 1, fp) == 1) {
        fflush(fp);
        out->rotate.bytes_written += bitmap_buffer_size;
      }
    }
    free(bitmap_buffer);
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
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

    uint64_t l = 1ULL << (ip % 64);
    bitmap_buffer[ip / 64] |= l;

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
    UNUSEDPARM(out);
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


