#ifndef PROTO_BANOUT_H
#define PROTO_BANOUT_H

/**
 * A structure for tracking one or more banners from a target.
 * There can be multiple banner information from a target, such
 * as SSL certificates, or HTTP headers separate from HTML
 * content, and so on.
 */
struct BannerOutput {
    struct BannerOutput *next;
    unsigned protocol;
    unsigned length;
    unsigned max_length;
    unsigned char banner[200];
};

void
banout_init(struct BannerOutput *banout);

void
banout_release(struct BannerOutput *banout);

void
banout_newline(struct BannerOutput *banout, unsigned proto);

void
banout_end(struct BannerOutput *banout, unsigned proto);

void
banout_append(struct BannerOutput *banout, unsigned proto, const void *px, size_t length);

void
banout_append_char(struct BannerOutput *banout, unsigned proto, int c);

const unsigned char *
banout_string(const struct BannerOutput *banout, unsigned proto);

unsigned
banout_string_length(const struct BannerOutput *banout, unsigned proto);

int
banout_selftest(void);

#endif
