#ifndef PROTO_BANOUT_H
#define PROTO_BANOUT_H
struct BannerBase64;

/**
 * A structure for tracking one or more banners from a target.
 * There can be multiple banner information from a target, such
 * as SSL certificates, or HTTP headers separate from HTML
 * content, and so on. This will be exploited more in the future
 * for extracting multiple bits of information from the same
 * port, but giving them different labels. This will also be
 * used for doing optional stuff, such as grabbing the entire
 * default webpage when connecting to port 80.
 */
struct BannerOutput {
    struct BannerOutput *next;
    unsigned protocol;
    unsigned length;
    unsigned max_length;
    unsigned char banner[200];
};

/**
 * Initialize the list of banners. This doesn't allocate any
 * memory, such sets it to zero.
 */
void
banout_init(struct BannerOutput *banout);

/**
 * Release any memory. If the list contains only one short
 * banner, then no memory was allocated, so nothing gets
 * freed.
 */
void
banout_release(struct BannerOutput *banout);

/**
 * Just appends a newline '\n' character. In the future, this may do something
 * more interesting, which is why it's a separate function.
 */
void
banout_newline(struct BannerOutput *banout, unsigned proto);

/**
 * End the banner of the current. This is called when the protocol parser
 * knows it's at the end. The major reason for this is processing the
 * SSL certficates, so that each certificate comes back as a separate
 * banner.
 */
void
banout_end(struct BannerOutput *banout, unsigned proto);

/**
 * Append text onto the banner. If this exceeds the buffer, then the
 * buffer will be expanded.
 */
void
banout_append(struct BannerOutput *banout, unsigned proto, const void *px, size_t length);
#define AUTO_LEN ((size_t)~0)

/**
 * Append a single character to the banner.
 */
void
banout_append_char(struct BannerOutput *banout, unsigned proto, int c);

/**
 * Append an integer, with hex digits, with the specified number of
 * digits
 */
void
banout_append_hexint(struct BannerOutput *banout, unsigned proto, unsigned long long number, int digits);

void
banout_append_unicode(struct BannerOutput *banout, unsigned proto, unsigned c);

/**
 * Select a specific string (of the specified protocol).
 */
const unsigned char *
banout_string(const struct BannerOutput *banout, unsigned proto);

/**
 * Get the length of a specific string of the specified protocol.
 */
unsigned
banout_string_length(const struct BannerOutput *banout, unsigned proto);


/**
 * Prepare to start calling banout_append_base64()
 */
void
banout_init_base64(struct BannerBase64 *base64);

/**
 * Converts the string to BASE64 and appends it to the banner.
 * Since this can be called iteratively as new input arrives,
 * a call to banout_init_base64() must be called before the first fragment,
 * and a call to banout_finalize_base64() must be called after the last
 * fragment
 */
void
banout_append_base64(struct BannerOutput *banout, unsigned proto,
                     const void *px, size_t length,
                     struct BannerBase64 *base64);

/**
 * Finish encoding the BASE64 string, appending the '==' things on the
 * end if necessary
 */
void
banout_finalize_base64(struct BannerOutput *banout, unsigned proto,
                       struct BannerBase64 *base64);

/**
 * Compares a banner string to a fixed string. This is primarily used
 * in the "self-test" feature in order to compare parsed banners from
 * expected banners.
 */
unsigned
banout_is_equal(const struct BannerOutput *banout, unsigned proto,
                const char *string);

unsigned
banout_is_contains(const struct BannerOutput *banout, unsigned proto,
                const char *string);

/**
 * Do the typical unit/regression test, for this module.
 */
int
banout_selftest(void);

#endif
