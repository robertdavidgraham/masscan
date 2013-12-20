#include "proto-banner1.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/***************************************************************************
 ***************************************************************************/
void
banout_init(struct BannerOutput *banout)
{
    banout->length = 0;
    banout->protocol = 0;
    banout->next = 0;
    banout->max_length = sizeof(banout->banner);
}

/***************************************************************************
 ***************************************************************************/
void
banout_release(struct BannerOutput *banout)
{
    while (banout->next) {
        struct BannerOutput *next = banout->next->next;
        free(banout->next);
        banout->next = next;
    }
}


/***************************************************************************
 ***************************************************************************/
struct BannerOutput *
banout_find_proto(struct BannerOutput *banout, unsigned proto)
{
    while (banout && banout->protocol != proto)
        banout = banout->next;
    return banout;
}

/***************************************************************************
 ***************************************************************************/
const unsigned char *
banout_string(const struct BannerOutput *banout, unsigned proto)
{
    while (banout && banout->protocol != proto)
        banout = banout->next;
    
    if (banout)
        return banout->banner;
    else
        return NULL;
}

/***************************************************************************
 ***************************************************************************/
unsigned
banout_string_length(const struct BannerOutput *banout, unsigned proto)
{
    while (banout && banout->protocol != proto)
        banout = banout->next;
    
    if (banout)
        return banout->length;
    else
        return 0;
}

/***************************************************************************
 ***************************************************************************/
void
banout_newline(struct BannerOutput *banout, unsigned proto)
{
    struct BannerOutput *p;
    
    p = banout_find_proto(banout, proto);
    if (p && p->length) {
        banout_append_char(banout, proto, '\n');
    }
}

/***************************************************************************
 ***************************************************************************/
void
banout_end(struct BannerOutput *banout, unsigned proto)
{
    struct BannerOutput *p;
    
    p = banout_find_proto(banout, proto);
    if (p && p->length) {
        p->protocol |= 0x80000000;
    }
}

/***************************************************************************
 ***************************************************************************/
void
banout_append_char(struct BannerOutput *banout, unsigned proto, int c)
{
    char cc = (char)c;
    banout_append(banout, proto, &cc, 1);
}

/***************************************************************************
 ***************************************************************************/
struct BannerOutput *
banout_new_proto(struct BannerOutput *banout, unsigned proto)
{
    struct BannerOutput *p;

    if (banout->protocol == 0 && banout->length == 0) {
        banout->protocol = proto;
        return banout;
    }

    p = (struct BannerOutput *)malloc(sizeof(*p));
    memset(p, 0, sizeof(*p));
    p->protocol = proto;
    p->max_length = sizeof(p->banner);
    p->next = banout->next;
    banout->next = p;
    return p;
}


/***************************************************************************
 ***************************************************************************/
struct BannerOutput *
banout_expand(struct BannerOutput *banout, struct BannerOutput *p)
{
    struct BannerOutput *n;

    /* Double the space */
    n = (struct BannerOutput *)malloc(  offsetof(struct BannerOutput, banner) 
                                        + 2 * p->max_length);
    if (n == NULL)
        exit(1);

    /* Copy the old structure */
    memcpy(n, p, offsetof(struct BannerOutput, banner) + p->max_length);
    n->max_length *= 2;

    if (p == banout) {
        /* 'p' is the head of the linked list, so we can't free it */
        banout->next = n;
        p->protocol = 0;
        p->length = 0;
    } else {
        /* 'p' is not the head, so replace it in the list with 'n',
         * then free it. */
        while (banout->next != p)
            banout = banout->next;
        banout->next = n;
        free(p);
    }

    return n;
}

/***************************************************************************
 ***************************************************************************/
void
banout_append(struct BannerOutput *banout, unsigned proto, const void *px, size_t length)
{
    struct BannerOutput *p;
    
    /*
     * Get the matching record for the protocol (e.g. HTML, SSL, etc.).
     * If it doesn't already exist, add the protocol object to the linked
     * list.
     */
    p = banout_find_proto(banout, proto);
    if (p == NULL) {
        p = banout_new_proto(banout, proto);
    }


    /*
     * If the current object isn't big enough, expand it
     */
    while (p->length + length >= p->max_length) {
        p = banout_expand(banout, p);
    }

    /*
     * Now that we are assured there is enough space, do the copy
     */
    memcpy(p->banner + p->length, px, length);
    p->length = (unsigned)(p->length + length);
}

/***************************************************************************
 ***************************************************************************/
int
banout_selftest(void)
{
    struct BannerOutput banout[1];
    unsigned i;

    banout_init(banout);

    for (i=0; i<10; i++) {
        banout_append(banout, 1, "xxxx", 4);
        banout_append(banout, 2, "yyyyy", 5);
    }

    if (banout->next == 0)
        return 1;
    if (banout_string_length(banout, 1) != 40)
        return 1;
    if (banout_string_length(banout, 2) != 50)
        return 1;
    
    banout_release(banout);
    if (banout->next != 0)
        return 1;

    return 0;
}

