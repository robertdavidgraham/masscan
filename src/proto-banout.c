/*
    Banner Output

    This module remembers "banners" from a connection. These are often
    simple strings, like the FTP hello string. The can also be more
    complex strings, parsed from binary protocols. They also may
    contain bulk data, such as BASE64 encoded X.509 certificates from
    SSL.

    One complication is that since we can extract multiple types of 
    information from the same connection, we can have more than one
    banner for the same connection.
*/
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
    banout_init(banout);
}


/***************************************************************************
 ***************************************************************************/
static struct BannerOutput *
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
    while (banout && (banout->protocol&0xFFFF) != proto)
        banout = banout->next;

    if (banout)
        return banout->banner;
    else
        return NULL;
}

/***************************************************************************
 ***************************************************************************/
unsigned
banout_is_equal(const struct BannerOutput *banout, unsigned proto,
                const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;

    /*
     * Grab the string
     */
    string2 = banout_string(banout, proto);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = banout_string_length(banout, proto);

    if (string_length != string2_length)
        return 0;
    
    return memcmp(string, string2, string2_length) == 0;
}

/***************************************************************************
 ***************************************************************************/
unsigned
banout_is_contains(const struct BannerOutput *banout, unsigned proto,
                const char *string)
{
    const unsigned char *string2;
    size_t string_length;
    size_t string2_length;
    size_t i;

    /*
     * Grab the string
     */
    string2 = banout_string(banout, proto);
    if (string2 == NULL)
        return string == NULL;

    if (string == NULL)
        return 0;
    
    string_length = strlen(string);
    string2_length = banout_string_length(banout, proto);

    if (string_length > string2_length)
        return 0;
    
    for (i=0; i<string2_length-string_length+1; i++) {
        if (memcmp(string, string2+i, string_length) == 0)
            return 1;
    }
    return 0;
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
void
banout_append_hexint(struct BannerOutput *banout, unsigned proto, unsigned long long number, int digits)
{
    if (digits == 0) {
        for (digits=16; digits>0; digits--)
            if (number>>((digits-1)*4) & 0xF)
                break;
    }
    
    for (;digits>0; digits--) {
        char c = "0123456789abcdef"[(number>>(unsigned long long)((digits-1)*4)) & 0xF];
        banout_append_char(banout, proto, c);
    }
}

/***************************************************************************
 * Output either a normal character, or the hex form of a UTF-8 string
 ***************************************************************************/
void
banout_append_unicode(struct BannerOutput *banout, unsigned proto, unsigned c)
{
    if (c & ~0xFFFF) {
        unsigned c2;
        c2 = 0xF0 | ((c>>18)&0x03);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>>12)&0x3F);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        banout_append_char(banout, proto, c2);
    } else if (c & ~0x7FF) {
        unsigned c2;
        c2 = 0xE0 | ((c>>12)&0x0F);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>> 6)&0x3F);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        banout_append_char(banout, proto, c2);
    } else if (c & ~0x7f) {
        unsigned c2;
        c2 = 0xc0 | ((c>> 6)&0x1F);
        banout_append_char(banout, proto, c2);
        c2 = 0x80 | ((c>> 0)&0x3F);
        banout_append_char(banout, proto, c2);
    } else
        banout_append_char(banout, proto, c);
}



/***************************************************************************
 ***************************************************************************/
static struct BannerOutput *
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
static struct BannerOutput *
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
banout_append(struct BannerOutput *banout, unsigned proto, 
              const void *px, size_t length)
{
    struct BannerOutput *p;

    if (length == AUTO_LEN)
        length = strlen((const char*)px);
    
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

/*****************************************************************************
 *****************************************************************************/
static const char *b64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789"
"+/";


/*****************************************************************************
 *****************************************************************************/
void
banout_init_base64(struct BannerBase64 *base64)
{
    base64->state = 0;
    base64->temp = 0;
}

/*****************************************************************************
 *****************************************************************************/
void
banout_append_base64(struct BannerOutput *banout, unsigned proto,
                     const void *vpx, size_t length,
                     struct BannerBase64 *base64)
{
    const unsigned char *px = (const unsigned char *)vpx;
    size_t i;
    unsigned x = base64->temp;
    unsigned state = base64->state;
    
    for (i=0; i<length; i++) {
        switch (state) {
            case 0:
                x = px[i]<<16;
                state++;
                break;
            case 1:
                x |= px[i]<<8;
                state++;
                break;
            case 2:
                x |= px[i];
                state = 0;
                banout_append_char(banout, proto, b64[(x>>18)&0x3F]);
                banout_append_char(banout, proto, b64[(x>>12)&0x3F]);
                banout_append_char(banout, proto, b64[(x>> 6)&0x3F]);
                banout_append_char(banout, proto, b64[(x>> 0)&0x3F]);
        }
    }
    
    base64->temp = x;
    base64->state = state;
}

/*****************************************************************************
 *****************************************************************************/
void
banout_finalize_base64(struct BannerOutput *banout, unsigned proto,
                       struct BannerBase64 *base64)
{
    unsigned x = base64->temp;
    switch (base64->state) {
        case 0:
            break;
        case 1:
            banout_append_char(banout, proto, b64[(x>>18)&0x3F]);
            banout_append_char(banout, proto, b64[(x>>12)&0x3F]);
            banout_append_char(banout, proto, '=');
            banout_append_char(banout, proto, '=');
            break;
        case 2:
            banout_append_char(banout, proto, b64[(x>>18)&0x3F]);
            banout_append_char(banout, proto, b64[(x>>12)&0x3F]);
            banout_append_char(banout, proto, b64[(x>>6)&0x3F]);
            banout_append_char(banout, proto, '=');
            break;
    }
}



/*****************************************************************************
 *****************************************************************************/
static int
banout_string_equals(struct BannerOutput *banout, unsigned proto,
                     const char *rhs)
{
    const unsigned char *lhs = banout_string(banout, proto);
    size_t lhs_length = banout_string_length(banout, proto);
    size_t rhs_length = strlen(rhs);
    
    if (lhs_length != rhs_length)
        return 0;
    return memcmp(lhs, rhs, rhs_length) == 0;
}

/*****************************************************************************
 *****************************************************************************/
int
banout_selftest(void)
{
    /*
     * Basic test
     */
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
    }
    
    /*
     * Test BASE64 encoding. We are going to do strings of various lengths
     * in order to test the boundary condition of finalizing various strings
     * properly
     */
    {
        struct BannerOutput banout[1];
        struct BannerBase64 base64[1];
    
        banout_init(banout);

        banout_init_base64(base64);
        banout_append_base64(banout, 1, "x", 1, base64);
        banout_finalize_base64(banout, 1, base64);
        
        banout_init_base64(base64);
        banout_append_base64(banout, 2, "bc", 2, base64);
        banout_finalize_base64(banout, 2, base64);
        
        banout_init_base64(base64);
        banout_append_base64(banout, 3, "mno", 3, base64);
        banout_finalize_base64(banout, 3, base64);
        
        banout_init_base64(base64);
        banout_append_base64(banout, 4, "stuv", 4, base64);
        banout_finalize_base64(banout, 4, base64);
        
        banout_init_base64(base64);
        banout_append_base64(banout, 5, "fghij", 5, base64);
        banout_finalize_base64(banout, 5, base64);
        
        
        if (!banout_string_equals(banout, 1, "eA=="))
            return 1;
        if (!banout_string_equals(banout, 2, "YmM="))
            return 1;
        if (!banout_string_equals(banout, 3, "bW5v"))
            return 1;
        if (!banout_string_equals(banout, 4, "c3R1dg=="))
            return 1;
        if (!banout_string_equals(banout, 5, "ZmdoaWo="))
            return 1;

        banout_release(banout);
    }
    
    
    return 0;
}

