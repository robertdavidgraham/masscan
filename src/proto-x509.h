#ifndef PROTO_X509_H
#define PROTO_X509_H
#include <time.h>
#include <stdint.h>
struct BannerOutput;

/****************************************************************************
 ****************************************************************************/
struct CertDecode {
    unsigned state;
    unsigned short remainings[7];
    unsigned char states[7];
    unsigned char remainings_count;
    time_t prev;
    struct {
        unsigned type;
    } subject;
    union {
        struct {
            unsigned short remaining;
            unsigned char length_of_length;
        } tag;
        uint64_t num;
        unsigned next_state;
        struct {
            uint64_t num;
            unsigned short state;
            unsigned char last_id;
        } oid;
        struct {
            unsigned state;
            unsigned year:7;
            unsigned month:4;
            unsigned day:5;
            unsigned hour:5;
            unsigned minute:6;
            unsigned second:6;
        } timestamp;
    } u;
};

void
x509_decode(struct CertDecode *x, const unsigned char *px, size_t length, struct BannerOutput *banout);

void
x509_init(void);

void
x509_init_state(struct CertDecode *x, size_t length);

#endif

