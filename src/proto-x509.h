#ifndef PROTO_X509_H
#define PROTO_X509_H
#include <time.h>
#include <stdint.h>
struct BannerOutput;

/****************************************************************************
 * This stores the "state" of the X.509 certificate parser
 ****************************************************************************/
struct CertDecode {
    /** This is the master 'state' variable in the massive switch statement */
    unsigned state;
    
    /** ASN.1 nests fields within fields. Therefore, as we parse down into
     * the structure, we push the parent length/state info on the stack,
     * and then when we exit a field, we pop it back off the stack.
     * NOTE: since space is at a premium, we have separate arrays
     * for the length/state, instead of a an array of objects containing
     * both. */
    struct {
        unsigned short remainings[9];
        unsigned char states[9];
        unsigned char depth;
    } stack;
    
    /** We catch some DER non-canonical encoding errors, but not all. Someday
     * we'll improve the parser to catch all of them */
    unsigned is_der_failure:1;
    unsigned is_capture_subject:1;
    unsigned is_capture_issuer:1;



    /** Number of certificates we've processed */
    unsigned char count;
    
    /** ??? */
    time_t prev;
    
    /** This parser was originally written just to grab the "subect name"
     * of a certificate, i.e. "*.google.com" for Google's certificates.
     * However, there are many different types of subject names. Each
     * subnect name comes in two parts, the first part being an OID
     * saying the type of subject, then the subject itself. We need to stash
     * the result of parsing the OID somewhere before parsing the subject
     */
    struct {
        unsigned type;
    } subject;

    unsigned child_state;
    unsigned brother_state;
    
    /**
     * This union contains the intermediate/partial values as we are decoding
     * them. Since a packet may end with a field only partially decoded,
     * we have to stash that value someplace before the next bytes arive
     * that complete the decoding
     */
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

/**
 * Called before parsing the first fragment of an X.509 certificate
 */
void
x509_decode_init(struct CertDecode *x, size_t length);

/**
 * Called to decode the next fragment of an X.509 certificate.
 * Must call x509_decode_init() first.
 */
void
x509_decode(struct CertDecode *x, 
            const unsigned char *px, size_t length, 
            struct BannerOutput *banout);

/**
 * Called at program startup to initialize internal parsing structures
 * for certificates. Once called, it creates static read-only thread-safe
 * structures
 */
void
x509_init(void);

#endif

