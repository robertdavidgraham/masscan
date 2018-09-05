#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>

#include <stdio.h>
#include "masscan-app.h"
#include "proto-banout.h"
#include "proto-x509.h"
#include "proto-spnego.h"

struct InteractiveData;
struct Banner1;
struct ProtocolState;

typedef void (*BannerParser)(
              const struct Banner1 *banner1,
              void *banner1_private,
              struct ProtocolState *stream_state,
              const unsigned char *px, size_t length,
              struct BannerOutput *banout,
              struct InteractiveData *more);
struct Banner1
{
    struct lua_State *L;
    struct SMACK *smack;
    struct SMACK *http_fields;
    struct SMACK *html_fields;
    struct SMACK *memcached_responses;
    struct SMACK *memcached_stats;

    unsigned is_capture_html:1;
    unsigned is_capture_cert:1;
    unsigned is_capture_heartbleed:1;
    unsigned is_capture_ticketbleed:1;
    unsigned is_heartbleed:1;
    unsigned is_ticketbleed:1;
    unsigned is_poodle_sslv3:1;

    struct {
        struct ProtocolParserStream *tcp[65536];
    } payloads;
    
    BannerParser parser[PROTO_end_of_list];
};

struct BannerBase64
{
    unsigned state:2;
    unsigned temp:24;
};

struct SSL_SERVER_HELLO {
    unsigned state;
    unsigned remaining;
    unsigned timestamp;
    unsigned short cipher_suite;
    unsigned short ext_tag;
    unsigned short ext_remaining;
    unsigned char compression_method;
    unsigned char version_major;
    unsigned char version_minor;
};
struct SSL_SERVER_CERT {
    unsigned state;
    unsigned remaining;
    struct {
        unsigned remaining;
    } sub;
    struct CertDecode x509;
};
struct SSL_SERVER_ALERT {
    unsigned char level;
    unsigned char description;
};

struct SSLRECORD {
    unsigned char type;
    unsigned char version_major;
    unsigned char version_minor;

    struct {
        unsigned state;
        unsigned char type;
        unsigned remaining;
    } handshake;

    union {
        struct {
            /* all these structs should start with state */
            unsigned state;
        } all;
        struct SSL_SERVER_HELLO server_hello;
        struct SSL_SERVER_CERT server_cert;
        struct SSL_SERVER_ALERT server_alert;
    } x;

};

struct PIXEL_FORMAT {
    unsigned short red_max;
    unsigned short green_max;
    unsigned short blue_max;
    unsigned char red_shift;
    unsigned char green_shift;
    unsigned char blue_shift;
    unsigned char bits_per_pixel;
    unsigned char depth;
    unsigned big_endian_flag:1;
    unsigned true_colour_flag:1;
};
struct VNCSTUFF {
    unsigned sectype;
    unsigned char version;
    unsigned char len;
    
    unsigned short width;
    unsigned short height;
    
    struct PIXEL_FORMAT pixel;    
};

struct FTPSTUFF {
    unsigned code;
    unsigned is_last:1;
};


struct SMTPSTUFF {
    unsigned code;
    unsigned is_last:1;
};

struct POP3STUFF {
    unsigned code;
    unsigned is_last:1;
};

struct MEMCACHEDSTUFF {
    unsigned match;
};

struct Smb72_Negotiate {
    uint16_t DialectIndex;
    uint16_t SecurityMode;
    uint64_t SystemTime;
    uint32_t SessionKey;
    uint32_t Capabilities;
    uint16_t ServerTimeZone;
    uint8_t  ChallengeLength;
    uint8_t  ChallengeOffset;
};

struct Smb73_Setup {
    uint16_t BlobLength;
    uint16_t BlobOffset;
};

struct SMBSTUFF {
    unsigned nbt_state;
    unsigned char nbt_type;
    unsigned char nbt_flags;
    unsigned is_printed_ver:1;
    unsigned is_printed_guid:1;
    unsigned is_printed_time:1;
    unsigned nbt_length;
    unsigned nbt_err;
    
    union {
        struct {
            unsigned char   command;
            unsigned        status;
            unsigned char   flags1;
            unsigned short  flags2;
            unsigned        pid;
            unsigned char   signature[8];
            unsigned short  tid;
            unsigned short  uid;
            unsigned short  mid;
            unsigned short  param_length;
            unsigned short  param_offset;
            unsigned short  byte_count;
            unsigned short  byte_offset;
            unsigned short  byte_state;
            unsigned short  unicode_char;
        } smb1;
        struct {
            unsigned seqno;
            unsigned short header_length;
            unsigned short offset;
            unsigned short state;
            unsigned short opcode;
            unsigned short struct_length;
            unsigned is_dynamic:1;
            unsigned char flags;
            unsigned ntstatus;
            unsigned number;
            unsigned short blob_offset;
            unsigned short blob_length;
        } smb2;
    } hdr;
    union {
        struct Smb72_Negotiate negotiate;
        struct Smb73_Setup setup;
        struct {
            uint64_t current_time;
            uint64_t boot_time;
        } negotiate2;
    } parms;
    struct SpnegoDecode spnego;
};

struct ProtocolState {
    unsigned state;
    unsigned remaining;
    unsigned short port;
    unsigned short app_proto;
    unsigned is_sent_sslhello:1;
    struct BannerBase64 base64;

    union {
        struct SSLRECORD ssl;
        struct VNCSTUFF vnc;
        struct FTPSTUFF ftp;
        struct SMTPSTUFF smtp;
        struct POP3STUFF pop3;
        struct MEMCACHEDSTUFF memcached;
        struct SMBSTUFF smb;
    } sub;
};

enum {
    CTRL_SMALL_WINDOW = 1,
};

/**
 * A registration structure for various TCP stream protocols
 * like HTTP, SSL, and SSH
 */
struct ProtocolParserStream {
    const char *name;
    unsigned port;
    const void *hello;
    size_t hello_length;
    unsigned ctrl_flags;
    int (*selftest)(void);
    void *(*init)(struct Banner1 *b);
    void (*parse)(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more);
    void (*cleanup)(struct ProtocolState *stream_state);
    void (*transmit_hello)(const struct Banner1 *banner1, struct InteractiveData *more);
    
    /* When multiple items are registered for a port. When one
     * connection is closed, the next will be opened.*/
    struct ProtocolParserStream *next;
    
    /*NOTE: the 'next' parameter should be the last one in this structure,
     * because we statically initialize the rest of the members at compile
     * time, and then use this last parameter to link up structures
     * at runtime */
};


struct Patterns {
    const char *pattern;
    unsigned pattern_length;
    unsigned id;
    unsigned is_anchored;
    unsigned extra;
};

struct Banner1 *
banner1_create(void);


void
banner1_destroy(struct Banner1 *b);

unsigned
banner1_parse(
        const struct Banner1 *banner1,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more);



/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
