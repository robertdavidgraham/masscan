#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>

#include <stdio.h>
#include "masscan-app.h"
#include "proto-banout.h"
#include "proto-x509.h"
#include "proto-spnego.h"

#include "crypto-aes256.h"
#include "crypto-rfc6234.h"

struct stack_handle_t;
struct Banner1;
struct StreamState;

typedef void (*BannerParser)(
              const struct Banner1 *banner1,
              void *banner1_private,
              struct StreamState *stream_state,
              const unsigned char *px, size_t length,
              struct BannerOutput *banout,
              struct stack_handle_t *socket);
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
    unsigned is_capture_servername:1;
    unsigned is_capture_heartbleed:1;
    unsigned is_capture_ticketbleed:1;
    unsigned is_heartbleed:1;
    unsigned is_ticketbleed:1;
    unsigned is_poodle_sslv3:1;

    struct {
        const struct ProtocolParserStream *tcp[65536];
    } payloads;
    
    BannerParser parser[PROTO_end_of_list];
};

struct BannerBase64
{
    unsigned state:2;
    unsigned temp:24;
};

struct AES_CTR_STATE {
    unsigned char counter[16]; // 128 bits
    struct aes256_context_t key;
    unsigned char buf[16];
    unsigned char offset; // how much the buf is filled
};

struct SSL_SERVER_HELLO {
    unsigned state;
    unsigned remaining;
    unsigned timestamp;
    unsigned short cipher_suite;
    struct {
        unsigned short tag;
        unsigned short len;
        unsigned short i;
    } ext;
    unsigned char compression_method;
    unsigned char version_major;
    unsigned char version_minor;
    unsigned char kx_data[32]; // x25519 server pubkey
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
struct SSL_APPLICATION_DATA {
    unsigned state;
    struct AES_CTR_STATE aes;
};

struct SSLRECORD {
    unsigned char type;
    unsigned char version_major;
    unsigned char version_minor;
    /* "sequence number is set to zero at the beginning of a
     * connection and whenever the key is changed" */
    unsigned long seqnum;

    struct {
        unsigned state;
        unsigned char type;
        unsigned remaining;
        unsigned negotiation_state;
        // For TLS 1.3, one must do the SHA384 of clienthello + serverhello
        SHA384Context sha384ctx;
        aes256_key_t client_handshake_key;
        aes256_key_t server_handshake_key;
        unsigned char client_handshake_iv[12];
        unsigned char server_handshake_iv[12];
    } handshake;

    struct SSL_APPLICATION_DATA application_data;

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

struct MCSTUFF {
    char * banmem;
    size_t totalLen;
    size_t imgstart;
    size_t imgend;
    int brackcount;
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
    unsigned is_printed_boottime:1;
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

struct RDPSTUFF {
    unsigned short tpkt_length;
    struct {
        unsigned state;
        unsigned short dstref;
        unsigned short srcref;
        unsigned char len;
        unsigned char type;
        unsigned char flags;
    } cotp;
    struct {
        unsigned state;
        unsigned result;
        unsigned char type;
        unsigned char flags;
        unsigned char len;
    } cc;
};

struct SSHSTUFF{
    size_t packet_length;
};

struct StreamState {
    unsigned state;
    unsigned remaining;
    unsigned short port;
    unsigned short app_proto;
    unsigned is_sent_sslhello:1;
    unsigned is_sent_tls13:1;
    struct BannerBase64 base64;

    union {
        struct SSLRECORD ssl;
        struct VNCSTUFF vnc;
        struct FTPSTUFF ftp;
        struct SMTPSTUFF smtp;
        struct POP3STUFF pop3;
        struct MEMCACHEDSTUFF memcached;
        struct SMBSTUFF smb;
        struct RDPSTUFF rdp;
        struct MCSTUFF mc;
        struct SSHSTUFF ssh;
    } sub;
};

enum StreamFlags {
    SF__none = 0,
    SF__close = 0x01, /* send FIN after the static Hello is sent*/
    SF__nowait_hello = 0x02,    /* send our hello immediately, don't wait for their hello */
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
    enum StreamFlags flags;
    int (*selftest)(void);
    void *(*init)(struct Banner1 *b);
    void (*parse)(
        const struct Banner1 *banner1,
        void *banner1_private,
        struct StreamState *stream_state,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket);
    void (*cleanup)(struct StreamState *stream_state);
    void (*transmit_hello)(const struct Banner1 *banner1, struct stack_handle_t *socket);
    
    /* When multiple items are registered for a port. When one
     * connection is closed, the next will be opened.*/
    struct ProtocolParserStream *next;
    
    /*NOTE: the 'next' parameter should be the last one in this structure,
     * because we statically initialize the rest of the members at compile
     * time, and then use this last parameter to link up structures
     * at runtime */
};


/**
 * Patterns that match the data from the start of a TCP connection.
 * This will hint at what protocol that connection might be.
 */
struct Patterns {
    
    /** A string like "SSH-" or "220 " that matches a banner */
    const char *pattern;
    
    /** The length of that string, since it may be binary containing
     * nul characters */
    unsigned pattern_length;
    
    /** An integer arbitrarily assigned to this pattern, which should
     * probably match the protocol ID that we are looking for */
    unsigned id;
    
    /**
     * Whether this string matches only at the beginning ('anchored')
     * or anywhere in the input. Virtually all the patterns are anchored.
     */
    unsigned is_anchored;
    
    /**
     * Some extra flags for the pattern matcher for a few of the patterns.
     */
    unsigned extra;
};

struct Banner1 *
banner1_create(void);


void
banner1_destroy(struct Banner1 *b);

unsigned
banner1_parse(
        const struct Banner1 *banner1,
        struct StreamState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct stack_handle_t *socket);



/**
 * Test the banner protocol-parsing system by reading
 * in a capture file
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
