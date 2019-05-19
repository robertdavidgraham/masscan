/*
     state machine for receiving banners
*/
#include "smack.h"
#include "rawsock-pcapfile.h"
#include "proto-preprocess.h"
#include "proto-interactive.h"
#include "proto-banner1.h"
#include "proto-http.h"
#include "proto-ssl.h"
#include "proto-smb.h"
#include "proto-ssh.h"
#include "proto-ftp.h"
#include "proto-smtp.h"
#include "proto-tcp-telnet.h"
#include "proto-tcp-rdp.h"
#include "proto-imap4.h"
#include "proto-pop3.h"
#include "proto-vnc.h"
#include "proto-memcached.h"
#include "masscan-app.h"
#include "scripting.h"
#include "versioning.h"
#include "util-malloc.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>



struct Patterns patterns[] = {
    {"\x00\x00" "**" "\xff" "SMB", 8, PROTO_SMB, SMACK_ANCHOR_BEGIN | SMACK_WILDCARDS, 0},
    {"\x00\x00" "**" "\xfe" "SMB", 8, PROTO_SMB, SMACK_ANCHOR_BEGIN | SMACK_WILDCARDS, 0},
    
    {"\x82\x00\x00\x00", 4, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Positive Session Response */
    
    {"\x83\x00\x00\x01\x80", 5, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Not listening on called name */
    {"\x83\x00\x00\x01\x81", 5, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Not listening for calling name */
    {"\x83\x00\x00\x01\x82", 5, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Called name not present */
    {"\x83\x00\x00\x01\x83", 5, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Called name present, but insufficient resources */
    {"\x83\x00\x00\x01\x8f", 5, PROTO_SMB, SMACK_ANCHOR_BEGIN, 0}, /* Unspecified error */

    /* ...the remainder can be in any order */
    {"SSH-1.",      6, PROTO_SSH1, SMACK_ANCHOR_BEGIN, 0},
    {"SSH-2.",      6, PROTO_SSH2, SMACK_ANCHOR_BEGIN, 0},
    {"HTTP/1.",     7, PROTO_HTTP, SMACK_ANCHOR_BEGIN, 0},
    {"220-",        4, PROTO_FTP, SMACK_ANCHOR_BEGIN, 0},
    {"220 ",        4, PROTO_FTP, SMACK_ANCHOR_BEGIN, 1},
    {"+OK ",        4, PROTO_POP3, SMACK_ANCHOR_BEGIN, 0},
    {"* OK ",       5, PROTO_IMAP4, SMACK_ANCHOR_BEGIN, 0},
    {"521 ",        4, PROTO_SMTP, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x00",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x01",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x02",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x16\x03\x03",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x00",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x01",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x02",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"\x15\x03\x03",3, PROTO_SSL3, SMACK_ANCHOR_BEGIN, 0},
    {"RFB 000.000\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 1}, /* UltraVNC repeater mode */
    {"RFB 003.003\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 3}, /* default version for everything */
    {"RFB 003.005\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 3}, /* broken, same as 003.003 */
    {"RFB 003.006\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 3}, /* broken, same as 003.003 */
    {"RFB 003.007\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 7}, 
    {"RFB 003.008\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8}, 
    {"RFB 003.889\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8}, /* Apple's remote desktop, 003.007 */
    {"RFB 003.009\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8}, 
    {"RFB 004.000\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8}, /* Intel AMT KVM */
    {"RFB 004.001\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8}, /* RealVNC 4.6 */
    {"RFB 004.002\n", 12, PROTO_VNC_RFB, SMACK_ANCHOR_BEGIN, 8},
    {"STAT pid ",      9, PROTO_MEMCACHED,SMACK_ANCHOR_BEGIN, 0}, /* memcached stat response */
    
    
    {"\xff\xfb\x01\xff\xf0", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfb", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfc", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\xff\xfe", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0a\x0d", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0d\x0a", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0d\x0d", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x0a\x0a", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb%\x25xff\xfb", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x26\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x18\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x20\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x23\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfd\x27\xff\xfd", 5, PROTO_TELNET, 0, 0},
    {"\xff\xfb\x01\x1b[",    5, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"\xff\xfb\x01Input",    8, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"\xff\xfb\x01   ",      6, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"\xff\xfb\x01login",    8, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"login:",               6, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    {"password:",            9, PROTO_TELNET, SMACK_ANCHOR_BEGIN, 0},
    
    {"\x03\x00\x00\x13\x0e\xd0\xbe\xef\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00\x00",
        12, PROTO_RDP, SMACK_ANCHOR_BEGIN, 0},
    {"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00\x00",
        12, PROTO_RDP, SMACK_ANCHOR_BEGIN, 0},

    {0,0,0,0,0}
};




/***************************************************************************
 ***************************************************************************/
unsigned
banner1_parse(
        const struct Banner1 *banner1,
        struct ProtocolState *tcb_state,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
{
    size_t x;
    unsigned offset = 0;
    unsigned proto;


    switch (tcb_state->app_proto) {
    case PROTO_NONE:
    case PROTO_HEUR:
        x = smack_search_next(
                        banner1->smack,
                        &tcb_state->state,
                        px, &offset, (unsigned)length);
        if (x != SMACK_NOT_FOUND)
            proto = patterns[x].id;
        else
            proto = 0xFFFFFFFF;
        if (proto != 0xFFFFFFFF
            && !(proto == PROTO_SSL3 && !tcb_state->is_sent_sslhello)) {
            unsigned i;

            /* re-read the stuff that we missed */
            for (i=0; patterns[i].id && patterns[i].id != tcb_state->app_proto; i++)
                ;

            /* Kludge: patterns look confusing, so add port info to the
             * pattern */
            switch (proto) {
            case PROTO_FTP:
                if (patterns[x].extra == 1) {
                    if (tcb_state->port == 25 || tcb_state->port == 587)
                        proto = PROTO_SMTP;
                }
                break;
            case PROTO_VNC_RFB:
                tcb_state->sub.vnc.version = (unsigned char)patterns[x].extra;
                break;
            }

            tcb_state->app_proto = (unsigned short)proto;

            /* reset the state back again */
            tcb_state->state = 0;

            /* If there is any data from a previous packet, re-parse that */
            {
                const unsigned char *s = banout_string(banout, PROTO_HEUR);
                unsigned s_len = banout_string_length(banout, PROTO_HEUR);

                if (s && s_len)
                banner1_parse(
                                banner1,
                                tcb_state,
                                s, s_len,
                                banout,
                                more);
            }
            banner1_parse(
                            banner1,
                            tcb_state,
                            px, length,
                            banout,
                            more);
        } else {
            banout_append(banout, PROTO_HEUR, px, length);
        }
        break;
    case PROTO_FTP:
            banner_ftp.parse(   banner1,
                             banner1->http_fields,
                             tcb_state,
                             px, length,
                             banout,
                             more);
            break;
        case PROTO_SMTP:
            banner_smtp.parse(   banner1,
                              banner1->http_fields,
                              tcb_state,
                              px, length,
                              banout,
                              more);
            break;
            
        case PROTO_TELNET:
            banner_telnet.parse(   banner1,
                              banner1->http_fields,
                              tcb_state,
                              px, length,
                              banout,
                              more);
            break;
        case PROTO_RDP:
            banner_rdp.parse(   banner1,
                                banner1->http_fields,
                                tcb_state,
                                px, length,
                                banout,
                                more);
            break;
        case PROTO_POP3:
            banner_pop3.parse(   banner1,
                              banner1->http_fields,
                              tcb_state,
                              px, length,
                              banout,
                              more);
            break;
    case PROTO_IMAP4:
            banner_imap4.parse(banner1,
                              banner1->http_fields,
                              tcb_state,
                              px, length,
                              banout,
                              more);
            break;
            
    case PROTO_SSH1:
    case PROTO_SSH2:
        /* generic text-based parser
         * TODO: in future, need to split these into separate protocols,
         * especially when binary parsing is added to SSH */
        banner_ssh.parse(   banner1,
                            banner1->http_fields,
                            tcb_state,
                            px, length,
                            banout,
                            more);
        break;
    case PROTO_HTTP:
        banner_http.parse(
                        banner1,
                        banner1->http_fields,
                        tcb_state,
                        px, length,
                        banout,
                        more);
        break;
    case PROTO_SSL3:
        banner_ssl.parse(
                        banner1,
                        banner1->http_fields,
                        tcb_state,
                        px, length,
                        banout,
                        more);
        break;
    case PROTO_SMB:
        banner_smb1.parse(
                        banner1,
                        banner1->http_fields,
                        tcb_state,
                        px, length,
                        banout,
                        more);
        break;
    case PROTO_VNC_RFB:
        banner_vnc.parse(    banner1,
                             banner1->http_fields,
                             tcb_state,
                             px, length,
                             banout,
                             more);
        break;
    case PROTO_MEMCACHED:
        banner_memcached.parse(    banner1,
                             banner1->http_fields,
                             tcb_state,
                             px, length,
                             banout,
                             more);
        break;
    case PROTO_SCRIPTING:
        banner_scripting.parse(    banner1,
                                   banner1->http_fields,
                                   tcb_state,
                                   px, length,
                                   banout,
                                   more);
        break;
    case PROTO_VERSIONING:
        banner_versioning.parse(      banner1,
                                   banner1->http_fields,
                                   tcb_state,
                                   px, length,
                                   banout,
                                   more);
        break;

    default:
        fprintf(stderr, "banner1: internal error\n");
        break;

    }

    return tcb_state->app_proto;
}


/***************************************************************************
 * Create the --banners systems
 ***************************************************************************/
struct Banner1 *
banner1_create(void)
{
    struct Banner1 *b;
    unsigned i;

    b = CALLOC(1, sizeof(*b));
    

    /*
     * This creates a pattern-matching blob for heuristically determining
     * a protocol that runs on wrong ports, such as how FTP servers
     * often respond with "220 " or VNC servers respond with "RFB".
     */
    b->smack = smack_create("banner1", SMACK_CASE_INSENSITIVE);
    for (i=0; patterns[i].pattern; i++)
        smack_add_pattern(
                    b->smack,
                    patterns[i].pattern,
                    patterns[i].pattern_length,
                    i,
                    patterns[i].is_anchored);
    smack_compile(b->smack);

    /*
     * [TODO] These need to be moved into the 'init' functions
     */
    b->payloads.tcp[80] = &banner_http;
    b->payloads.tcp[8080] = &banner_http;
    b->payloads.tcp[139] = (void*)&banner_smb0;
    b->payloads.tcp[445] = (void*)&banner_smb1;
    b->payloads.tcp[443] = (void*)&banner_ssl;   /* HTTP/s */
    b->payloads.tcp[465] = (void*)&banner_ssl;   /* SMTP/s */
    b->payloads.tcp[990] = (void*)&banner_ssl;   /* FTP/s */
    b->payloads.tcp[991] = (void*)&banner_ssl;
    b->payloads.tcp[992] = (void*)&banner_ssl;   /* Telnet/s */
    b->payloads.tcp[993] = (void*)&banner_ssl;   /* IMAP4/s */
    b->payloads.tcp[994] = (void*)&banner_ssl;
    b->payloads.tcp[995] = (void*)&banner_ssl;   /* POP3/s */
    b->payloads.tcp[2083] = (void*)&banner_ssl;  /* cPanel - SSL */
    b->payloads.tcp[2087] = (void*)&banner_ssl;  /* WHM - SSL */
    b->payloads.tcp[2096] = (void*)&banner_ssl;  /* cPanel webmail - SSL */
    b->payloads.tcp[8443] = (void*)&banner_ssl;  /* Plesk Control Panel - SSL */
    b->payloads.tcp[9050] = (void*)&banner_ssl;  /* Tor */
    b->payloads.tcp[8140] = (void*)&banner_ssl;  /* puppet */
    b->payloads.tcp[11211] = (void*)&banner_memcached;
    b->payloads.tcp[23] = (void*)&banner_telnet;
    b->payloads.tcp[3389] = (void*)&banner_rdp;
    
    /* 
     * This goes down the list of all the TCP protocol handlers and initializes
     * them.
     */
    banner_ftp.init(b);
    banner_http.init(b);
    banner_imap4.init(b);
    banner_memcached.init(b);
    banner_pop3.init(b);
    banner_smtp.init(b);
    banner_ssh.init(b);
    banner_ssl.init(b);
    banner_smb0.init(b);
    banner_smb1.init(b);
    banner_telnet.init(b);
    banner_rdp.init(b);
    banner_vnc.init(b);
    
    /* scripting/versioning come after the rest */
    banner_scripting.init(b);
    banner_versioning.init(b);


    return b;
}


/***************************************************************************
 ***************************************************************************/
void
banner1_destroy(struct Banner1 *b)
{
    if (b == NULL)
        return;
    if (b->smack)
        smack_destroy(b->smack);
    if (b->http_fields)
        smack_destroy(b->http_fields);
    free(b);
}





/***************************************************************************
 * Test the banner1 detection system by throwing random frames at it
 ***************************************************************************/
void
banner1_test(const char *filename)
{
    struct PcapFile *cap;
    unsigned link_type;

    cap = pcapfile_openread(filename);
    if (cap == NULL) {
        fprintf(stderr, "%s: can't open capture file\n", filename);
        return;
    }

    link_type = pcapfile_datalink(cap);

    for (;;) {
        int packets_read;
        unsigned secs;
        unsigned usecs;
        unsigned origlength;
        unsigned length;
        unsigned char px[65536];
        struct PreprocessedInfo parsed;
        unsigned x;


        packets_read = pcapfile_readframe(
                    cap,    /* capture dump file */
                    &secs, &usecs,
                    &origlength, &length,
                    px, sizeof(px));
        if (packets_read == 0)
            break;


        x = preprocess_frame(px, length, link_type, &parsed);
        if (x == 0)
            continue;

    }

    pcapfile_close(cap);
}

/***************************************************************************
 ***************************************************************************/
int
banner1_selftest()
{
    unsigned i;
    struct Banner1 *b;
    struct ProtocolState tcb_state[1];
    const unsigned char *px;
    unsigned length;
    struct BannerOutput banout[1];
    static const char *http_header =
        "HTTP/1.0 302 Redirect\r\n"
        "Date: Tue, 03 Sep 2013 06:50:01 GMT\r\n"
        "Connection: close\r\n"
        "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f ])\r\n"
        "Server: YTS/1.20.13\r\n"
        "Cache-Control: no-store\r\n"
        "Content-Type: text/html\r\n"
        "Content-Language: en\r\n"
        "Location: http://failsafe.fp.yahoo.com/404.html\r\n"
        "Content-Length: 227\r\n"
        "\r\n<title>hello</title>\n";
    px = (const unsigned char *)http_header;
    length = (unsigned)strlen(http_header);


    /*
     * First, test the "banout" subsystem
     */
    if (banout_selftest() != 0) {
        fprintf(stderr, "banout: failed\n");
        return 1;
    }


    /*
     * Test one character at a time
     */
    b = banner1_create();
    banout_init(banout);

    memset(tcb_state, 0, sizeof(tcb_state[0]));

    for (i=0; i<length; i++) {
        struct InteractiveData more = {0,0};

        banner1_parse(
                    b,
                    tcb_state,
                    px+i, 1,
                    banout,
                    &more);
    }


    {
        const unsigned char *s = banout_string(banout, PROTO_HTTP);
        if (memcmp(s, "HTTP/1.0 302", 11) != 0) {
            printf("banner1: test failed\n");
            return 1;
        }
    }
    banout_release(banout);
    banner1_destroy(b);

    /*
     * Test whole buffer
     */
    b = banner1_create();

    memset(tcb_state, 0, sizeof(tcb_state[0]));

    banner1_parse(
                    b,
                    tcb_state,
                    px, length,
                    banout,
                    0);
    banner1_destroy(b);
    /*if (memcmp(banner, "Via:HTTP/1.1", 11) != 0) {
        printf("banner1: test failed\n");
        return 1;
    }*/


    {
        int x = 0;

        x = banner_ssl.selftest();
        if (x) {
            fprintf(stderr, "SSL banner: selftest failed\n");
            return 1;
        }
        
        x = banner_smb1.selftest();
        if (x) {
            fprintf(stderr, "SMB banner: selftest failed\n");
            return 1;
        }
        
        x = banner_http.selftest();
        if (x) {
            fprintf(stderr, "HTTP banner: selftest failed\n");
            return 1;
        }
        
        x = banner_telnet.selftest();
        if (x) {
            fprintf(stderr, "Telnet banner: selftest failed\n");
            return 1;
        }
        
        x = banner_rdp.selftest();
        if (x) {
            fprintf(stderr, "RDP banner: selftest failed\n");
            return 1;
        }
        
        return x;
    }
}

