#include "proto-tcp-telnet.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "util-malloc.h"
#include <ctype.h>
#include <string.h>
#include "string_s.h"

struct TelnetOptions {
    unsigned num;
    const char *text;
};

/*
 This is a list of the options during negotiation that we might be interested
 in.
*/
struct TelnetOptions options[] = {
    { 0, "binary"},       /* 0x00     Binary */
    { 1, "echo"},             /* 0x01     Echo */
    //{ 2, "recon"},      /* 0x02     Reconnection  */
    { 3, "sga"},             /* 0x03     Supress go ahead */
    //{ 4, "msgsz"},      /* 0x04     Approx Message Size Negotiation */
    { 5, "status"},       /* 0x05     Status  */
    { 6, "timing-mark"},  /* 0x06     Timing Mark */
    /*
    7     Remote Controlled Trans and Echo                   [107,JBP]
    8     Output Line Width                                   [40,JBP]
    9     Output Page Size                                    [41,JBP]
    10     Output Carriage-Return Disposition                  [28,JBP]
    11     Output Horizontal Tab Stops                         [32,JBP]
    12     Output Horizontal Tab Disposition                   [31,JBP]
    13     Output Formfeed Disposition                         [29,JBP]
    14     Output Vertical Tabstops                            [34,JBP]
    15     Output Vertical Tab Disposition                     [33,JBP]
    16     Output Linefeed Disposition                         [30,JBP]
    17     Extended ASCII                                     [136,JBP]
    18     Logout                                              [25,MRC]
    19     Byte Macro                                          [35,JBP]
    20     Data Entry Terminal                             [145,38,JBP]*/
    //{21, "supdup"},     /* 0x15    SUPDUP */
    {22, "supdupout"},  /* 0x16    SUPDUP Output */
    {23, "sendloc"},    /* 0x17    Send Location */
    {24, "term"},       /* 0x18    Terminal type */
/*  25     End of Record                                      [103,JBP]
    26     TACACS User Identification                           [1,BA4]
    27     Output Marking                                     [125,SXS]
    28     Terminal Location Number                            [84,RN6]
    29     Telnet 3270 Regime                                 [116,JXR]
    30     X.3 PAD                                            [70,SL70]
 */
    {31, "naws"},       /* 0x1f    Negotiate About Window Size */
    {32, "tspeed"},     /* 0x20    Terminal Speed */
    {33, "rflow"},      /* 0x21  ! Remote Flow Control */
    {34, "linemode"},   /* 0x22  " Linemode  */
    {35, "xloc"},       /* 0x23  # X Display Location  */
    {36, "env"},        /* 0x24  $ Environment Option                                    [DB14]*/
    {37, "auth"},       /* 0x25  % Authentication Option  */
    {38, "encrypt"},    /* 0x26  & Encryption Option */
    {39, "new-env"},    /* 0x27  ' */
    
    {46, "starttls"},   /* 0x2e  . STARTTLS */
/*
    255     Extended-Options-List                              [109,JBP]
*/
    {0,0}
};

static const char *
option_name_lookup(unsigned optnum)
{
    size_t i;
    for (i=0; options[i].text; i++) {
        if (options[i].num == optnum)
            return options[i].text;
    }
    return 0;
}

enum {
    FLAG_WILL=1,
    FLAG_WONT=2,
    FLAG_DO=4,
    FLAG_DONT=8,
};

/***************************************************************************
 ***************************************************************************/
static void
telnet_parse(  const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more)
{
    unsigned state = pstate->state;
    size_t offset;
    enum {
        TELNET_DATA,
        TELNET_IAC,
        TELNET_DO,
        TELNET_DONT,
        TELNET_WILL,
        TELNET_WONT,
        TELNET_SB,
        TELNET_SB_DATA,
        TELNET_INVALID,
    };
    static const char *foobar[4] = {"DO", "DONT", "WILL", "WONT"};
    unsigned char nego[256] = {0};

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    UNUSEDPARM(more);

    for (offset=0; offset<length; offset++) {
        int c = px[offset];
        switch (state) {
            case 0:
                if (c == 0xFF) {
                    /* Telnet option code negotiation */
                    state = TELNET_IAC;
                } else if (c == '\r') {
                    /* Ignore carriage returns */
                    continue;
                } else if (c == '\n') {
                    banout_append(banout, PROTO_TELNET, "\\n ", AUTO_LEN);
                } else {
                    /* Append the raw text */
                    banout_append_char(banout, PROTO_TELNET, c);
                }
                break;
            case TELNET_IAC:
                switch (c) {
                    case 240: /* 0xF0 SE - End of subnegotiation parameters */
                        state = 0;
                        break;
                    case 246: /* 0xF6 Are you there? - The function AYT. */
                        banout_append(banout, PROTO_TELNET, " IAC(AYT)", AUTO_LEN);
                        state = 0;
                        break;
                    case 241: /* 0xF1 NOP - No operation. */
                        banout_append(banout, PROTO_TELNET, " IAC(NOP)", AUTO_LEN);
                        state = 0;
                        break;
                    case 242: /* 0xF2 Data mark */
                        banout_append(banout, PROTO_TELNET, " IAC(MRK)", AUTO_LEN);
                        state = 0;
                        break;
                    case 243: /* 0xF3 BRK - NVT character BRK. */
                        banout_append(banout, PROTO_TELNET, " IAC(NOP)", AUTO_LEN);
                        state = 0;
                        break;
                    case 244: /* 0xF4 Interrupt process - The function IP. */
                        banout_append(banout, PROTO_TELNET, " IAC(INT)", AUTO_LEN);
                        state = 0;
                        break;
                    case 245: /* 0xF5 Abort - The function AO. */
                        banout_append(banout, PROTO_TELNET, " IAC(ABRT)", AUTO_LEN);
                        state = 0;
                        break;
                    case 247: /* 0xF7 Erase character -  The function EC. */
                        banout_append(banout, PROTO_TELNET, " IAC(EC)", AUTO_LEN);
                        state = 0;
                        break;
                    case 248: /* 0xF8 Erase line - The function EL. */
                        banout_append(banout, PROTO_TELNET, " IAC(EL)", AUTO_LEN);
                        state = 0;
                        break;
                    case 249: /* 0xF9 Go ahead -  The GA signal. */
                        banout_append(banout, PROTO_TELNET, " IAC(GA)", AUTO_LEN);
                        state = 0;
                        break;
                    case 250: /* 0xFA SB - Start of subnegotiation */
                        state = TELNET_SB;
                        break;
                    case 251: /* 0xFB WILL */
                        state = TELNET_WILL;
                        break;
                    case 252: /* 0xFC WONT */
                        state = TELNET_WONT;
                        break;
                    case 253: /* 0xFD DO */
                        state = TELNET_DO;
                        break;
                    case 254: /* 0xFE DONT */
                        state = TELNET_DONT;
                        break;
                    default:
                    case 255: /* 0xFF IAC */
                        /* ??? */
                        state = TELNET_INVALID;
                        break;
                }
                break;
            case TELNET_SB_DATA:
                if (c == 0xFF)
                    state = TELNET_IAC;
                else
                    ;
                break;
            case TELNET_SB:
                {
                    const char *name = option_name_lookup(c);
                    char tmp[16];
                    if (name == NULL) {
                        sprintf_s(tmp, sizeof(tmp), "0x%02x", c);
                        name = tmp;
                    }
                    if (name[0]) {
                        banout_append_char(banout, PROTO_TELNET, ' ');
                        banout_append(banout, PROTO_TELNET, "SB", AUTO_LEN);
                        banout_append_char(banout, PROTO_TELNET, '(');
                        banout_append(banout, PROTO_TELNET, name, AUTO_LEN);
                        banout_append_char(banout, PROTO_TELNET, ')');
                    }
                    state = TELNET_SB_DATA;
                }
                break;
            case TELNET_DO:
            case TELNET_DONT:
            case TELNET_WILL:
            case TELNET_WONT:
                switch (state) {
                    case TELNET_DO:
                        nego[c] = FLAG_WONT;
                        break;
                    case TELNET_DONT:
                        nego[c] = FLAG_WONT;
                        break;
                    case TELNET_WILL:
                        nego[c] = FLAG_DONT;
                        break;
                    case TELNET_WONT:
                        nego[c] = FLAG_DONT;
                        break;
                }
            {
                const char *name = option_name_lookup(c);
                char tmp[16];
                if (name == NULL) {
                    sprintf_s(tmp, sizeof(tmp), "0x%02x", c);
                    name = tmp;
                }
                if (name[0]) {
                    banout_append_char(banout, PROTO_TELNET, ' ');
                    banout_append(banout, PROTO_TELNET, foobar[state-TELNET_DO], AUTO_LEN);
                    banout_append_char(banout, PROTO_TELNET, '(');
                    banout_append(banout, PROTO_TELNET, name, AUTO_LEN);
                    banout_append_char(banout, PROTO_TELNET, ')');
                }
            }
                state = 0;
                break;
            default:
                offset = (unsigned)length;
                break;
        }
    }
    
    {
#define r_length (256*3*4)
        unsigned char reply[r_length];
        size_t r_offset = 0;
        size_t i;
        
        for (i=0; i<256 && r_offset + 3 < r_length; i++) {
            if (nego[i] & FLAG_WILL) {
                reply[r_offset++] = 0xFF; /* IAC */
                reply[r_offset++] = 0xFB; /* WILL */
                reply[r_offset++] = (unsigned char)i;
            }
            if (nego[i] & FLAG_WONT) {
                reply[r_offset++] = 0xFF; /* IAC */
                reply[r_offset++] = 0xFC; /* WONT */
                reply[r_offset++] = (unsigned char)i;
            }
            if (nego[i] & FLAG_DO) {
                reply[r_offset++] = 0xFF; /* IAC */
                reply[r_offset++] = 0xFD; /* DO */
                reply[r_offset++] = (unsigned char)i;
            }
            if (nego[i] & FLAG_DONT) {
                reply[r_offset++] = 0xFF; /* IAC */
                reply[r_offset++] = 0xFE; /* DONT */
                reply[r_offset++] = (unsigned char)i;
            }
        }
        if (r_offset) {
            unsigned char *outbuf = MALLOC(r_offset);
            memcpy(outbuf, reply, r_offset);
            tcp_transmit(more, outbuf, r_offset, 1);
        }
    }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *
telnet_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
telnet_selftest_item(const char *input, const char *output)
{
    struct Banner1 *banner1;
    struct ProtocolState pstate[1];
    struct BannerOutput banout1[1];
    struct InteractiveData more;
    int x;
    
    /*
     * Initiate a pseudo-environment for the parser
     */
    banner1 = banner1_create();
    banout_init(banout1);
    memset(&pstate[0], 0, sizeof(pstate[0]));
    
    /*
     * Parse the input payload
     */
    telnet_parse(banner1,
                 0,
                 pstate,
                 (const unsigned char *)input,
                 strlen(input),
                 banout1,
                 &more
                 );
    //fprintf(stderr, "%.*s\n", (int)banout_string_length(banout1, PROTO_TELNET), banout_string(banout1, PROTO_TELNET));
    /*
     * Verify that somewhere in the output is the string
     * we are looking for
     */
    x = banout_is_contains(banout1, PROTO_TELNET, output);
    if (x == 0)
        printf("telnet parser failure: %s\n", output);
    banner1_destroy(banner1);
    banout_release(banout1);
    
    return (x==0)?1:0;
}

/***************************************************************************
 ***************************************************************************/
static int
telnet_selftest(void)
{
    struct {
        const char *input;
        const char *output;
    } tests[] = {
        {"\xff\xfd\x1flogin:", "login"},
        {"\xff\xfd\x27\xff\xfd\x18 ", " "},
        {
            "\xff\xfb\x25\xff\xfd\x03\xff\xfb\x18\xff\xfb\x1f\xff\xfb\x20\xff" \
            "\xfb\x21\xff\xfb\x22\xff\xfb\x27\xff\xfd\x05"
            "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"
            "\xff\xfa\x18\x01\xff\xf0"
            "\x0d\x0a\x55\x73\x65\x72\x20\x41\x63\x63\x65\x73\x73\x20\x56\x65" \
            "\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x0d\x0a\x0d\x0a"
            ,
            "User Access"
            
        },
        {   "\xff\xfd\x01\xff\xfd\x1f\xff\xfd\x21\xff\xfb\x01\xff\xfb\x03\x46"
            "\x36\x37\x30\x0d\x0a\x0d\x4c\x6f\x67\x69\x6e\x3a\x20",
            "F670\\n Login:"
        },
        {0,0}
    };
    size_t i;
    
    for (i=0; tests[i].input; i++) {
        int err;
        
        err = telnet_selftest_item(tests[i].input, tests[i].output);
        if (err) {
            fprintf(stderr, "telnet: selftest fail, item %u\n", (unsigned)i);
            return err;
        }
    }
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_telnet = {
    "telnet", 23, "\xff\xf6", 2, 0,
    telnet_selftest,
    telnet_init,
    telnet_parse,
};
