#include "proto-vnc.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "string_s.h"
#include "smack.h"
#include <ctype.h>


static void
vnc_append_sectype(struct BannerOutput *banout, unsigned sectype)
{
    char foo[16];

    /*
     http://www.iana.org/assignments/rfb/rfb.xml
    Value 	Name 	Reference 
    0	Invalid	[RFC6143]
    1	None	[RFC6143]
    2	VNC Authentication	[RFC6143]
    3-15	RealVNC	historic assignment
    16	Tight	historic assignment
    17	Ultra	historic assignment
    18	TLS	historic assignment
    19	VeNCrypt	historic assignment
    20	GTK-VNC SASL	historic assignment
    21	MD5 hash authentication	historic assignment
    22	Colin Dean xvp	historic assignment
    23-29	Unassigned	
    30-35	Apple Inc.	[Michael_Stein]
    36-127	Unassigned	
    128-255	RealVNC	historic assignment
    */
    switch (sectype) {
        case 0:
            banout_append(banout, PROTO_VNC_RFB, "invalid", AUTO_LEN); 
            break;
        case 1:
            banout_append(banout, PROTO_VNC_RFB, "none", AUTO_LEN); 
            break;
        case 2:
            banout_append(banout, PROTO_VNC_RFB, "VNC-chap", AUTO_LEN); 
            break;
        case 5:
            banout_append(banout, PROTO_VNC_RFB, "RA2", AUTO_LEN); 
            break;
        case 6:
            banout_append(banout, PROTO_VNC_RFB, "RA2ne", AUTO_LEN); 
            break;
        case 7:
            banout_append(banout, PROTO_VNC_RFB, "SSPI", AUTO_LEN); 
            break;
        case 8:
            banout_append(banout, PROTO_VNC_RFB, "SSPIne", AUTO_LEN); 
            break;
        case 16:
            banout_append(banout, PROTO_VNC_RFB, "Tight", AUTO_LEN); 
            break;
        case 17:
            banout_append(banout, PROTO_VNC_RFB, "Ultra", AUTO_LEN); 
            break;
        case 18:
            banout_append(banout, PROTO_VNC_RFB, "TLS", AUTO_LEN); 
            break;
        case 19:
            banout_append(banout, PROTO_VNC_RFB, "VeNCrypt", AUTO_LEN); 
            break;
        case 20:
            banout_append(banout, PROTO_VNC_RFB, "GTK-VNC-SASL", AUTO_LEN); 
            break;
        case 21:
            banout_append(banout, PROTO_VNC_RFB, "MD5", AUTO_LEN); 
            break;
        case 22:
            banout_append(banout, PROTO_VNC_RFB, "Colin-Dean-xvp", AUTO_LEN); 
            break;
        case 30:
            banout_append(banout, PROTO_VNC_RFB, "Apple30", AUTO_LEN); 
            break;
        case 35:
            banout_append(banout, PROTO_VNC_RFB, "Apple35", AUTO_LEN); 
            break;
        default:
            sprintf_s(foo, sizeof(foo), "%u", sectype);
            banout_append(banout, PROTO_VNC_RFB, foo, AUTO_LEN); 
            break;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
vnc_parse(  const struct Banner1 *banner1,
          void *banner1_private,
          struct ProtocolState *pstate,
          const unsigned char *px, size_t length,
          struct BannerOutput *banout,
          struct InteractiveData *more)
{
    unsigned state = pstate->state;
    unsigned i;
    char foo[64];
    
    enum {
        RFB3_3_SECURITYTYPES=50,
        RFB_SECURITYERROR=60,
        RFB3_7_SECURITYTYPES=100,
        RFB_SERVERINIT=200,
        RFB_SECURITYRESULT=300,
        RFB_DONE=0x7fffffff,
    };
    
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    
    for (i=0; i<length; i++)
        switch (state) {
            case 0: 
                
            
            case 1: case 2: case 3: case 4: case 5: case 6:
            case 7: case 8: case 9:
                state++;
                banout_append_char(banout, PROTO_VNC_RFB, px[i]);
                break;
            case 10:
                state++;
                banout_append_char(banout, PROTO_VNC_RFB, px[i]);
                break;
            case 11:
                if ('\n' == px[i]) {
                    static const char *response[] = {
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.003\n",
                        "RFB 003.007\n",
                        "RFB 003.008\n",
                        "RFB 003.008\n",
                    };
                    unsigned version = pstate->sub.vnc.version % 10;
                    
                    tcp_transmit(more, response[version], 12, 0);

                    if (version < 7)
                        /* Version 3.3: the server selects either "none" or
                         * "vnc challenge/response" and informs us which one
                         * to use */
                        state = RFB3_3_SECURITYTYPES;
                    else {
                        /* Version 3.7 onwards: the server will send us a list
                         * of security types it supports, from which the
                         * client will select one */
                        state = RFB3_7_SECURITYTYPES;
                    }
                } else {
                    state = 0xFFFFFFFF;
                    tcp_close(more);
                }
                break;
            case RFB3_3_SECURITYTYPES:
            case RFB_SECURITYERROR:
            case RFB_SECURITYRESULT:
            case RFB_SERVERINIT+20:
                pstate->sub.vnc.sectype = px[i];
                state++;
                break;
            case RFB3_3_SECURITYTYPES+1:
            case RFB3_3_SECURITYTYPES+2:
            case RFB_SECURITYERROR+1:
            case RFB_SECURITYERROR+2:
            case RFB_SECURITYRESULT+1:
            case RFB_SECURITYRESULT+2:
            case RFB_SERVERINIT+21:
            case RFB_SERVERINIT+22:
                pstate->sub.vnc.sectype <<= 8;
                pstate->sub.vnc.sectype |= px[i];
                state++;
                break;
            case RFB3_3_SECURITYTYPES+3:
                pstate->sub.vnc.sectype <<= 8;
                pstate->sub.vnc.sectype |= px[i];
                banout_append(banout, PROTO_VNC_RFB, " auth=[", AUTO_LEN);
                vnc_append_sectype(banout, pstate->sub.vnc.sectype);
                banout_append(banout, PROTO_VNC_RFB, "]", AUTO_LEN);
                if (pstate->sub.vnc.sectype == 0)
                    state = RFB_SECURITYERROR;
                else if (pstate->sub.vnc.sectype == 1) {
                    /* v3.3 sectype=none
                     * We move immediately to ClientInit stage */
                    tcp_transmit(more, "\x01", 1, 0);
                    state = RFB_SERVERINIT;
                } else {
                    state = RFB_DONE;
                    tcp_close(more);
                }
                break;
            case RFB_SECURITYRESULT+3:
                pstate->sub.vnc.sectype <<= 8;
                pstate->sub.vnc.sectype |= px[i];
                if (pstate->sub.vnc.sectype == 0) {
                    /* security ok, move to client init */
                    tcp_transmit(more, "\x01", 1, 0);
                    state = RFB_SERVERINIT;
                } else {
                    /* error occurred, so grab error message */
                    state = RFB_SECURITYERROR;
                }
                break;
            case RFB_SECURITYERROR+3:
                pstate->sub.vnc.sectype <<= 8;
                pstate->sub.vnc.sectype = px[i];
                banout_append(banout, PROTO_VNC_RFB, " ERROR=", AUTO_LEN);
                state++;
                break;
            case RFB_SECURITYERROR+4:
                if (pstate->sub.vnc.sectype == 0) {
                    state = RFB_DONE;
                    tcp_close(more);
                } else {
                    pstate->sub.vnc.sectype--;
                    banout_append_char(banout, PROTO_VNC_RFB, px[i]);
                }
                break;
            case RFB3_7_SECURITYTYPES:
                pstate->sub.vnc.len = px[i];
                if (pstate->sub.vnc.len == 0)
                    state = RFB_SECURITYERROR;
                else {
                    state++;
                    banout_append(banout, PROTO_VNC_RFB, " auth=[", AUTO_LEN);
                }
                break;
            case RFB3_7_SECURITYTYPES+1:
                if (pstate->sub.vnc.len != 0) {
                    pstate->sub.vnc.len--;
                    vnc_append_sectype(banout, px[i]);
                }
                if (pstate->sub.vnc.len == 0) {
                    banout_append(banout, PROTO_VNC_RFB, "]", AUTO_LEN);
                    if (pstate->sub.vnc.version < 7) {
                        state = RFB_SERVERINIT;
                        tcp_transmit(more, "\x01", 1, 0);
                    } else if (pstate->sub.vnc.version == 7) {
                        state = RFB_SERVERINIT;
                        tcp_transmit(more, "\x01\x01", 2, 0);
                    } else {
                        state = RFB_SECURITYRESULT;
                        tcp_transmit(more, "\x01", 1, 0);
                    }
                } else {
                    banout_append(banout, PROTO_VNC_RFB, "/", AUTO_LEN);
                }
                break;
            
            
                
            case RFB_SERVERINIT:
                pstate->sub.vnc.width = px[i];
                state++;
                break;
            case RFB_SERVERINIT+1:
                pstate->sub.vnc.width <<= 8;
                pstate->sub.vnc.width |= px[i];
                sprintf_s(foo, sizeof(foo), " width=%u", pstate->sub.vnc.width);
                banout_append(banout, PROTO_VNC_RFB, foo, AUTO_LEN);
                state++;
                break;
            case RFB_SERVERINIT+2:
                pstate->sub.vnc.height = px[i];
                state++;
                break;
            case RFB_SERVERINIT+3:
                pstate->sub.vnc.height <<= 8;
                pstate->sub.vnc.height |= px[i];
                sprintf_s(foo, sizeof(foo), " height=%u", pstate->sub.vnc.height);
                banout_append(banout, PROTO_VNC_RFB, foo, AUTO_LEN);
                state++;
                break;
            
            case RFB_SERVERINIT+ 4:
            case RFB_SERVERINIT+ 5:
            case RFB_SERVERINIT+ 6:
            case RFB_SERVERINIT+ 7:
            case RFB_SERVERINIT+ 8:
            case RFB_SERVERINIT+ 9:
            case RFB_SERVERINIT+10:
            case RFB_SERVERINIT+11:
            case RFB_SERVERINIT+12:
            case RFB_SERVERINIT+13:
            case RFB_SERVERINIT+14:
            case RFB_SERVERINIT+15:
            case RFB_SERVERINIT+16:
            case RFB_SERVERINIT+17:
            case RFB_SERVERINIT+18:
            case RFB_SERVERINIT+19:
                state++;
                break;
                
            case RFB_SERVERINIT+23:
                pstate->sub.vnc.sectype <<= 8;
                pstate->sub.vnc.sectype |= px[i];
                state++;
                if (pstate->sub.vnc.sectype) {
                    banout_append(banout, PROTO_VNC_RFB, " name=[", AUTO_LEN);
                } else {
                    state = RFB_DONE;
                    tcp_close(more);
                }
                break;
                
            case RFB_SERVERINIT+24:
                pstate->sub.vnc.sectype--;
                banout_append_char(banout, PROTO_VNC_RFB, px[i]);
                if (pstate->sub.vnc.sectype == 0) {
                    banout_append(banout, PROTO_VNC_RFB, "]", AUTO_LEN);
                    state = RFB_DONE;
                    tcp_close(more);
                }
                break;


                
            case RFB_DONE:
                tcp_close(more);
                i = (unsigned)length;
                break;
            default:
                i = (unsigned)length;
                break;
        }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *
vnc_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
vnc_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_vnc = {
    "vnc", 5900, 0, 0, 0,
    vnc_selftest,
    vnc_init,
    vnc_parse,
};
