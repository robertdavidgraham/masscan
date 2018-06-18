/*
 
    POP3 banner checker
 
 
 */

#include "proto-pop3.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-interactive.h"
#include "proto-ssl.h"
#include <ctype.h>
#include <string.h>


/***************************************************************************
 ***************************************************************************/
static void
pop3_parse(  const struct Banner1 *banner1,
           void *banner1_private,
           struct ProtocolState *pstate,
           const unsigned char *px, size_t length,
           struct BannerOutput *banout,
           struct InteractiveData *more)
{
    unsigned state = pstate->state;
    unsigned i;
    
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    
    
    for (i=0; i<length; i++) {
        if (px[i] == '\r')
            continue;

       
        switch (state) {
            case 0: case 1: case 2:
                banout_append_char(banout, PROTO_POP3, px[i]);
                if ("+OK"[state] != px[i]) {
                    state = 0xffffffff;
                    tcp_close(more);
                } else
                    state++;
                break;
            case 3:
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '\n') {
                    tcp_transmit(more, "CAPA\r\n", 6, 0);
                    state++;
                }
                break;
            case 4:
            case 204:
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '-')
                    state = 100;
                else if (px[i] == '+')
                    state++;
                else {
                    state = 0xffffffff;
                    tcp_close(more);
                }
                break;
            case 5:
            case 205:
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == 'O')
                    state++;
                else {
                    state = 0xffffffff;
                    tcp_close(more);
                }
                break;
            case 6:
            case 206:
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == 'K')
                    state += 2; /* oops, I had too many states here */
                else {
                    state = 0xffffffff;
                    tcp_close(more);
                }
                break;
            case 8:
                if (px[i] == '\r')
                    continue;
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '\n')
                    state++;
                break;
            case 9:
                if (px[i] == '\r')
                    continue;
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '.')
                    state++;
                else if (px[i] == '\n')
                    continue;
                else
                    state--;
                break;
            case 10:
                if (px[i] == '\r')
                    continue;
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '\n') {
                    tcp_transmit(more, "STLS\r\n", 6, 0);
                    state = 204;
                } else {
                    state = 8;
                }
                break;
            
            case 208:
                if (px[i] == '\r')
                    continue;
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '\n') {
                    /* change the state here to SSL */
                    unsigned port = pstate->port;
                    memset(pstate, 0, sizeof(*pstate));
                    pstate->app_proto = PROTO_SSL3;
                    pstate->is_sent_sslhello = 1;
                    pstate->port = (unsigned short)port;
                    state = 0;
                    
                    tcp_transmit(more, banner_ssl.hello, banner_ssl.hello_length, 0);
                    
                    break;
                }
                break;

            case 100:
                if (px[i] == '\r')
                    continue;
                banout_append_char(banout, PROTO_POP3, px[i]);
                if (px[i] == '\n') {
                    state = 0xffffffff;
                    tcp_close(more);
                }
                break;
            default:
                i = (unsigned)length;
                break;
        }
    }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *
pop3_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
pop3_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_pop3 = {
    "pop3", 21, 0, 0, 0,
    pop3_selftest,
    pop3_init,
    pop3_parse,
};
