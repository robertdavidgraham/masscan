#include "proto-ftp.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-ssl.h"
#include "proto-tcp-transmit.h"
#include "proto-stream-default.h"
#include <ctype.h>
#include <string.h>


/***************************************************************************
 ***************************************************************************/
static void
ftp_parse(  const struct Banner1 *banner1,
          void *banner1_private,
          struct ProtocolState *pstate,
          const unsigned char *px, size_t length,
          struct BannerOutput *banout,
          struct TCP_Control_Block *tcb)
{
    unsigned state = pstate->state;
    unsigned i;
    struct FTPSTUFF *ftp = &pstate->sub.ftp;
    
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    
    for (i=0; i<length; i++) {
        
        switch (state) {
            case 0:
            case 100:
                ftp->code = 0;
                state++;
                /* fall through */
            case 1:
            case 2:
            case 3:
            case 101:
            case 102:
            case 103:
                if (!isdigit(px[i]&0xFF)) {
                    state = STATE_DONE;
                } else {
                    ftp->code *= 10;
                    ftp->code += (px[i] - '0');
                    state++;
                    banout_append_char(banout, PROTO_FTP, px[i]);
                }
                break;
            case 4:
            case 104:
                if (px[i] == ' ') {
                    ftp->is_last = 1;
                    state++;
                    banout_append_char(banout, PROTO_FTP, px[i]);
                } else if (px[i] == '-') {
                    ftp->is_last = 0;
                    state++;
                    banout_append_char(banout, PROTO_FTP, px[i]);
                } else {
                    state = STATE_DONE;
                }
                break;
            case 5:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    if (ftp->is_last) {
                        tcp_add_xmit(tcb, "AUTH TLS\r\n", 10, XMIT_STATIC);
                        state = 100;
                        banout_append_char(banout, PROTO_FTP, px[i]);
                    } else {
                        banout_append_char(banout, PROTO_FTP, px[i]);
                        state = 0;
                    }
                } else if (px[i] == '\0' || !isprint(px[i])) {
                    state = STATE_DONE;
                    continue;
                } else {
                    banout_append_char(banout, PROTO_FTP, px[i]);
                }
                break;
            case 105:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    
                    if (ftp->code == 234) {
                        ssl_switch(tcb, pstate);
                        return;                                                
                    } else {
                        state = STATE_DONE;
                    }
                } else if (px[i] == '\0' || !isprint(px[i])) {
                    state = STATE_DONE;
                    continue;
                } else {
                    banout_append_char(banout, PROTO_FTP, px[i]);
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
ftp_init(struct Banner1 *banner1, struct ProtocolParserStream *self)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(self);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
ftp_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_ftp = {
    "ftp", 21, 
    //0, 0, 0,
    ftp_selftest,
    ftp_init,
    ftp_parse,
    default_hello,
    default_set_parameter,
};
