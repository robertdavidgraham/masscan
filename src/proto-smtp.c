/*

    SMTP banner checker
 
 This file interacts with an SMTP server when it finds a connection on
 an SMTP port like 25 with a "220 " as the banner.
 
 Firstly, SMTP requires that the client send a "EHLO" command in order to
 announce its presence. This command will tell us about some optional
 features of the server, which we'll record as part of the [smtp] banner.
 
 Secondly, we'll attempt to do a STARTTLS command, regardless whether the
 server advertised the capability. This should either get back an "OK" 
 message or an error, which we also record as part of the banner.
 
 If we get an OK, then we switch the parser to SSL, and continue as if 
 this were an SSL connection. Any SSL data will show up as an [ssl] protocol
 rather than an SMTP protocol.
 
*/

#include "proto-smtp.h"
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
smtp_parse(  const struct Banner1 *banner1,
          void *banner1_private,
          struct ProtocolState *pstate,
          const unsigned char *px, size_t length,
          struct BannerOutput *banout,
          struct InteractiveData *more)
{
    unsigned state = pstate->state;
    unsigned i;
    struct SMTPSTUFF *smtp = &pstate->sub.smtp;
    
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    
    
    for (i=0; i<length; i++) {
        
        switch (state) {
            case 0:
            case 100:
            case 200:
                smtp->code = 0;
                state++;
                /* fall through */
            case 1:
            case 2:
            case 3:
            case 101:
            case 102:
            case 103:
            case 201:
            case 202:
            case 203:
                if (!isdigit(px[i]&0xFF)) {
                    state = 0xffffffff;
                    tcp_close(more);
                } else {
                    smtp->code *= 10;
                    smtp->code += (px[i] - '0');
                    state++;
                    banout_append_char(banout, PROTO_SMTP, px[i]);
                }
                break;
            case 4:
            case 104:
            case 204:
                if (px[i] == ' ') {
                    smtp->is_last = 1;
                    state++;
                    banout_append_char(banout, PROTO_SMTP, px[i]);
                } else if (px[i] == '-') {
                    smtp->is_last = 0;
                    state++;
                    banout_append_char(banout, PROTO_SMTP, px[i]);
                } else {
                    state = 0xffffffff;
                    tcp_close(more);
                }
                break;
            case 5:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    if (smtp->is_last) {
                        tcp_transmit(more, "EHLO masscan\r\n", 14, 0);
                        state = 100;
                        banout_append_char(banout, PROTO_SMTP, px[i]);
                    } else {
                        banout_append_char(banout, PROTO_SMTP, px[i]);
                        state = 0;
                    }
                } else if (px[i] == '\0' || !isprint(px[i])) {
                    state = 0xffffffff;
                    tcp_close(more);
                    continue;
                } else {
                    banout_append_char(banout, PROTO_SMTP, px[i]);
                }
                break;
            case 105:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    if (smtp->is_last) {
                        tcp_transmit(more, "STARTTLS\r\n", 10, 0);
                        state = 200;
                        banout_append_char(banout, PROTO_SMTP, px[i]);
                    } else {
                        banout_append_char(banout, PROTO_SMTP, px[i]);
                        state = 100;
                    }
                } else if (px[i] == '\0' || !isprint(px[i])) {
                    state = 0xffffffff;
                    tcp_close(more);
                    continue;
                } else {
                    banout_append_char(banout, PROTO_SMTP, px[i]);
                }
                break;
            case 205:
                if (px[i] == '\r')
                    continue;
                else if (px[i] == '\n') {
                    
                    if (smtp->code == 220) {
                        
                        /* change the state here to SSL */
                        unsigned port = pstate->port;
                        memset(pstate, 0, sizeof(*pstate));
                        pstate->app_proto = PROTO_SSL3;
                        pstate->is_sent_sslhello = 1;
                        pstate->port = (unsigned short)port;
                        state = 0;
                        
                        tcp_transmit(more, banner_ssl.hello, banner_ssl.hello_length, 0);
                        
                    } else {
                        state = 0xffffffff;
                        tcp_close(more);
                    }
                } else if (px[i] == '\0' || !isprint(px[i])) {
                    state = 0xffffffff;
                    tcp_close(more);
                    continue;
                } else {
                    banout_append_char(banout, PROTO_SMTP, px[i]);
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
smtp_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
smtp_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_smtp = {
    "smtp", 25, 0, 0, 0,
    smtp_selftest,
    smtp_init,
    smtp_parse,
};
