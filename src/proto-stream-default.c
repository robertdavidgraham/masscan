/*

    Default stream protocol

*/

#include "proto-stream-default.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-ssl.h"
#include "proto-tcp-transmit.h"
#include "crypto-base64.h"
#include "misc-name-equals.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

extern const struct ProtocolParserStream banner_default;

/***************************************************************************
 ***************************************************************************/
static void
default_parse(  const struct Banner1 *banner1,
           void *banner1_private,
           struct ProtocolState *pstate,
           const unsigned char *px, size_t length,
           struct BannerOutput *banout,
           struct TCP_Control_Block *tcb)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(pstate);
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(banout);
    UNUSEDPARM(tcb);
}

/***************************************************************************
 ***************************************************************************/
void 
default_hello(const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        struct TCP_Control_Block *tcb)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(stream_state);

    /* blindly transmit the 'hello' string */
    tcp_add_xmit(   tcb, 
                    banner_default.private_hello, 
                    banner_default.private_hello_length, 
                    XMIT_STATIC);
}

/***************************************************************************
 ***************************************************************************/
void
default_set_parameter(
        const struct Banner1 *banner1,
        struct ProtocolParserStream *self,
        const char *name,
        size_t value_length,
        const void *value)
{
    UNUSEDPARM(banner1);
    if (name_equals(name, "hello-string")) {
        self->private_hello = malloc(value_length);
        self->private_hello_length = base64_decode(
                                            self->private_hello, 
                                            value_length,
                                            value, 
                                            value_length);
        return;
    }
}

/***************************************************************************
 ***************************************************************************/
static void *
default_init(struct Banner1 *banner1, struct ProtocolParserStream *self)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(self);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
default_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_default = {
    "default", 0, 
    //0, 0, 0,
    default_selftest,
    default_init,
    default_parse,
    default_hello,
    default_set_parameter,
};
