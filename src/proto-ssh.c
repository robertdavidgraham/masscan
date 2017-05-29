#include "proto-ssh.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-stream-default.h"
#include <ctype.h>


/***************************************************************************
 ***************************************************************************/
static void
ssh_parse(  const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct TCP_Control_Block *tcb)
{
    unsigned state = pstate->state;
    unsigned i;

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    UNUSEDPARM(tcb);

    for (i=0; i<length; i++)
    switch (state) {
    case 0:
        if (px[i] == '\r')
            continue;
        if (px[i] == '\n' || px[i] == '\0' || !isprint(px[i])) {
            state = STATE_DONE;
            continue;
        }
        banout_append_char(banout, PROTO_SSH2, px[i]);
        break;
    default:
        i = (unsigned)length;
        break;
    }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void 
ssh_hello(const struct Banner1 *banner1,
        void *banner1_private,
        struct ProtocolState *stream_state,
        struct TCP_Control_Block *tcb)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(stream_state);
    UNUSEDPARM(tcb);
}

/***************************************************************************
 ***************************************************************************/
static void *
ssh_init(struct Banner1 *banner1, struct ProtocolParserStream *self)
{
    UNUSEDPARM(banner1);
    UNUSEDPARM(self);
    return 0;
}


/***************************************************************************
 ***************************************************************************/
static int
ssh_selftest(void)
{
    return 0;
}

/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_ssh = {
    "ssh", 22, 
    ssh_selftest,
    ssh_init,
    ssh_parse,
    ssh_hello,
    default_set_parameter,
};
