#include "proto-ssh.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include <ctype.h>


/***************************************************************************
 ***************************************************************************/
static void
ssh_parse(  const struct Banner1 *banner1,
        void *banner1_private,
        struct Banner1State *pstate,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned state = pstate->state;
    unsigned i;

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    for (i=0; i<length; i++)
    switch (state) {
    case 0:
        if (px[i] == '\r')
            continue;
        if (px[i] == '\n' || px[i] == '\0' || !isprint(px[i])) {
            state = STATE_DONE;
            continue;
        }
        if (*banner_offset < banner_max)
            banner[(*banner_offset)++] = px[i];
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
ssh_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
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
struct Banner1Stream banner_ssh = {
    "ssh", 22, 0, 0,
    ssh_selftest,
    ssh_init,
    ssh_parse,
};
