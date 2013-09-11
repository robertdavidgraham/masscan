#include "proto-ssh.h"
#include "proto-banner1.h"
#include <ctype.h>

/***************************************************************************
 ***************************************************************************/
unsigned
banner_ssh(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned i;

    banner1=banner1;

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
    return state;
}
