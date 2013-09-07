#include "output.h"
#include "masscan.h"

/****************************************************************************
 ****************************************************************************/
static void
binary_out_open(struct Output *out, FILE *fp)
{
    char firstrecord[2+'a'];

    UNUSEDPARM(out);


    memset(firstrecord, 0, 2+'a');
    sprintf_s(firstrecord, 2+'a', "masscan/1.1.01");
    fwrite( firstrecord, 1, 2+'a', fp);
}


/****************************************************************************
 ****************************************************************************/
static void
binary_out_close(struct Output *out, FILE *fp)
{
    char firstrecord[2+'a'];

    UNUSEDPARM(out);

    memset(firstrecord, 0, 2+'a');
    sprintf_s(firstrecord, 2+'a', "masscan/1.1");
    fwrite( firstrecord, 1, 2+'a', fp);
}

/****************************************************************************
 ****************************************************************************/
static void
binary_out_status(struct Output *out, FILE *fp, int status, unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    unsigned char foo[256];

    UNUSEDPARM(out);

    /* [TYPE] field */
    switch (status) {
    case Port_Open:
        foo[0] = 1;
        break;
    case Port_Closed:
        foo[0] = 2;
        break;
    default:
        return;
    }

    /* [LENGTH] field */
    foo[1] = 12;

    /* [TIMESTAMP] field */
    foo[2] = (unsigned char)(global_now>>24);
    foo[3] = (unsigned char)(global_now>>16);
    foo[4] = (unsigned char)(global_now>> 8);
    foo[5] = (unsigned char)(global_now>> 0);

    foo[6] = (unsigned char)(ip>>24);
    foo[7] = (unsigned char)(ip>>16);
    foo[8] = (unsigned char)(ip>> 8);
    foo[9] = (unsigned char)(ip>> 0);

    foo[10] = (unsigned char)(port>>8);
    foo[11] = (unsigned char)(port>>0);

    foo[12] = (unsigned char)reason;
    foo[13] = (unsigned char)ttl;



    fwrite(&foo, 1, 14, fp);
}


/****************************************************************************
 ****************************************************************************/
static void
binary_out_banner(struct Output *out, FILE *fp, unsigned ip, unsigned port,
        unsigned proto, const unsigned char *px, unsigned length)
{
    unsigned char foo[256];
    unsigned i;

    UNUSEDPARM(out);

    /* [TYPE] field */
    foo[0] = 3; /*banner*/

    /* [LENGTH] field */
    if (length >= 128 * 128 - 12)
        return;
    if (length <= 128 - 12) {
        foo[1] = (unsigned char)(length + 12);
        i = 2;
    } else {
        foo[1] = (unsigned char)((length + 12)>>7) | 0x80;
        foo[2] = (unsigned char)((length + 12) & 0x7F);
        i = 2;
    }

    /* [TIMESTAMP] field */
    foo[i+0] = (unsigned char)(global_now>>24);
    foo[i+1] = (unsigned char)(global_now>>16);
    foo[i+2] = (unsigned char)(global_now>> 8);
    foo[i+3] = (unsigned char)(global_now>> 0);

    foo[i+4] = (unsigned char)(ip>>24);
    foo[i+5] = (unsigned char)(ip>>16);
    foo[i+6] = (unsigned char)(ip>> 8);
    foo[i+7] = (unsigned char)(ip>> 0);

    foo[i+8] = (unsigned char)(port>>8);
    foo[i+9] = (unsigned char)(port>>0);

    foo[i+10] = (unsigned char)(proto>>8);
    foo[i+11] = (unsigned char)(proto>>0);

    /* Banner */
    memcpy(foo+i+12, px, length);


    fwrite(&foo, 1, length+i+12, fp);
}


/****************************************************************************
 ****************************************************************************/
const struct OutputType binary_output = {
    "scan",
    0,
    binary_out_open,
    binary_out_close,
    binary_out_status,
    binary_out_banner,
};


