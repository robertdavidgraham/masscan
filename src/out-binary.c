#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"

/****************************************************************************
 ****************************************************************************/
static void
binary_out_open(struct Output *out, FILE *fp)
{
    char firstrecord[2+'a'];
    size_t bytes_written;

    UNUSEDPARM(out);


    memset(firstrecord, 0, 2+'a');
    sprintf_s(firstrecord, 2+'a', "masscan/1.1.02\ns:%u\n", 
        (unsigned)out->when_scan_started);
    bytes_written = fwrite(firstrecord, 1, 2+'a', fp);
    if (bytes_written != 2+'a') {
        perror("output");
        exit(1);
    }

    out->rotate.bytes_written += bytes_written;
}


/****************************************************************************
 ****************************************************************************/
static void
binary_out_close(struct Output *out, FILE *fp)
{
    char firstrecord[2+'a'];
    size_t bytes_written;

    UNUSEDPARM(out);

    memset(firstrecord, 0, 2+'a');
    sprintf_s(firstrecord, 2+'a', "masscan/1.1");
    bytes_written = fwrite(firstrecord, 1, 2+'a', fp);
    if (bytes_written != 2+'a') {
        perror("output");
        exit(1);
    }
    out->rotate.bytes_written += bytes_written;
}

/****************************************************************************
 ****************************************************************************/
static void
binary_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    unsigned char foo[256];
    size_t bytes_written;

    UNUSEDPARM(out);

    /* [TYPE] field */
    switch (status) {
    case PortStatus_Open:
        foo[0] = Out_Open2;
        break;
    case PortStatus_Closed:
        foo[0] = Out_Closed2;
        break;
    case PortStatus_Arp:
        foo[0] = Out_Arp2;
        break;
    default:
        return;
    }

    /* [LENGTH] field */
    foo[1] = 13;

    /* [TIMESTAMP] field */
    foo[2] = (unsigned char)(timestamp>>24);
    foo[3] = (unsigned char)(timestamp>>16);
    foo[4] = (unsigned char)(timestamp>> 8);
    foo[5] = (unsigned char)(timestamp>> 0);

    foo[6] = (unsigned char)(ip>>24);
    foo[7] = (unsigned char)(ip>>16);
    foo[8] = (unsigned char)(ip>> 8);
    foo[9] = (unsigned char)(ip>> 0);

    foo[10] = (unsigned char)(ip_proto);

    foo[11] = (unsigned char)(port>>8);
    foo[12] = (unsigned char)(port>>0);

    foo[13] = (unsigned char)reason;
    foo[14] = (unsigned char)ttl;



    bytes_written = fwrite(&foo, 1, 15, fp);
    if (bytes_written != 15) {
        perror("output");
        exit(1);
    }
    out->rotate.bytes_written += bytes_written;
}


/****************************************************************************
 ****************************************************************************/
static void
binary_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    unsigned char foo[32768];
    unsigned i;
    size_t bytes_written;
    static const unsigned HeaderLength = 14;

    UNUSEDPARM(out);

    /* [TYPE] field */
    foo[0] = Out_Banner9; /*banner*/

    /* [LENGTH] field*/
    if (length >= 128 * 128 - HeaderLength)
        return;
    if (length < 128 - HeaderLength) {
        foo[1] = (unsigned char)(length + HeaderLength);
        i = 2;
    } else {
        foo[1] = (unsigned char)((length + HeaderLength)>>7) | 0x80;
        foo[2] = (unsigned char)((length + HeaderLength) & 0x7F);
        i = 3;
    }

    /* [TIMESTAMP] field */
    foo[i+0] = (unsigned char)(timestamp>>24);
    foo[i+1] = (unsigned char)(timestamp>>16);
    foo[i+2] = (unsigned char)(timestamp>> 8);
    foo[i+3] = (unsigned char)(timestamp>> 0);

    foo[i+4] = (unsigned char)(ip>>24);
    foo[i+5] = (unsigned char)(ip>>16);
    foo[i+6] = (unsigned char)(ip>> 8);
    foo[i+7] = (unsigned char)(ip>> 0);

    foo[i+8] = (unsigned char)(ip_proto);

    foo[i+ 9] = (unsigned char)(port>>8);
    foo[i+10] = (unsigned char)(port>>0);

    foo[i+11] = (unsigned char)(proto>>8);
    foo[i+12] = (unsigned char)(proto>>0);

    foo[i+13] = (unsigned char)(ttl);

    /* Banner */
    memcpy(foo+i+14, px, length);


    bytes_written = fwrite(&foo, 1, length+i+HeaderLength, fp);
    if (bytes_written != length+i+HeaderLength) {
        perror("output");
        exit(1);
    }
    out->rotate.bytes_written += bytes_written;
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


