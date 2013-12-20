/*
    Read in the binary file produced by "out-binary.c". This allows you to
    translate the "binary" format into any of the other output formats.
*/
#include "in-binary.h"
#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "main-globals.h"
#include "output.h"
#include "string_s.h"

static const size_t BUF_MAX = 1024*1024;

struct MasscanRecord {
    unsigned timestamp;
    unsigned ip;
    unsigned char ip_proto;
    unsigned short port;
    unsigned char reason;
    unsigned char ttl;
    enum ApplicationProtocol app_proto;
};


/***************************************************************************
 ***************************************************************************/
static void
parse_status(struct Output *out,
        enum PortStatus status, /* open/closed */
        const unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;

    if (buf_length < 12)
        return;

    /* parse record */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.port      = buf[8]<<8 | buf[9];
    record.reason    = buf[10];
    record.ttl       = buf[11];

    /*
     * Now report ther result
     */
    output_report_status(out,
                    record.timestamp,
                    status,
                    record.ip,
                    record.port,
                    record.reason,
                    record.ttl);

}

/***************************************************************************
 * [OBSOLETE]
 *  This parses an old version of the banner record. I've still got files
 *  hanging around with this version, so I'm keeping it in the code for
 *  now, but eventually I'll get rid of it.
 ***************************************************************************/
static void
parse_banner3(struct Output *out, unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.port      = buf[8]<<8 | buf[9];
    record.app_proto = buf[10]<<8 | buf[11];


    /*
     * Now print the output
     */
    output_report_banner(
                out,
                record.timestamp,
                record.ip,
                6, /* this is always TCP */
                record.port,
                record.app_proto,
                buf+12, (unsigned)buf_length-12
                );
}

/***************************************************************************
 * Parse the BANNER record, extracting the timestamp, IP addres, and port
 * number. We also convert the banner string into a safer form.
 ***************************************************************************/
static void
parse_banner4(struct Output *out, unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    record.app_proto = buf[11]<<8 | buf[12];

    /*
     * Now print the output
     */
    output_report_banner(
                out,
                record.timestamp,
                record.ip,
                record.ip_proto,    /* TCP=6, UDP=17 */
                record.port,
                record.app_proto,   /* HTTP, SSL, SNMP, etc. */
                buf+13, (unsigned)buf_length-13
                );
}

/***************************************************************************
 * Read in the file, one record at a time.
 ***************************************************************************/
static uint64_t
parse_file(struct Output *out, const char *filename)
{
    FILE *fp = 0;
    unsigned char *buf = 0;
    size_t bytes_read;
    uint64_t total_records = 0;
    int x;

    /* Allocate a buffer of up to one megabyte per record */
    buf = (unsigned char *)malloc(BUF_MAX);
    if (buf == NULL) {
        fprintf(stderr, "memory allocation failure\n");
        goto end;
    }

    /* Open the file */
    x = fopen_s(&fp, filename, "rb");
    if (x != 0 || fp == NULL) {
        perror(filename);
        goto end;
    }

    /* first record is pseudo-record */
    bytes_read = fread(buf, 1, 'a'+2, fp);
    if (bytes_read < 'a'+2) {
        perror(filename);
        goto end;
    }

    /* Make sure it's got the format string */
    if (memcmp(buf, "masscan/1.1", 11) != 0) {
        fprintf(stderr,
                "%s: unknown file format (expeced \"masscan/1.1\")\n",
                filename);
        goto end;
    }

    /* Now read all records */
    for (;;) {
        unsigned type;
        unsigned length;


        /* [TYPE]
         * This is one or more bytes indicating the type of type of the
         * record
         */
        bytes_read = fread(buf, 1, 1, fp);
        if (bytes_read != 1)
            break;
        type = buf[0] & 0x7F;
        while (buf[0] & 0x80) {
            bytes_read = fread(buf, 1, 1, fp);
            if (bytes_read != 1)
                break;
            type = (type << 7) | (buf[0] & 0x7F);
        }

        /* [LENGTH]
         * Is one byte for lengths smaller than 127 bytes, or two
         * bytes for lengths up to 16384.
         */
        bytes_read = fread(buf, 1, 1, fp);
        if (bytes_read != 1)
            break;
        length = buf[0] & 0x7F;
        while (buf[0] & 0x80) {
            bytes_read = fread(buf, 1, 1, fp);
            if (bytes_read != 1)
                break;
            length = (length << 7) | (buf[0] & 0x7F);
        }
        if (length > BUF_MAX) {
            fprintf(stderr, "file corrupt\n");
            goto end;
        }


        /* get the remainder fo the record */
        bytes_read = fread(buf, 1, length, fp);
        if (bytes_read < (int)length)
            break; /* eof */

        /* Depending on record type, do something different */
        switch (type) {
            case 1: /* STATUS: open */
                parse_status(out, Port_Open, buf, bytes_read);
                break;
            case 2: /* STATUS: closed */
                parse_status(out, Port_Closed, buf, bytes_read);
                break;
            case 3: /* BANNER */
                parse_banner3(out, buf, bytes_read);
                break;
            case 4:
                if (fread(buf+bytes_read,1,1,fp) != 1) {
                    fprintf(stderr, "read() error\n");
                    exit(1);
                }
                bytes_read++;
                parse_banner4(out, buf, bytes_read);
                break;
            case 5:
                parse_banner4(out, buf, bytes_read);
                break;
            case 'm': /* FILEHEADER */
                //goto end;
                break;
            default:
                fprintf(stderr, "file corrupt: unknown type %u\n", type);
                goto end;
        }
        total_records++;
        if ((total_records & 0xFFFF) == 0)
            fprintf(stderr, "%s: %8llu\r", filename, total_records);
    }

end:
    if (buf)
        free(buf);
    if (fp)
        fclose(fp);
    return total_records;
}


/*****************************************************************************
 * When masscan is called with the "--readscan" parameter, it doesn't
 * do a scan of the live network, but instead reads scan results from
 * a file. Those scan results can then be written out in any of the
 * other formats. This preserves the original timestamps.
 *****************************************************************************/
void
convert_binary_files(struct Masscan *masscan,
                     int arg_first, int arg_max, char *argv[])
{
    struct Output *out;
    int i;

    out = output_create(masscan, 0);

    /*
     * We don't parse the entire argument list, just a subrange
     * containing the list of files. The 'arg_first' parameter
     * points to the first filename after the '--readscan'
     * parameter, and 'arg_max' is the parameter after
     * the last filename. For example, consider an argument list that
     * looks like:
     *   masscan --foo --readscan file1.scan file2.scan --bar
     * Then arg_first=3 and arg_max=5.
     */
    for (i=arg_first; i<arg_max; i++) {
        parse_file(out, argv[i]);
    }

    output_destroy(out);
}


