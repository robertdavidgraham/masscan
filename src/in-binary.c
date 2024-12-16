/*
    Read in the binary file produced by "out-binary.c". This allows you to
    translate the "binary" format into any of the other output formats.
*/
#include "massip-addr.h"
#include "in-binary.h"
#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "main-globals.h"
#include "output.h"
#include "util-safefunc.h"
#include "in-filter.h"
#include "in-report.h"
#include "util-malloc.h"
#include "util-logger.h"

#include <stdlib.h>
#include <assert.h>

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

static const size_t BUF_MAX = 1024*1024;

struct MasscanRecord {
    unsigned timestamp;
    ipaddress ip;
    unsigned char ip_proto;
    unsigned short port;
    unsigned char reason;
    unsigned char ttl;
    unsigned char mac[6];
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
    record.ip.ipv4   = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip.version = 4;
    record.port      = buf[8]<<8 | buf[9];
    record.reason    = buf[10];
    record.ttl       = buf[11];

    /* if ARP, then there will be a MAC address */
    if (record.ip.ipv4 == 0 && buf_length >= 12+6)
        memcpy(record.mac, buf+12, 6);
    else
        memset(record.mac, 0, 6);

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    switch (record.port) {
    case 53:
    case 123:
    case 137:
    case 161: 
        record.ip_proto = 17;
        break;
    case 36422:
    case 36412:
    case 2905:
        record.ip_proto = 132;
        break;
    default:
        record.ip_proto = 6;
        break;
    }

    /*
     * Now report the result
     */
    output_report_status(out,
                    record.timestamp,
                    status,
                    record.ip,
                    record.ip_proto,
                    record.port,
                    record.reason,
                    record.ttl,
                    record.mac);

}

/***************************************************************************
 ***************************************************************************/
static void
parse_status2(struct Output *out,
        enum PortStatus status, /* open/closed */
        const unsigned char *buf, size_t buf_length,
        struct MassIP *filter)
{
    struct MasscanRecord record;

    if (buf_length < 13)
        return;

    /* parse record */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip.ipv4   = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip.version = 4;
    record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    record.reason    = buf[11];
    record.ttl       = buf[12];

    /* if ARP, then there will be a MAC address */
    if (record.ip.ipv4 == 0 && buf_length >= 13+6)
        memcpy(record.mac, buf+13, 6);
    else
        memset(record.mac, 0, 6);

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    /* Filter for known IP/ports, if specified on command-line */
    if (filter && filter->count_ipv4s) {
        if (!massip_has_ip(filter, record.ip))
            return;
    }
    if (filter && filter->count_ports) {
        if (!massip_has_port(filter, record.port))
            return;
    }

    /*
     * Now report the result
     */
    output_report_status(out,
                    record.timestamp,
                    status,
                    record.ip,
                    record.ip_proto,
                    record.port,
                    record.reason,
                    record.ttl,
                    record.mac);

}

static unsigned char
_get_byte(const unsigned char *buf, size_t length, size_t *offset)
{
    unsigned char result;
    if (*offset < length) {
        result = buf[*offset];
    } else {
        result = 0xFF;
    }
    (*offset)++;
    return result;
}
static unsigned
_get_integer(const unsigned char *buf, size_t length, size_t *r_offset)
{
    unsigned result;
    size_t offset = *r_offset;
    (*r_offset) += 4;
    
    if (offset + 4 <= length) {
        result = buf[offset+0]<<24
                | buf[offset+1]<<16
                | buf[offset+2]<<8
                | buf[offset+3]<<0;
    } else {
        result = 0xFFFFFFFF;
    }
    return result;
}
static unsigned short
_get_short(const unsigned char *buf, size_t length, size_t *r_offset)
{
    unsigned short result;
    size_t offset = *r_offset;
    (*r_offset) += 2;
    
    if (offset + 2 <= length) {
        result = buf[offset+0]<<8
        | buf[offset+1]<<0;
    } else {
        result = 0xFFFF;
    }
    return result;
}

static unsigned long long
_get_long(const unsigned char *buf, size_t length, size_t *r_offset)
{
    unsigned long long result;
    size_t offset = *r_offset;
    (*r_offset) += 8;
    
    if (offset + 8 <= length) {
        result =
          (unsigned long long)buf[offset+0]<<56ULL
        | (unsigned long long)buf[offset+1]<<48ULL
        | (unsigned long long)buf[offset+2]<<40ULL
        | (unsigned long long)buf[offset+3]<<32ULL
        | (unsigned long long)buf[offset+4]<<24ULL
        | (unsigned long long)buf[offset+5]<<16ULL
        | (unsigned long long)buf[offset+6]<<8ULL
        | (unsigned long long)buf[offset+7]<<0ULL;

    } else {
        result = 0xFFFFFFFFffffffffULL;
    }
    return result;
}

/***************************************************************************
 ***************************************************************************/
static void
parse_status6(struct Output *out,
        enum PortStatus status, /* open/closed */
        const unsigned char *buf, size_t length,
        struct MassIP *filter)
{
    struct MasscanRecord record;
    size_t offset = 0;

    /* parse record */
    record.timestamp = _get_integer(buf, length, &offset);
    record.ip_proto  = _get_byte(buf, length, &offset);
    record.port      = _get_short(buf, length, &offset);
    record.reason    = _get_byte(buf, length, &offset);
    record.ttl       = _get_byte(buf, length, &offset);
    record.ip.version= _get_byte(buf, length, &offset);
    if (record.ip.version != 6) {
        fprintf(stderr, "[-] corrupt record\n");
        return;
    }
    record.ip.ipv6.hi = _get_long(buf, length, &offset);
    record.ip.ipv6.lo = _get_long(buf, length, &offset);

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    /* Filter for known IP/ports, if specified on command-line */
    if (filter && filter->count_ipv4s) {
        if (!massip_has_ip(filter, record.ip))
            return;
    }
    if (filter && filter->count_ports) {
        if (!massip_has_port(filter, record.port))
            return;
    }

    /*
     * Now report the result
     */
    output_report_status(out,
                    record.timestamp,
                    status,
                    record.ip,
                    record.ip_proto,
                    record.port,
                    record.reason,
                    record.ttl,
                    record.mac);

}

/***************************************************************************
 ***************************************************************************/
static void
parse_banner6(struct Output *out, unsigned char *buf, size_t length,
              const struct MassIP *filter,
              const struct RangeList *btypes)
{
    struct MasscanRecord record;
    size_t offset = 0;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = _get_integer(buf, length, &offset);
    record.ip_proto  = _get_byte(buf, length, &offset);
    record.port      = _get_short(buf, length, &offset);
    record.app_proto = _get_short(buf, length, &offset);
    record.ttl       = _get_byte(buf, length, &offset);
    record.ip.version= _get_byte(buf, length, &offset);
    if (record.ip.version != 6) {
        fprintf(stderr, "[-] corrupt record\n");
        return;
    }
    record.ip.ipv6.hi = _get_long(buf, length, &offset);
    record.ip.ipv6.lo = _get_long(buf, length, &offset);
    
    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    
    /*
     * Filter out records if requested
     */
    if (!readscan_filter_pass(record.ip, record.port, record.app_proto,
              filter, btypes))
          return;
    
    /*
     * Now print the output
     */
    if (offset > length)
        return;
    output_report_banner(
                out,
                record.timestamp,
                record.ip,
                record.ip_proto,    /* TCP=6, UDP=17 */
                record.port,
                record.app_proto,   /* HTTP, SSL, SNMP, etc. */
                record.ttl, /* ttl */
                NULL, 0,
                buf+offset, (unsigned)(length-offset)
                );
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
    record.ip.ipv4   = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip.version = 4;
    record.port      = buf[8]<<8 | buf[9];
    record.app_proto = buf[10]<<8 | buf[11];

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

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
                0, /* ttl */
                NULL, 0,
                buf+12, (unsigned)buf_length-12
                );
}

/***************************************************************************
 * Parse the BANNER record, extracting the timestamp, IP address, and port
 * number. We also convert the banner string into a safer form.
 ***************************************************************************/
static void
parse_banner4(struct Output *out, unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;

    if (buf_length < 13)
        return;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip.ipv4   = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip.version = 4;
    record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    record.app_proto = buf[11]<<8 | buf[12];

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

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
                0, /* ttl */
                NULL, 0,
                buf+13, (unsigned)buf_length-13
                );
}


/***************************************************************************
 ***************************************************************************/
static void
parse_banner9(struct Output *out, unsigned char *buf, size_t buf_length,
              const struct MassIP *filter,
              const struct RangeList *btypes)
{
    struct MasscanRecord record;
    unsigned char *data = buf+14;
    size_t data_length = buf_length-14;

    if (buf_length < 14)
        return;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip.ipv4   = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip.version = 4;
    record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    record.app_proto = buf[11]<<8 | buf[12];
    record.ttl       = buf[13];

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    /*
     * KLUDGE: when doing SSL stuff, add a IP:name pair to a database
     * so we can annotate [VULN] strings with this information
     */
    //readscan_report(record.ip, record.app_proto, &data, &data_length);


    /*
     * Filter out records if requested
     */
    if (!readscan_filter_pass(record.ip, record.port, record.app_proto,
              filter, btypes))
          return;
    
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
                record.ttl, /* ttl */
                NULL, 0,
                data, (unsigned)data_length
                );
}

/***************************************************************************
 * Read in the file, one record at a time.
 ***************************************************************************/
static uint64_t
_binaryfile_parse(struct Output *out, const char *filename,
           struct MassIP *filter,
           const struct RangeList *btypes)
{
    FILE *fp = 0;
    unsigned char *buf = 0;
    size_t bytes_read;
    uint64_t total_records = 0;

    /* Allocate a buffer of up to one megabyte per record */
    buf = MALLOC(BUF_MAX);

    /* Open the file */
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[-] FAIL: --readscan\n");
        fprintf(stderr, "[-] %s: %s\n", filename, strerror(errno));
        goto end;
    }

    LOG(0, "[+] --readscan %s\n", filename);
    
    if (feof(fp)) {
        LOG(0, "[-] %s: file is empty\n", filename);
        goto end;
    }
    
    /* first record is pseudo-record */
    bytes_read = fread(buf, 1, 'a'+2, fp);
    if (bytes_read < 'a'+2) {
        LOG(0, "[-] %s: %s\n", filename, strerror(errno));
        goto end;
    }

    /* Make sure it's got the format string */
    if (memcmp(buf, "masscan/1.1", 11) != 0) {
        LOG(0,
                "[-] %s: unknown file format (expeced \"masscan/1.1\")\n",
                filename);
        goto end;
    }

    /*
     * Look for start time
     */
    if (buf[11] == '.' && strtoul((char*)buf+12,0,0) >= 2) {
        unsigned i;

        /* move to next field */
        for (i=0; i<'a' && buf[i] && buf[i] != '\n'; i++)
            ;
        i++;

        if (buf[i] == 's')
            i++;
        if (buf[i] == ':')
            i++;

        /* extract timestamp */
        if (i < 'a')
            out->when_scan_started = strtoul((char*)buf+i,0,0);
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
            LOG(0, "[-] file corrupt\n");
            goto end;
        }


        /* get the remainder of the record */
        bytes_read = fread(buf, 1, length, fp);
        if (bytes_read < length)
            break; /* eof */

        /* Depending on record type, do something different */
        switch (type) {
            case 1: /* STATUS: open */
                if (!btypes->count)
                    parse_status(out, PortStatus_Open, buf, bytes_read);
                break;
            case 2: /* STATUS: closed */
                if (!btypes->count)
                    parse_status(out, PortStatus_Closed, buf, bytes_read);
                break;
            case 3: /* BANNER */
                parse_banner3(out, buf, bytes_read);
                break;
            case 4:
                if (fread(buf+bytes_read,1,1,fp) != 1) {
                    LOG(0, "[-] read() error\n");
                    exit(1);
                }
                bytes_read++;
                parse_banner4(out, buf, bytes_read);
                break;
            case 5:
                parse_banner4(out, buf, bytes_read);
                break;
            case 6: /* STATUS: open */
                if (!btypes->count)
                    parse_status2(out, PortStatus_Open, buf, bytes_read, filter);
                break;
            case 7: /* STATUS: closed */
                if (!btypes->count)
                    parse_status2(out, PortStatus_Closed, buf, bytes_read, filter);
                break;
            case 9:
                parse_banner9(out, buf, bytes_read, filter, btypes);
                break;
            case 10: /* Open6 */
                if (!btypes->count)
                    parse_status6(out, PortStatus_Open, buf, bytes_read, filter);
                break;
            case 11: /* Closed6 */
                if (!btypes->count)
                    parse_status6(out, PortStatus_Closed, buf, bytes_read, filter);
                break;
            case 13: /* Banner6 */
                parse_banner6(out, buf, bytes_read, filter, btypes);
                break;
            case 'm': /* FILEHEADER */
                //goto end;
                break;
            default:
                LOG(0, "[-] file corrupt: unknown type %u\n", type);
                goto end;
        }
        total_records++;
        if ((total_records & 0xFFFF) == 0)
            LOG(0, "[+] %s: %8" PRIu64 "\r", filename, total_records);
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
readscan_binary_scanfile(struct Masscan *masscan,
                     int arg_first, int arg_max, char *argv[])
{
    struct Output *out;
    int i;

    /*
     * Create the output system, such as XML or JSON output
     */
    out = output_create(masscan, 0);
    
    /*
     * Set the start time to zero. We'll read it from the first file
     * that we parse
     */
    out->when_scan_started = 0;

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
        _binaryfile_parse(out, argv[i], &masscan->targets, &masscan->banner_types);
    }

    /* Done! */
    output_destroy(out);
}


