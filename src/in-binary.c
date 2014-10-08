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
                    record.ttl);

}

/***************************************************************************
 ***************************************************************************/
static void
parse_status2(struct Output *out,
        enum PortStatus status, /* open/closed */
        const unsigned char *buf, size_t buf_length,
        const struct RangeList *ips,
        const struct RangeList *ports)
{
    struct MasscanRecord record;

    if (buf_length < 13)
        return;

    /* parse record */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    record.reason    = buf[11];
    record.ttl       = buf[12];

    if (out->when_scan_started == 0)
        out->when_scan_started = record.timestamp;

    /*
     * Filter
     */
    if (ips && ips->count) {
        if (!rangelist_is_contains(ips, record.ip))
            return;
    }
    if (ports && ports->count) {
        if (!rangelist_is_contains(ports, record.port))
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
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
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
                buf+13, (unsigned)buf_length-13
                );
}

struct CNDB_Entry {
    unsigned ip;
    char *name;
    struct CNDB_Entry *next;
};

struct CNDB_Database {
    struct CNDB_Entry *entries[65536];
};

/***************************************************************************
 ***************************************************************************/
static struct CNDB_Database *db = NULL;

/***************************************************************************
 ***************************************************************************/
static const char *
cndb_lookup(unsigned ip)
{
    const struct CNDB_Entry *entry;
    
    entry = db->entries[ip&0xFFFF];
    while (entry && entry->ip != ip)
        entry = entry->next;
    if (entry)
        return entry->name;
    else {
        return 0;
    }
}
/***************************************************************************
 ***************************************************************************/
static void
cndb_add(unsigned ip, const unsigned char *data, size_t length)
{
    size_t offset = 0;
    size_t name_offset;
    size_t name_length;
    
    if (length < 7)
        return;
    
    /*cipher:0x39 , safe-we1.dyndns.org*/
    if (memcmp(data+offset, "cipher:", 7) != 0)
        return;
    offset += 7;
    
    /* skip to name */
    while (offset < length && data[offset] != ',')
        offset++;
    if (offset >= length)
        return;
    else
        offset++; /* skip ',' */
    while (offset < length && data[offset] == ' ')
        offset++;
    if (offset >= length)
        return;
    
    /* we should have a good name */
    name_offset = offset;
    while (offset < length && data[offset] != ',')
        offset++;
    name_length = offset - name_offset;
    
    /* now insert into database */
    if (db == NULL) {
        db = malloc(sizeof(*db));
        memset(db, 0, sizeof(*db));
    }
    {
        struct CNDB_Entry *entry;
        
        entry = malloc(sizeof(*entry));
        entry->ip =ip;
        entry->name = malloc(name_length+1);
        memcpy(entry->name, data+name_offset, name_length+1);
        entry->name[name_length] = '\0';
        entry->next = db->entries[ip&0xFFFF];
        db->entries[ip&0xFFFF] = entry;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
parse_banner9(struct Output *out, unsigned char *buf, size_t buf_length,
              const struct RangeList *ips,
              const struct RangeList *ports,
              const struct RangeList *btypes)
{
    struct MasscanRecord record;
    const unsigned char *data = buf+14;
    size_t data_length = buf_length-14;

    if (buf_length < 14)
        return;

    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
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
    if (record.app_proto == PROTO_SSL3) {
        cndb_add(record.ip, data, data_length);
    } else if (record.app_proto == PROTO_VULN) {
        const char *name = cndb_lookup(record.ip);
        
        if (data_length == 15 && memcmp(data, "SSL[heartbeat] ", 15) == 0)
            return;

        if (name && strlen(name) < 300) {
            //printf("vuln=%s\n", name);
            ((char*)data)[data_length] = ' ';
            memcpy((char*)data+data_length+1, name, strlen(name)+1);
            data_length += strlen(name)+1;
        }
    }
    
    /*
     * Filter
     */
    if (ips && ips->count) {
        if (!rangelist_is_contains(ips, record.ip))
            return;
    }
    if (ports && ports->count) {
        if (!rangelist_is_contains(ports, record.port))
            return;
    }
    if (btypes && btypes->count) {
        if (!rangelist_is_contains(btypes, record.app_proto))
            return;
    }
    
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
                data, (unsigned)data_length
                );
}

/***************************************************************************
 * Read in the file, one record at a time.
 ***************************************************************************/
static uint64_t
parse_file(struct Output *out, const char *filename,
           const struct RangeList *ips,
           const struct RangeList *ports,
           const struct RangeList *btypes)
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
                    fprintf(stderr, "read() error\n");
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
                    parse_status2(out, PortStatus_Open, buf, bytes_read, ips, ports);
                break;
            case 7: /* STATUS: closed */
                if (!btypes->count)
                    parse_status2(out, PortStatus_Closed, buf, bytes_read, ips, ports);
                break;
            case 9:
                parse_banner9(out, buf, bytes_read, ips, ports, btypes);
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
            fprintf(stderr, "%s: %8" PRIu64 "\r", filename, total_records);
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
read_binary_scanfile(struct Masscan *masscan,
                     int arg_first, int arg_max, char *argv[])
{
    struct Output *out;
    int i;

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
        parse_file(out, argv[i], &masscan->targets, &masscan->ports,
                   &masscan->banner_types);
    }

    output_destroy(out);
}


