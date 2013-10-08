/*
    Converts Masscan "scan" binary format to text

    The "masscan/1.1" file format starts (and ends) with a 12 byte 
    string with the exact value of "masscan/1.1\0". If this string 
    isn't found, then the data is in some other format. We will 
    likely change this format in a couple months as we add new scan
    types (UDP, ICMP, etc.).
 
    The file consists of a series of TLV (type-length-value) records.
    The first field is the "type" of the record. The next field indicates
    the number of remaining bytes.

    Everything is BIG-ENDIAN.
 
    Both the the "type" and "length" fields are variable length. If the
    high-order bit is set, then the byte is followed by another one. Here are
    some examples
    0x05 - encodes the value '5'
    0x7F - encodes the value '127'
    0x80 0x00 - encodes the value '128'
    0x80 0x01 - encodes the value '129'
    0xFF 0x7F - encodes the value '32767'
    0x81 0x00 0x00 - encodes the value '32768'
    0x80 0x05 - encodes the value '5', unecessarily


    Some record types currently produced by the program:
    1 - STATUS (minimal open/closed port record)
    2 - BANNER (banner for a port)
    109 - FILEHEADER (the file header record)
 
    The FILEHEADER record is the first header in the file. It's contents are 
    always exactly 97 bytes long. That's because the file starts with the
    string "masscan", and the letter 'm' maps to the value 109, and the 
    letter 'a' maps to the value 97.
 

    The STATUS record is formatted as the following:

    +--------+
    |  0x01  |
    +--------+
    |  0x0C  |
    +--------+--------+--------+--------+
    |            timestamp              |
    +--------+--------+--------+--------+
    |          IPv4 address             |
    +--------+--------+--------+--------+
    |     TCP port    |
    +--------+--------+
    | reason |  either "rst" or "syn", ack or other flags too
    +--------+
    |  TTL   |
    +--------+
 
 The BANNER record is formatted as the following. Like all records,
 it starts with the type/length fields. I the length of the banner
 is too long, the length field may be more than 1 byte long. Like many
 other records, it contains a timestamp, IP address, and port number.
 The length of the banner-text is the length
 +--------+
 |  0x03  |
 +--------+ . . . .
 |? length:        :
 +--------+--------+--------+--------+
 |            timestamp              |
 +--------+--------+--------+--------+
 |          IPv4 address             |
 +--------+--------+--------+--------+
 |     TCP port    |
 +--------+--------+ . . . . . .  .  .  .   .   .   .    .    .     .
 | the banner text
 +--------+--------+ . . . . . .  .  .  .   .   .   .    .    .     .

*/
#define _CRT_SECURE_NO_WARNINGS
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>


enum {
    PROTO_UNKNOWN,
    PROTO_SSH1,
    PROTO_SSH2,
    PROTO_HTTP,
    PROTO_FTP1,
    PROTO_FTP2,
    PROTO_DNS_VERSIONBIND,
};

struct Configuration {
    unsigned do_ssh;
    unsigned do_http;
    unsigned do_dns_version;
    unsigned do_xml;
    unsigned is_quiet;
};


struct MasscanRecord {
    unsigned timestamp;
    unsigned ip;
	unsigned char ip_proto;
    unsigned short port;
    unsigned char reason;
    unsigned char ttl;
};

static const size_t BUF_MAX = 1024*1024;

struct BannerRecord {
    unsigned count;
    unsigned length;
    struct BannerRecord *next;
    char str[1];
};

#define BUCKET_COUNT (1024*1024)
struct BannerDB
{
    struct BannerRecord *records[BUCKET_COUNT];
} *mydb;

void
db_print(const struct BannerDB *db)
{
    unsigned i;
    for (i=0; i<BUCKET_COUNT; i++) {
        struct BannerRecord *rec = db->records[i];
        while (rec) {
            printf("%8u %.*s\n", rec->count, rec->length, rec->str);
            rec = rec->next;
        }
    }
}

/***************************************************************************
 * used for some banners to keep track of the most popular ones
 ***************************************************************************/
void
db_lookup(struct BannerDB *db, const char *str, unsigned length)
{
    struct BannerRecord *rec;
    uint64_t hash = 0;
    unsigned i;

    for (i=0; i<length; i++) {
        hash += str[i];
        hash += str[i]<<8;
        hash ^= str[i]<<4;
    }

    /* lookup */
    rec = db->records[hash & (BUCKET_COUNT-1)];
    while (rec) {
        if (rec->length == length && memcmp(rec->str, str, length) == 0)
            break;
        else
            rec = rec->next;
    }
    if (rec == NULL) {
        rec = (struct BannerRecord *)malloc(sizeof(*rec) + length);
        rec->count = 0;
        rec->length = length;
        memcpy(rec->str, str, length);

        rec->next = db->records[hash & (BUCKET_COUNT-1)];
        db->records[hash & (BUCKET_COUNT-1)] = rec;
    }

    rec->count++;
}



const char *
reason_string(unsigned x, char *buffer, size_t sizeof_buffer)
{
    sprintf(buffer, "%s%s%s%s%s%s%s%s",
        (x&0x01)?"fin-":"",
        (x&0x02)?"syn-":"",
        (x&0x04)?"rst-":"",
        (x&0x08)?"psh-":"",
        (x&0x10)?"ack-":"",
        (x&0x20)?"urg-":"",
        (x&0x40)?"ece-":"",
        (x&0x80)?"cwr-":""
        );
    if (buffer[0] == '\0')
        return "none";
    else
        buffer[strlen(buffer)-1] = '\0';
    return buffer;
}

void parse_status(const unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;
    char timebuf[80];
    char addrbuf[20];
    char reasonbuf[80];

    if (buf_length < 12)
        return;
    
    /* parse record */        
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.port      = buf[8]<<8 | buf[9];
    record.reason    = buf[10];
    record.ttl       = buf[11];
    
    /* format time */
    {
        time_t timestamp = (time_t)record.timestamp;
        struct tm *tm;
        tm = localtime(&timestamp);
        
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    }
    
    /* format IP into fixed-length field */
    sprintf(addrbuf, "%u.%u.%u.%u", 
            (record.ip>>24)&0xFF, (record.ip>>16)&0xFF,
            (record.ip>>8)&0xFF, (record.ip>>0)&0xFF);
    
    /* format reason (tcp flags) field */
    reason_string(record.reason, reasonbuf, sizeof(reasonbuf));
    
    
    /* output string */
    printf("%s %-15s :%5u %s %u\n",
           timebuf,
           addrbuf,
           record.port,
           reasonbuf,
           record.ttl);

}

/**
 * Normalize the string 'in-place' in the buffer. All non-printable characters,
 * include sensitive charactes like < and &, are converted to hex notation
 * like \x83.
 *
 * @param px
 *      the buffer containing the banner string we are normalizing
 * @param offset
 *      where within the buffer the banner starts
 * @param length
 *      where in the buffer the banner ends
 * @param max
 *      the maximum length of the buffer holding the banner, because as we
 *      increase the size of the banner string, we don't want to overwrite
 *      the end of the buffer.
 * @return
 *      a nul-terminated banner string with sensitive characters converted
 */
const char *
normalize_string(unsigned char *px, size_t offset, size_t length, size_t max)
{
    size_t i=0;
    px += offset;
    max -= offset;
    
    for (i=0; i<length; i++) {
        unsigned char c = px[i];
        
        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\') {
            /* do nothing */
        } else {
            if (i + 6 < max) {
                memmove(px+i+5, px+i, length-i+1);
                px[i++] = '\\';
                px[i++] = 'x';
                px[i++] = "0123456789abdef"[c >> 4];
                px[i  ] = "0123456789abdef"[c >> 0];
            }
        }
    }
    
    px[i] = '\0';
    
    return (char*)px;
}

/***************************************************************************
 ***************************************************************************/
const char *
banner_protocol_string(unsigned proto)
{
    switch (proto) {
    case 0: return "generic";
    case 1: return "SSHv1";
    case 2: return "SSHv2";
    case 3: return "HTTP";
    case 4: return "FTP";
    case 5: return "FTP";
        case PROTO_DNS_VERSIONBIND: return "DNS-VER";
    default: return "UNKNOWN";
    }
}

/***************************************************************************
 * Parse the BANNER record, extracting the timestamp, IP addres, and port
 * number. We also convert the banner string into a safer form.
 ***************************************************************************/
void
parse_banner(const struct Configuration *conf, unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;
    unsigned proto;
    char timebuf[80];
    char addrbuf[20];
    
    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
    record.port      = buf[8]<<8 | buf[9];
    proto            = buf[10]<<8 | buf[11];
    
    /*
     * Pretty-print the timestamp format
     */
    {
        time_t timestamp = (time_t)record.timestamp;
        struct tm *tm;
        tm = localtime(&timestamp);
        
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    }
    
    /* format IP into fixed-length field */
    sprintf(addrbuf, "%u.%u.%u.%u", 
            (record.ip>>24)&0xFF, (record.ip>>16)&0xFF,
            (record.ip>>8)&0xFF, (record.ip>>0)&0xFF);
    
    
    
    /* output string */
    if (buf_length > 12) {
        const char *s;
        s = normalize_string(buf, 12, buf_length-12, BUF_MAX);
        if (!conf->is_quiet)
        printf("%s %-15s :%5u %s \"%s\"\n",
               timebuf,
               addrbuf,
               record.port,
               banner_protocol_string(proto),
               s
               );
        switch (proto) {
            case PROTO_SSH1:
            case PROTO_SSH2:
                if (conf->do_ssh)
                    db_lookup(mydb, s, strlen(s));
                break;
            case PROTO_HTTP:
                if (conf->do_http)
                    db_lookup(mydb, s, strlen(s));
                break;
            case PROTO_DNS_VERSIONBIND:
                if (conf->do_dns_version)
                    db_lookup(mydb, s, strlen(s));
                break;
        }
    }
}

int is_nominum(const char *px, size_t len)
{
	if (len >= 7 && memcmp(px, "Nominum", 7) == 0)
		return 1;
	else
		return 0;
}
int is_dnsmasq(const char *px, size_t len)
{
	if (len >= 7 && memcmp(px, "dnsmasq", 7) == 0)
		return 1;
	else
		return 0;
}
int is_powerdns(const char *px, size_t len)
{
	if (len >= 8 && memcmp(px, "PowerDNS", 8) == 0)
		return 1;
	else
		return 0;
}
int is_nsd(const char *px, size_t len)
{
	if (len >= 4 && memcmp(px, "NSD ", 4) == 0)
		return 1;
	else
		return 0;
}
int is_unbound(const char *px, size_t len)
{
	if (len >= 7 && memcmp(px, "unbound", 7) == 0)
		return 1;
	else
		return 0;
}
int is_bind(const char *px, size_t len)
{
	if (memcmp(px, "yamutech-bind", 13) == 0 && len >= 13)
		return 1;
	if (len < 4)
		return 0;
	if (!(px[0] == '9' || px[0] == '8') || px[1] != '.')
		return 0;
	if (!isdigit(px[2]))
		return 0;

	return 1;
}

/***************************************************************************
 * Parse the BANNER record, extracting the timestamp, IP addres, and port
 * number. We also convert the banner string into a safer form.
 ***************************************************************************/
void
parse_banner4(const struct Configuration *conf, unsigned char *buf, size_t buf_length)
{
    struct MasscanRecord record;
    unsigned proto;
    char timebuf[80];
    char addrbuf[20];
    
    /*
     * Parse the parts that are common to most records
     */
    record.timestamp = buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3];
    record.ip        = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
	record.ip_proto  = buf[8];
    record.port      = buf[9]<<8 | buf[10];
    proto            = buf[11]<<8 | buf[12];
    
    /*
     * Pretty-print the timestamp format
     */
    {
        time_t timestamp = (time_t)record.timestamp;
        struct tm *tm;
        tm = localtime(&timestamp);
        
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    }
    
    /* format IP into fixed-length field */
    sprintf(addrbuf, "%u.%u.%u.%u", 
            (record.ip>>24)&0xFF, (record.ip>>16)&0xFF,
            (record.ip>>8)&0xFF, (record.ip>>0)&0xFF);
    
    
    
    /* output string */
    if (buf_length > 13) {
        const char *s;
        s = normalize_string(buf, 13, buf_length-13, BUF_MAX);
        if (!conf->is_quiet)
        printf("%s %-15s :%5u %s \"%s\"\n",
               timebuf,
               addrbuf,
               record.port,
               banner_protocol_string(proto),
               s
               );
        switch (proto) {
            case PROTO_SSH1:
            case PROTO_SSH2:
                if (conf->do_ssh)
                    db_lookup(mydb, s, strlen(s));
                break;
            case PROTO_HTTP:
                if (conf->do_http)
                    db_lookup(mydb, s, strlen(s));
                break;
            case PROTO_DNS_VERSIONBIND:
                if (conf->do_dns_version) {
					if (is_bind(s, strlen(s)))
						db_lookup(mydb, "BIND", 4);
					else if (is_dnsmasq(s, strlen(s)))
						db_lookup(mydb, "dnsmasq", 7);
					else if (is_nominum(s, strlen(s)))
						db_lookup(mydb, "nominum", 7);
					else if (is_powerdns(s, strlen(s)))
						db_lookup(mydb, "PowerDNS", 8);
					else if (is_nsd(s, strlen(s)))
						db_lookup(mydb, "NSD", 3);
					else if (is_unbound(s, strlen(s)))
						db_lookup(mydb, "unbound", 7);
					else
						db_lookup(mydb, s, strlen(s));
				}
                break;
        }
    }
}

/***************************************************************************
 * Read in the file, one record at a time.
 *
 * @param conf
 *      Configuration settings telling us what to look for
 * @param filename
 *      The file we read.
 * @return
 *      the number of records successfully parsed
 ***************************************************************************/
uint64_t
parse_file(const struct Configuration *conf, const char *filename)
{
    FILE *fp = 0;
    unsigned char *buf = 0;
    int bytes_read;
    uint64_t total_records = 0;
    
    buf = (unsigned char *)malloc(BUF_MAX);
    if (buf == 0) {
        fprintf(stderr, "memory allocation failure\n");
        goto end;
    }

    fp = fopen(filename, "rb");
    if (fp == NULL) {
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
        if (bytes_read < length)
            break; /* eof */

        /* Depending on record type, do something different */
        switch (type) {
            case 1: /* STATUS: open */
            case 2: /* STATUS: closed */
                if (!conf->is_quiet)
                    parse_status(buf, bytes_read);
                break;
            case 3: /* BANNER */
                parse_banner(conf, buf, bytes_read);
                break;
			case 4:
				fread(buf+bytes_read,1,1,fp);
				bytes_read++;
                parse_banner4(conf, buf, bytes_read);
                break;
			case 5:
                parse_banner4(conf, buf, bytes_read);
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

/***************************************************************************
 ***************************************************************************/
int
main(int argc, char *argv[])
{
    int i;
    uint64_t total_records = 0;
    struct Configuration conf[1];
    
    memset(conf, 0, sizeof(conf[0]));
    
    if (argc <= 1) {
        printf("usage:\n masscan2text <scanfile>\ndecodes and prints text\n");
        return 1;
    }
    
    /*
     * Go through and look for some options
     */
    for (i=1; i<argc; i++) {
        if (strcmp(argv[i], "--ssh") == 0)
            conf->do_ssh = 1;
        else if (strcmp(argv[i], "--http") == 0)
            conf->do_http = 1;
        else if (strcmp(argv[i], "--quiet") == 0)
            conf->is_quiet = 1;
        else if (strcmp(argv[i], "--dns-version") == 0)
            conf->do_dns_version = 1;
        else if (strcmp(argv[i], "--xml") == 0)
            conf->do_xml = 1;
        else if (argv[i][0] == '\0')
            fprintf(stderr, "%s: unknown option\n", argv[i]);
    }
    
    /*
     * Create a table for storing banners
     */
    mydb = (struct BannerDB*)malloc(sizeof(*mydb));
    memset(mydb, 0, sizeof(*mydb));

    
    fprintf(stderr, "--- scan2text for masscan/1.1 format ---\n");
    
    /*
     * go through all files
     */
    for (i=1; i<argc; i++) {
        if (argv[i][0] == '-')
            continue;
        total_records += parse_file(conf, argv[i]);
    }
    
    fprintf(stderr, "--- %llu records scanned  ---\n", total_records);

    db_print(mydb);
    return 0;
}