/*
    Converts Masscan "scan" binary format to text

    The "masscan/1.0" file format starts (and ends) with a 12 byte 
    string with the exact value of "masscan/1.0\0". If this string 
    isn't found, then the data is in some other format. We will 
    likely change this format in a couple months as we add new scan
    types (UDP, ICMP, etc.).

    The file consists of 12 byte records in LITTLE-ENDIAN format:

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

*/
#include <stdio.h>
#include <string.h>
#include <time.h>

struct MasscanRecord {
    unsigned timestamp;
    unsigned ip;
    unsigned short port;
    unsigned char reason;
    unsigned char ttl;
};

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


void parse_file(const char *filename)
{
    FILE *fp;
    unsigned char buf[12];
    int bytes_read;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror(filename);
        return;
    }

    /* first record is pseudo-record */
    bytes_read = fread(buf, 1, 12, fp);
    if (bytes_read < 12) {
        perror(filename);
        fclose(fp);
        return;
    }

    /* Make sure it's got the format string */
    if (memcmp(buf, "masscan/1.0\0", 12) != 0) {
        fprintf(stderr, "%s: unknown file format (expeced \"masscan/1.0\")\n", filename);
        fclose(fp);
        return;
    }

    /* Now read all records */
    for (;;) {
        struct MasscanRecord record;
        char timebuf[80];
        char addrbuf[20];
        char reasonbuf[80];

        bytes_read = fread(buf, 1, 12, fp);
        if (bytes_read < 12)
            break; /* eof */
        if (memcmp(buf, "masscan/1.0\0", 12) == 0)
            break; /* repeat = terminating record */

        /* parse record */        
        record.timestamp = buf[0] | buf[1]<<8 | buf[2]<<16 | buf[3]<<24;
        record.ip =  buf[4] | buf[5]<<8 | buf[6]<<16 | buf[7]<<24;
        record.port = buf[8] | buf[9]<<8;
        record.reason = buf[10];
        record.ttl = buf[11];

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


    fclose(fp);
}

int main(int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {
        parse_file(argv[i]);
    }

    return 0;
}