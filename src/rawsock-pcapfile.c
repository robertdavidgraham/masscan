/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*

  PCAPFILE

  This is a small bit of code for reading/writing libpcap files.
  This is for offline use of the product in cases where people
  want to post-process files without having to install libpcap.

  Since the file format is trivial to parse, and a lot of people
  may not have libpcap installed, we decode it ourselves in this
  module rather than using the libpcap module.

  Also, this has the feature of being able to read corrupted
  files. When it encounters a malformed back (such as one with
  an impossibly large packet), it skips the malformed data and
  searches forward for a packet that looks good.

*/
#define _CRT_SECURE_NO_WARNINGS
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include "rawsock-pcapfile.h"

/****************************************************************************
 * <PORTABILITY BLOCK>
 ****************************************************************************/
#ifdef _MSC_VER
#define snprintf _snprintf
#define PRId64 "I64d"
#define PRIu64 "I64u"
#define PRIx64 "I64x"
#else
#include <inttypes.h>
#endif
static int64_t ftell_x(FILE *fp)
{
#if defined(WIN32) && defined(__GNUC__)
    return ftello64(fp);
#elif defined(WIN32) && defined(_MSC_VER)
    return _ftelli64(fp);
#else
    return ftello(fp);
#endif
}
static int fseek_x(FILE *fp, int64_t offset, int origin)
{
#if defined(WIN32) && defined(__GNUC__)
    return fseeko64(fp, offset, origin);
#elif defined(WIN32) && defined(_MSC_VER)
    return _fseeki64(fp, offset, origin);
#else
    return fseeko(fp, offset, origin);
#endif
}
/****************************************************************************
 * </PORTABILITY BLOCK>
 ****************************************************************************/




/* PCAP file-format

typedef struct pcap_hdr_s {
        guint32 magic_number;   / * magic number * /
        guint16 version_major;  / * major version number * /
        guint16 version_minor;  / * minor version number * /
        gint32  thiszone;       / * GMT to local correction * /
        guint32 sigfigs;        / * accuracy of timestamps * /
        guint32 snaplen;        / * max length of captured packets, in octets * /
        guint32 network;        / * data link type * /
} pcap_hdr_t;


 0  32-bits - "magic number"
 4  16-bits - major version
    16-bits - minor version
 8  32-bits - timezone offset (should be zero)
12  32-bits - time stamp accuracy (should be zero)
16  32-bits - snap/slice length (maximum packet size)
20  32-bits - link layer type

Magic number:
    a1 b2 c3 d4 = big-endian
    d4 c3 b2 a1 = little-endian

Version:
    2.4 = most common version

Timezone offset, Timestamp accuracy:
    these fields are no longer used

Link-layer type:
    0        BSD loopback devices, except for later OpenBSD
    1        Ethernet, and Linux loopback devices
    6        802.5 Token Ring
    7        ARCnet
    8        SLIP
    9        PPP
    10        FDDI
    100        LLC/SNAP-encapsulated ATM
    101        "raw IP", with no link
    102        BSD/OS SLIP
    103        BSD/OS PPP
    104        Cisco HDLC
    105        802.11
    108        later OpenBSD loopback devices (with the AF_
            value in network byte order)
    113        special Linux "cooked" capture
    114        LocalTalk


*/
/*

802.11
    11     *  802.11b - 11-mbps
    12     *  802.11d - operation in multiple regulatory domains
    13     *  802.11e - wireless multimedia extensions
    14     *  802.11g - 54-mbps
    15     *  802.11h - power management
    16     *  802.11i - MAC security enhancements

 */

struct PcapFile
{
    FILE *fp;

    unsigned is_file_header_written:1;

    unsigned start_sec;
    unsigned start_usec;
    unsigned end_sec;
    unsigned end_usec;
    char filename[256];
    int byte_order;
    int linktype;
    int64_t frame_number;

    uint64_t file_size;
    uint64_t bytes_read;

    /**
     * This is for asynchronous reading of the file.
     */
    unsigned char *aio_buffer;
    size_t aio_buffer_size;
};

#define CAPFILE_BIGENDIAN       1
#define CAPFILE_LITTLEENDIAN   2
#define CAPFILE_ENDIANUNKNOWN   3


/** Read a 16-bit value from a capture file, depending upon the byte
 * order within that file */
static unsigned PCAP16(unsigned byte_order, const unsigned char *buf)
{
    switch (byte_order) {
    case CAPFILE_BIGENDIAN: return buf[0]*256 + buf[1];
    case CAPFILE_LITTLEENDIAN: return buf[1]*256 + buf[0];
    default: return (unsigned)0xa3a3;
    }
}
/** Read a 32-bit value from a capture file, depending upon the byte
 * order within that file */
static unsigned PCAP32(unsigned byte_order, const unsigned char *buf)
{
    switch (byte_order) {
    case CAPFILE_BIGENDIAN: return buf[0]<<24 | buf[1]<<16 | buf[2] << 8 | buf[3];
    case CAPFILE_LITTLEENDIAN: return buf[3]<<24 | buf[2]<<16 | buf[1] << 8 | buf[0];
    default: return (unsigned)0xa3a3;
    }
}

/**
 * Return the "link" type, such as Ethernet, WiFi, Token Ring, etc.
 */
unsigned
pcapfile_datalink(struct PcapFile *handle)
{
    if (handle)
        return (unsigned)handle->linktype;
    else
        return 0;
}


/**
 * Determine if the blob (the chunk of from the file read at a certain offset)
 * looks like a valid packet
 */
static unsigned
smells_like_valid_packet(const unsigned char *px, unsigned length, unsigned byte_order, unsigned link_type)
{
    unsigned secs, usecs, original_length, captured_length;

    if (length < 16)
        return 0;

    secs = PCAP32(byte_order, px+0);
    usecs = PCAP32(byte_order, px+4);
    captured_length = PCAP32(byte_order, px+8);
    original_length = PCAP32(byte_order, px+12);

    if (secs > 0x50000000) return 0; /* after 2010 */
    if (secs < 0x26000000) return 0; /* before 1990 */
    if (usecs > 1000000) return 0;
    if (captured_length > 10000) return 0;
    if (captured_length < 16) return 0;
    if (original_length < captured_length) return 0;
    if (original_length > 10000) return 0;

    if (captured_length + 16 < length) {
        unsigned secs2, usecs2, original_length2, captured_length2;
        const unsigned char *px2 = px + captured_length + 16;

        secs2 = PCAP32(byte_order, px2+0);
        usecs2 = PCAP32(byte_order, px2+4);
        captured_length2 = PCAP32(byte_order, px2+8);
        original_length2 = PCAP32(byte_order, px2+12);

        if (secs2 > 0x50000000)
            return 0;
        if (secs2 < 0x26000000)
            return 0;
        if (usecs2 > 1000000)
            return 0;
        if (captured_length2 > 10000)
            return 0;
        if (captured_length2 < 16)
            return 0;
        if (original_length2 < captured_length2)
            return 0;
        if (original_length2 > 10000)
            return 0;
        return 1;
    } else
    switch (link_type) {
    case 1: /*ethernet*/
        if (px[12] == 0x08 && px[13] == 0x00 && px[13] == 0x45)
            return 1;
    }

    return 0;
}


unsigned pcapfile_percentdone(struct PcapFile *capfile, uint64_t *r_bytes_read)
{
    if (r_bytes_read)
        *r_bytes_read = capfile->bytes_read;

    if (capfile->fp == NULL)
        return 100;
    return (unsigned)(capfile->bytes_read*100/capfile->file_size);
}


/**
 * Read the next packet from the file stream.
 */
int pcapfile_readframe(
    struct PcapFile *capfile,
    unsigned *r_time_secs,
    unsigned *r_time_usecs,
    unsigned *r_original_length,
    unsigned *r_captured_length,
    unsigned char *buf,
    unsigned sizeof_buf
    )
{
    size_t bytes_read;
    unsigned char header[16];
    unsigned byte_order = capfile->byte_order;
    unsigned is_corrupt = 0;

    again:
    /* Read in the 16-byte frame header. */
    bytes_read = fread(header, 1, 16, capfile->fp);
    if (bytes_read < 16) {
        if (bytes_read <= 0) {
            //fprintf(stderr, "%s: failed to read header\n", capfile->filename);
            //perror(capfile->filename);
        } else if (bytes_read == 0)
            ; /* normal end-of-file */
        else
            fprintf(stderr, "%s: premature end-of-file\n", capfile->filename);
        return 0;
    }
    capfile->bytes_read += bytes_read;

    /* Parse the frame header into its four fields */
    *r_time_secs = PCAP32(byte_order, header);
    *r_time_usecs = PCAP32(byte_order, header+4);
    *r_captured_length = PCAP32(byte_order, header+8);
    *r_original_length = PCAP32(byte_order, header+12);


    /* Test the frame heade fields to make sure they are sane */
    if (*r_time_usecs > 1000100) {
        if (*r_time_usecs < 1000100) {
            *r_time_secs += 1;
            *r_time_usecs -= 1000000;
        } if (*r_time_usecs > 0xFFFFFF00) {
            *r_time_secs -= 1;
            *r_time_usecs += 1000000;
            *r_time_usecs &= 0xFFFFFFFF; /* mask off in case of 64-bit ints */
        } else
            is_corrupt = 1; /* shouldn't be more than 1-second, but some capture porgrams erroneously do that */
    }
    if (*r_time_usecs == 0
        && *r_time_secs == 0
        && *r_original_length == 0
        && *r_captured_length == 0)
        goto again;

    if (*r_captured_length > sizeof_buf)
        is_corrupt = 1;
    if (*r_original_length < *r_captured_length)
        is_corrupt = 1;
    if (*r_original_length < 8)
        is_corrupt = 1;
    if (*r_original_length > 160000)
        is_corrupt = 1;


    /*
     * If the file is corrupted, let's move forward in the
     * stream and look for packets that aren't corrupted
     */
    while (is_corrupt) {
        /* TODO: we should go backwards a bit in the file */
        unsigned char tmp[16384];
        int64_t position;
        unsigned i;



        /* Remember the current location. We are going to seek
         * back to an offset from this location once we find a good
         * packet.*/
        position = ftell_x(capfile->fp);
        if (position == -1) {
            fprintf(stderr, "%s: could not resolve file corruption (ftell) frame #%" PRId64 "\n",
                capfile->filename, capfile->frame_number);
            perror(capfile->filename);
            fseek_x(capfile->fp, 0, SEEK_END);
            return 0;
        }

        /* Print an error message indicating corruption was found. Note
         * that if corruption happens past 4-gigs on a 32-bit system, this
         * will print an inaccurate number */
        fprintf(stderr, "%s(%" PRIu64 "): corruption found at 0x%08" PRIx64 " (%" PRId64 ")\n",
            capfile->filename,
            capfile->frame_number,
            position,
            position
            );



        /* Read in the next chunk of data following the corruption. We'll search
         * this chunk looking for a non-corrupt packet */
        bytes_read = fread(tmp, 1, sizeof(tmp), capfile->fp);

        /* If we reach the end without finding a good frame, then stop */
        if (bytes_read == 0) {
            if (bytes_read <= 0) {
                fprintf(stderr, "%s: error at end of file\n", capfile->filename);
                perror(capfile->filename);
            } else
                fprintf(stderr, "%s: premature end of file\n", capfile->filename);
            return 0;
        }
        capfile->bytes_read += bytes_read;

        /* Scan forward (one byte at a time ) looking for a non-corrupt
         * packet located at that spot */
        for (i=0; i<bytes_read; i++) {

            /* Test the current location */
            if (!smells_like_valid_packet(tmp+i, (unsigned)(bytes_read-i), byte_order, capfile->linktype))
                continue;

            /* Woot! We have a non-corrupt packet. Let's now change the
             * the current file-pointer to point to that location.
             * Notice that we have to be careful when working with
             * large (>4gig) files on 32-bit systems. The 'fpos_t' is
             * usually a 64-bit value and can be used to set a position,
             * but we cannot manipulate it directory (it's an opaque
             * structure, not an integer), so we have seek back to the
             * saved value, fthen seek relatively forward to the
             * known-good spot */
            position = position + i;
            if (fseek_x(capfile->fp, position, SEEK_SET) != 0) {
                fprintf(stderr, "%s: could not resolve file corruption (seek forward)\n", capfile->filename);
                perror(capfile->filename);
                fseek_x(capfile->fp, 0, SEEK_END);
                return 0;
            }

#if 0
            /* We could stop here, but we are going to try one more thing.
             * Most cases of corruption will be because the PREVOUS packet
             * was truncated, not becausae the CURRENT packet was bad.
             * Since we have seeked forward to find the NEXT packet, we
             * want to now seek backwards and see if there is actually
             * a good CURRENT packet. */
            if (fseek(capfile->fp, -2000, SEEK_CUR) == 0) {
                unsigned endpoint = 2000;
                unsigned j;

                /* We read in the 2000 bytes prior to the known-good
                 * packet that we discovered above, and also 16 bytes
                 * of the current frame (because the validity check
                 * looks for back-to-back good headers */
                bytes_read = fread(tmp, 1, endpoint+16, capfile->fp);

                /* Scan BACKWARDS through this chunk looking for a
                 * length field that points forward back to the known
                 * good packet */
                for (j=0; j<endpoint-16; j++) {

                    /* Test the current 4-byte length field and see if it
                     * matches it's reverse offset. In other words, 108 bytes
                     * backwards in the data should be a 4-byte length field
                     * with a value of 100 */
                    if (PCAP32(byte_order, tmp+endpoint-j-8) != j)
                        continue;

                    /* Woot! Now that we have found the length field, let's
                     * test the rest of the data around this point to see
                     * if it also matches. Note that we are checking the
                     * PREVIOUS 16-byte header, PREVIOUS contents, and the
                     * CURRENT 16-byte header */
                    if (smells_like_valid_packet(tmp+endpoint-j-16, j+16+16, byte_order, capfile->linktype)) {
                        /* Woot! We have found a good packet. Let's now use that
                         * as the new location. */
                        fseek(capfile->fp, -(signed)(j+16+16), SEEK_CUR);
                        break;
                    }
                }
            } else {
                /* Oops, there was an error seeking backwards. I'm
                 * not quite sure what to do here, so we are just
                 * going to repeat the reset of the file location
                 * that we did above */
                if (fseek_x(capfile->fp, position, SEEK_SET) != 0) {
                    perror(capfile->filename);
                    fseek_x(capfile->fp, 0, SEEK_END);
                    return 0;
                }
                fseek_x(capfile->fp, i, SEEK_CUR);

            }
#endif

            /* Print a message saying we've found a good packet. This will
             * help people figure out where in the file the corruption
             * happened, so they can figure out why it was corrupt.*/
            position = ftell_x(capfile->fp);
            fprintf(stderr, "%s(%" PRId64 "): good packet found at 0x%08" PRIx64 " (%" PRId64 ")\n",
                capfile->filename,
                capfile->frame_number,
                position,
                position
                );

            /* Recurse, continue reading from where we know a good
             * packet is within the file */
            return pcapfile_readframe(capfile, r_time_secs, r_time_usecs, r_original_length, r_captured_length, buf, sizeof_buf);
        }

        /* If we get to this point, we are totally hosed and the corruption
         * is more severe than a few packets. */
        printf("No valid packet found in chunk\n");
    }

    /*
     * Read the packet data
     */
    bytes_read = fread(buf, 1, *r_captured_length, capfile->fp);
    if (bytes_read < *r_captured_length) {
        if (bytes_read <= 0) {
            fprintf(stderr, "%s: could not read packet data, frame #%" PRId64 "\n",
                capfile->filename, capfile->frame_number);
            perror(capfile->filename);
        } else
            fprintf(stderr, "%s: premature end of file\n", capfile->filename);
        return 0;
    }
    capfile->bytes_read += bytes_read;

    if (capfile->frame_number == 0) {
        capfile->start_sec = *r_time_secs;
        capfile->start_usec = *r_time_usecs;
    }
    capfile->end_sec = *r_time_secs;
    capfile->end_usec = *r_time_usecs;
    capfile->frame_number++;
    return 1;
}

void pcapfile_get_timestamps(struct PcapFile *capfile, time_t *start, time_t *end)
{
    *start = capfile->start_sec;
    *end = capfile->end_sec;
}


/**
 * Open a capture file for reading.
 */
struct PcapFile *pcapfile_openread(const char *capfilename)
{
    FILE *fp;
    size_t bytes_read;
    unsigned char buf[24];
    unsigned byte_order;
    unsigned linktype;
    uint64_t file_size = 0xFFFFffff;

    if (capfilename == NULL)
        return 0;

    /*
     * Open the file
     */
    fp = fopen(capfilename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "%s: could not open capture file\n", capfilename);
        perror(capfilename);
        return 0;
    }

    /* Grab info about the file */
    {
        struct stat s;
        memset(&s, 0, sizeof(s));
        if (stat(capfilename, &s) == 0) {
            file_size = s.st_size;
        }
    }

    /*
     * Read in the file header
     */
    bytes_read = fread(buf, 1, 24, fp);
    if (bytes_read < 24) {
        if (bytes_read <= 0) {
            fprintf(stderr, "%s: could not read PCAP header\n", capfilename);
            perror(capfilename);
        } else if (bytes_read == 0)
            fprintf(stderr, "%s: file empty\n", capfilename);
        else
            fprintf(stderr, "%s: file too short\n", capfilename);
        fclose(fp);
        return 0;
    }

    /*
     * Find the "Magic Number", which will tell us what the byte-order
     * is going to be. There are also odd magic number used by some
     * speciality systems that hint at other features, such as a 64-bit
     * version of the file.
     */
    switch (buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3]) {
    case 0xa1b2c3d4:   byte_order = CAPFILE_BIGENDIAN; break;
    case 0xd4c3b2a1:   byte_order = CAPFILE_LITTLEENDIAN; break;
    default:
        fprintf(stderr, "%s: unknown byte-order in cap file\n", capfilename);
        byte_order = CAPFILE_ENDIANUNKNOWN; break;
    }


    /* Version (of the libpcap standard) */
    {
        unsigned major = PCAP16(byte_order, buf+4);
        unsigned minor = PCAP16(byte_order, buf+6);

        if (major != 2 || minor != 4)
            fprintf(stderr, "%s: unknown version %d.%d\n", capfilename, major, minor);
    }

    /* Protocol (ethernet, wifi, etc.) */
    linktype = PCAP32(byte_order, buf+20);
    if (linktype == 0)
        linktype = 1;
    switch (linktype) {
    case 0x7f:   /* WiFi, with radiotap headers */
    case 1:       /*ethernet*/
    case 0x69:   /* WiFi, no radiotap headers */
    case 119:   /* Prism II headers (also used for things like Atheros madwifi) */
        break;
    default:
        fprintf(stderr, "%s: unknown cap file linktype = %d (expected Ethernet or wifi)\n", capfilename, linktype);
        fclose(fp);
        return 0;
        break;
    }

    /* Read the first frame's timestamp */
    {
        int loc;
        char tsbuf[8];
        size_t x;

        loc = ftell(fp);
        if (loc == -1) {
            fprintf(stderr, "%s: ftell failed (file system error? seen with VMware HGFS bug)\n", capfilename);
            perror(capfilename);
            fclose(fp);
            return 0;
        }
        x = fread(tsbuf, 1, 8, fp);
        if (x != 8) {
            perror(capfilename);
            fclose(fp);
            return 0;
        }

        if (fseek(fp, loc, SEEK_SET) != 0) {
            fprintf(stderr, "%s: fseek failed (file system error?)\n", capfilename);
            perror(capfilename);
            fclose(fp);
            return 0;
        }
    }

    /*
     * Now that the file is open and we have read in the header,
     * allocate a structure that contains this information
     * and return that structure.
     */
    {
        struct PcapFile *capfile = 0;
        capfile = (struct PcapFile*)malloc(sizeof(*capfile));
        if (capfile == NULL)
            exit(1);
        memset(capfile,0,sizeof(*capfile));
        capfile->byte_order = byte_order;

        snprintf(capfile->filename, sizeof(capfile->filename),
                 "%s", capfilename);
        capfile->fp = fp;
        capfile->byte_order = byte_order;
        capfile->linktype = linktype;
        capfile->file_size = file_size;
        capfile->bytes_read = 24; /*from the header*/
        return capfile;
    }
}


/**
 * Open a capture file for writing
 */
struct PcapFile *pcapfile_openwrite(const char *capfilename, unsigned linktype)
{
    char buf[] =
            "\xd4\xc3\xb2\xa1\x02\x00\x04\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00"
            "\xff\xff\x00\x00\x69\x00\x00\x00";
    FILE *fp;

    buf[20] = (char)(linktype>>0);
    buf[21] = (char)(linktype>>8);


    fp = fopen(capfilename, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Could not open capture file\n");
        perror(capfilename);
        return 0;
    }


    if (fwrite(buf, 1, 24, fp) != 24) {
        fprintf(stderr, "Could not write capture file header\n");
        perror(capfilename);
        fclose(fp);
        return 0;
    }

    {
        struct PcapFile *capfile = 0;
        capfile = (struct PcapFile*)malloc(sizeof(*capfile));
        if (capfile == NULL)
            exit(1);
        memset(capfile,0,sizeof(*capfile));

        snprintf(capfile->filename, sizeof(capfile->filename),
                 "%s", capfilename);

        capfile->fp = fp;
        capfile->byte_order = CAPFILE_LITTLEENDIAN;
        capfile->linktype = linktype;
        return capfile;
    }

}

/**
 * Open a capture file for "appending". This requires that we first
 * read from it and find out how it's formatted, then figure out
 * where the end of the file is so that we can start adding
 * packets at that point.
 */
struct PcapFile *pcapfile_openappend(const char *capfilename, unsigned linktype)
{
    struct PcapFile *capfile;
    unsigned char buf[24];
    unsigned byte_order;
    unsigned file_linktype;
    FILE *fp;



    /* open the file for appending and reading */
    fp = fopen(capfilename, "ab+");
    if (fp == NULL && errno == ENOENT) {
        return pcapfile_openwrite(capfilename, linktype);
    }
    if (fp == NULL) {
        fprintf(stderr, "Could not open capture file to append frame\n");
        perror(capfilename);
        return pcapfile_openappend(capfilename, linktype);
    }

    /* Read in the header to discover link type and byte order */
    if (fread(buf, 1, 24, fp) != 24) {
        fprintf(stderr, "Error reading capture file header\n");
        perror(capfilename);
        fclose(fp);
        return pcapfile_openappend(capfilename, linktype);
    }

    /* Seek to the end of the file, where we will start writing
     * frames from now on. Note that we aren't checking to see if the frames
     * are corrupt at the end (which happens when the program crashes),
     * so we may end up writing these frames in a way that cannot be read. */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Could not seek to end of capture file\n");
        perror(capfilename);
        fclose(fp);
        return 0;
    }


    /* Find out the byte order */
    switch (buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3]) {
    case 0xa1b2c3d4:   byte_order = CAPFILE_BIGENDIAN; break;
    case 0xd4c3b2a1:   byte_order = CAPFILE_LITTLEENDIAN; break;
    default:
        fprintf(stderr, "%s: unknown byte-order in cap file\n", capfilename);
        fclose(fp);
        return pcapfile_openappend(capfilename, linktype);
    }


    /* Version */
    {
        unsigned major = PCAP16(byte_order, buf+4);
        unsigned minor = PCAP16(byte_order, buf+6);

        if (major != 2 || minor != 4)
            fprintf(stderr, "%s: unknown version %d.%d\n", capfilename, major, minor);
    }

    /* Protocol */
    file_linktype = PCAP32(byte_order, buf+20);
    if (linktype != file_linktype) {
        /* oops, the link types do not agree. Since we want a program to generate
         * dumps while simultaneously processing multiple inputs, we are going to
         * create a kludge. Instead of writing to the originally specified file,
         * we are going to create a new file with the linktype added to it's name */
        char linkspec[32];
        size_t linkspec_length;
        char newname[sizeof(capfile->filename)];
        size_t i;

        fclose(fp);

        snprintf(linkspec, sizeof(linkspec), "-linktype%d", linktype);
        linkspec_length = strlen(linkspec);

        if (strstr(capfilename, linkspec) || strlen(capfilename) + linkspec_length + 1 > sizeof(newname)) {
            /* Oops, we have a problem, it looks like the filename already
             * has the previous linktype in its name for some reason. At this
             * unlikely point, we just give up */
            fprintf(stderr, "Giving up on appending %d-type frames onto a %d-type file\n", linktype, file_linktype);
            return 0;
        }

        if (strchr(capfilename, '.'))
            i = strchr(capfilename, '.')-capfilename;
        else
            i = strlen(capfilename);

        memcpy(newname, capfilename, i);
        memcpy(newname+i, linkspec, linkspec_length);
        memcpy(newname+i+linkspec_length, capfilename+i, strlen(capfilename+i)+1);

        return pcapfile_openappend(newname, linktype);
    }

    /* Now that everything has checked out, create a file structure and
     * return it */
    {

        capfile = (struct PcapFile*)malloc(sizeof(*capfile));
        if (capfile == NULL)
            exit(1);
        memset(capfile,0,sizeof(*capfile));
        capfile->byte_order = byte_order;
        snprintf(capfile->filename, sizeof(capfile->filename),
                 "%s", capfilename);
        capfile->fp = fp;
        capfile->byte_order = byte_order;
        capfile->linktype = linktype;
    }

    return capfile;
}


/**
 * Close a capture file created by one of the open functions
 * such as 'pcapfile_openread()', 'pcapfile_openwrite()', or
 * 'pcapfile_openappend()'.
 */
void pcapfile_close(struct PcapFile *handle)
{
    if (handle == NULL)
        return;
    if (handle->fp)
        fclose(handle->fp);
    free(handle);
}


/**
 * Called to write a frame of data in libpcap format. This format has a
 * 16-byte header (microseconds, seconds, sliced-length, original-length)
 * followed by the captured data */
void pcapfile_writeframe(
    struct PcapFile *capfile,
    const void *buffer,
    unsigned buffer_size,
    unsigned original_length,
    unsigned time_sec,
    unsigned time_usec)
{
    unsigned char header[16];

    if (capfile == NULL || capfile->fp == NULL)
        return;

    /*
     * Write timestamp
     */
    if (capfile->byte_order == CAPFILE_BIGENDIAN) {
        header[ 0] = (unsigned char)(time_sec>>24);
        header[ 1] = (unsigned char)(time_sec>>16);
        header[ 2] = (unsigned char)(time_sec>> 8);
        header[ 3] = (unsigned char)(time_sec>> 0);

        header[ 4] = (unsigned char)(time_usec>>24);
        header[ 5] = (unsigned char)(time_usec>>16);
        header[ 6] = (unsigned char)(time_usec>> 8);
        header[ 7] = (unsigned char)(time_usec>> 0);

        header[ 8] = (unsigned char)(buffer_size>>24);
        header[ 9] = (unsigned char)(buffer_size>>16);
        header[10] = (unsigned char)(buffer_size>> 8);
        header[11] = (unsigned char)(buffer_size>> 0);

        header[12] = (unsigned char)(original_length>>24);
        header[13] = (unsigned char)(original_length>>16);
        header[14] = (unsigned char)(original_length>> 8);
        header[15] = (unsigned char)(original_length>> 0);

    } else {
        header[ 0] = (unsigned char)(time_sec>> 0);
        header[ 1] = (unsigned char)(time_sec>> 8);
        header[ 2] = (unsigned char)(time_sec>>16);
        header[ 3] = (unsigned char)(time_sec>>24);

        header[ 4] = (unsigned char)(time_usec>> 0);
        header[ 5] = (unsigned char)(time_usec>> 8);
        header[ 6] = (unsigned char)(time_usec>>16);
        header[ 7] = (unsigned char)(time_usec>>24);

        header[ 8] = (unsigned char)(buffer_size>> 0);
        header[ 9] = (unsigned char)(buffer_size>> 8);
        header[10] = (unsigned char)(buffer_size>>16);
        header[11] = (unsigned char)(buffer_size>>24);

        header[12] = (unsigned char)(original_length>> 0);
        header[13] = (unsigned char)(original_length>> 8);
        header[14] = (unsigned char)(original_length>>16);
        header[15] = (unsigned char)(original_length>>24);

    }

    if (fwrite(header, 1, 16, capfile->fp) != 16) {
        fprintf(stderr, "%s: could write packet header, frame #%" PRId64 "\n",
            capfile->filename, capfile->frame_number);
        perror(capfile->filename);
        fclose(capfile->fp);
        capfile->fp = NULL;
    }

    if (fwrite(buffer, 1, buffer_size, capfile->fp) != buffer_size) {
        fprintf(stderr, "%s: could write packet contents, frame #%" PRId64 "\n",
            capfile->filename, capfile->frame_number);
        perror(capfile->filename);
        fclose(capfile->fp);
        capfile->fp = NULL;
    }
}

