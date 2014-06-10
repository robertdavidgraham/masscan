/*
    output logging/reporting

    This is the file that formats the output files -- that is to say,
    where we report everything we find.

    PLUGINS

    The various types of output (XML, binary, Redis, etc.) are written vaguely
    as "plugins", which means as a structure with function pointers. In the
    future, it should be possible to write plugins as DDLs/shared-objects
    and load them at runtime, but right now, they are just hard coded.

    ROTATE

    Files can be "rotated". This is done by prefixing the file with the
    date/time when the file was created.

    A key feature of this design is to prevent files being lost during
    rotation. Therefore, the files are renamed while they are still open.
    If the rename function fails, then the file is left in-place and still
    open for writing, with continued appending to the file.

    Thus, you could start the program logging to "--rotate-dir ../foobar"
    and then notice the error messages saying that rotating isn't working,
    then go create the "foobar" directory, at which point rotating will now
    work -- it's just that the first rotated file will contain several
    periods of data.
*/
#include "output.h"
#include "masscan.h"
#include "masscan-status.h"
#include "string_s.h"
#include "logger.h"
#include "proto-banner1.h"
#include "masscan-app.h"
#include "main-globals.h"
#include "pixie-file.h"
#include "pixie-sockets.h"

#include <limits.h>
#include <ctype.h>
#include <string.h>


/*****************************************************************************
 * The 'status' variable contains both the open/closed info as well as the
 * protocol info. This splits it back out into two values.
 *****************************************************************************/
const char *
name_from_ip_proto(unsigned ip_proto)
{
    switch (ip_proto) {
        case 0: return "arp";
        case 1: return "icmp";
        case 6: return "tcp";
        case 17: return "udp";
        case 132: return "sctp";
        default: return "err";
    }
}


/*****************************************************************************
 * The actual 'status' variable is narrowly defined depending on the
 * underlying protocol. This function creates a gross "open" v. "closed"
 * string based on the narrow variable.
 *****************************************************************************/
const char *
status_string(enum PortStatus status)
{
    switch (status) {
        case PortStatus_Open: return "open";
        case PortStatus_Closed: return "closed";
        case PortStatus_Arp: return "up";
        default: return "unknown";
    }
}


/*****************************************************************************
 * Convert TCP flags into an nmap-style "reason" string
 *****************************************************************************/
const char *
reason_string(int x, char *buffer, size_t sizeof_buffer)
{
    sprintf_s(buffer, sizeof_buffer, "%s%s%s%s%s%s%s%s",
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


/*****************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 *****************************************************************************/
const char *
normalize_string(const unsigned char *px, size_t length,
                 char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;


    for (i=0; i<length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\'') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 5 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'x';
                buf[offset++] = "0123456789abcdef"[px[i]>>4];
                buf[offset++] = "0123456789abcdef"[px[i]&0xF];
            }
        }
    }

    buf[offset] = '\0';

    return buf;
}


/*****************************************************************************
 * PORTABILITY: WINDOWS
 *
 * Windows POSIX functions open the file without the "share-delete" flag,
 * meaning they can't be renamed while open. Therefore, we need to
 * construct our own open flag.
 *****************************************************************************/
static FILE *
open_rotate(struct Output *out, const char *filename)
{
    FILE *fp = 0;
    unsigned is_append = out->is_append;
    int x;

    /*
     * KLUDGE: do something special for redis
     */
    if (out->format == Output_Redis) {
        ptrdiff_t fd = out->redis.fd;
        if (fd < 1) {
            struct sockaddr_in sin = {0};
            fd = (ptrdiff_t)socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                LOG(0, "redis: socket() failed to create socket\n");
                exit(1);
            }
            sin.sin_addr.s_addr = htonl(out->redis.ip);
            sin.sin_port = htons((unsigned short)out->redis.port);
            sin.sin_family = AF_INET;
            x = connect(fd, (struct sockaddr*)&sin, sizeof(sin));
            if (x != 0) {
                LOG(0, "redis: connect() failed\n");
                perror("connect");
            }
            out->redis.fd = fd;
        }
        out->funcs->open(out, (FILE*)fd);

        return (FILE*)fd;
    }

    /* Do something special for the "-" filename */
    if (filename[0] == '-' && filename[1] == '\0')
        fp = stdout;

    /* open a "shareable" file. On Windows, by default files can't be renamed
     * while they are open, so we need a special function that takes care
     * of this. */
    if (fp == 0) {
        x = pixie_fopen_shareable(&fp, filename, is_append);
        if (x != 0 || fp == NULL) {
            fprintf(stderr, "out: could not open file for %s\n",
                    is_append?"appending":"writing");
            perror(filename);
            control_c_pressed = 1;
            return NULL;
        }
    }

    /*
     * Mark the file as newly opened. That way, before writing any data
     * to it, we'll first have to write headers
     */
    out->is_virgin_file = 1;

    return fp;
}


/*****************************************************************************
 * Write the remaining data the file and close it. This function is
 * called "rotate", but it doesn't actually rotate, this name just reflects
 * how it's used in the rotate process.
 *****************************************************************************/
static void
close_rotate(struct Output *out, FILE *fp)
{
    if (out == NULL)
        return;
    if (fp == NULL)
        return;

    /*
     * Write the format-specific trailers, like </xml>
     */
    if (!out->is_virgin_file)
        out->funcs->close(out, fp);

    memset(&out->counts, 0, sizeof(out->counts));

    /* Redis Kludge*/
    if (out->format == Output_Redis)
        return;

    fflush(fp);
    fclose(fp);
}


/*****************************************************************************
 * Returns the time when the next rotate should occur. Rotations are
 * aligned to the period, which means that if you rotate hourly, it's done
 * on the hour every hour, like at 9:00:00 o'clock exactly. In other words,
 * a period of "hourly" doesn't really mean "every 60 minutes", but
 * on the hour". Since the program will be launched midway in a period,
 * that means the first rotation will happen in less than a full period.
 *****************************************************************************/
static time_t
next_rotate_time(time_t last_rotate, unsigned period, unsigned offset)
{
    time_t next;

    next = last_rotate - (last_rotate % period) + period + offset;

    return next;
}


#if 0
/*****************************************************************************
 *****************************************************************************/
static int
ends_with(const char *filename, const char *extension)
{
    if (filename == NULL || extension == NULL)
        return 0;
    if (strlen(filename) + 1 < strlen(extension))
        return 0;
    if (memcmp(filename + strlen(filename) - strlen(extension),
                extension, strlen(extension)) != 0)
        return 0;
    if (filename[strlen(filename) - strlen(extension) - 1] != '.')
        return 0;

    return 1;
}
#endif

/*****************************************************************************
 * strdup(): compilers don't like strdup(), so I just write my own here. I
 * should probably find a better solution.
 *****************************************************************************/
static char *
duplicate_string(const char *str)
{
    size_t length;
    char *result;

    /* Find the length of the string. We allow NULL strings, in which case
     * the length is zero */
    if (str == NULL)
        length = 0;
    else
        length = strlen(str);

    /* Allocate memory for the string */
    result = (char*)malloc(length + 1);
    if (result == 0) {
        fprintf(stderr, "output: out of memory error\n");
        exit(1);
    }

    /* Copy the string */
    memcpy(result, str, length+1);
    result[length] = '\0';

    return result;
}

/*****************************************************************************
 * Adds the index variable to just before the file extension. For example,
 * if the original filename is "foo.bar", and the index is 1, then the
 * new filename becomes "foo.01.bar". By putting the index before the
 * extension, it preserves the file type. By prepending a zero on the index,
 * it allows up to 100 files while still being able to easily sort the files.
 *****************************************************************************/
static char *
indexed_filename(const char *filename, unsigned index)
{
    size_t len = strlen(filename);
    size_t ext;
    char *new_filename;
    size_t new_length = strlen(filename) + 32;

    /* find the extension */
    ext = len;
    while (ext) {
        ext--;
        if (filename[ext] == '.')
            break;
        if (filename[ext] == '/' || filename[ext] == '\\') {
            /* no dot found, so ext is end of file */
            ext = len;
            break;
        }
    }
    if (ext == 0 && len > 0 && filename[0] != '.')
        ext = len;

    /* allocate memory */
    new_filename = (char*)malloc(new_length);
    if (new_filename == NULL) {
        fprintf(stderr, "output: out of memory\n");
        exit(1);
    }

    /* format the new name */
    sprintf_s(new_filename, new_length, "%.*s.%02u%s",
              (unsigned)ext, filename,
              index,
              filename+ext);

    return new_filename;

}

/*****************************************************************************
 * Create an "output" structure. If we are writing a file, we create the
 * file now, so that any errors creating the file are caught immediately,
 * rather than later in the scan when it might fail.
 *****************************************************************************/
struct Output *
output_create(const struct Masscan *masscan, unsigned thread_index)
{
    struct Output *out;
    unsigned i;

    /* allocate/initialize memory */
    out = (struct Output *)malloc(sizeof(*out));
    if (out == NULL)
        return NULL;
    memset(out, 0, sizeof(*out));
    out->masscan = masscan;
    out->when_scan_started = time(0);
    out->is_virgin_file = 1;

    /*
     * Copy the configuration information from the 'masscan' structure.
     */
    out->rotate.period = masscan->output.rotate.timeout;
    out->rotate.offset = masscan->output.rotate.offset;
    out->rotate.filesize = masscan->output.rotate.filesize;
    out->redis.port = masscan->redis.port;
    out->redis.ip = masscan->redis.ip;
    out->is_banner = masscan->is_banners;
    out->is_gmt = masscan->is_gmt;
    out->is_interactive = masscan->output.is_interactive;
    out->is_show_open = masscan->output.is_show_open;
    out->is_show_closed = masscan->output.is_show_closed;
    out->is_show_host = masscan->output.is_show_host;
    out->is_append = masscan->output.is_append;
    out->xml.stylesheet = duplicate_string(masscan->output.stylesheet);
    out->rotate.directory = duplicate_string(masscan->output.rotate.directory);
    if (masscan->nic_count <= 1)
        out->filename = duplicate_string(masscan->output.filename);
    else
        out->filename = indexed_filename(masscan->output.filename, thread_index);

    for (i=0; i<8; i++) {
        out->src[i] = masscan->nic[i].src;
    }

    /*
     * Link the appropriate output module.
     * TODO: support multiple output modules
     */
    out->format = masscan->output.format;
    switch (out->format) {
    case Output_List:
        out->funcs = &text_output;
        break;
    case Output_XML:
        out->funcs = &xml_output;
        break;
    case Output_JSON:
        out->funcs = &json_output;
        break;
    case Output_Certs:
        out->funcs = &certs_output;
        break;
    case Output_Binary:
        out->funcs = &binary_output;
        break;
    case Output_Grepable:
        out->funcs = &grepable_output;
        break;
    case Output_Redis:
        out->funcs = &redis_output;
        break;
    case Output_None:
        out->funcs = &null_output;
        break;
    default:
        out->funcs = &null_output;
        break;
    }

    /*
     * Open the desired output file. We do this now at the start of the scan
     * so that we can immediately notify the user of an error, rather than
     * waiting midway through a long scan and have it fail.
     */
    if (masscan->output.filename[0] && out->funcs != &null_output) {
        FILE *fp;

        fp = open_rotate(out, masscan->output.filename);
        if (fp == NULL) {
            perror(masscan->output.filename);
            exit(1);
        }

        out->fp = fp;
        out->rotate.last = time(0);
    }

    /*
     * Set the time of the next rotation. If we aren't rotating files, then
     * this time will be set at "infinity" in the future.
     * TODO: this code isn't Y2036 compliant.
     */
    if (masscan->output.rotate.timeout == 0) {
        /* TODO: how does one find the max time_t value??*/
        out->rotate.next = (time_t)LONG_MAX;
    } else {
        if (out->rotate.offset > 1) {
            out->rotate.next = next_rotate_time(
                                    out->rotate.last-out->rotate.period,
                                    out->rotate.period, out->rotate.offset);
        } else {
            out->rotate.next = next_rotate_time(
                                    out->rotate.last,
                                    out->rotate.period, out->rotate.offset);
        }
    }



    return out;
}


/*****************************************************************************
 * Rotate the file, moving it from the local directory to a remote directory
 * and changing the name to include the timestamp. This is done while the file
 * is still open: we move the file and rename it first, then close it.
 *****************************************************************************/
static FILE *
output_do_rotate(struct Output *out, int is_closing)
{
    const char *dir = out->rotate.directory;
    const char *filename = out->filename;
    char *new_filename;
    size_t new_filename_size;
    struct tm tm;
    int err;

    /* Don't do anything if there is no file */
    if (out->fp == NULL)
        return NULL;

    /* Make sure that all output has been flushed to the file */
    fflush(out->fp);

    /* Remove directory prefix from filename, we just want the root filename
     * to start with */
    while (strchr(filename, '/') || strchr(filename, '\\')) {
        filename = strchr(filename, '/');
        if (*filename == '/')
            filename++;
        filename = strchr(filename, '\\');
        if (*filename == '\\')
            filename++;
    }

    /* Allocate memory for the new filename */
    new_filename_size =     strlen(dir)
                            + strlen("/")
                            + strlen(filename)
                            + strlen("1308201101-")
                            + strlen(filename)
                            + 1  /* - */
                            + 1; /* nul */
    new_filename = (char*)malloc(new_filename_size);
    if (new_filename == NULL) {
        LOG(0, "rotate: out of memory error\n");
        return out->fp;
    }

    /* Get the proper timestamp for the file */
    if (out->is_gmt) {
        err = gmtime_s(&tm, &out->rotate.last);
    } else {
        err = localtime_s(&tm, &out->rotate.last);
    }
    if (err != 0) {
        perror("gmtime(): file rotation ended");
        return out->fp;
    }


    /* Look for a name that doesn't collide with an exist name. If the desired
     * file already exists, then increment the filename. This should never
     * happen. */
    err = 0;
again:
    sprintf_s(new_filename, new_filename_size,
              "%s/%02u%02u%02u-%02u%02u%02u" "-%s",
        dir,
        tm.tm_year % 100,
        tm.tm_mon+1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        filename);
    if (access(new_filename, 0) == 0) {
        tm.tm_sec++;
        if (err++ == 0)
            goto again;
    }
    filename = out->filename;

    /*
     * Move the file
     */
    err = rename(filename, new_filename);
    if (err) {
        LOG(0, "rename(\"%s\", \"%s\"): failed\n", filename, new_filename);
        perror("rename()");
        free(new_filename);
        return out->fp;
    }

    /*
     * Set the next rotate time, which is the current time plus the period
     * length
     */
    out->rotate.bytes_written = 0;

    if (out->rotate.period) {
        out->rotate.next = next_rotate_time(time(0),
                                        out->rotate.period, out->rotate.offset);
    }

    LOG(1, "rotated: %s\n", new_filename);
    free(new_filename);

    /*
     * Now create a new file
     */
    if (is_closing)
        out->fp = NULL; /* program shutting down, so don't create new file */
    else {
        FILE *fp;

        fp = open_rotate(out, filename);
        if (fp == NULL) {
            LOG(0, "rotate: %s: failed: %s\n", filename, strerror_x(errno));
        } else {
            close_rotate(out, out->fp);
            out->fp = fp;
            out->rotate.last = time(0);
            LOG(1, "rotate: started new file: %s\n", filename);
        }
    }
    return out->fp;
}

/***************************************************************************
 ***************************************************************************/
static int
is_rotate_time(const struct Output *out, time_t now)
{
    if (out->is_virgin_file)
        return 0;
    if (now >= out->rotate.next)
        return 1;
    if (out->rotate.filesize != 0 &&
        out->rotate.bytes_written >= out->rotate.filesize)
        return 1;
    return 0;
}


/***************************************************************************
 * Report simply "open" or "closed", with little additional information.
 * This is called directly from the receive thread when responses come
 * back.
 ***************************************************************************/
void
output_report_status(struct Output *out, time_t timestamp, int status,
        unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;

    /* if "--open"/"--open-only" parameter specified on command-line, then
     * don't report the status of closed-ports */
    if (!out->is_show_closed && status == PortStatus_Closed)
        return;
    if (!out->is_show_open && status == PortStatus_Open)
        return;

    /* If in "--interactive" mode, then print the banner to the command
     * line screen */
    if (out->is_interactive || out->format == 0) {
        unsigned count;

        count = fprintf(stdout, "Discovered %s port %u/%s on %u.%u.%u.%u",
                    status_string(status),
                    port,
                    name_from_ip_proto(ip_proto),
                    (ip>>24)&0xFF,
                    (ip>>16)&0xFF,
                    (ip>> 8)&0xFF,
                    (ip>> 0)&0xFF
                    );

        /* Because this line may overwrite the "%done" status line, print
         * some spaces afterward to completely cover up the line */
        if (count < 80)
            fprintf(stdout, "%.*s", (int)(79-count),
                    "                                          "
                    "                                          ");

        fprintf(stdout, "\n");

    }


    if (fp == NULL)
        return;

    /* Rotate, if we've pass the time limit. Rotating the log files happens
     * inline while writing output, whenever there's output to write to the
     * file, rather than in a separate thread right at the time interval.
     * Thus, if results are coming in slowly, the rotation won't happen
     * on precise boundaries */
    if (is_rotate_time(out, now)) {
        fp = output_do_rotate(out, 0);
        if (fp == NULL)
            return;
    }


    /* Keep some statistics so that the user can monitor how much stuff is
     * being found. */
    switch (status) {
        case PortStatus_Open:
            switch (ip_proto) {
            case 1:
                out->counts.icmp.echo++;
                break;
            case 6:
                out->counts.tcp.open++;
                break;
            case 17:
                out->counts.udp.open++;
                break;
            case 132:
                out->counts.sctp.open++;
                break;
            }
            if (!out->is_show_open)
                return;
            break;
        case PortStatus_Closed:
            switch (ip_proto) {
            case 6:
                out->counts.tcp.closed++;
                break;
            case 17:
                out->counts.udp.closed++;
                break;
            case 132:
                out->counts.sctp.closed++;
                break;
            }
            if (!out->is_show_closed)
                return;
            break;
        case PortStatus_Arp:
            out->counts.arp.open++;
            break;
        default:
            LOG(0, "unknown status type: %u\n", status);
            return;
    }

    /*
     * If this is a newly opened file, then write file headers
     */
    if (out->is_virgin_file) {
        out->funcs->open(out, fp);
        out->is_virgin_file = 0;
    }

    /*
     * Now do the actual output, whether it be XML, binary, JSON, Redis,
     * and so on.
     */
    out->funcs->status(out, fp, timestamp, status, ip, ip_proto, port, reason, ttl);
}


/***************************************************************************
 ***************************************************************************/
void
output_report_banner(struct Output *out, time_t now,
                unsigned ip, unsigned ip_proto, unsigned port,
                unsigned proto, 
                unsigned ttl, 
                const unsigned char *px, unsigned length)
{
    FILE *fp = out->fp;

    /* If we aren't doing banners, then don't do anything. That's because
     * when doing UDP scans, we'll still get banner information from
     * decoding the response packets, even if the user isn't interested */
    if (!out->is_banner)
        return;

    /* If in "--interactive" mode, then print the banner to the command
     * line screen */
    if (out->is_interactive || out->format == 0) {
        unsigned count;
        char banner_buffer[4096];

        count = fprintf(stdout, "Banner on port %u/%s on %u.%u.%u.%u: [%s] %s",
            port,
            name_from_ip_proto(ip_proto),
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            masscan_app_to_string(proto),
            normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
            );

        /* Because this line may overwrite the "%done" status line, print
         * some spaces afterward to completely cover up the line */
        if (count < 80)
            fprintf(stdout, "%.*s", (int)(79-count),
                    "                                          "
                    "                                          ");

        fprintf(stdout, "\n");
    }

    /* If not outputing to a file, then don't do anything */
    if (fp == NULL)
        return;

    /* Rotate, if we've pass the time limit. Rotating the log files happens
     * inline while writing output, whenever there's output to write to the
     * file, rather than in a separate thread right at the time interval.
     * Thus, if results are coming in slowly, the rotation won't happen
     * on precise boundaries */
    if (is_rotate_time(out, now)) {
        fp = output_do_rotate(out, 0);
        if (fp == NULL)
            return;
    }

    /*
     * If this is a newly opened file, then write file headers
     */
    if (out->is_virgin_file) {
        out->funcs->open(out, fp);
        out->is_virgin_file = 0;
    }

    /*
     * Now do the actual output, whether it be XML, binary, JSON, Redis,
     * and so on.
     */
    out->funcs->banner(out, fp, now, ip, ip_proto, port, proto, ttl, px, length);

}


/***************************************************************************
 * Called on exit of the program to close/free everything
 ***************************************************************************/
void
output_destroy(struct Output *out)
{
    if (out == NULL)
        return;

    /* If rotating files, then do one last rotate of this file to the
     * destination directory */
    if (out->rotate.period)
        output_do_rotate(out, 1);

    /* If not rotating files, then simply close this file. Remember
     * that some files will write closing information before closing
     * the file */
    if (out->fp)
        close_rotate(out, out->fp);



    free(out->xml.stylesheet);
    free(out->rotate.directory);
    free(out->filename);

    free(out);
}


/*****************************************************************************
 * Regression tests for this unit.
 *****************************************************************************/
int
output_selftest(void)
{
    char *f;

    f = indexed_filename("foo.bar", 1);
    if (strcmp(f, "foo.01.bar") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    f = indexed_filename("foo.b/ar", 2);
    if (strcmp(f, "foo.b/ar.02") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    f = indexed_filename(".foobar", 3);
    if (strcmp(f, ".03.foobar") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    return 0;
}

