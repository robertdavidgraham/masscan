/*
    output logging/reporting

    This is the file that formats the output files -- that is to say,
    where we report everything we find.

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
#include "string_s.h"
#include "logger.h"
#include "proto-banner1.h"
#include "masscan-app.h"
#include "main-globals.h"
#include "pixie-file.h"
#include "pixie-sockets.h"

#include <limits.h>
#include <ctype.h>




/***************************************************************************
 ***************************************************************************/
const char *
status_string(int x)
{
    switch (x) {
        case Port_Open: return "open";
        case Port_Closed: return "closed";
        case Port_UdpOpen: return "open";
        case Port_UdpClosed: return "closed";
        case Port_IcmpEchoResponse: return "exists";
		case Port_ArpOpen: return "open";
        default: return "unknown";
    }
}


/***************************************************************************
 * Convert TCP flags into an nmap-style "reason" string
 ***************************************************************************/
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


/***************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 ***************************************************************************/
const char *
normalize_string(const unsigned char *px, size_t length, char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;


    for (i=0; i<length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\') {
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


/***************************************************************************
 * PORTABILITY: WINDOWS
 *
 * Windows POSIX functions open the file without the "share-delete" flag,
 * meaning they can't be renamed while open. Therefore, we need to
 * construct our own open flag.
 ***************************************************************************/
static FILE *
open_rotate(struct Output *output, const char *filename)
{
    FILE *fp;
    const struct Masscan *masscan = output->masscan;
    unsigned is_append = masscan->nmap.append;
    int x;

    /*
     * KLUDGE: do something special for redis
     */
    if (masscan->nmap.format == Output_Redis) {
        ptrdiff_t fd = output->redis.fd;
        if (fd < 1) {
            struct sockaddr_in sin = {0};
            fd = (ptrdiff_t)socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                LOG(0, "redis: socket() failed to create socket\n");
                exit(1);
            }
            sin.sin_addr.s_addr = htonl(output->redis.ip);
            sin.sin_port = htons((unsigned short)output->redis.port);
            sin.sin_family = AF_INET;
            x = connect(fd, (struct sockaddr*)&sin, sizeof(sin));
            if (x != 0) {
                LOG(0, "redis: connect() failed\n");
                perror("connect");
            }
            output->redis.fd = fd;
        }
        output->funcs->open(output, (FILE*)fd);

        return (FILE*)fd;
    }


    x = pixie_fopen_shareable(&fp, filename, is_append);
    if (x != 0 || fp == NULL) {
        fprintf(stderr, "out: could not open file for %s\n", is_append?"appending":"writing");
        perror(filename);
        control_c_pressed = 1;
        return NULL;
    }

    /*
     * Write the format-specific headers, like <xml>
     */
    output->funcs->open(output, fp);

    return fp;
}


/***************************************************************************
 ***************************************************************************/
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
    out->funcs->close(out, fp);

    memset(&out->counts, 0, sizeof(out->counts));
 
    /* Redis Kludge*/
    if (out->masscan->nmap.format == Output_Redis)
        return;

    fflush(fp);
    fclose(fp);
}

/***************************************************************************
 ***************************************************************************/
static time_t
next_rotate(time_t last_rotate, unsigned period, unsigned offset)
{
    time_t next;

    next = last_rotate - (last_rotate % period) + period + offset;

    return next;
}


/***************************************************************************
 ***************************************************************************/
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


/***************************************************************************
 ***************************************************************************/
struct Output *
output_create(const struct Masscan *masscan)
{
    struct Output *out;
    unsigned i;

    /* allocate/initialize memory */
    out = (struct Output *)malloc(sizeof(*out));
    if (out == NULL)
        return NULL;
    memset(out, 0, sizeof(*out));
    out->masscan = masscan;
    out->period = masscan->rotate_output;
    out->offset = masscan->rotate_offset;
    out->redis.port = masscan->redis.port;
    out->redis.ip = masscan->redis.ip;
    out->is_banner = masscan->is_banners;

    for (i=0; i<8; i++) {
        out->src[i] = masscan->nic[i].src;
    }

    switch (masscan->nmap.format) {
    case Output_List:
        out->funcs = &text_output;
        break;
    case Output_XML:
        out->funcs = &xml_output;
        break;
    case Output_Binary:
        out->funcs = &binary_output;
        break;
    case Output_Redis:
        out->funcs = &redis_output;
        break;
    case Output_None:
        out->funcs = &null_output;
        break;
    default:
        out->funcs = &null_output;
        //masscan->is_interactive = 1;
        break;
    }

    /*
     * Open the desired output file
     */
    if (masscan->nmap.filename[0] && out->funcs != &null_output) {
        FILE *fp;

        fp = open_rotate(out, masscan->nmap.filename);
        if (fp == NULL) {
            perror(masscan->nmap.filename);
            exit(1);
        }

        out->fp = fp;
        out->last_rotate = time(0);
    }

    /*
     * Set the rotation time
     */
    if (masscan->rotate_output == 0) {
        /* TODO: how does one find the max time_t value??*/
        out->next_rotate = (time_t)LONG_MAX;
    } else {
        if (out->offset > 1)
            out->next_rotate = next_rotate(out->last_rotate-out->period, out->period, out->offset);
        else
            out->next_rotate = next_rotate(out->last_rotate, out->period, out->offset);
    }



    return out;
}


/***************************************************************************
 ***************************************************************************/
static FILE *
output_do_rotate(struct Output *out)
{
    const char *dir = out->masscan->rotate_directory;
    const char *filename = out->masscan->nmap.filename;
    char *new_filename;
    size_t new_filename_size;
    struct tm tm;
    int err;

    if (out->fp == NULL)
        return NULL;

    fflush(out->fp);

    /* remove directories from filename */
    while (strchr(filename, '/') || strchr(filename, '\\')) {
        filename = strchr(filename, '/');
        if (*filename == '/')
            filename++;
        filename = strchr(filename, '\\');
        if (*filename == '\\')
            filename++;
    }

    new_filename_size =     strlen(dir)
                            + strlen("/")
                            + strlen(filename)
                            + strlen("1308201101-")
                            + strlen(filename)
                            + 1  /* - */
                            + 1; /* nul */


    err = localtime_s(&tm, &out->last_rotate);
    if (err != 0) {
        perror("gmtime(): file rotation ended");
        return out->fp;
    }

    new_filename = (char*)malloc(new_filename_size);
    if (new_filename == NULL)
        return out->fp;

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
    filename = out->masscan->nmap.filename;

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
    out->next_rotate = next_rotate(time(0), out->period, out->offset);

    LOG(1, "rotated: %s\n", new_filename);
    free(new_filename);
    
    /*
     * Now create a new file
     */
    {
        FILE *fp;

        fp = open_rotate(out, filename);
        if (fp == NULL) {
            LOG(0, "rotate: %s: failed: %s\n", filename, strerror_x(errno));
        } else {
            close_rotate(out, out->fp);
            out->fp = fp;
            out->last_rotate = time(0);
            LOG(1, "rotate: started new file: %s\n", filename);
        }
    }
    return out->fp;
}

/***************************************************************************
 ***************************************************************************/
const char *
proto_from_status(unsigned status)
{
    switch (status) {
        case Port_Open: return "tcp";
        case Port_Closed: return "tcp";
        case Port_IcmpEchoResponse: return "icmp";
        case Port_UdpOpen: return "udp";
        case Port_UdpClosed: return "udp";
		case Port_ArpOpen: return "arp";
		default: return "err";
    }
}

/***************************************************************************
 ***************************************************************************/
void
output_report_status(struct Output *out, time_t timestamp, int status, 
        unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    const struct Masscan *masscan = out->masscan;
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;

    if (masscan->nmap.open_only)
    switch (status) {
    case Port_Open:
    case Port_IcmpEchoResponse:
    case Port_UdpOpen:
	case Port_ArpOpen:
    default:
        break;

    case Port_Closed:
    case Port_UdpClosed:
        return;
    }

    if (masscan->is_interactive) {
        if (status == Port_IcmpEchoResponse) {
            fprintf(stdout, "Discovered %s port %u/%s on %u.%u.%u.%u"
                    "                               \n",
                    status_string(status),
                    port,
                    proto_from_status(status),
                    (ip>>24)&0xFF, 
                    (ip>>16)&0xFF,
                    (ip>> 8)&0xFF,
                    (ip>> 0)&0xFF
                    );
            
        } else
        fprintf(stdout, "Discovered %s port %u/%s on %u.%u.%u.%u"
                            "                               \n",
            status_string(status),
            port,
            proto_from_status(status),
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF
            );
    }


    if (fp == NULL)
        return;

    if (now >= out->next_rotate) {
        fp = output_do_rotate(out);
        if (fp == NULL)
            return;
    }


    switch (status) {
        case Port_Open:
            out->counts.tcp.open++;
            break;
        case Port_Closed:
            out->counts.tcp.closed++;
            if (masscan->nmap.open_only)
                return;
            break;
        case Port_IcmpEchoResponse:
            out->counts.icmp.echo++;
            break;
        case Port_UdpOpen:
            out->counts.udp.open++;
            break;
        case Port_UdpClosed:
            out->counts.udp.closed++;
            if (masscan->nmap.open_only)
                return;
            break;
        case Port_ArpOpen:
            out->counts.arp.open++;
            break;
        default:
            LOG(0, "unknown status type: %u\n", status);
            if (masscan->nmap.open_only)
                return;
    }

    out->funcs->status(out, fp, timestamp, status, ip, port, reason, ttl);

}

/***************************************************************************
 ***************************************************************************/
void
output_report_banner(struct Output *out, time_t now,
                unsigned ip, unsigned ip_proto, unsigned port,
                unsigned proto, const unsigned char *px, unsigned length)
{
    const struct Masscan *masscan = out->masscan;
    FILE *fp = out->fp;
    
    if (!out->is_banner)
        return;

    if (masscan->is_interactive) {
        unsigned count;
        char banner_buffer[4096];

        count = fprintf(stdout, "Banner on port %u/tcp on %u.%u.%u.%u: %s",
            port,
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
            );
        if (count < 80)
            fprintf(stdout, "%.*s\n", (int)(79-count),
"                                                                                    ");
        else
            fprintf(stdout, "\n");
    }


    if (fp == NULL)
        return;

    if (now >= out->next_rotate) {
        fp = output_do_rotate(out);
        if (fp == NULL)
            return;
    }

    out->funcs->banner(out, fp, now, ip, ip_proto, port, proto, px, length);

}

/***************************************************************************
 ***************************************************************************/
void
output_destroy(struct Output *out)
{
    if (out == NULL)
        return;

    if (out->period)
        output_do_rotate(out); /*TODO: this leaves an empty file behind */

    if (out->fp)
        close_rotate(out, out->fp);

    free(out);
}

