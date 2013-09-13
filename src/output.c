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

#include <limits.h>
#include <ctype.h>

#if defined(WIN32)
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#define access _access
#else
#include <unistd.h>
#endif

extern unsigned control_c_pressed;


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
        default: return "unknown";
    }
}
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

const char *
proto_string(unsigned proto)
{
    static char tmp[64];
    switch (proto) {
    case PROTO_SSH1: return "ssh";
    case PROTO_SSH2: return "ssh";
    case PROTO_HTTP: return "http";
    case PROTO_FTP1: return "ftp";
    case PROTO_FTP2: return "ftp";
    default:
        sprintf_s(tmp, sizeof(tmp), "(%u)", proto);
        return tmp;
    }
}
const char *
normalize_string(const unsigned char *px, size_t length, char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;

    for (i=0; i<length; i++) {

        if (isprint(px[i]) && px[i] != '<' && px[i] != '>' && px[i] != '&' && px[i] != '\\') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 5 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'x';
                buf[offset++] = "0123456789abdef"[px[i]>>4];
                buf[offset++] = "0123456789abdef"[px[i]>>0];
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
FILE *
open_rotate(struct Output *output, const char *filename)
{
    FILE *fp;
    const struct Masscan *masscan = output->masscan;
    unsigned is_append =masscan->nmap.append;

#if defined(WIN32)
    /* PORTABILITY: WINDOWS
     *  This bit of code deals with the fact that on Windows, fopen() opens
     *  a file so that it can't be moved. This code opens it a different
     *  way so that we can move it.
     *
     * NOTE: this is probably overkill, it appears that there is a better
     * API _fsopen() that does what I want without all this nonsense.
     */
    HANDLE hFile;
    int fd;

    /* The normal POSIX C functions lock the file */
    /* int fd = open(filename, O_RDWR | O_CREAT, _S_IREAD | _S_IWRITE); */ /* Fails */
    /* int fd = _sopen(filename, O_RDWR | O_CREAT, _SH_DENYNO, _S_IREAD | _S_IWRITE); */ /* Also fails */

    /* We need to use WINAPI + _open_osfhandle to be able to use
       file descriptors (instead of WINAPI handles) */
    hFile = CreateFileA(    filename,
                            GENERIC_WRITE | (is_append?FILE_APPEND_DATA:0),
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY,
                            NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        control_c_pressed = 1;
        return NULL;
    }

    fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_RDONLY | _O_TEMPORARY);
    if (fd == -1) {
        perror("_open_osfhandle");
        control_c_pressed = 1;
        return NULL;
    }

    fp = _fdopen(fd, "w");


#else
    fp = fopen(filename, is_append?"a":"w");
#endif

    if (fp == NULL) {
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
int
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

    for (i=0; i<8; i++) {
        out->nics[i].ip_me = masscan->nic[i].adapter_ip;
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
FILE *
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
    sprintf_s(new_filename, new_filename_size, "%s/%02u%02u%02u-%02u%02u%02u" "-%s",
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

const char *
proto_from_status(unsigned status)
{
    switch (status) {
        case Port_Open: return "tcp";
        case Port_Closed: return "tcp";
        case Port_IcmpEchoResponse: return "icmp";
        case Port_UdpOpen: return "udp";
        case Port_UdpClosed: return "udp";
        default: return "err";
    }
}
/***************************************************************************
 ***************************************************************************/
void
output_report_status(struct Output *out, int status, 
        unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    const struct Masscan *masscan = out->masscan;
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;


    if (masscan->is_interactive || fp == NULL) {
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
        default:
            LOG(0, "unknown status type: %u\n", status);
            if (masscan->nmap.open_only)
                return;
    }

    out->funcs->status(out, fp, status, ip, port, reason, ttl);

}

/***************************************************************************
 ***************************************************************************/
void
output_report_banner(struct Output *out, unsigned ip, unsigned port,
                unsigned proto, const unsigned char *px, unsigned length)
{
    const struct Masscan *masscan = out->masscan;
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;


    if (masscan->is_interactive || fp == NULL) {
        unsigned count;
        count = fprintf(stdout, "Banner on port %u/tcp on %u.%u.%u.%u: %.*s",
            port,
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            length, px
            );
        if (count < 80)
            fprintf(stdout, "%.*s\n", (size_t)(79-count),
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

    out->funcs->banner(out, fp, ip, port, proto, px, length);

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

