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

#include <limits.h>

#if defined(WIN32)
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#define access _access
#elif defined(__linux__)
#include <unistd.h>
#endif

extern unsigned control_c_pressed;
struct Output
{
    struct Masscan *masscan;
    FILE *fp;
    time_t next_rotate;
    time_t last_rotate;
    unsigned period;
    unsigned offset;
    uint64_t open_count;
    uint64_t closed_count;
};


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
    struct Masscan *masscan = output->masscan;
    unsigned is_append =masscan->nmap.append;

#if defined(WIN32)
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
        perror(filename);
        control_c_pressed = 1;
        return NULL;
    }

    switch (masscan->nmap.format) {
    case Output_List:
        fprintf(fp, "#masscan\n");
        break;
    case Output_XML:
        fprintf(fp, "<?xml version=\"1.0\"?>\r\n");
        fprintf(fp, "<!-- masscan v1.0 scan -->\r\n");
        if (masscan->nmap.stylesheet[0]) {
            fprintf(fp, "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\r\n",
                masscan->nmap.stylesheet);
        }
        fprintf(fp, "<nmaprun scanner=\"%s\" start=\"%u\" version=\"%s\"  xmloutputversion=\"%s\">\r\n",
            "masscan",
            (unsigned)time(0),
            "1.0-BETA",
            "1.03" /* xml output version I copied from their site */
            );
        fprintf(fp, "<scaninfo type=\"%s\" protocol=\"%s\" />\r\n",
            "syn", "tcp" );
        break;
    }

    return fp;
}


/***************************************************************************
 ***************************************************************************/
static void
close_rotate(struct Output *out, FILE *fp)
{
    char buffer[256];
    time_t now = time(0);
    struct tm tm;
 
    localtime_s(&tm, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    
    if (out == NULL)
        return;
    if (fp == NULL)
        return;

    switch (out->masscan->nmap.format) {
    case Output_List:
        fprintf(fp, "# end\n");
        break;
    case Output_XML:
        /*
        */
        fprintf(fp,
            "<runstats>\r\n"
              "<finished time=\"%u\" timestr=\"%s\" elapsed=\"%u\" />\r\n"
              "<hosts up=\"%llu\" down=\"%llu\" total=\"%llu\" />\r\n"
            "</runstats>\r\n"
            "</nmaprun>\r\n",
        now,                    /* time */
        buffer,                 /* timestr */
        now - out->last_rotate, /* elapsed */
        out->open_count,
        out->closed_count,
        out->open_count + out->closed_count
        );
        break;
    }

    out->open_count = 0;
    out->closed_count = 0;
    out->last_rotate = time(0);

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
struct Output *
output_create(struct Masscan *masscan)
{
    struct Output *out;

    out = (struct Output *)malloc(sizeof(*out));
    if (out == NULL)
        return NULL;
    memset(out, 0, sizeof(*out));

    out->masscan = masscan;
    out->period = masscan->rotate_output;
    out->offset = masscan->rotate_offset;


    /*
     * Open the desired output file
     */
    if (masscan->nmap.format != Output_Interactive && masscan->nmap.filename[0]) {
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
void
output_destroy(struct Output *out)
{
    if (out == NULL)
        return;
    if (out->fp)
        close_rotate(out, out->fp);

    free(out);
}

/***************************************************************************
 ***************************************************************************/
static const char *
status_string(int x)
{
    switch (x) {
    case Port_Open: return "open";
    case Port_Closed: return "closed";
    default: return "unknown";
    }
}
static const char *
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
 ***************************************************************************/

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

/***************************************************************************
 ***************************************************************************/
void 
output_report(struct Output *out, int status, unsigned ip, unsigned port, unsigned reason, unsigned ttl)
{
    struct Masscan *masscan = out->masscan;
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;


    if (masscan->nmap.format == Output_Interactive || masscan->nmap.format == Output_All) {
        fprintf(stdout, "Discovered %s port %u/tcp on %u.%u.%u.%u                          \n",
            status_string(status),
            port,
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
        out->open_count++;
        break;
    case Port_Closed:
        out->closed_count++;
        break;
    }

    if (masscan->nmap.format == Output_List || masscan->nmap.format == Output_All) {
        fprintf(fp, "%s tcp %u %u.%u.%u.%u %u\n",
            status_string(status),
            port,
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            (unsigned)global_now
            );
    }
    if (masscan->nmap.format == Output_XML || masscan->nmap.format == Output_All) {
        char reason_buffer[128];
        fprintf(fp, "<host endtime=\"%u\">"
                     "<ports>"
                      "<port protocol=\"tcp\" portid=\"%u\">"
                       "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%u\"/>"
                      "</port>"
                     "</ports>"
                    "</host>"  
                    "\r\n",
            (unsigned)global_now,
            port,
            status_string(status),
            reason_string(reason, reason_buffer, sizeof(reason_buffer)),
            ttl,
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            (unsigned)global_now
            );
    }

}

