/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PCAPFILE_H
#define __PCAPFILE_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <time.h>

struct PcapFile;


unsigned pcapfile_datalink(struct PcapFile *handle);

void pcapfile_writeframe(
    struct PcapFile *capfile,
    const void *buffer,
    unsigned buffer_size,
    unsigned original_length,
    unsigned time_sec,
    unsigned time_usec
    );

struct PcapFile *pcapfile_openread(const char *capfilename);
struct PcapFile *pcapfile_openwrite(const char *capfilename, unsigned linktype);
struct PcapFile *pcapfile_openappend(const char *capfilename, unsigned linktype);

unsigned pcapfile_percentdone(struct PcapFile *handle, uint64_t *r_bytes_read);

void pcapfile_get_timestamps(struct PcapFile *handle, time_t *start, time_t *end);

/**
 * Set a "maximum" size for a file. When the current file fills up with data,
 * it will close that file and open a new one, then continue to write
 * from that point on in the new file.
 */
void pcapfile_set_max(struct PcapFile *capfile, unsigned max_megabytes, unsigned max_files);

/**
 *  Read a single frame from the file.
 *  Returns 0 if failed to read (from error or end of file), and
 *  returns 1 if successful.
 */
int pcapfile_readframe(
    struct PcapFile *capfile,
    unsigned *r_time_secs,
    unsigned *r_time_usecs,
    unsigned *r_original_length,
    unsigned *r_captured_length,
    unsigned char *buf,
    unsigned sizeof_buf
    );


void pcapfile_close(struct PcapFile *handle);

#ifdef __cplusplus
}
#endif
#endif /*__PCAPFILE_H*/
