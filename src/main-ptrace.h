#ifndef masscan_main_ptrace_h
#define masscan_main_ptrace_h
#include <stdio.h>
#include <stdint.h>

extern double global_timestamp_start;

void packet_trace(FILE *fp, const unsigned char *px, size_t length, unsigned is_sent);


#endif
