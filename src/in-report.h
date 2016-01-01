#ifndef IN_REPORT_H
#define IN_REPORT_H
#include <stdio.h>

void
readscan_report(  unsigned ip,
                  unsigned app_proto,
                  unsigned char **data,
                  size_t *data_length);

void
readscan_report_init(void);

void
readscan_report_print(void);




#endif
