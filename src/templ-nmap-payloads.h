/*
    Parses the "nmap-payloads" file.
 */
#ifndef TEMPL_NMAP_PAYLOADS_H
#define TEMPL_NMAP_PAYLOADS_H
#include <stdio.h>
struct PayloadsUDP;
struct RangeList;

typedef unsigned
(*payloads_datagram_add_cb)(struct PayloadsUDP *payloads,
                      const unsigned char *buf, size_t length,
                      struct RangeList *ports, unsigned source_port
                    );

void
read_nmap_payloads(FILE *fp, const char *filename,
                      struct PayloadsUDP *payloads,
                      payloads_datagram_add_cb add_payload
                      );

int
templ_nmap_selftest(void);

#endif
