/*
    Reads the 'nmap-service-probes' file.
 */
#ifndef READ_SERVICE_PROBES_H
#define READ_SERVICE_PROBES_H
#include <stdio.h>
#include "ranges.h"

/*
 Exclude <port specification>
 Probe <protocol> <probename> <probestring>
 match <service> <pattern> [<versioninfo>]
 softmatch <service> <pattern>
 ports <portlist>
 sslports <portlist>
 totalwaitms <milliseconds>
 tcpwrappedms <milliseconds>
 rarity <value between 1 and 9>
 fallback <Comma separated list of probes>
 */
enum SvcP_RecordType {
    SvcP_Unknown,
    SvcP_Exclude,
    SvcP_Probe,
    SvcP_Match,
    SvcP_Softmatch,
    SvcP_Ports,
    SvcP_Sslports,
    SvcP_Totalwaitms,
    SvcP_Tcpwrappedms,
    SvcP_Rarity,
    SvcP_Fallback,
};

enum SvcV_InfoType {
    SvcV_Unknown,
    SvcV_ProductName,
    SvcV_Version,
    SvcV_Info,
    SvcV_Hostname,
    SvcV_OperatingSystem,
    SvcV_DeviceType,
    SvcV_CpeName,
};

struct ServiceVersionInfo {
    enum SvcV_InfoType type;
    char *value;
    struct ServiceVersionInfo *next;
    unsigned is_a:1;
};

struct ServiceProbeFallback {
    char *name;
    struct ServiceProbeFallback *next;
};

struct ServiceProbeMatch {
    struct ServiceProbeMatch *next;
    char *service;
    char *regex;
    struct ServiceVersionInfo *versioninfo;
    unsigned is_case_insensitive:1;
    unsigned is_include_newlines:1;
    unsigned is_softmatch:1;
};

struct NmapServiceProbe {
    char *name;
    char *hellostring;
    size_t hellolength;
    unsigned protocol;
    unsigned totalwaitms;
    unsigned tcpwrappedms;
    unsigned rarity;
    struct RangeList ports;
    struct RangeList sslports;
    struct ServiceProbeMatch *match;
    struct ServiceProbeFallback *fallback;
};

struct NmapServiceProbeList {
    struct NmapServiceProbe **list;
    struct RangeList exclude;
    unsigned count;
    unsigned max;
    const char *filename;
    unsigned line_number;
};


struct NmapServiceProbeList *
nmapserviceprobes_read_file(const char *filename);

void
nmapserviceprobes_free(struct NmapServiceProbeList *service_probes);

int
nmapserviceprobes_selftest(void);

/**
 * Print to a file for testing purposes
 */
void
nmapserviceprobes_print(const struct NmapServiceProbeList *list, FILE *fp);

#endif

