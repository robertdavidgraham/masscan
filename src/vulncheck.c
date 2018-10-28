#include "vulncheck.h"
#include "string_s.h"

extern struct MassVulnCheck vuln_ntp_monlist;


struct MassVulnCheck *
vulncheck_lookup(const char *name)
{
    if (strcmp(name, vuln_ntp_monlist.name) == 0)
        return &vuln_ntp_monlist;
    return 0;
}

