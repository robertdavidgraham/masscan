#include "script.h"
#include "string_s.h"

extern struct MassScript script_ntp_monlist;


struct MassScript *
script_lookup(const char *name)
{
    if (strcmp(name, script_ntp_monlist.name) == 0)
        return &script_ntp_monlist;
    return 0;
}

