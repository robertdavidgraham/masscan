#include "read-service-probes.h"
#include "util-malloc.h"
#include "templ-port.h"
#include "unusedparm.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WIN32)
#pragma warning(disable:4996)
#define strncasecmp _strnicmp
#endif

/*****************************************************************************
 * Translate string name into enumerated type
 *****************************************************************************/
static enum SvcP_RecordType
parse_type(const char *line, size_t *r_offset, size_t line_length)
{
    static const struct {
        const char *name;
        size_t length;
        enum SvcP_RecordType type;
    } name_to_types[] = {
        {"exclude",      7, SvcP_Exclude},
        {"probe",        5, SvcP_Probe},
        {"match",        5, SvcP_Match},
        {"softmatch",    9, SvcP_Softmatch},
        {"ports",        5, SvcP_Ports},
        {"sslports",     8, SvcP_Sslports},
        {"totalwaitms", 11, SvcP_Totalwaitms},
        {"tcpwrappedms",12, SvcP_Tcpwrappedms},
        {"rarity",       6, SvcP_Rarity},
        {"fallback",     8, SvcP_Fallback},
        {0, SvcP_Unknown}
    };

    size_t i;
    size_t offset = *r_offset;
    size_t name_length;
    size_t name_offset;
    enum SvcP_RecordType result;
    
    /* find length of command name */
    name_offset = offset;
    while (offset < line_length && !isspace(line[offset]))
        offset++; /* name = all non-space chars until first space */
    name_length = offset - name_offset;
    while (offset < line_length && isspace(line[offset]))
        offset++; /* trim whitespace after name */
    *r_offset = offset;
    
    /* Lookup the command name */
    for (i=0; name_to_types[i].name; i++) {
        if (name_length != name_to_types[i].length)
            continue;
        if (strncasecmp(line+name_offset, name_to_types[i].name, name_length) == 0) {
            break;
        }
    }
    result = name_to_types[i].type;
    
    /* return the type */
    return result;
}

/*****************************************************************************
 *****************************************************************************/
static int
is_hexchar(int c)
{
    switch (c) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            return 1;
        default:
            return 0;
    }
}

/*****************************************************************************
 *****************************************************************************/
static unsigned
hexval(int c)
{
    switch (c) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return c - '0';
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            return c - 'a' + 10;
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            return c - 'A' + 10;
        default:
            return (unsigned)~0;
    }
}

/*****************************************************************************
 *****************************************************************************/
static struct RangeList
parse_ports(struct NmapServiceProbeList *list, const char *line, size_t offset, size_t line_length)
{
    /* Examples:
        Exclude 53,T:9100,U:30000-40000
        ports 21,43,110,113,199,505,540,1248,5432,30444
        ports 111,4045,32750-32810,38978
        sslports 443
     */
    unsigned is_error = 0;
    const char *p;
    struct RangeList ranges = {0};

    UNUSEDPARM(line_length);
    
    p = rangelist_parse_ports(&ranges, line + offset, &is_error, 0);
    
    if (is_error) {
        fprintf(stderr, "%s:%u:%u: bad port spec\n", list->filename, list->line_number, (unsigned)(p-line));
        rangelist_remove_all(&ranges);
    }
    
    return ranges;
}

/*****************************************************************************
 *****************************************************************************/
static unsigned
parse_number(struct NmapServiceProbeList *list, const char *line, size_t offset, size_t line_length)
{
    /* Examples:
     totalwaitms 6000
     tcpwrappedms 3000
     rarity 6
     */
    unsigned number = 0;
    
    while (offset < line_length && isdigit(line[offset])) {
        number = number * 10;
        number = number + (line[offset] - '0');
        offset++;
    }
    while (offset < line_length && isspace(line[offset]))
        offset++;
    
    if (offset != line_length) {
        fprintf(stderr, "%s:%u:%u: unexpected character '%c'\n", list->filename, list->line_number, (unsigned)offset, isprint(line[offset])?line[offset]:'.');
    }
    
    return number;
}


/*****************************************************************************
 *****************************************************************************/
static char *
parse_name(const char *line, size_t *r_offset, size_t line_length)
{
    size_t name_offset = *r_offset;
    size_t name_length;
    char *result;
    
    /* grab all characters until first space */
    while (*r_offset < line_length && !isspace(line[*r_offset]))
        (*r_offset)++;
    name_length = *r_offset - name_offset;
    if (name_length == 0)
        return 0;
    
    /* trim trailing white space */
    while (*r_offset < line_length && isspace(line[*r_offset]))
        (*r_offset)++;
    
    /* allocate result string */
    result = MALLOC(name_length+1);
    memcpy(result, line + name_offset, name_length+1);
    result[name_length] = '\0';
    
    return result;
}

/*****************************************************************************
 *****************************************************************************/
static struct ServiceProbeFallback *
parse_fallback(struct NmapServiceProbeList *list, const char *line, size_t offset, size_t line_length)
{
    /* Examples:
     fallback GetRequest,GenericLines
     */
    struct ServiceProbeFallback *result = 0;
    
    while (offset < line_length) {
        size_t name_offset;
        size_t name_length;
        struct ServiceProbeFallback *fallback;
        struct ServiceProbeFallback **r_fallback;
        
        /* grab all characters until first space */
        name_offset = offset;
        while (offset < line_length && !isspace(line[offset]) && line[offset] != ',')
            offset++;
        name_length = offset - name_offset;
        while (offset < line_length && (isspace(line[offset]) || line[offset] == ','))
            offset++; /* trim trailing whitespace */
        if (name_length == 0) {
            fprintf(stderr, "%s:%u:%u: name too short\n", list->filename, list->line_number, (unsigned)name_offset);
            break;
        }
        
        /* Alocate a record */
        fallback = CALLOC(1, sizeof(*fallback));
        
        fallback->name = MALLOC(name_length+1);
        memcpy(fallback->name, line+name_offset, name_length+1);
        fallback->name[name_length] = '\0';
        
        /* append to end of list */
        for (r_fallback=&result; *r_fallback; r_fallback = &(*r_fallback)->next)
            ;
        fallback->next = *r_fallback;
        *r_fallback = fallback;

    }
    
    return result;
}

/*****************************************************************************
 *****************************************************************************/
static void
parse_probe(struct NmapServiceProbeList *list, const char *line, size_t offset, size_t line_length)
{
    /* Examples:
     Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
     Probe UDP DNSStatusRequest q|\0\0\x10\0\0\0\0\0\0\0\0\0|
     Probe TCP NULL q||
     */
    const char *filename = list->filename;
    unsigned line_number = list->line_number;
    struct NmapServiceProbe *probe;
    
    /*
     * We have a new 'Probe', so append a blank record to the end of
     * our list
     */
    probe = CALLOC(1, sizeof(*probe));
    if (list->count + 1 >= list->max) {
        list->max = list->max * 2 + 1;
        list->list = REALLOCARRAY(list->list, sizeof(list->list[0]), list->max);
    }
    list->list[list->count++] = probe;
    
    /*
     * <protocol>
     */
    if (line_length - offset <= 3) {
        fprintf(stderr, "%s:%u:%u: line too short\n", filename, line_number, (unsigned)offset);
        goto parse_error;
    }
    if (memcmp(line+offset, "TCP", 3) == 0)
        probe->protocol = 6;
    else if (memcmp(line+offset, "UDP", 3) == 0)
        probe->protocol = 17;
    else {
        fprintf(stderr, "%s:%u:%u: unknown protocol\n", filename, line_number, (unsigned)offset);
        goto parse_error;
    }
    offset += 3;
    if (!isspace(line[offset])) {
        fprintf(stderr, "%s:%u:%u: unexpected character\n", filename, line_number, (unsigned)offset);
        goto parse_error;
    }
    while (offset < line_length && isspace(line[offset]))
        offset++;
    
    /*
     * <probename>
     */
    probe->name = parse_name(line, &offset, line_length);
    if (probe->name == 0) {
        fprintf(stderr, "%s:%u:%u: probename parse error\n", filename, line_number, (unsigned)offset);
        goto parse_error;
    }
    
    /*
     * <probestring>
     *  - must start with a 'q' character
     *  - a delimiter character starts/stop the string, typically '|'
     *  - Traditional C-style escapes work:
     *      \\ \0, \a, \b, \f, \n, \r, \t, \v, and \xXX
     */
    {
        char delimiter;
        char *x;
        size_t x_offset;
        
        if (line_length - offset <= 2) {
            fprintf(stderr, "%s:%u:%u: line too short\n", filename, line_number, (unsigned)offset);
            goto parse_error;
        }
        if (line[offset++] != 'q') {
            fprintf(stderr, "%s:%u:%u: expected 'q', found '%c'\n", filename, line_number, (unsigned)offset, isprint(line[offset-1])?line[offset-1]:'.');
            goto parse_error;
        }
        
        /* The next character is a 'delimiter' that starts and stops the next
         * string of characters, it it usually '|' but may be anything, like '/',
         * as long as the delimiter itself is not contained inside the string */
        delimiter = line[offset++];
        
        /* allocate a buffer at least as long as the remainder of the line. This is
         * probably too large, but cannot be too small. It's okay if we waste a
         * few characters. */
        x = CALLOC(1, line_length - offset + 1);
        probe->hellostring = x;
        
        /* Grab all the characters until the next delimiter, translating escaped
         * characters as needed */
        x_offset = 0;
        while (offset < line_length && line[offset] != delimiter) {
            
            /* Normal case: unescaped characters */
            if (line[offset] != '\\') {
                x[x_offset++] = line[offset++];
                continue;
            }
            
            /* skip escape character '\\' */
            offset++;
            if (offset >= line_length || line[offset] == delimiter) {
                fprintf(stderr, "%s:%u:%u: premature end of field\n", filename, line_number, (unsigned)offset);
                goto parse_error;
            }
            
            /* Handled escape sequence */
            switch (line[offset++]) {
                default:
                    fprintf(stderr, "%s:%u: %.*s\n", filename, line_number, (unsigned)line_length, line);
                    fprintf(stderr, "%s:%u:%u: unexpected escape character '%c'\n", filename, line_number, (unsigned)offset-1, isprint(line[offset-1])?line[offset-1]:'.');
                    goto parse_error;
                case '\\':
                    x[x_offset++] = '\\';
                    break;
                case '0':
                    x[x_offset++] = '\0';
                    break;
                case 'a':
                    x[x_offset++] = '\a';
                    break;
                case 'b':
                    x[x_offset++] = '\b';
                    break;
                case 'f':
                    x[x_offset++] = '\f';
                    break;
                case 'n':
                    x[x_offset++] = '\n';
                    break;
                case 'r':
                    x[x_offset++] = '\r';
                    break;
                case 't':
                    x[x_offset++] = '\t';
                    break;
                case 'v':
                    x[x_offset++] = '\v';
                    break;
                case 'x':
                    /* make sure at least 2 characters exist in input, either due
                     * to line-length or the delimiter */
                    if (offset + 2 >= line_length || line[offset+0] == delimiter || line[offset+1] == delimiter) {
                        fprintf(stderr, "%s:%u:%u: line too short\n", filename, line_number, (unsigned)offset);
                        goto parse_error;
                    }
                    
                    /* make sure those two characters are hex digits */
                    if (!is_hexchar(line[offset+0]) || !is_hexchar(line[offset+1])) {
                        fprintf(stderr, "%s:%u:%u: expected hex, found '%c%c'\n", filename, line_number, (unsigned)offset,
                                isprint(line[offset+1])?line[offset+1]:'.',
                                isprint(line[offset+2])?line[offset+2]:'.'
                                );
                        goto parse_error;
                    }
                    
                    /* parse those two hex digits */
                    x[x_offset++] = (char)(hexval(line[offset+0])<< 4 | hexval(line[offset+1]));
                    offset += 2;
                    break;
            }
        }
        probe->hellolength = x_offset;
        
        if (offset >= line_length || line[offset] != delimiter) {
            fprintf(stderr, "%s:%u:%u: missing end delimiter '%c'\n", filename, line_number, (unsigned)offset, isprint(delimiter)?delimiter:'.');
            goto parse_error;
        }
        //offset++;
    }

    
    return;
    
parse_error:
    if (probe->name != 0)
        free(probe->name);
    if (probe->hellostring != 0)
        free(probe->hellostring);
    probe->hellostring = 0;
    free(probe);
    list->count--;
}



/*****************************************************************************
 *****************************************************************************/
static struct ServiceProbeMatch *
parse_match(struct NmapServiceProbeList *list, const char *line, size_t offset, size_t line_length)
{
    /* Examples:
     match ftp m/^220.*Welcome to .*Pure-?FTPd (\d\S+\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/
     match ssh m/^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)\r?\n/i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
     match mysql m|^\x10\0\0\x01\xff\x13\x04Bad handshake$| p/MySQL/ cpe:/a:mysql:mysql/
     match chargen m|@ABCDEFGHIJKLMNOPQRSTUVWXYZ|
     match uucp m|^login: login: login: $| p/NetBSD uucpd/ o/NetBSD/ cpe:/o:netbsd:netbsd/a
     match printer m|^([\w-_.]+): lpd: Illegal service request\n$| p/lpd/ h/$1/
     match afs m|^[\d\D]{28}\s*(OpenAFS)([\d\.]{3}[^\s\0]*)\0| p/$1/ v/$2/
     */
    const char *filename = list->filename;
    unsigned line_number = list->line_number;
    struct ServiceProbeMatch *match;
    
    
    match = CALLOC(1, sizeof(*match));
    
    /*
     * <servicename>
     */
    match->service = parse_name(line, &offset, line_length);
    if (match->service == 0) {
        fprintf(stderr, "%s:%u:%u: servicename is empty\n", filename, line_number, (unsigned)offset);
        goto parse_error;
    }
    
    /*
     * <pattern>
     *  - must start with a 'm' character
     *  - a delimiter character starts/stop the string, tpyically '/' or '|'
     *  - contents are PCRE regex
     */
    {
        char delimiter;
        size_t regex_offset;
        size_t regex_length;
        
        /* line must start with 'm' */
        if (line_length - offset <= 2) {
            fprintf(stderr, "%s:%u:%u: line too short\n", filename, line_number, (unsigned)offset);
            goto parse_error;
        }
        if (line[offset] != 'm') {
            fprintf(stderr, "%s:%u:%u: expected 'm', found '%c'\n", filename, line_number, (unsigned)offset, isprint(line[offset])?line[offset]:'.');
            goto parse_error;
        }
        offset++;
        
        /* next character is the delimiter */
        delimiter = line[offset++];
        
        /* Find the length of the regex */
        regex_offset = offset;
        while (offset < line_length && line[offset] != delimiter)
            offset++;
        regex_length = offset - regex_offset;
        if (offset >= line_length || line[offset] != delimiter) {
            fprintf(stderr, "%s:%u:%u: missinged ending delimiter '%c'\n", filename, line_number, (unsigned)offset, isprint(delimiter)?delimiter:'.');
            goto parse_error;
        } else
            offset++;
        
        /* add regex pattern to record */
        match->regex_length = regex_length;
        match->regex = MALLOC(regex_length  + 1);
        memcpy(match->regex, line+regex_offset, regex_length + 1);
        match->regex[regex_length] = '\0';
        
        
        /* Verify the regex options characters */
        while (offset<line_length && !isspace(line[offset])) {
            switch (line[offset]) {
                case 'i':
                    match->is_case_insensitive = 1;
                    break;
                case 's':
                    match->is_include_newlines = 1;
                    break;
                default:
                    fprintf(stderr, "%s:%u:%u: unknown regex pattern option '%c'\n", filename, line_number, (unsigned)offset, isprint(line[offset])?line[offset]:'.');
                    goto parse_error;
            }
            offset++;
        }
        while (offset<line_length && isspace(line[offset]))
            offset++;
    }
    
    /*
     * <versioninfo>
     *  - several optional fields
     *  - each file starts with identifier (p v i h o d cpe:)
     *  - next comes the delimiter character (preferrably '/' slash)
     *  - next comes data
     *  - ends with delimiter
     */
    while (offset < line_length) {
        char id;
        char delimiter;
        size_t value_length;
        size_t value_offset;
        int is_a = 0;
        enum SvcV_InfoType type;
        
        /* Make sure we have enough characters for a versioninfo string */
        if (offset >= line_length)
            break;
        if (offset + 2 >= line_length) {
            fprintf(stderr, "%s:%u:%u: unexpected character at end of line '%c'\n", filename, line_number, (unsigned)offset, isprint(line[offset])?line[offset]:'.');
            goto parse_error;
        }
        
        /* grab the 'id' character, which is either singe letter or the string 'cpe:' */
        id = line[offset++];
        if (id == 'c') {
            if (offset + 3 >= line_length) {
                fprintf(stderr, "%s:%u:%u: unexpected character at end of line '%c'\n", filename, line_number, (unsigned)offset, isprint(line[offset])?line[offset]:'.');
                goto parse_error;
            }
            if (memcmp(line+offset, "pe:", 3) != 0) {
                fprintf(stderr, "%s:%u:%u: expected string 'cpe:'\n", filename, line_number, (unsigned)offset);
                goto parse_error;
            }
            offset += 3;
        }
        switch (id) {
            case 'p':
                type = SvcV_ProductName;
                break;
            case 'v':
                type = SvcV_Version;
                break;
            case 'i':
                type = SvcV_Info;
                break;
            case 'h':
                type = SvcV_Hostname;
                break;
            case 'o':
                type = SvcV_OperatingSystem;
                break;
            case 'd':
                type = SvcV_DeviceType;
                break;
            case 'c':
                type = SvcV_CpeName;
                break;
            default:
                fprintf(stderr, "%s:%u:%u: versioninfo unknown identifier '%c'\n", filename, line_number, (unsigned)offset, isprint(id)?id:'.');
                goto parse_error;
        }
        
        /* grab the delimiter */
        if (offset + 2 >= line_length) {
            fprintf(stderr, "%s:%u:%u: line too short\n", filename, line_number, (unsigned)offset);
            goto parse_error;
        }
        delimiter = line[offset++];
        
        /* Grab the contents of this string */
        value_offset = offset;
        while (offset < line_length && line[offset] != delimiter)
            offset++;
        value_length = offset - value_offset;
        if (offset >= line_length || line[offset] != delimiter) {
            fprintf(stderr, "%s:%u:%u: missinged ending delimiter '%c'\n", filename, line_number, (unsigned)offset, isprint(delimiter)?delimiter:'.');
            goto parse_error;
        } else
            offset++;
        if (id == 'c' && offset + 1 <= line_length && line[offset] == 'a') {
            is_a = 1;
            offset++;
        }
        if (offset < line_length && !isspace(line[offset])) {
            fprintf(stderr, "%s:%u:%u: unexpected character after delimiter '%c'\n", filename, line_number, (unsigned)offset, isprint(delimiter)?delimiter:'.');
            goto parse_error;
        }
        while (offset < line_length && isspace(line[offset]))
            offset++;

        /* Create a versioninfo record */
        {
            struct ServiceVersionInfo *v;
            struct ServiceVersionInfo **r_v;
            
            
            v = CALLOC(1, sizeof(*v));
            v->type = type;
            v->value = MALLOC(value_length + 1);
            memcpy(v->value, line+value_offset, value_length+1);
            v->value[value_length] = '\0';
            v->is_a = is_a;
            
            /* insert at end of list */
            for (r_v = &match->versioninfo; *r_v; r_v = &(*r_v)->next)
                ;
            v->next = *r_v;
            *r_v = v;
            
        }
        
    }
    
    return match;
    
parse_error:
    free(match->regex);
    free(match->service);
    while (match->versioninfo) {
        struct ServiceVersionInfo *v = match->versioninfo;
        match->versioninfo = v->next;
        if (v->value)
            free(v->value);
        free(v);
    }
    free(match);
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void
parse_line(struct NmapServiceProbeList *list, const char *line)
{
    const char *filename = list->filename;
    unsigned line_number = list->line_number;
    size_t line_length;
    size_t offset;
    enum SvcP_RecordType type;
    struct RangeList ranges = {0};
    struct NmapServiceProbe *probe;
    
    
    /* trim whitespace */
    offset = 0;
    line_length = strlen(line);
    while (offset && isspace(line[offset]))
        offset++;
    while (line_length && isspace(line[line_length-1]))
        line_length--;
    
    /* Ignore comment lines */
    if (ispunct(line[offset]))
        return;
    
    /* Ignore empty lines */
    if (offset >= line_length)
        return;
    
    /* parse the type field field */
    type = parse_type(line, &offset, line_length);
    
    /* parse the remainder of the line, depending upon the type */
    switch ((int)type) {
        case SvcP_Unknown:
            fprintf(stderr, "%s:%u:%u: unknown type: '%.*s'\n", filename, line_number, (unsigned)offset, (int)offset-0, line);
            return;
        case SvcP_Exclude:
            if (list->count) {
                /* The 'Exclude' directive is only valid at the top of the file,
                 * before any Probes */
                fprintf(stderr, "%s:%u:%u: 'Exclude' directive only valid before any 'Probe'\n", filename, line_number, (unsigned)offset);
            } else {
                ranges = parse_ports(list, line, offset, line_length);
                if (ranges.count == 0) {
                    fprintf(stderr, "%s:%u:%u: 'Exclude' bad format\n", filename, line_number, (unsigned)offset);
                } else {
                    rangelist_merge(&list->exclude, &ranges);
                    rangelist_remove_all(&ranges);
                }
            }
            return;
        case SvcP_Probe:
            /* Creates a new probe record, all the other types (except 'Exclude') operate
             * on the current probe reocrd */
            parse_probe(list, line, offset, line_length);
            return;
    }
    
    /*
     * The remaining items only work in the context of the current 'Probe'
     * directive
     */
    if (list->count == 0) {
        fprintf(stderr, "%s:%u:%u: 'directive only valid after a 'Probe'\n", filename, line_number, (unsigned)offset);
        return;
    }
    probe = list->list[list->count-1];
    
    switch ((int)type) {
        case SvcP_Ports:
            ranges = parse_ports(list, line, offset, line_length);
            if (ranges.count == 0) {
                fprintf(stderr, "%s:%u:%u: bad ports format\n", filename, line_number, (unsigned)offset);
            } else {
                rangelist_merge(&probe->ports, &ranges);
                rangelist_remove_all(&ranges);
            }
            break;
        case SvcP_Sslports:
            ranges = parse_ports(list, line, offset, line_length);
            if (ranges.count == 0) {
                fprintf(stderr, "%s:%u:%u: bad ports format\n", filename, line_number, (unsigned)offset);
            } else {
                rangelist_merge(&probe->sslports, &ranges);
                rangelist_remove_all(&ranges);
            }
            break;
        case SvcP_Match:
        case SvcP_Softmatch:
            {
                struct ServiceProbeMatch *match;
            
                match = parse_match(list, line, offset, line_length);
                if (match) {
                    struct ServiceProbeMatch **r_match;
                    
                    /* put at end of list */
                    for (r_match = &probe->match; *r_match; r_match = &(*r_match)->next)
                        ;
                    match->next = *r_match;
                    *r_match = match;
                    match->is_softmatch = (type == SvcP_Softmatch);
                }
            }
            break;
        
        case SvcP_Totalwaitms:
            probe->totalwaitms = parse_number(list, line, offset, line_length);
            break;
        case SvcP_Tcpwrappedms:
            probe->tcpwrappedms = parse_number(list, line, offset, line_length);
            break;
        case SvcP_Rarity:
            probe->rarity = parse_number(list, line, offset, line_length);
            break;
        case SvcP_Fallback:
        {
            struct ServiceProbeFallback *fallback;
            fallback = parse_fallback(list, line, offset, line_length);
            if (fallback) {
                fallback->next = probe->fallback;
                probe->fallback = fallback;
            }
        }
            break;
    }

}

/*****************************************************************************
 *****************************************************************************/
static struct NmapServiceProbeList *
nmapserviceprobes_new(const char *filename)
{
    struct NmapServiceProbeList *result;
    
    result = CALLOC(1, sizeof(*result));
    result->filename = filename;

    return result;
}

/*****************************************************************************
 *****************************************************************************/
struct NmapServiceProbeList *
nmapserviceprobes_read_file(const char *filename)
{
    FILE *fp;
    char line[32768];
    struct NmapServiceProbeList *result;
    
    /*
     * Open the file
     */
    fp = fopen(filename, "rt");
    if (fp == NULL) {
        perror(filename);
        return 0;
    }

    /*
     * Create the result structure
     */
    result = nmapserviceprobes_new(filename);
    
    /*
     * parse all lines in the text file
     */
    while (fgets(line, sizeof(line), fp)) {

        /* Track line number for error messages */
        result->line_number++;

        /* Parse this string into a record */
        parse_line(result, line);
    }
    
    fclose(fp);
    result->filename = 0; /* name no longer valid after this point */
    result->line_number = (unsigned)~0; /* line number no longer valid after this point */
    
    nmapserviceprobes_print(result, stdout);
    
    return result;
}

/*****************************************************************************
 *****************************************************************************/
static void
nmapserviceprobes_free_record(struct NmapServiceProbe *probe)
{
    if (probe->name)
        free(probe->name);
    if (probe->hellostring)
        free(probe->hellostring);
    rangelist_remove_all(&probe->ports);
    rangelist_remove_all(&probe->sslports);
    while (probe->match) {
        struct ServiceProbeMatch *match = probe->match;
        probe->match = match->next;
        free(match->regex);
        free(match->service);
        while (match->versioninfo) {
            struct ServiceVersionInfo *v = match->versioninfo;
            match->versioninfo = v->next;
            if (v->value)
                free(v->value);
            free(v);
        }
        free(match);
    }
    while (probe->fallback) {
        struct ServiceProbeFallback *fallback;
        
        fallback = probe->fallback;
        probe->fallback = fallback->next;
        if (fallback->name)
            free(fallback->name);
        free(fallback);
    }

    free(probe);
}

/*****************************************************************************
 *****************************************************************************/
static void
nmapserviceprobes_print_ports(const struct RangeList *ranges, FILE *fp, const char *prefix, int default_proto)
{
    unsigned i;
    
    /* don't print anything if no ports */
    if (ranges == NULL || ranges->count == 0)
        return;
    
    /* 'Exclude', 'ports', 'sslports' */
    fprintf(fp, "%s ", prefix);
    
    /* print all ports */
    for (i=0; i<ranges->count; i++) {
        int proto;
        int begin = ranges->list[i].begin;
        int end = ranges->list[i].end;
        
        if (Templ_TCP <= begin && begin < Templ_UDP)
            proto = Templ_TCP;
        else if (Templ_UDP <= begin && begin < Templ_SCTP)
            proto = Templ_UDP;
        else
            proto = Templ_SCTP;
        
        /* If UDP, shift down */
        begin -= proto;
        end -= proto;
        
        /* print comma between ports, but not for first port */
        if (i)
            fprintf(fp, ",");
        
        /* Print either one number for a single port, or two numbers for a range */
        if (default_proto != proto) {
            default_proto = proto;
            switch (proto) {
                case Templ_TCP: fprintf(fp, "T:"); break;
                case Templ_UDP: fprintf(fp, "U:"); break;
                case Templ_SCTP: fprintf(fp, "S"); break;
                case Templ_ICMP_echo: fprintf(fp, "e");  break;
                case Templ_ICMP_timestamp: fprintf(fp, "t");  break;
                case Templ_ARP: fprintf(fp, "A"); break;
                case Templ_VulnCheck: fprintf(fp, "v"); break;
            }
        }
        fprintf(fp, "%u", begin);
        if (end > begin)
            fprintf(fp, "-%u", end);
    }
    fprintf(fp, "\n");
}

/*****************************************************************************
 *****************************************************************************/
static int
contains_char(const char *string, size_t length, int c)
{
    size_t i;
    for (i=0; i<length; i++) {
        if (string[i] == c)
            return 1;
    }
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void
nmapserviceprobes_print_dstring(FILE *fp, const char *string, size_t length, int delimiter)
{
    size_t i;
    
    /* If the string contains the preferred delimiter, then choose a different
     * delimiter */
    if (contains_char(string, length, delimiter)) {
        static const char *delimiters = "|/\"'#*+-!@$%^&()_=";
        
        for (i=0; delimiters[i]; i++) {
            delimiter = delimiters[i];
            if (!contains_char(string, length, delimiter))
                break;
        }
    }
    
    /* print start delimiter */
    fprintf(fp, "%c", delimiter);
    
    /* print the string */
    for (i=0; i<length; i++) {
        char c = string[i];
        fprintf(fp, "%c", c);
    }
    
    /* print end delimiter */
    fprintf(fp, "%c", delimiter);
    
}
/*****************************************************************************
 *****************************************************************************/
static void
nmapserviceprobes_print_hello(FILE *fp, const char *string, size_t length, int delimiter)
{
    size_t i;
    
    /* If the string contains the preferred delimiter, then choose a different
     * delimiter */
    if (contains_char(string, length, delimiter)) {
        static const char *delimiters = "|/\"'#*+-!@$%^&()_=";
        
        for (i=0; delimiters[i]; i++) {
            delimiter = delimiters[i];
            if (!contains_char(string, length, delimiter))
                break;
        }
    }
    
    /* print start delimiter */
    fprintf(fp, "%c", delimiter);
    
    /* print the string */
    for (i=0; i<length; i++) {
        char c = string[i];
        
        switch (c) {
            case '\\':
                fprintf(fp, "\\\\");
                break;
            case '\0':
                fprintf(fp, "\\0");
                break;
            case '\a':
                fprintf(fp, "\\a");
                break;
            case '\b':
                fprintf(fp, "\\b");
                break;
            case '\f':
                fprintf(fp, "\\f");
                break;
            case '\n':
                fprintf(fp, "\\n");
                break;
            case '\r':
                fprintf(fp, "\\r");
                break;
            case '\t':
                fprintf(fp, "\\t");
                break;
            case '\v':
                fprintf(fp, "\\v");
                break;
            default:
                if (isprint(c))
                    fprintf(fp, "%c", c);
                else
                    fprintf(fp, "\\x%02x", ((unsigned)c)&0xFF);
                break;
                
        }
    }
    
    /* print end delimiter */
    fprintf(fp, "%c", delimiter);
    
}

/*****************************************************************************
 *****************************************************************************/
void
nmapserviceprobes_print(const struct NmapServiceProbeList *list, FILE *fp)
{
    unsigned i;
    if (list == NULL)
        return;
    
    nmapserviceprobes_print_ports(&list->exclude, fp, "Exclude", ~0);
    
    for (i=0; i<list->count; i++) {
        struct NmapServiceProbe *probe = list->list[i];
        struct ServiceProbeMatch *match;
        
        /* print the first part of the probe */
        fprintf(fp, "Probe %s %s q",
                (probe->protocol==6)?"TCP":"UDP",
                probe->name);
        
        /* preting the query/hello string */
        nmapserviceprobes_print_hello(fp, probe->hellostring, probe->hellolength, '|');
        
        fprintf(fp, "\n");
        if (probe->rarity)
            fprintf(fp, "rarity %u\n", probe->rarity);
        if (probe->totalwaitms)
            fprintf(fp, "totalwaitms %u\n", probe->totalwaitms);
        if (probe->tcpwrappedms)
            fprintf(fp, "tcpwrappedms %u\n", probe->tcpwrappedms);
        nmapserviceprobes_print_ports(&probe->ports, fp, "ports", (probe->protocol==6)?Templ_TCP:Templ_UDP);
        nmapserviceprobes_print_ports(&probe->sslports, fp, "sslports", (probe->protocol==6)?Templ_TCP:Templ_UDP);
        
        for (match=probe->match; match; match = match->next) {
            struct ServiceVersionInfo *vi;
            
            fprintf(fp, "match %s m", match->service);
            nmapserviceprobes_print_dstring(fp, match->regex, match->regex_length, '/');
            if (match->is_case_insensitive)
                fprintf(fp, "i");
            if (match->is_include_newlines)
                fprintf(fp, "s");
            fprintf(fp, " ");
            
            for (vi=match->versioninfo; vi; vi=vi->next) {
                const char *tag = "";
                switch (vi->type) {
                    case SvcV_Unknown:          tag = "u"; break;
                    case SvcV_ProductName:      tag = "p"; break;
                    case SvcV_Version:          tag = "v"; break;
                    case SvcV_Info:             tag = "i"; break;
                    case SvcV_Hostname:         tag = "h"; break;
                    case SvcV_OperatingSystem:  tag = "o"; break;
                    case SvcV_DeviceType:       tag = "e"; break;
                    case SvcV_CpeName:          tag = "cpe:"; break;
                }
                fprintf(fp, "%s", tag);
                nmapserviceprobes_print_dstring(fp, vi->value, strlen(vi->value), '/');
                if (vi->is_a)
                    fprintf(fp, "a");
                fprintf(fp, " ");
            }
            fprintf(fp, "\n");
        }
        
    }
}

/*****************************************************************************
 *****************************************************************************/
void
nmapserviceprobes_free(struct NmapServiceProbeList *list)
{
    unsigned i;
    
    if (list == NULL)
        return;
    
    for (i=0; list->count; i++) {
        nmapserviceprobes_free_record(list->list[i]);
    }
    
    if (list->list)
        free(list->list);
    free(list);
}

/*****************************************************************************
 *****************************************************************************/
int
nmapserviceprobes_selftest(void)
{
    const char *lines[] = {
        "Exclude 53,T:9100,U:30000-40000\n",
        "Probe UDP DNSStatusRequest q|\\0\\0\\x10\\0\\0\\0\\0\\0\\0\\0\\0\\0|\n",
        "Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|\n",
        "ports 80\n",
        "sslports 443\n",
        "Probe TCP NULL q||\n",
        "ports 21,43,110,113,199,505,540,1248,5432,30444\n",
        "match ftp m/^220.*Welcome to .*Pure-?FTPd (\\d\\S+\\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/\n",
        "match ssh m/^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)\\r?\\n/i p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/\n",
        "match mysql m|^\\x10\\0\\0\\x01\\xff\\x13\\x04Bad handshake$| p/MySQL/ cpe:/a:mysql:mysql/\n",
        "match chargen m|@ABCDEFGHIJKLMNOPQRSTUVWXYZ|\n",
        "match uucp m|^login: login: login: $| p/NetBSD uucpd/ o/NetBSD/ cpe:/o:netbsd:netbsd/a\n",
        "match printer m|^([\\w-_.]+): lpd: Illegal service request\\n$| p/lpd/ h/$1/\n",
        "match afs m|^[\\d\\D]{28}\\s*(OpenAFS)([\\d\\.]{3}[^\\s\\0]*)\\0| p/$1/ v/$2/\n",
        0
    };
    unsigned i;
    struct NmapServiceProbeList *list = nmapserviceprobes_new("<selftest>");
    
    for (i=0; lines[i]; i++) {
        list->line_number = i;
        parse_line(list, lines[i]);
    }
    
    //nmapserviceprobes_print(list, stdout);
    return 0;
}


