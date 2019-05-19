#include "masscan-app.h"
#include "string_s.h"

/******************************************************************************
 * When outputing results, we call this function to print out the type of 
 * banner that we've collected
 ******************************************************************************/
const char *
masscan_app_to_string(enum ApplicationProtocol proto)
{
    static char tmp[64];

    switch (proto) {
    case PROTO_NONE: return "unknown";
    case PROTO_HEUR: return "unknown";
    case PROTO_SSH1: return "ssh";
    case PROTO_SSH2: return "ssh";
    case PROTO_HTTP: return "http";
    case PROTO_FTP: return "ftp";
    case PROTO_DNS_VERSIONBIND: return "dns-ver";
    case PROTO_SNMP: return "snmp";
    case PROTO_NBTSTAT: return "nbtstat";
    case PROTO_SSL3:    return "ssl";
    case PROTO_SMB:     return "smb";
    case PROTO_SMTP:    return "smtp";
    case PROTO_POP3:    return "pop";
    case PROTO_IMAP4:   return "imap";
    case PROTO_UDP_ZEROACCESS: return "zeroaccess";
    case PROTO_X509_CERT: return "X509";
    case PROTO_HTML_TITLE: return "title";
    case PROTO_HTML_FULL: return "html";
    case PROTO_NTP:     return "ntp";
    case PROTO_VULN:    return "vuln";
    case PROTO_HEARTBLEED:    return "heartbleed";
    case PROTO_TICKETBLEED:    return "ticketbleed";
    case PROTO_VNC_RFB: return "vnc";
    case PROTO_SAFE:    return "safe";
    case PROTO_MEMCACHED: return "memcached";
    case PROTO_SCRIPTING:      return "scripting";
    case PROTO_VERSIONING:     return "versioning";
    case PROTO_COAP:           return "coap";
    case PROTO_TELNET:         return "telnet";
    case PROTO_RDP:            return "rdp";
            
    default:
        sprintf_s(tmp, sizeof(tmp), "(%u)", proto);
        return tmp;
    }
}

/******************************************************************************
 ******************************************************************************/
enum ApplicationProtocol
masscan_string_to_app(const char *str)
{
    const static struct {
        const char *name;
        enum ApplicationProtocol value;
    } list[] = {
        {"ssh1",    PROTO_SSH1},
        {"ssh2",    PROTO_SSH2},
        {"ssh",     PROTO_SSH2},
        {"http",    PROTO_HTTP},
        {"ftp",     PROTO_FTP},
        {"dns-ver", PROTO_DNS_VERSIONBIND},
        {"snmp",    PROTO_SNMP},
        {"ssh2",    PROTO_SSH2},
        {"nbtstat", PROTO_NBTSTAT},
        {"ssl",     PROTO_SSL3},
        {"smtp",    PROTO_SMTP},
        {"smb",     PROTO_SMB},
        {"pop",     PROTO_POP3},
        {"imap",    PROTO_IMAP4},
        {"x509",    PROTO_X509_CERT},
        {"zeroaccess",  PROTO_UDP_ZEROACCESS},
        {"title",       PROTO_HTML_TITLE},
        {"html",        PROTO_HTML_FULL},
        {"ntp",         PROTO_NTP},
        {"vuln",        PROTO_VULN},
        {"heartbleed",  PROTO_HEARTBLEED},
        {"ticketbleed", PROTO_TICKETBLEED},
        {"vnc",         PROTO_VNC_RFB},
        {"safe",        PROTO_SAFE},
        {"memcached",   PROTO_MEMCACHED},
        {"scripting",   PROTO_SCRIPTING},
        {"versioning",  PROTO_VERSIONING},
        {"coap",        PROTO_COAP},
        {"telnet",      PROTO_TELNET},
        {"rdp",         PROTO_RDP},
        {0,0}
    };
    size_t i;
    
    for (i=0; list[i].name; i++) {
        if (strcmp(str, list[i].name) == 0)
            return list[i].value;
    }
    return 0;
}
