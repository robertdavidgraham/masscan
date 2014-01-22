#include "masscan-app.h"
#include "string_s.h"

/***************************************************************************
 ***************************************************************************/
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
    case PROTO_FTP1: return "ftp";
    case PROTO_FTP2: return "ftp";
    case PROTO_DNS_VERSIONBIND: return "dns-ver";
    case PROTO_SNMP: return "snmp";
    case PROTO_NBTSTAT: return "nbtstat";
    case PROTO_SSL3:    return "ssl";
    case PROTO_SMTP:    return "smtp";
    case PROTO_POP3:    return "pop";
    case PROTO_IMAP4:   return "imap";
    case PROTO_UDP_ZEROACCESS: return "zeroaccess";
    case PROTO_X509_CERT: return "X509";
    case PROTO_HTML_TITLE: return "title";
    case PROTO_HTML_FULL: return "html";
    case PROTO_NTP:     return "ntp";
    default:
        sprintf_s(tmp, sizeof(tmp), "(%u)", proto);
        return tmp;
    }
}
