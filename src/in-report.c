#include "in-report.h"
#include "masscan-app.h"
#include "crypto-base64.h"
#include "proto-x509.h"
#include "proto-banout.h"
#include "smack.h"
#include "util-malloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct CNDB_Entry {
    unsigned ip;
    char *name;
    struct CNDB_Entry *next;
};

struct CNDB_Database {
    struct CNDB_Entry *entries[65536];
};

/***************************************************************************
 ***************************************************************************/
static struct CNDB_Database *db = NULL;

/***************************************************************************
 ***************************************************************************/
static const char *
cndb_lookup(unsigned ip)
{
    const struct CNDB_Entry *entry;
    
    if (db == NULL)
        return 0;

    entry = db->entries[ip&0xFFFF];
    while (entry && entry->ip != ip)
        entry = entry->next;
    if (entry)
        return entry->name;
    else {
        return 0;
    }
}

/***************************************************************************
 ***************************************************************************/
static void
cndb_add(unsigned ip, const unsigned char *name, size_t name_length)
{
    struct CNDB_Entry *entry;

    if (name_length == 0)
        return;
    
    if (db == NULL) {
        db = CALLOC(1, sizeof(*db));
    }
        
    entry = MALLOC(sizeof(*entry));
    entry->ip =ip;
    entry->name = MALLOC(name_length+1);
    memcpy(entry->name, name, name_length+1);
    entry->name[name_length] = '\0';
    entry->next = db->entries[ip&0xFFFF];
    db->entries[ip&0xFFFF] = entry;

}

/***************************************************************************
 ***************************************************************************/
#if 0
static void
cndb_add_cn(unsigned ip, const unsigned char *data, size_t length)
{
    size_t offset = 0;
    size_t name_offset;
    size_t name_length;
    
    if (length < 7)
        return;
    
    /*cipher:0x39 , safe-we1.dyndns.org*/
    if (memcmp(data+offset, "cipher:", 7) != 0)
        return;
    offset += 7;
    
    /* skip to name */
    while (offset < length && data[offset] != ',')
        offset++;
    if (offset >= length)
        return;
    else
        offset++; /* skip ',' */
    while (offset < length && data[offset] == ' ')
        offset++;
    if (offset >= length)
        return;
    
    /* we should have a good name */
    name_offset = offset;
    while (offset < length && data[offset] != ',')
        offset++;
    name_length = offset - name_offset;
    
    /* now insert into database */
    cndb_add(ip, data+name_offset, name_length);
}
#endif

/***************************************************************************
 ***************************************************************************/
#if 0
static unsigned
found(const char *str, size_t str_len, const unsigned char *p, size_t length)
{
    size_t i;
  
    if (str_len > length)
        return 0;

    for (i=0; i<length; i++) {
        if (str[0] == p[i] && memcmp(str, p+i, str_len) == 0)
            return 1;
    }
    return 0;
}
#endif

enum {
    XUnknown,
    XNas,
    XWiFi,
    XFW,
    X509,
    XCom,
    XVM,
    XCam,
    XVPN,
    XPBX,
    Xprint,
    Xdefault,
    XMail,
    Xadmin,
    Xav,
    Xpot,
    Xbox,

    Xend
};

unsigned counts[32];

static void
print_counts()
{
    unsigned i;
    const char *count_names[] = {
        "Unknown", "NAS", "WiFi", "FW", "X509",
        "Conf", "VM", "Cam", "VPN", "PBX", "Printer",
        "default", "mail", "admin", "AV", "honeypot", "box",
        0, "", "", ""};

    printf("----counts----\n");
    for (i=0; i<Xend; i++) {
        printf("%10u %s\n", counts[i], count_names[i]);
    }
    printf("---------------\n");

    assert(count_names[i] == NULL);
}

struct Names {
    unsigned code;
    unsigned length;
    const char *name;

} mynames[] = {

/* raspberry pi */
/* issuer[Debian */

    
    
    


    {XNas,   9, "nasend~~]"},
    {XPBX,  13, "issuer[iPECS]"},
    {Xav,   13, "issuer[McAfee"},
    {Xadmin,14, "issuer[webmin]"},
    {Xadmin,14, "issuer[Webmin "},
    {Xprint,15, "subject[HP-IPG]"},
    {XNas,  16, "issuer[LaCie SA]"},
    {XWiFi, 16, "subject[OpenWrt]"},
    {Xadmin,16, "issuer[Puppet CA"},
    {Xav,   16, "issuer[Kaspersky"},
    {XFW,   17, "subject[Fortinet]"},
    {XFW,   17, "issuer[ICC-FW CA]"},
    {XCam,  17, "issuer[HIKVISION]"}, 
    {Xprint,17, "subject[SHARP MX-"},
    {X509,  18, "issuer[GANDI SAS]"},
    {XFW,   18, "subject[FortiGate]"},
    {XFW,   18, "issuer[watchguard]"},
    {XVM,   18, "issuer[VMware Inc]"}, 
    {Xbox,  19, "issuer[eBox Server]"},
    {XFW,   19, "subject[WatchGuard]"}, 
    {X509,  19, "issuer[RapidSSL CA]"},
    {X509,  19, "issuer[AddTrust AB]"},
    {XCom,  19, "issuer[Cisco SSCA2]"},
    {XCom,  19, "subject[Cisco SSCA2]"},
   {Xdefault,19,"issuer[v] issuer[v]"},
    {X509,  20, "issuer[Register.com]"},
    {X509,  20, "issuer[Thawte, Inc.]"},
    {X509,  20, "issuer[thawte, Inc.]"},
    {XMail, 20, "issuer[EQ-MT-RAPTOR]"},
    {X509,  20, "issuer[DigiCert Inc]"},
    {X509,  21, "issuer[TERENA SSL CA]"},
    {XFW,   21, "issuer[WatchGuard CA]"},  
    {XVPN,  21, "issuer[OpenVPN Web CA"},
    {X509,  21, "issuer[GeoTrust Inc.]"},
    {XNas,  21, "issuer[TS Series NAS]"},
    {XCom,  21, "subject[Polycom Inc.]"},
    {XFW,   21, "issuer[Fortinet Ltd.]"},
    {XNas,  21, "issuer[Synology Inc.]"},
   {Xdefault,21,"issuer[XX] issuer[XX]"},
    {XWiFi, 21, "2Wire]Gateway Device]"},
    {X509,  21, "subject[DigiCert Inc]"},
    {XCam,  22, "issuer[SamsungTechwin]"}, 
    {X509,  22, "issuer[TAIWAN-CA INC.]"},
    {X509,  22, "issuer[GeoTrust, Inc.]"},    
    {X509,  22, "issuer[ValiCert, Inc.]"},
    {0,     22, "issuer[Apache Friends]"},
    {X509,  22, "issuer[VeriSign, Inc.]"},
    {X509,  22, "issuer[Cybertrust Inc]"},
    {XCam,  23, "subject[HiTRON SYSTEMS]"},
    {XFW,   23, "issuer[SonicWALL, Inc.]"},
    {XFW,   23, "issuer[Future Systems.]"},
    {XCom,  23, "issuer[Polycom Root CA]"},
    {X509,  24, "issuer[AlphaSSL CA - G2]"},
    {X509,  24, "issuer[GlobalSign nv-sa]"},
    {XVPN,  24, "SonicWALL, Inc.]SSL-VPN]"},
    {X509,  25, "issuer[Comodo CA Limited]"},
    {X509,  25, "issuer[COMODO CA Limited]"},    
    {X509,  25, "issuer[GoDaddy.com, Inc.]"},
    {Xbox,  26, "subject[Barracuda Networks]"},
    {X509,  26, "issuer[Equifax Secure Inc.]"},
    {X509,  28, "issuer[Gandi Standard SSL CA]"},
    {X509,  28, "issuer[The USERTRUST Network]"},
    {XCom,  28, "subject[Polycom] subject[VSG]"},
    {X509,  28, "issuer[EuropeanSSL Server CA]"},
    {0,     28, "issuer[SuSE Linux Web Server]"},
    {XWiFi, 29, "issuer[CradlePoint Technology]"},
    {XVPN,  29, "SonicWALL]Secure Remote Access]"},
    {Xdefault,29,"subject[SomeOrganizationalUnit]"},
    {Xdefault,29,"issuer[Internet Widgits Pty Ltd]"},
    {X509,  30, "issuer[Network Solutions L.L.C.]"},
    {X509,  30, "issuer[The Go Daddy Group, Inc.]"},
    {Xpot,  30, "issuer[Nepenthes Development Team]"},
    {X509,  30, "issuer[WoSign Class 1 DV Server CA]"},
    {XCom,  30, "issuer[Polycom Equipment Policy CA]"},
    {X509,  30, "issuer[Starfield Technologies, Inc.]"},
    {X509,  30, "issuer[Certum Certification Authority]"},
    {XNas,  30, "subject[Fujitsu CELVIN(R) NAS Server]"},
    {XVPN,  35, "SonicWALL, Inc.]Secure Remote Access]"},
    {X509,  40, "issuer[Secure Digital Certificate Signing]"},
    {X509,  40, "issuer[Equifax Secure Certificate Authority]"},
    {XVM,   40, "subject[VMware ESX Server Default Certificate]"}, 
    {XCam,  40, "issuer[Cisco Systems] issuer[Cisco Manufacturing CA]"},
    {0,0, 0}
};

static struct SMACK *global_xnames;
static void
xname_init(void)
{
    unsigned i;

    global_xnames = smack_create("readscan-x509-names", 0);

    for (i=0; mynames[i].name; i++) {
        const char *pattern = mynames[i].name;
        unsigned len = mynames[i].length;
        unsigned id = mynames[i].code;


        smack_add_pattern(  global_xnames,
                            pattern,
                            len,
                            id,
                            0
                            );
    }

    smack_compile(global_xnames);

}

/***************************************************************************
 ***************************************************************************/
static unsigned
found_type(const unsigned char *banner, size_t banner_length)
{
    size_t id;
    unsigned state = 0;
    unsigned offset = 0;

    /*for (i=0; mynames[i].name; i++) {
        if (found(mynames[i].name, mynames[i].length, banner, banner_length))
            return 1;
    }*/

    id = smack_search_next( global_xnames,
                                        &state,
                                        banner,
                                        &offset,
                                        (unsigned)banner_length);
    if (id == SMACK_NOT_FOUND)
        return 0;
    
    counts[id]++;

    return 1;
}

void
readscan_report(  unsigned ip,
                  unsigned app_proto,
                  unsigned char **r_data,
                  size_t *r_data_length)
{
    size_t data_length = *r_data_length;
    unsigned char *data = *r_data;


    if (app_proto == PROTO_X509_CERT) {
        unsigned char *der = MALLOC(data_length);
        struct CertDecode x;
        size_t der_length;
        struct BannerOutput banout[1];
        const unsigned char *banner;
        size_t banner_length;

        banout_init(banout);

        der_length = base64_decode(der, data_length, data, data_length);
        
        x509_decode_init(&x, data_length);
        x.is_capture_issuer = 1;
        x.is_capture_subject = 1;
        x509_decode(&x, der, der_length, banout);

        banner = banout_string(banout, PROTO_SSL3);
        banner_length = banout_string_length(banout, PROTO_SSL3);

        if (banner_length) {
            if (!found_type(banner, banner_length))
                cndb_add(ip, banner, banner_length);
        }

        banout_release(banout);
    /*} else if (0 && app_proto == PROTO_SSL3) {
        cndb_add(ip, data, data_length);*/
    } else if (app_proto == PROTO_VULN) {
        const char *name = cndb_lookup(ip);
        
        if (data_length == 15 && memcmp(data, "SSL[heartbeat] ", 15) == 0)
            return;

        if (name && strlen(name) < 300) {
            //printf("vuln=%s\n", name);
            ((char*)data)[data_length] = ' ';
            memcpy((char*)data+data_length+1, name, strlen(name)+1);
            data_length += strlen(name)+1;
        }

        /* kludge */
        if (data_length == 31 && memcmp(data, "SSL[heartbeat] SSL[HEARTBLEED] ", 31) == 0)
            return;
    }

}

void
readscan_report_init(void)
{
    if (global_xnames == NULL)
        xname_init();
}

void
readscan_report_print(void)
{
  print_counts();
}

