/*
 Reads in UDP payload templates.

 This supports two formats. The first format is the "nmap-payloads" file
 included with the nmap port scanner.

 The second is the "libpcap" format that reads in real packets,
 extracting just the payloads, associated them with the destination
 UDP port.

 */
#include "templ-payloads.h"
#include "massip-port.h"
#include "rawsock-pcapfile.h"   /* for reading payloads from pcap files */
#include "proto-preprocess.h"   /* parse packets */
#include "util-logger.h"
#include "proto-zeroaccess.h"   /* botnet p2p protocol */
#include "proto-snmp.h"
#include "proto-memcached.h"
#include "proto-coap.h"         /* constrained app proto for IoT udp/5683*/
#include "proto-ntp.h"
#include "proto-dns.h"
#include "proto-isakmp.h"
#include "util-malloc.h"
#include "massip.h"
#include "templ-nmap-payloads.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

struct PayloadUDP_Item {
    unsigned port;
    unsigned source_port; /* not used yet */
    unsigned length;
    unsigned xsum;
    unsigned rarity;
    SET_COOKIE set_cookie;
    unsigned char buf[1];
};
struct PayloadUDP_Default {
    unsigned port;
    unsigned source_port;
    unsigned length;
    unsigned xsum;
    SET_COOKIE set_cookie;
    char *buf;

};

struct PayloadsUDP {
    unsigned count;
    size_t max;
    struct PayloadUDP_Item **list;
};


struct PayloadUDP_Default hard_coded_oproto_payloads[] = {
    /* ECHO protocol - echoes back whatever we send */
    {47, 65536, 4, 0, 0, "\0\0\0\0"},
    {0,0,0,0,0}
};


struct PayloadUDP_Default hard_coded_udp_payloads[] = {
    /* ECHO protocol - echoes back whatever we send */
    {7, 65536, 12, 0, 0, "masscan-test 0x00000000"},

    /* QOTD - quote of the day (amplifier) */
    {17, 65536, 12, 0, 0, "masscan-test"},
    
    /* chargen - character generator (amplifier) */
    {19, 65536, 12, 0, 0, "masscan-test"},
    
    {53, 65536, 0x1f, 0, dns_set_cookie,
        /* 00 */"\x50\xb6"  /* transaction id */
        /* 02 */"\x01\x20"  /* query */
        /* 04 */"\x00\x01"  /* query = 1 */
        /* 06 */"\x00\x00\x00\x00\x00\x00"
        /* 0c */"\x07" "version"  "\x04" "bind" "\x00"
        /* 1b */"\x00\x10" /* TXT */
        /* 1d */"\x00\x03" /* CHAOS */
        /* 1f */
    },

    {69, 65536, 24, 0, 0,
        "\x00\x01"          /* opcode = read */
        "masscan-test" "\0" /* filename = "masscan-test" */
        "netascii" "\0"     /* type = "netascii" */
    },
    /* portmapper */
    {111, 65536, 40, 0, dns_set_cookie,
        "\x00\x00\x00\x00" /* xid - first two bytes set by dns_set_cookie() */
        "\x00\x00\x00\x00" /* RPC opcode = CALL*/
        "\x00\x00\x00\x02" /* RPC version = 2 */
        "\x00\x01\x86\xa0" /* RPC program = NFS */
        "\x00\x00\x00\x02" /* portmapper version = 2 */
        "\x00\x00\x00\x00" /* portmapper procedure = 0 (NULL, ping) */
        "\x00\x00\x00\x00\x00\x00\x00\x00" /* credentials = none*/
        "\x00\x00\x00\x00\x00\x00\x00\x00" /* verifier = none   */
    },

    {123, 65536, 48, 0, ntp_set_cookie,
        "\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },
    {137, 65536, 50, 0, dns_set_cookie,
        "\xab\x12" /* transaction id */
        "\x00\x00" /* query */
        "\x00\x01\x00\x00\x00\x00\x00\x00" /* one question */
        "\x20" /*name length*/
        "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\x00"
        "\x00\x21" /* type = nbt */
        "\x00\x01" /* class = iternet*/
    },

    /* NetBIOS-SMB BROWSER protocol */
    {138, 65536, 174, 0, 0,
        "\x11" /* broadcast datagram */
        "\x0a" /* flags */
        "\xc1\x00" /* datagram id */
        "\x0a\x01\x01\xd5" /* source IP */
        "\x00\x8a" /* source port */
        "\x00\xa0" /* length */
        "\x00\x00" /* packet offset */
        "\x20" /* namelength = 32 bytes*/
        "ENEBFDFDEDEBEOCNFEEFFDFECACACAAA" /* "MASSCAN-TEST<00>" */
        "\x00"
        "\x20"
        "FHEPFCELEHFCEPFFFACACACACACACABN" /* "WORKGROUP<1D>*/
        "\x00"
        "\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        "\x11\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x06\x00\x56\x00\x03\x00\x01\x00\x01"
        "\x00\x02\x00\x17\x00\x5c\x4d\x41\x49\x4c\x53\x4c\x4f\x54\x5c\x42"
        "\x52\x4f\x57\x53\x45\x00"

        "\x09\x04\x01\x00\x00\x00"
    },

    {161, 65536, 59, 0, snmp_set_cookie,
        "\x30" "\x39"
        "\x02\x01\x00"                    /* version */
        "\x04\x06" "public"               /* community = public */
        "\xa0" "\x2c"                     /* type = GET */
        "\x02\x04\x00\x00\x00\x00"      /* transaction id = ???? */
        "\x02\x01\x00"                  /* error = 0 */
        "\x02\x01\x00"                  /* error index = 0 */
        "\x30\x1e"
        "\x30\x0d"
        "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x01\x00" /*sysName*/
        "\x05\x00"          /*^^^^_____IDS LULZ HAH HA HAH*/
        "\x30\x0d"
        "\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x05\x00" /*sysDesc*/
        "\x05\x00"},        /*^^^^_____IDS LULZ HAH HA HAH*/

    {443, 65536, 115, 0, 0,
        "\x16" /* opcode = handshake */
        "\xfe\xff" /* version = dTLS v1.0 */
        "\x00\x00" /* epoch = 0 */
        "\x00\x00\x00\x00\x00\x07" /* sequence number = 7 */
        "\x00\x66" /* length 104 */

        "\x01" /* opcode = client hello */
        "\x00\x00\x5a" /* length 90 */
        "\x00\x00" /* sequence number = 0 */
        "\x00\x00\x00" /* fragment offset = 0 */
        "\x00\x00\x5a" /* framgent length = 90 */
        "\xfe\xfd" /* version = dTLS v1.2 */
        "\x1d\xb1\xe3\x52\x2e\x89\x94\xb7\x15\x33\x2f\x30\xff\xff\xcf\x76"
        "\x27\x77\xab\x04\xe4\x86\x6f\x21\x18\x0e\xf8\xdd\x70\xcc\xab\x9e"
        "\x00" /* session id length = 0 */
        "\x00" /* cookie length = 0 */
        "\x00\x04" /* cipher suites length = 4 */
        "\xc0\x30" /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
        "\x00\xff"
        "\x01" /* compression methods length = 1*/
        "\x00" /* NULL compression */
        "\x00\x2c" /* extensions length = 44 */
        "\x00\x0b\x00\x04\x03\x00\x01\x02"
        "\x00\x0a\x00\x0c\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18"
        "\x00\x23\x00\x00"
        "\x00\x16\x00\x00"
        "\x00\x17\x00\x00"
        "\x00\x0d\x00\x04\x00\x02\x05\x01"
    },

    {520, 65536, 24, 0, 0,
        "\x01"  /* opcode = request */
        "\x01"  /* version = 1 */
        "\x00\x00" /* padding */
        "\x00\x02" /* address familly = IPv4 */
        "\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x10" /* metric = 16 */

    },

    /* RADIUS  */
    {1645, 65536, 20, 0, 0,
        "\x01" /* opcode = access request */
        "\x00" /* packet id = 0 */
        "\x00\x14" /* length = 20 */
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },
    {1812, 65536, 20, 0, 0,
        "\x01" /* opcode = access request */
        "\x00" /* packet id = 0 */
        "\x00\x14" /* length = 20 */
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },
    {1646, 65536, 20, 0, 0,
        "\x04" /* opcode = access request */
        "\x00" /* packet id = 0 */
        "\x00\x14" /* length = 20 */
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },
    {1813, 65536, 20, 0, 0,
        "\x04" /* opcode = access request */
        "\x00" /* packet id = 0 */
        "\x00\x14" /* length = 20 */
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    },

    /* L2TP */
    {1701, 65536, 60, 0, 0,
        "\xc8\x02" /* flags */
        "\x00\x3c" /* length = 60 */
        "\x00\x00" /* tunnel id = 0 */
        "\x00\x00" /* session id = 0 */
        "\x00\x00" /* Nsent = 0 */
        "\x00\x00" /* Nrecvd = 0 */
        "\x80\x08\x00\x00\x00\x00\x00\x01" /* control message */
        "\x80\x08\x00\x00\x00\x02\x01\x00" /* protocol version */
        "\x80\x0e\x00\x00\x00\x07" "masscan1" /* hostname */
        "\x80\x0a\x00\x00\x00\x03\x00\x00\x00\x03" /* framing capabilities */
        "\x80\x08\x00\x00\x00\x09\x00\x00" /* assigned tunnel */
    },

    /* UPnP SSDP - Univeral Plug-n-Play Simple Service Discovery Protocol */
    {1900, 65536, 0xFFFFFFFF, 0, 0,
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "USER-AGENT: unix/1.0 UPnP/1.1 masscan/1.x\r\n"},

    /* NFS - kludge: use the DNS cookie, setting first 2 bytes instead of 4 */
    {2049, 65536, 40, 0, dns_set_cookie,
        "\x00\x00\x00\x00" /* xid - first two bytes set by dns_set_cookie() */
        "\x00\x00\x00\x00" /* RPC opcode = CALL*/
        "\x00\x00\x00\x02" /* RPC version = 2 */
        "\x00\x01\x86\xa3" /* RPC program = NFS */
        "\x00\x00\x00\x02" /* NFS version = 2 */
        "\x00\x00\x00\x00" /* NFS procedure = 0 (NULL, ping) */
        "\x00\x00\x00\x00\x00\x00\x00\x00" /* credentials = none*/
        "\x00\x00\x00\x00\x00\x00\x00\x00" /* verifier = none   */
    },
    {5060, 65536, 0xFFFFFFFF, 0, 0,
        "OPTIONS sip:carol@chicago.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n"
        "Max-Forwards: 70\r\n"
        "To: <sip:carol@chicago.com>\r\n"
        "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710\r\n"
        "CSeq: 63104 OPTIONS\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n"
        "Accept: application/sdp\r\n"
        "Content-Length: 0\r\n"
    },
    
    /* CoAP (contrained app proto for IoT) GET /.well-known/core request */
    {5683, 65536, 21, 0, coap_udp_set_cookie,
        "\x40"      /* ver=1 type=con */
        "\x01"      /* code=GET */
        "\x01\xce"  /* message id (changed by set-cookie) */
        "\xbb" /* ".well-known */
        "\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e"
        "\x04" /* "core" */
        "\x63\x6f\x72\x65"

    },

    /* memcached "stats" request. This looks for memcached systems that can
     * be used for DDoS amplifiers */
    {11211, 65536, 15, 0, memcached_udp_set_cookie,
        "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
    },

    //16464,16465,16470, 16471
    {16464, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16465, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16470, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},
    {16471, 65536, zeroaccess_getL_length, 0, 0,
        (char *)zeroaccess_getL},

    /* Quake 3 (amplifier)
     * http://blog.alejandronolla.com/2013/06/24/amplification-ddos-attack-with-quake3-servers-an-analysis-1-slash-2/
     */
    {27960, 65536, 0xFFFFFFFF, 0, 0,
        "\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10"},

    /* ISAKMP */
    {500, 500, 352, 0, isakmp_set_cookie,
     /* ISAKMP */
     "\x00\x11\x22\x33\x44\x55\x66\x77"/* init_cookie, overwritten on send() */
     "\x00\x00\x00\x00\x00\x00\x00\x00" /* resp_cookie*/
     "\x01" /* next_payload: SA */
     "\x10" /* version */
     "\x02" /* exch_type: identity prot. */
     "\x00" /* flags */
     "\x00\x00\x00\x00" /* id */
     "\x00\x00\x01\x60" /* length: 352 */
     /* ISAKMP_SA */
     "\x00" /* next_payload: None */
     "\x00" /* reserved */
     "\x01\x44" /* length: 324 */
     "\x00\x00\x00\x01" /* DOI: IPSEC */
     "\x00\x00\x00\x01" /* situation: identity */
     /* Proposal */
     "\x00" /* next_payload: None */
     "\x00" /* reserved */
     "\x01\x38" /* length: 312 */
     "\x01" /* proposal: 1 */
     "\x01" /* protocol: ISAKMP */
     "\x00" /* SPIsize: 0 */
     "\x0d" /* trans_count: 13 */
     "" /* SPI */
     /* Tranforms */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x20" /* length: 32 */
     "\x00" /* num */
     "\x01" /* id: KEY_IKE */
     "\x00\x00" /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02"
     "\x80\x0b\x00\x01\x80\x0c\x00\x01"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'),
        ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'),
        ('LifeDuration', 1) */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x20" /* length: 32 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02"
     "\x80\x0b\x00\x01\x80\x0c\x00\x01"
     /* ('Encryption', 'DES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'),
        ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'),
        ('LifeDuration', 1) */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x20" /* length: 32 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x07\x80\x02\x00\x04\x80\x03\x00\x01\x80\x04\x00\x0e"
     "\x80\x0b\x00\x01\x80\x0c\x00\x01"
     /* ('Encryption', 'AES-CBC'), ('Hash', 'SHA2-256'),
        ('Authentication', 'PSK'), ('GroupDesc', '2048MODPgr'),
        ('LifeType', 'Seconds'), ('LifeDuration', 1) */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x02"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'DSS') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x03"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'RSA Sig') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x04"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'RSA Encryption') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x08"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'ECDSA Sig') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdd"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'HybridInitRSA') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdf"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'HybridInitDSS') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xe9"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'XAUTHInitPreShared') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xeb"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'XAUTHInitDSS') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xed"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'XAUTHInitRSA') */
     "\x03" /* next_payload: Transform */
     "\x00" /* reserved */
     "\x00\x14" /* length: 20 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */
     "\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xef"
     /* ('Encryption', '3DES-CBC'), ('Hash', 'SHA'),
        ('Authentication', 'XAUTHInitRSAEncryption') */
     "\x00" /* next_payload: None */
     "\x00" /* reserved */
     "\x00\x08" /* length: 8 */
     "\x00" /* num */
     "\x01"  /* id: KEY_IKE */
     "\x00\x00"  /* reserved */},

    {0,0,0,0,0}
};


/***************************************************************************
 * Calculate the partial checksum of the payload. This allows us to simply
 * add this to the checksum when transmitting instead of recalculating
 * everything.
 ***************************************************************************/
static unsigned
partial_checksum(const unsigned char *px, size_t icmp_length)
{
    uint64_t xsum = 0;
    unsigned i;

    for (i=0; i<icmp_length; i += 2) {
        xsum += px[i]<<8 | px[i + 1];
    }

    xsum -= (icmp_length & 1) * px[i - 1]; /* yea I know going off end of packet is bad so sue me */
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    return (unsigned)xsum;
}

/***************************************************************************
 * If we have the port, return the best payload for that port.
 ***************************************************************************/
int
payloads_udp_lookup(
                    const struct PayloadsUDP *payloads,
                    unsigned port,
                    const unsigned char **px,
                    unsigned *length,
                    unsigned *source_port,
                    uint64_t *xsum,
                    SET_COOKIE *set_cookie)
{
    unsigned i;
    if (payloads == 0)
        return 0;

    port &= 0xFFFF;

    /* This is just a linear search, done once at startup, to search
     * through all the payloads for the best match. */
    for (i=0; i<payloads->count; i++) {
        if (payloads->list[i]->port == port) {
            *px = payloads->list[i]->buf;
            *length = payloads->list[i]->length;
            *source_port = payloads->list[i]->source_port;
            *xsum = payloads->list[i]->xsum;
            *set_cookie = payloads->list[i]->set_cookie;
            return 1;
        }
    }
    return 0;
}


/***************************************************************************
 * cleanup on program shutdown
 ***************************************************************************/
void
payloads_udp_destroy(struct PayloadsUDP *payloads)
{
    unsigned i;
    if (payloads == NULL)
        return;

    for (i=0; i<payloads->count; i++)
        free(payloads->list[i]);

    if (payloads->list)
        free(payloads->list);

    free(payloads);
}

/***************************************************************************
 * We read lots of UDP payloads from the files. However, we probably
 * aren't using most, or even any, of them. Therefore, we use this
 * function to remove the ones we won't be using. This makes lookups
 * faster, ideally looking up only zero or one rather than twenty.
 ***************************************************************************/
void
payloads_udp_trim(struct PayloadsUDP *payloads, const struct MassIP *targets)
{
    unsigned i;
    struct PayloadUDP_Item **list2;
    unsigned count2 = 0;

    /* Create a new list */
    list2 = REALLOCARRAY(0, payloads->max, sizeof(list2[0]));

    /* Add to the new list any used ports */
    for (i=0; i<payloads->count; i++) {
        unsigned found;

        found = massip_has_port(targets, payloads->list[i]->port + Templ_UDP);
        if (found) {
            list2[count2++] = payloads->list[i];
        } else {
            free(payloads->list[i]);
        }
        //payloads->list[i] = 0;
    }

    /* Replace the old list */
    free(payloads->list);
    payloads->list = list2;
    payloads->count = count2;
}

void
payloads_oproto_trim(struct PayloadsUDP *payloads, const struct MassIP *targets)
{
    unsigned i;
    struct PayloadUDP_Item **list2;
    unsigned count2 = 0;
    
    /* Create a new list */
    list2 = REALLOCARRAY(0, payloads->max, sizeof(list2[0]));
    
    /* Add to the new list any used ports */
    for (i=0; i<payloads->count; i++) {
        unsigned found;
        
        found = massip_has_port(targets, payloads->list[i]->port + Templ_Oproto_first);
        if (found) {
            list2[count2++] = payloads->list[i];
        } else {
            free(payloads->list[i]);
        }
    }
    
    /* Replace the old list */
    free(payloads->list);
    payloads->list = list2;
    payloads->count = count2;
}


/***************************************************************************
 * Adds a payloads template for the indicated datagram protocol, which
 * is UDP or Oproto ("other IP protocol").
 ***************************************************************************/
static unsigned
payloads_datagram_add(struct PayloadsUDP *payloads,
                      const unsigned char *buf, size_t length,
                      struct RangeList *ports, unsigned source_port,
                      SET_COOKIE set_cookie)
{
    unsigned count = 1;
    struct PayloadUDP_Item *p;
    uint64_t port_count = rangelist_count(ports);
    uint64_t i;

    for (i=0; i<port_count; i++) {
        /* grow the list if we need to */
        if (payloads->count + 1 > payloads->max) {
            size_t new_max = payloads->max*2 + 1;
            payloads->list = REALLOCARRAY(payloads->list, new_max, sizeof(payloads->list[0]));
            payloads->max = new_max;
        }

        /* allocate space for this record */
        p = MALLOC(sizeof(p[0]) + length);
        p->port = rangelist_pick(ports, i);
        p->source_port = source_port;
        p->length = (unsigned)length;
        memcpy(p->buf, buf, length);
        p->xsum = partial_checksum(buf, length);
        p->set_cookie = set_cookie;

        /* insert in sorted order */
        {
            unsigned j;

            for (j=0; j<payloads->count; j++) {
                if (p->port <= payloads->list[j]->port)
                    break;
            }

            if (j < payloads->count) {
                if (p->port == payloads->list[j]->port) {
                    free(payloads->list[j]);
                    count = 0; /* don't increment count */
                } else
                    memmove(payloads->list + j + 1,
                            payloads->list + j,
                            (payloads->count-j) * sizeof(payloads->list[0]));
            }
            payloads->list[j] = p;

            payloads->count += count;
            count = 1;
        }
    }
    return count; /* zero or one */
}

static unsigned
payloads_datagram_add_nocookie(struct PayloadsUDP *payloads,
                               const unsigned char *buf, size_t length,
                               struct RangeList *ports, unsigned source_port
                               ) {
    return payloads_datagram_add(payloads,
                                 buf, length,
                                 ports, source_port,
                                 0);

}


/***************************************************************************
 * Called during processing of the "--pcap-payloads <filename>" directive.
 * This is the well-known 'pcap' file format. This code strips off the
 * headers of the packets then preserves just the payload portion
 * and port number.
 ***************************************************************************/
void
payloads_read_pcap(const char *filename,
                   struct PayloadsUDP *payloads,
                   struct PayloadsUDP *oproto_payloads)
{
    struct PcapFile *pcap;
    unsigned count = 0;

    LOG(2, "payloads:'%s': opening packet capture\n", filename);

    /* open packet-capture */
    pcap = pcapfile_openread(filename);
    if (pcap == NULL) {
        fprintf(stderr, "payloads: can't read from file '%s'\n", filename);
        return;
    }

    /* for all packets in the capture file
     *  - read in packet
     *  - parse packet
     *  - save payload
     */
    for (;;) {
        unsigned x;
        unsigned captured_length;
        unsigned char buf[65536];
        struct PreprocessedInfo parsed;
        struct RangeList ports[1] = {{0}};
        struct Range range[1] = {{0}};

        /*
         * Read the next packet from the capture file
         */
        {
            unsigned time_secs;
            unsigned time_usecs;
            unsigned original_length;

            x = pcapfile_readframe(pcap,
                                   &time_secs, &time_usecs,
                                   &original_length, &captured_length,
                                   buf, (unsigned)sizeof(buf));
        }
        if (!x)
            break;

        /*
         * Parse the packet up to its headers
         */
        x = preprocess_frame(buf, captured_length, 1, &parsed);
        if (!x)
            continue; /* corrupt packet */

        /*
         * Make sure it has UDP
         */
        switch (parsed.found) {
            case FOUND_DNS:
            case FOUND_UDP:
                /*
                 * Kludge: mark the port in the format the API wants
                 */
                ports->list = range;
                ports->count = 1;
                ports->max = 1;
                range->begin = parsed.port_dst;
                range->end = range->begin;
                
                /*
                 * Now we've completely parsed the record, so add it to our
                 * list of payloads
                 */
                count += payloads_datagram_add(   payloads,
                                               buf + parsed.app_offset,
                                               parsed.app_length,
                                               ports,
                                               0x10000,
                                               0);
                break;
            case FOUND_OPROTO:
                /*
                 * Kludge: mark the port in the format the API wants
                 */
                ports->list = range;
                ports->count = 1;
                ports->max = 1;
                range->begin = parsed.ip_protocol;
                range->end = range->begin;
                
                /*
                 * Now we've completely parsed the record, so add it to our
                 * list of payloads
                 */
                count += payloads_datagram_add(oproto_payloads,
                                               buf + parsed.transport_offset,
                                               parsed.transport_length,
                                               ports,
                                               0x10000,
                                               0);
                break;
            default:
                continue;
        }

    }

    LOG(2, "payloads:'%s': imported %u unique payloads\n", filename, count);
    LOG(2, "payloads:'%s': closed packet capture\n", filename);
    pcapfile_close(pcap);
}

/***************************************************************************
 * Called from the "conf" subsystem in order read in the file
 * "nmap-payloads". We call the function 'read_nmap_payloads()" defined
 * in a different file that focuses on parsing that file format.
 ***************************************************************************/
void
payloads_udp_readfile(FILE *fp, const char *filename,
                      struct PayloadsUDP *payloads) {
    read_nmap_payloads(fp, filename, payloads, payloads_datagram_add_nocookie);
}

/***************************************************************************
 ***************************************************************************/
struct PayloadsUDP *
payloads_udp_create(void)
{
    unsigned i;
    struct PayloadsUDP *payloads;
    struct PayloadUDP_Default *hard_coded = hard_coded_udp_payloads;
    
    payloads = CALLOC(1, sizeof(*payloads));
    
    /*
     * For popular parts, include some hard-coded default UDP payloads
     */
    for (i=0; hard_coded[i].length; i++) {
        //struct Range range;
        struct RangeList list = {0};
        unsigned length;

        /* Kludge: create a pseudo-rangelist to hold the one port */
        /*list.list = &range;
         list.count = 1;
         range.begin = hard_coded[i].port;
         range.end = range.begin;*/
        rangelist_add_range(&list, hard_coded[i].port, hard_coded[i].port);

        length = hard_coded[i].length;
        if (length == 0xFFFFFFFF)
            length = (unsigned)strlen(hard_coded[i].buf);

        /* Add this to our real payloads. This will get overwritten
         * if the user adds their own with the same port */
        payloads_datagram_add(payloads,
                              (const unsigned char*)hard_coded[i].buf,
                              length,
                              &list,
                              hard_coded[i].source_port,
                              hard_coded[i].set_cookie);

        rangelist_remove_all(&list);
    }
    return payloads;
}

/***************************************************************************
 * (same code as for UDP)
 ***************************************************************************/
struct PayloadsUDP *
payloads_oproto_create(void)
{
    unsigned i;
    struct PayloadsUDP *payloads;
    struct PayloadUDP_Default *hard_coded = hard_coded_oproto_payloads;
    
    payloads = CALLOC(1, sizeof(*payloads));
    
    /*
     * Some hard-coded ones, like GRE
     */
    for (i=0; hard_coded[i].length; i++) {
        //struct Range range;
        struct RangeList list = {0};
        unsigned length;
        
        /* Kludge: create a pseudo-rangelist to hold the one port */
        rangelist_add_range(&list, hard_coded[i].port, hard_coded[i].port);
        
        length = hard_coded[i].length;
        if (length == 0xFFFFFFFF)
            length = (unsigned)strlen(hard_coded[i].buf);
        
        /* Add this to our real payloads. This will get overwritten
         * if the user adds their own with the same port */
        payloads_datagram_add(payloads,
                              (const unsigned char*)hard_coded[i].buf,
                              length,
                              &list,
                              hard_coded[i].source_port,
                              hard_coded[i].set_cookie);
        
        rangelist_remove_all(&list);
    }
    return payloads;
}


int
templ_payloads_selftest(void) {
    return templ_nmap_selftest();
}
