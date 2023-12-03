/* ISAKMP protocol support 
 
 1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Initiator                            !
!                            Cookie                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Responder                            !
!                            Cookie                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                          Message ID                           !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
!                            Length                             !
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


 */

#include "proto-isakmp.h"
#include "proto-banout.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "massip-port.h"
#include "output.h"
#include "util-extract.h"
#include "util-logger.h"
#include <stdarg.h>
#include <string.h>

typedef struct payload_t {
    unsigned char next;
    unsigned char reserved;
    size_t length;
    struct ebuf_t ebuf;
} payload_t;

static payload_t
_get_payload(const struct ebuf_t *ebuf) {
    payload_t result = {0};
    result.ebuf = *ebuf;
    result.next = e_next_byte(&result.ebuf);
    result.reserved = e_next_byte(&result.ebuf);
    result.length = e_next_short16(&result.ebuf, EBUF_BE);
    
    if (result.length >= 4) {
        result.ebuf.max = result.ebuf.offset + result.length - 4;
    }
    return result;
}

static unsigned
_parse_transform(struct BannerOutput *banout,
                unsigned proto,
               struct ebuf_t in_ebuf) {
    struct ebuf_t *ebuf = &in_ebuf;
    unsigned transform_id;


    e_next_byte(ebuf); /* transform number */
    transform_id = e_next_byte(ebuf);
    switch (transform_id) {
        case 1: {
            banout_printf(banout, proto, "trans=IKE ");
            e_next_short16(ebuf, EBUF_BE); /* reserved */
            while (ebuf->offset < ebuf->max) {
                unsigned x = e_next_short16(ebuf, EBUF_BE);
                unsigned val = e_next_short16(ebuf, EBUF_BE);
                if ((x & 0x8000) == 0)
                    return 1;
                switch (x&0x7fff) {
                    case 1: /* encryption algorithm */
                        switch (val) {
                            case 5:
                                banout_printf(banout, proto, "%s ", "3DES-CBC");
                                break;
                            case 7:
                                banout_printf(banout, proto, "%s ", "AES-CBC");
                                break;
                            default:
                                banout_printf(banout, proto, "encrypt=0x%x ", val);
                                break;
                        }
                        break;
                    case 2: /* hash algorithm */
                        switch (val) {
                            case 2:
                                banout_printf(banout, proto, "%s ", "SHA");
                                break;
                            default:
                                banout_printf(banout, proto, "hash=0x%x ", val);
                                break;
                        }
                        break;
                    case 3: /* auth */
                        switch (val) {
                            case 1:
                                banout_printf(banout, proto, "%s ", "PSK");
                                break;
                            case 5:
                                banout_printf(banout, proto, "%s ", "PSK");
                                break;
                            default:
                                banout_printf(banout, proto, "auth=0x%x ", val);
                                break;
                        }
                        break;
                    case 4: /* group */
                        break;
                    case 11: /* life type */
                        break;
                    case 12: /* life duration*/
                        break;
                    case 14: /* key length */
                        banout_printf(banout, proto, "key=%ubits ", val);
                        break;
                    default:
                        banout_printf(banout, proto, "val=0x%04x%04x ", x&0x7fff, val);
                        break;
                        
                }
            }
        }
            break;
        default:
            banout_printf(banout, proto, "trans=%u ", transform_id);
            break;
    }
    return 1;
}

static unsigned
_parse_transforms(struct BannerOutput *banout,
                unsigned proto,
               struct ebuf_t ebuf,
               unsigned next_payload
                 ) {
    
    while (ebuf.offset + 4 <= ebuf.max) {
        payload_t payload = _get_payload(&ebuf);
        _parse_transform(banout, proto, payload.ebuf);

        /* loop around */
        ebuf.offset += payload.length;
        next_payload = payload.next;
        if (next_payload == 0)
            break;
    }
    return 0;
}

static unsigned
_parse_proposal(struct BannerOutput *banout,
                unsigned proto,
               struct ebuf_t ebuf) {
    unsigned proto_id;

        
    banout_printf(banout, proto, "%u ", e_next_byte(&ebuf));
    proto_id = e_next_byte(&ebuf);
    switch (proto_id) {
        case 1:
            banout_printf(banout, proto, "id=ISAKMP ");
            break;
        default:
            banout_printf(banout, proto, "id=%u ", proto_id);
            break;
    }
    e_next_byte(&ebuf); /* spi size */
    e_next_byte(&ebuf); /* proposal transforms */
    
    _parse_transforms(banout, proto, ebuf, 0);
    
    return 1;
}

static unsigned
_parse_proposals(struct BannerOutput *banout,
                unsigned proto,
               struct ebuf_t ebuf,
               unsigned next_payload
                 ) {
    
    while (ebuf.offset + 4 <= ebuf.max) {
        payload_t payload = _get_payload(&ebuf);
        _parse_proposal(banout, proto, payload.ebuf);

        /* loop around */
        ebuf.offset += payload.length;
        next_payload = payload.next;
        if (next_payload == 0)
            break;
    }
    return 0;
}

static unsigned
_payload_security_association(struct BannerOutput *banout, unsigned proto, struct ebuf_t ebuf) {
    unsigned doi;
    unsigned bitmap;

    doi = e_next_int32(&ebuf, EBUF_BE);
    bitmap = e_next_int32(&ebuf, EBUF_BE);
    switch (doi) {
        case 0: /* generic */
            banout_printf(banout, proto, "DOI=generic ");
            break;
        case 1: /* IPsec */
            banout_printf(banout, proto, "DOI=ipsec ");
            if (bitmap & 0x00000001)
                banout_printf(banout, proto, "IDENTITY ");
            if (bitmap & 0x00000002)
                banout_printf(banout, proto, "SECRECY ");
            if (bitmap & 0x00000004)
                banout_printf(banout, proto, "INTEGRITY ");
            _parse_proposals(banout, proto, ebuf, 0);
            break;
        default:
            banout_printf(banout, proto, "DOI=%u ", doi);
            break;
    }
    return 1;
}

static unsigned
_payload_vendor_id(struct BannerOutput *banout, unsigned proto, struct ebuf_t ebuf) {
    size_t i;
    size_t length = ebuf.max - ebuf.offset;
    struct {
        unsigned length;
        const char *vendor;
        const char *name;
    } vendors[] = {
        {16, "\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f", "RFC-39947-NAT"},
        {16, "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00", "CISCO-UNITY"},
        {16, "\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00", "RFC3706-DPD"},
        {8, "\x09\x00" "&\x89\xdf\xd6\xb7\x12", "XAUTH"},
        {0,0}
    };
    
    for (i=0; vendors[i].length; i++) {
        if (length != vendors[i].length)
            continue;
        if (memcmp(vendors[i].vendor, ebuf.buf + ebuf.offset, length) == 0) {
            banout_printf(banout, proto, "{%s} ", vendors[i].name);
            break;
        }
    }
    return 1;
}


static unsigned
_parse_response(struct BannerOutput *banout, unsigned proto,
                    const unsigned char *px, size_t length
                    ) {
    struct ebuf_t ebuf[1] = {{px, 0, length}};
    unsigned next_payload;
    unsigned version;
    unsigned flags;
    unsigned exchange_type;
    unsigned my_length;
    static const char *payload_names[] = {
        "[0]", "[SEC-ASSOC]", "[2]", "[3]",
        "[KEY-XCHG]", "[5]", "[6]", "[7]",
        "[8]", "[9]", "[NONCE]", "[11]",
        "[12]", ""/*vendor-id*/, "[14]", "[15]",
        "[16]", "[17]", "[18]", "[19]",
        "[NAT-D]", "[21]", "[22]", "[23]",
        "[24]", "[25]", "[26]", "[27]",
        "[28]", "[29]", "[30]", "[31]",
    };
    
    
    
    /*
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                          Initiator                            !
     !                            Cookie                             !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                          Responder                            !
     !                            Cookie                             !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                          Message ID                           !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                            Length                             !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */

    /* Skip the cookies */
    e_next_long64(ebuf, EBUF_BE);
    e_next_long64(ebuf, EBUF_BE);
    
    /* Parse the header */
    next_payload = e_next_byte(ebuf);
    version = e_next_byte(ebuf);
    exchange_type = e_next_byte(ebuf);
    flags = e_next_byte(ebuf); /* flags */
    e_next_int32(ebuf, 0);
    my_length = e_next_int32(ebuf, EBUF_BE);
    if (ebuf->max >= my_length)
        ebuf->max = my_length;
    banout_printf(banout, proto, "v%u.%u ", (version>>4)&0xF, version&0xF);
    switch (exchange_type) {
        case 2:
            banout_printf(banout, proto, "xchg=id-prot ");
            break;
        default:
            banout_printf(banout, proto, "xchg=%u ", exchange_type);
            break;
    }
    
    if (flags & 1) {
        banout_printf(banout, proto, "ENCRYPTED ", exchange_type);
        return 1;
    }
    
    /*
     * Enumerate all the payloads
     */
    while (next_payload && ebuf->offset + 4 <= ebuf->max) {
        
        /*
         * Parse this payload-header
         */
        payload_t payload = _get_payload(ebuf);

        
        /* 
         * Print the payload name if it's in our list of known names,
         * or print a number if it isn't
         */
        if (next_payload < sizeof(payload_names)/sizeof(payload_names[0]))
            banout_printf(banout, proto, "%s ", payload_names[next_payload]);
        else
            banout_printf(banout, proto, "[%u] ", next_payload);
        
        
        /*
         * Handle the individual payload if it's a known type
         */
        switch (next_payload) {
            case 1:
                _payload_security_association(banout, proto, payload.ebuf);
                break;
            case 4: /* key exchange */
                //banout_printf(banout, proto, "KEY-EXCH ");
                break;
            case 10: /* nonce */
                //banout_printf(banout, proto, "NONCE ");
                break;
            case 13: /* vendir id */
                _payload_vendor_id(banout, proto, payload.ebuf);
                break;
            case 20:
                //banout_printf(banout, proto, "NAT-D ");
                break;
            default:
                break;
            
        }
        
        /*
         * Loop around to the next payload
         */
        ebuf->offset += payload.length;
        next_payload = payload.next;
    }
    return 1;
}

unsigned
isakmp_parse(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy
            )
{
    ipaddress ip_them;
    ipaddress ip_me;
    unsigned port_them = parsed->port_src;
    unsigned port_me = parsed->port_dst;
    uint64_t cookie;
    uint64_t resp_cookie;
    
    /* All responses will be at least 8 bytes */
    if (length < 16)
        return 0;
    
    /* Grab IP addresses */
    ip_them = parsed->src_ip;
    ip_me = parsed->dst_ip;
    
    /* Calculate the expected SYN-cookie */
    cookie = (unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy);
    
    /* Extract the SYN-cookie from the response. We just do this byte-by-byte */
    resp_cookie = (uint64_t)px[0] << 56ull;
    resp_cookie |= (uint64_t)px[1] << 48ull;
    resp_cookie |= (uint64_t)px[2] << 40ull;
    resp_cookie |= (uint64_t)px[3] << 32ull;
    resp_cookie |= (uint64_t)px[4] << 24ull;
    resp_cookie |= (uint64_t)px[5] << 16ull;
    resp_cookie |= (uint64_t)px[6] << 8ull;
    resp_cookie |= (uint64_t)px[7] << 0ull;

    if (resp_cookie != cookie) {
        /* If they aren't equal, then this is some other protocol.
         * TODO: we should use a heuristic on these bytes to
         * discover what the protocol probably is */
        /*output_report_banner(out, timestamp, ip_them, 17, port_them,
                             PROTO_ERROR, parsed->ip_ttl,
                             (unsigned char *) "IP-MISSMATCH", 12);*/
        return 0;
    } else {
        /* We've found our protocol, so report the banner 
         * TODO: we should parse this better. */
        struct BannerOutput banout[1];
        banout_init(banout);

        /* Parse the packet and generate strings */
        _parse_response(banout, PROTO_ISAKMP, px, length);
        
        /* Print the banner to the output */
        output_report_banner(
            out, timestamp,
            ip_them, 17, port_them,
            PROTO_ISAKMP,
            parsed->ip_ttl,
            banout_string(banout, PROTO_ISAKMP),
            banout_string_length(banout, PROTO_ISAKMP));
        
        banout_release(banout);
        return 1;
    }

}

unsigned
isakmp_set_cookie(unsigned char *px, size_t length, uint64_t seqno)
{
    /*
    The frame header starts with an 8 bytes init cookie, which is just
    fine for us
    */

    unsigned char i;

    if (length < 8)
        return 0;

    for(i = 0; i < 8; i++)
        px[i] = (unsigned char)(seqno >> (56 - 8 * i));

    return 0;
}

static const unsigned char
sample1[] =
    "\x00\x00\x00\x00\xc1\x18"
    "\x84\xda\xbe\x3d\xc6\x8e\xea\xf2\xda\xac\x01\x10\x02\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x50\x00\x00\x00\x34\x00\x00\x00\x01\x00\x00"
    "\x00\x01\x00\x00\x00\x28\x01\x01\x00\x01\x00\x00\x00\x20\x01\x01"
    "\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03"
    "\x00\x01\x80\x0b\x00\x01\x80\x0c\x00\x01";

static const unsigned char
sample2[] = "\xe4\x7a\x59\x1f\xd0\x57"
    "\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\x01\x10\x02\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x6c\x0d\x00\x00\x3c\x00\x00\x00\x01\x00\x00"
    "\x00\x01\x00\x00\x00\x30\x01\x01\x00\x01\x00\x00\x00\x28\x01\x01"
    "\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x04"
    "\x00\x02\x80\x03\x00\x01\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01"
    "\x51\x80\x00\x00\x00\x14\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57"
    "\x28\xf2\x0e\x95\x45\x2f";

static const unsigned char sample3[] =
"\xe4\x7a\x59\x1f\xd0\x57\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec"
"\x04\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01\x30\x0a\x00\x00\x84"
"\x6d\x02\x6d\x56\x16\xc4\x5b\xe0\x5e\x5b\x89\x84\x11\xe9\xf9\x5d"
"\x19\x5c\xea\x00\x9a\xd2\x2c\x62\xbe\xf0\x6c\x57\x1b\x7c\xfb\xc4"
"\x79\x2f\x45\x56\x4e\xc7\x10\xac\x58\x4a\xa1\x8d\x20\xcb\xc8\xf5"
"\xf8\x91\x06\x66\xb8\x9e\x4e\xe2\xf9\x5a\xbc\x02\x30\xe2\xcb\xa1"
"\xb8\x8a\xc4\xbb\xa7\xfc\xc8\x18\xa9\x86\xc0\x1a\x4c\xa8\x65\xa5"
"\xeb\x82\x88\x4d\xbe\xc8\x5b\xfd\x7d\x1a\x30\x3b\x09\x89\x4d\xcf"
"\x2e\x37\x85\xfd\x79\xdb\xa2\x25\x37\x7c\xf8\xcc\xa0\x09\xce\xff"
"\xbb\x6a\xa3\x8b\x64\x8c\x4b\x05\x40\x4f\x1c\xfa\xac\x36\x1a\xff"
"\x0d\x00\x00\x18\x15\xb6\x88\x42\x1e\xd5\xc3\xdd\x92\xd3\xb8\x6e"
"\x47\xa7\x6f\x0d\x39\xcc\x09\xe0\x0d\x00\x00\x14\x12\xf5\xf2\x8c"
"\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00\x0d\x00\x00\x14"
"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00"
"\x0d\x00\x00\x14\x55\xcc\x29\xed\x90\x2a\xb8\xec\x53\xb1\xdf\x86"
"\x7c\x61\x09\x29\x14\x00\x00\x0c\x09\x00\x26\x89\xdf\xd6\xb7\x12"
"\x14\x00\x00\x18\xfe\xbf\x46\x2f\x1c\xd7\x58\x05\xa7\xba\xa2\x87"
"\x47\xe7\x69\xd6\x74\xf8\x56\x00\x00\x00\x00\x18\x15\x74\xd6\x4c"
"\x01\x65\xba\xd1\x6a\x02\x3f\x03\x8d\x45\xa0\x74\x98\xd8\xd0\x51";

const char sample4[] =
"\xe4\x7a\x59\x1f\xd0\x57\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec"
"\x05\x10\x02\x01\x00\x00\x00\x00\x00\x00\x00\x4c\xb0\x32\xaa\xa6"
"\x2a\x70\x71\x8e\xf2\xf0\x99\xcd\xd8\xbf\x6e\xb9\x04\x42\xed\x9d"
"\x72\x6d\xaa\x6b\x6d\xad\x62\x40\x26\xf5\xfb\xb1\x73\xd9\xf7\x75"
"\x71\xc2\x32\xa5\x6a\xcf\xe1\x2c\x74\x03\xe9\x53";

static int
_test_sample(const void *sample, size_t sizeof_sample, const char *expected) {
    int is_valid;
    struct BannerOutput banout[1];
    
    /* Initialize printing banners */
    banout_init(banout);
    
    /* Parse the sample */
    is_valid = _parse_response(banout, PROTO_ISAKMP,
                               (const unsigned char*)sample,
                               sizeof_sample);
    
    /* If there was a parse error, then*/
    if (!is_valid)
        goto fail;
    
    
    {
        const unsigned char *str = banout_string(banout, PROTO_ISAKMP);
        size_t str_length = banout_string_length(banout, PROTO_ISAKMP);
        //printf("%.*s\n", (unsigned)str_length, str);
        if (str_length < strlen(expected) || memcmp(str, expected, strlen(expected)) != 0)
            goto fail;
    }
    
    banout_release(banout);
    return 0;
fail:
    banout_release(banout);
    return 0;
}

/****************************************************************************
 ****************************************************************************/
int
proto_isakmp_selftest(void)
{
    unsigned fail_count = 0;
    
    LOG(1, "[ ] ISAKMP: selftesting...\n");
    
    
    fail_count += _test_sample(
                               sample1, sizeof(sample1)-1,
                               "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC SHA PSK");
    fail_count += _test_sample(
                               sample2, sizeof(sample2)-1,
                               "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE AES-CBC key=128bits SHA PSK  {RFC-39947-NAT}");
     
    
    fail_count += _test_sample(
                               sample3, sizeof(sample3)-1,
                               "v1.0 xchg=id-prot [KEY-XCHG] [NONCE]  {CISCO-UNITY}  {RFC3706-DPD}   {XAUTH} [NAT-D] [NAT-D]");
     
    fail_count += _test_sample(
                               sample4, sizeof(sample4)-1,
                               "v1.0 xchg=id-prot ENCRYPTED");
    

    if (fail_count)
        goto fail;

    LOG(1, "[-] ISAKMP: success\n");
    return 0;
fail:
    LOG(1, "[-] ISAKMP: fail\n");
    return 1;
}

