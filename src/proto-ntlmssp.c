#include "proto-ntlmssp.h"
#include "masscan-app.h"
#include "proto-banout.h"
#include "string_s.h"
#include "util-malloc.h"
#include <string.h>
#include <stdlib.h>

/*
 +--------+--------+--------+--------+
 |  'N'   |  'T'   |  'L'   |  'M'   |
 +-      -+-      -+-      -+-      -+
 |  'S'   |  'S'   |  'P'   | '\0'   |
 +--------+--------+--------+--------+
 |           MessageType             |
 +--------+--------+--------+--------+
 |  TargetNameLen  | TargetNameMaxLen| TagetName fields set to zero if
 +--------+--------+--------+--------+ NTLMSSP_REQUEST_TARGET  flag not set
 |           TargetNameOffset        |
 +--------+--------+--------+--------+
 |            NegotiateFlags         |
 +--------+--------+--------+--------+
 |                                   |
 +-          ServerChallenge        -+
 |                                   |
 +--------+--------+--------+--------+
 |                                   |
 +-             Reserved            -+
 |                                   |
 +--------+--------+--------+--------+
 |  TargetInfoLen  | TargetInfoMaxLen| TagetInfo fields set to zero if
 +--------+--------+--------+--------+ NTLMSSP_NEGOTIATE_TARGET_INFO  flag not set
 |           TargetInfoOffset        |
 +--------+--------+--------+--------+
 |MajorVer|MinorVer|   ProductBuild  |
 +--------+--------+--------+--------+
 |          Reserved        |NTLMver |
 +--------+--------+--------+--------+
 |                                   |
 +-      -+-      -+-      -+-      -+
 . . . . . . . . . . . . . . . . . . .
 +-      -+-      -+-      -+-      -+
 |        |        |        |        |
 +--------+--------+--------+--------+

 
 Signature (8 bytes):
    "An 8-byte character array that MUST contain the ASCII string
    ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0')."
 MessageType (4 bytes):
    "A 32-bit unsigned integer that indicates the message type. This field MUST
    be set to 0x00000002."
 
 
 TargetNameLen (2 bytes):
    "A 16-bit unsigned integer that defines the size, in bytes, of
    TargetName in Payload."
    Zero if NTLMSSP_REQUEST_TARGET not set.
 TargetNameMaxLen (2 bytes):
    "A 16-bit unsigned integer that SHOULD be set to the value
    of TargetNameLen and MUST be ignored on receipt."
    Zero if NTLMSSP_REQUEST_TARGET not set.
 TargetNameBufferOffset (4 bytes):
    "A 32-bit unsigned integer that defines the offset, in
    bytes, from the beginning of the CHALLENGE_MESSAGE to TargetName in Payload. If
    TargetName is a Unicode string, the values of TargetNameBufferOffset and
    TargetNameLen MUST be multiples of 2."
 
 
 
 VERSION FIELDS:
    These fields are valid only if "NTLMSSP_NEGOTIATE_VERSION" flag is set.
 
  MajorVer [ProductMajorVersion] (1 byte):
    "An 8-bit unsigned integer that SHOULD contain the major
    version number of the operating system in use."
  MinorVer [ProductMinorVersion] (1 byte):
    "An 8-bit unsigned integer that SHOULD<34> contain the minor
    version number of the operating system in use."
  ProductBuild (2 bytes):
    "A 16-bit unsigned integer that contains the build number of the operating
    system in use. This field SHOULD be set to a 16-bit quantity that identifies the operating system
    build number."
  NTLMRevisionCurrent (1 byte):
    "An 8-bit unsigned integer that contains a value indicating the
    current revision of the NTLMSSP in use. This field SHOULD contain the following value:"
        "NTLMSSP_REVISION_W2K3 (0x0F): Version 15 of the NTLMSSP is in use."
 
 
 */

static void
append_unicode_string(struct BannerOutput *banout, unsigned proto, const char *name, const unsigned char *value, size_t value_length)
{
    unsigned j;
    banout_append_char(banout, proto, ' ');
    banout_append(banout, PROTO_SMB, name, AUTO_LEN);
    banout_append_char(banout, proto, '=');
    for (j=0; j<value_length; j += 2) {
        unsigned c = value[j] | value[j+1]<<8;
        banout_append_unicode(banout, PROTO_SMB, c);
    }
}

void
ntlmssp_decode(struct NtlmsspDecode *x,
              const unsigned char *px, size_t length,
              struct BannerOutput *banout)
{
    unsigned message_type;
    unsigned name_offset;
    unsigned name_length;
    unsigned info_offset;
    unsigned info_length;
    //unsigned flags;
    unsigned i;
    
    if (length > x->length - x->offset)
        length = x->length - x->offset;
    
    /* See if we have a fragment, in which case we need to allocate a buffer
     * to contain it */
    if (x->offset == 0 && x->length > length) {
        x->buf = MALLOC(x->length);
        memcpy(x->buf, px, length);
        x->offset = (unsigned)length;
        return;
    } else if (x->offset) {
        memcpy(x->buf + x->offset, px, length);
        x->offset += (unsigned)length;
        if (x->offset < x->length)
            return;
        
        /* now reset the input to point to our buffer instead */
        px = x->buf;
        length = x->length;
    }
    
    if (length < 56)
        goto end;
    
    /* Verify the signature. There are other protocols that we could possibly
     * detect at this point and do something else useful with, but for right now,
     * we are just doing NTLM */
    if (memcmp("NTLMSSP", px, 8) != 0)
        goto end;
    
    /* Verify this is a "challenge" packet, which has all the interesting
     * fields. */
    message_type = px[8] | px[9]<<8 | px[10]<<16 | px[11]<<24;
    if (message_type != 2)
        goto end;
    
    /* Grab the Domain field. This is a pointer in these 8 bytes here
     * that points into the payload section of the chunk */
    name_length = px[12] | px[13]<<8;
    name_offset = px[16] | px[17]<<8 | px[18]<<16 | px[19]<<24;
    if (name_length && name_length + name_offset < length) {
        append_unicode_string(banout, PROTO_SMB, "domain", px+name_offset, name_length);
    }
    
    /* Grab flags */
    //flags = px[20] | px[21]<<8 | px[22]<<16 | px[23]<<24;
    
    /* Info field */
    info_length = px[40] | px[41]<<8;
    info_offset = px[44] | px[45]<<8 | px[46]<<16 | px[47]<<24;

    /* Version field */
    {
        char buf[64];
        sprintf_s(buf, sizeof(buf), " version=%u.%u.%u ntlm-ver=%u",
                  px[48],
                  px[49],
                  px[50] | px[51]<<8,
                  px[55]
                  );
        banout_append(banout, PROTO_SMB, buf, AUTO_LEN);
    }

    /* Parse all the fields */
    for (i=info_offset; i+4<info_offset+info_length && i+4<length; ) {
        unsigned type = px[i] | px[i+1]<<8;
        size_t len = px[i+2] | px[i+3]<<8;
        i += 4;
        
        if (len > info_offset + info_length - i)
            len = info_offset + info_length - i;
        if (len > length - i)
            len = length - i;
        
        switch (type) {
            case 0x00: /* MsvAvEOL */
                i = info_offset + info_length;
                continue;
            case 1: /* MsvAvNbComputerName */
                append_unicode_string(banout, PROTO_SMB, "name", px+i, len);
                break;
            case 2: /* MsvAvNbDomainName */
                append_unicode_string(banout, PROTO_SMB, "domain", px+i, len);
                break;
            case 3: /* MsvAvDnsComputerName */
                append_unicode_string(banout, PROTO_SMB, "name-dns", px+i, len);
                break;
            case 4: /* MsvAvDnsDomainName */
                append_unicode_string(banout, PROTO_SMB, "domain-dns", px+i, len);
                break;
            case 5: /* MsvAvDnsTreeName */
                append_unicode_string(banout, PROTO_SMB, "forest", px+i, len);
                break;
            case 6: /* MsvAvFlags */
                break;
            case 7: /* MsvAvTimestamp */
                break;
            case 8: /* MsvAvSingleHost */
                break;
            case 9: /* MsvAvTargetName */
                append_unicode_string(banout, PROTO_SMB, "target", px+i, len);
                break;
            case 10: /* MsvChannelBindings */
                break;
            default:
                break;
        }
        i += (unsigned)len;
    }

    
    
    /* Grab the other fields. This*/
    
end:
    /*
     * Free the buffer if needed
     */
    if (x->buf) {
        free(x->buf);
        x->buf = 0;
    }
    
}

void
ntlmssp_cleanup(struct NtlmsspDecode *x)
{
    if (x->buf) {
        free(x->buf);
        x->buf = 0;
    }
}

void
ntlmssp_decode_init(struct NtlmsspDecode *x, size_t length)
{
    memset(x, 0, sizeof(*x));
    
    /* [security] Double-check this input, since it's ultimately driven by user-input.
     * The code that leads to here should already have double-checked this, but I'm
     * doing it again just in case. This is larger than any input that should be
     * seen in the real world that a hacker isn't messing with.
     */
    if (length > 65536)
        length = 65536;
    
    x->length = (unsigned)length;
    x->offset = 0;
    x->buf = NULL;
    
}

