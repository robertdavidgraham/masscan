/*
    SMB parser
 
 */
#include "proto-smb.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "siphash24.h"
#include "string_s.h"
#include "unusedparm.h"
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stddef.h>


/*
    "NT LM 0.12"    -   Win2k
    "SMB 2.002"     0x0202      Vista
    "SMB 2.???"     0x02FF      Win7, Windows 2008
    "PC NETWORK PROGRAM 1.0"    MS-DOS
    "MICROSOFT NETWORKS 1.03"   MS-DOS
    "MICROSOFT NETWORKS 3.0"    MS-DOS
    "LANMAN 1.0"                OS/2
    "LM1.2X002"                 OS/2
 */
/*
PC NETWORK PROGRAM 1.0
LANMAN1.0
Windows for Workgroups 3.1a
LM1.2X002
LANMAN2.1
NT LM 0.12
SMB 2.002
SMB 2.???
Samba
XENIX CORE
*/
/*
  References:
 http://pubs.opengroup.org/onlinepubs/9697999099/toc.pdf
 */

struct SmbParams {
    unsigned short command;
    unsigned short external_offset;
    unsigned char external_length;
    unsigned char internal_type;
    unsigned short internal_offset;
};

enum InternalType {
    IT_uint0,
    IT_uint8,
    IT_uint16,
    IT_uint32,
    IT_uint64,
};

struct SmbParams params[] = {
/*
 USHORT DialectIndex;
 UCHAR SecurityMode;
 USHORT MaxMpxCount;
 USHORT MaxNumberVcs;
 ULONG MaxBufferSize;
 ULONG MaxRawSize;
 ULONG SessionKey;
 ULONG Capabilities;
 FILETIME SystemTime;
 SHORT ServerTimeZone;
 UCHAR ChallengeLength;
 */
    {0x72,  0,   2, IT_uint16, offsetof(struct Smb72_Negotiate, DialectIndex)},
    {0x72,  2,   1, IT_uint8,  offsetof(struct Smb72_Negotiate, SecurityMode)},
    //{0x72,  3,   2, IT_uint16, offsetof(struct Smb72_Negotiate, MaxMpxCount)},
    //{0x72,  5,   2, IT_uint16, offsetof(struct Smb72_Negotiate, MaxNumberVcs)},
    //{0x72,  7,   4, IT_uint32, offsetof(struct Smb72_Negotiate, MaxBufferSize)},
    //{0x72, 11,   4, IT_uint32, offsetof(struct Smb72_Negotiate, MaxRawSize)},
    {0x72, 15,   4, IT_uint32, offsetof(struct Smb72_Negotiate, SessionKey)},
    {0x72, 19,   4, IT_uint32, offsetof(struct Smb72_Negotiate, Capabilities)},
    {0x72, 23,   8, IT_uint64, offsetof(struct Smb72_Negotiate, SystemTime)},
    {0x72, 31,   2, IT_uint16, offsetof(struct Smb72_Negotiate, ServerTimeZone)},
    {0x72, 33,   1, IT_uint8,  offsetof(struct Smb72_Negotiate, ChallengeLength)},
    
    {0x73,  6,   2, IT_uint16, offsetof(struct Smb73_Setup, BlobLength)},
    
    {0xFF, 0,  0xFF, IT_uint0,  0},
    
};

#define memberat(t, s, offset) (t*)((char*)(s)+(offset))


static const char
smb1_hello_template[] = {
    0x00, 0x00, 0x00, 0x45, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02,
    0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
    0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20,
    0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
    0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f,
    0x00
    
};

static const char
smb1_hello_template_v1[] = {
    0x00, 0x00, 0x00, 0x45, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00,
    0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
    0x02, 0x54, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,
    0x02, 0x54, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00
};

void smb_set_hello_v1(struct ProtocolParserStream *smb)
{
    smb->hello = smb1_hello_template_v1;
    smb->hello_length = sizeof(smb1_hello_template_v1);
}

static unsigned char smb1_null_session_setup[] = {
    0x00, 0x00, 0x00, 0x7e, 0xff, 0x53, 0x4d, 0x42,
    0x73, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x01, 0x00, 0x0d, 0xff, 0x00, 0x00,
    0x00, 0x04, 0x41, 0x32, 0x00, 0xef, 0x00, 0x53,
    0x45, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x5c, 0xc0, 0x80, 0x00, 0x41,
    0x00, 0x00, 0x47, 0x00, 0x55, 0x00, 0x45, 0x00,
    0x53, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4d, 0x00, 0x61, 0x00, 0x63, 0x00, 0x20, 0x00,
    0x4f, 0x00, 0x53, 0x00, 0x20, 0x00, 0x58, 0x00,
    0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00,
    0x31, 0x00, 0x33, 0x00, 0x00, 0x00, 0x53, 0x00,
    0x4d, 0x00, 0x42, 0x00, 0x46, 0x00, 0x53, 0x00,
    0x20, 0x00, 0x33, 0x00, 0x2e, 0x00, 0x32, 0x00,
    0x00, 0x00
};

static char smb1_null_session_setup_ex[] = {
    0x00, 0x00, 0x00, 0xb8, 0xff, 0x53, 0x4d, 0x42,
    0x73, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x0c, 0xff, 0x00, 0x00,
    0x00, 0x04, 0x41, 0x32, 0x00, 0xf1, 0x00, 0xa5,
    0x12, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x5c, 0xc0, 0x80, 0x80, 0x7d, 0x00, 0x60,
    0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05,
    0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30,
    0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a, 0x04,
    0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x02, 0x88,
    0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x01, 0xb0, 0x1d, 0x0f, 0x00, 0x00,
    0x00, 0x00, 0x4d, 0x00, 0x61, 0x00, 0x63, 0x00,
    0x20, 0x00, 0x4f, 0x00, 0x53, 0x00, 0x20, 0x00,
    0x58, 0x00, 0x20, 0x00, 0x31, 0x00, 0x30, 0x00,
    0x2e, 0x00, 0x31, 0x00, 0x33, 0x00, 0x00, 0x00,
    0x53, 0x00, 0x4d, 0x00, 0x42, 0x00, 0x46, 0x00,
    0x53, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2e, 0x00,
    0x32, 0x00, 0x00, 0x00
};

char smb2_negotiate_request[] = {
    0x00, 0x00, 0x00, 0x6c, 0xfe, 0x53, 0x4d, 0x42,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00,
    0x17, 0x97, 0x90, 0x40, 0xcd, 0xf0, 0x5e, 0x31,
    0x8d, 0xea, 0xef, 0x98, 0xcd, 0xa5, 0x08, 0xda,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03
};
char smb2_null_session_setup[] = {
    0x00, 0x00, 0x00, 0xa2, 0xfe, 0x53, 0x4d, 0x42,
    0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x02,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x58, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x60, 0x48, 0x06, 0x06,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e,
    0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
    0x02, 0x0a, 0xa2, 0x2a, 0x04, 0x28, 0x4e, 0x54,
    0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x15, 0x82, 0x88, 0x62, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01,
    0xb0, 0x1d, 0x0f, 0x00, 0x00, 0x00
};

/*****************************************************************************
 *
 * ****** WARNING: UGLY HACK !!!! ******
 *
 * This code is an ugly hack so I can express SMB parameters (word_count)
 * headers as a structure instead of writing individual parsers for them.
 * This code makes no sense. If you find a bug in it, it's probably worth
 * rewriting rather than figure out its convoluted logic. No really, I mean
 * this.
 *
 *****************************************************************************/
static size_t
smb_params_parse(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max)
{
    size_t original_offset = offset;
    size_t c;
    
    if (max > offset + (smb->hdr.smb1.param_length - smb->hdr.smb1.param_offset))
        max = offset + (smb->hdr.smb1.param_length - smb->hdr.smb1.param_offset);
    
    
    /* Find the correct header */
    for (c=0; params[c].command != smb->hdr.smb1.command && params[c].command != 0xFF; c++)
        ;
    
    for (; offset < max; offset++, smb->hdr.smb1.param_offset++) {
        again:
        
        //printf("\n%u/%u %u\n", (unsigned)smb->hdr.smb1.param_offset, (unsigned)smb->hdr.smb1.param_length, (unsigned)c);
        
        /* If we've gone past our header, just continue consuming bytes */
        if (params[c].command != smb->hdr.smb1.command)
            continue;
        
        /* If we've gone past the end of this field, goto next field */
        if (params[c].external_offset + params[c].external_length <= smb->hdr.smb1.param_offset) {
            c++;
            goto again;
        }
        /* Haven't reached the next field yet */
        if (params[c].external_offset > smb->hdr.smb1.param_offset)
            continue;
        
        //printf("\n%u/%u %u [%02x]\n", (unsigned)smb->hdr.smb1.param_offset, (unsigned)smb->hdr.smb1.param_length, (unsigned)c, px[offset]);
        
        /* Shift the type, because all fields little-endian */
        switch (params[c].internal_type) {
            case IT_uint0:
            default:
                break;
            case IT_uint8:
            {
                uint8_t *x = memberat(uint8_t, &smb->parms, params[c].internal_offset);
                *x = px[offset];
            }
                break;
            case IT_uint16:
            {
                uint16_t *x = memberat(uint16_t, &smb->parms, params[c].internal_offset);
                //*x <<= 8;
                *x |= px[offset] << ((smb->hdr.smb1.param_offset - params[c].external_offset)*8);
            }
                break;
            case IT_uint32:
            {
                uint32_t *x = memberat(uint32_t, &smb->parms, params[c].internal_offset);
                //*x <<= 8;
                *x |= px[offset] << ((smb->hdr.smb1.param_offset - params[c].external_offset)*8);
            }
                break;
            case IT_uint64:
            {
                uint64_t *x = memberat(uint64_t, &smb->parms, params[c].internal_offset);
                //*x <<= 8;
                *x |= (uint64_t)px[offset] << (uint64_t)((smb->hdr.smb1.param_offset - params[c].external_offset)*8);
            }
                break;
        }
        
    }
    
    /* Return the number of bytes processed */
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static const unsigned long long TICKS_PER_SECOND = 10000000LL;
static const unsigned long long EPOCH_DIFFERENCE = 11644473600LL;
static time_t
convert_windows_time(long long int filetime)
{
    unsigned long long seconds = filetime / TICKS_PER_SECOND;
    seconds -= EPOCH_DIFFERENCE;
    return (time_t)seconds;
}

/*****************************************************************************
 *****************************************************************************/



/*****************************************************************************
 *****************************************************************************/
static size_t
smb1_parse_negotiate1(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb1.byte_state;
    enum {
        D_NEGOT_CHALLENGE,
        D_NEGOT_DOMAINA_PRE,
        D_NEGOT_NAMEA_PRE,
        D_NEGOT_DOMAINA,
        D_NEGOT_NAMEA,
        D_NEGOT_ENDA,
        D_NEGOT_DOMAINU1,
        D_NEGOT_DOMAINU2,
        D_NEGOT_DOMAIN1,
        D_NEGOT_DOMAIN2,
        D_NEGOT_NAMEU1,
        D_NEGOT_NAMEU2,
        D_NEGOT_NAME1,
        D_NEGOT_NAME2,
        D_NEGOT_END,
        
        D_UNKNOWN,
    };
    
    if (max > offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset))
        max = offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset);
    
    for (;offset<max; offset++)
    switch (state) {
        case D_NEGOT_CHALLENGE:
            if (smb->parms.negotiate.ChallengeLength == 0) {
                if (smb->hdr.smb1.flags2 & 0x8000) {
                    state = D_NEGOT_DOMAINU1;
                } else {
                    state = D_NEGOT_DOMAINA_PRE;
                }
                offset--;
            } else
                smb->parms.negotiate.ChallengeLength--;
            break;
        case D_NEGOT_DOMAINU1:
        case D_NEGOT_NAMEU1:
            smb->hdr.smb1.unicode_char = px[offset];
            state++;
            break;
        case D_NEGOT_DOMAINU2:
            smb->hdr.smb1.unicode_char |= px[offset]<<8;
            if (smb->hdr.smb1.unicode_char == 0) {
                state = D_NEGOT_NAMEU1;
            } else {
                banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                state++;
            }
            break;
        case D_NEGOT_NAMEU2:
            smb->hdr.smb1.unicode_char |= px[offset]<<8;
            if (smb->hdr.smb1.unicode_char == 0) {
                state = D_NEGOT_END;
            } else {
                banout_append(banout, PROTO_SMB, " name=", AUTO_LEN);
                banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                state++;
            }
            break;
        case D_NEGOT_DOMAIN1:
        case D_NEGOT_NAME1:
            smb->hdr.smb1.unicode_char = px[offset];
            state++;
            break;
        case D_NEGOT_DOMAIN2:
        case D_NEGOT_NAME2:
            smb->hdr.smb1.unicode_char |= px[offset]<<8;
            if (smb->hdr.smb1.unicode_char == 0) {
                state++;
            } else {
                banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                state--;
            }
            break;
            
        case D_NEGOT_DOMAINA_PRE:
            if (px[offset] == 0) {
                state = D_NEGOT_NAMEA_PRE;
            } else {
                banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                banout_append_char(banout, PROTO_SMB, px[offset]);
                state = D_NEGOT_DOMAINA;
            }
            break;
        case D_NEGOT_NAMEA_PRE:
            if (px[offset] == 0) {
                state = D_NEGOT_END;
            } else {
                banout_append(banout, PROTO_SMB, " name=", AUTO_LEN);
                banout_append_char(banout, PROTO_SMB, px[offset]);
                state = D_NEGOT_NAMEA;
            }
            break;
        case D_NEGOT_DOMAINA:
        case D_NEGOT_NAMEA:
            if (px[offset] == 0) {
                state++;
            } else {
                banout_append_char(banout, PROTO_SMB, px[offset]);
            }
            break;
            
        default:
            break;
    }
    
    smb->hdr.smb1.byte_state = (unsigned short)state;
    smb->hdr.smb1.byte_offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static size_t
smb1_parse_setup1(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb1.byte_state;
    enum {
        D_PADDING,
        D_OSA1,
        D_OSA2,
        D_VERSIONA1,
        D_VERSIONA2,
        D_DOMAINA1,
        D_DOMAINA2,
        D_ENDA,
        
        D_OSU1,
        D_OSU2,
        D_OSU3,
        D_OSU4,
        D_VERSION1,
        D_VERSION2,
        D_VERSION3,
        D_VERSION4,
        D_DOMAIN1,
        D_DOMAIN2,
        D_DOMAIN3,
        D_DOMAIN4,
        
        D_UNKNOWN,
    };
    
    if (max > offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset))
        max = offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset);
    
    for (;offset<max; offset++) {
        
        switch (state) {
            case D_PADDING:
                if (smb->hdr.smb1.flags2 & 0x8000) {
                    state = D_OSU1;
                } else {
                    state = D_OSA1;
                }
                break;
            case D_OSA1:
                if (px[offset] == 0)
                    state = D_VERSIONA1;
                else {
                    banout_append(banout, PROTO_SMB, " os=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_OSA2;
                }
                break;
            case D_OSA2:
                if (px[offset] == 0)
                    state = D_VERSIONA1;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;

            case D_VERSIONA1:
                if (px[offset] == 0)
                    state = D_DOMAINA1;
                else {
                    banout_append(banout, PROTO_SMB, " ver=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_VERSIONA2;
                }
                break;
            case D_VERSIONA2:
                if (px[offset] == 0)
                    state = D_DOMAINA1;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;
            case D_DOMAINA1:
                if (px[offset] == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_DOMAINA2;
                }
                break;
            case D_DOMAINA2:
                if (px[offset] == 0)
                    state = D_UNKNOWN;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;

            case D_OSU1:
            case D_OSU3:
            case D_VERSION1:
            case D_VERSION3:
            case D_DOMAIN1:
            case D_DOMAIN3:
                smb->hdr.smb1.unicode_char = px[offset];
                state++;
                break;
                
            case D_OSU2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_VERSION1;
                else {
                    banout_append(banout, PROTO_SMB, " os=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_OSU3;
                }
                break;
                
            case D_OSU4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_VERSION1;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;
                

            case D_VERSION2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_DOMAIN1;
                else {
                    banout_append(banout, PROTO_SMB, " ver=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_VERSION3;
                }
                break;

            case D_VERSION4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_DOMAIN1;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;

            case D_DOMAIN2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_DOMAIN3;
                }
                break;

            case D_DOMAIN4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;
          default:
                break;
        }
    }
    
    smb->hdr.smb1.byte_state = (unsigned short)state;
    smb->hdr.smb1.byte_offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}
/*****************************************************************************
 *****************************************************************************/
static size_t
smb1_parse_setup2(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb1.byte_state;
    enum {
        D_BLOB,
        D_PADDING,
        D_PADDING2,
        D_OSA1,
        D_OSA2,
        D_VERSIONA1,
        D_VERSIONA2,
        D_DOMAINA1,
        D_DOMAINA2,
        D_ENDA,
        
        D_OSU1,
        D_OSU2,
        D_OSU3,
        D_OSU4,
        D_VERSION1,
        D_VERSION2,
        D_VERSION3,
        D_VERSION4,
        D_DOMAIN1,
        D_DOMAIN2,
        D_DOMAIN3,
        D_DOMAIN4,
        
        D_UNKNOWN,
    };
    
    if (max > offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset))
        max = offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset);
    
    for (;offset<max; offset++) {
        
        switch (state) {
            case D_BLOB:
                if (smb->parms.setup.BlobOffset == 0) {
                    spnego_decode_init(&smb->spnego, smb->parms.setup.BlobLength);
                }
            {
                size_t new_max = max;
                if (new_max > offset + smb->parms.setup.BlobLength - smb->parms.setup.BlobOffset)
                    new_max = offset + smb->parms.setup.BlobLength - smb->parms.setup.BlobOffset;
                spnego_decode(&smb->spnego, px+offset, new_max-offset, banout);
                
                smb->parms.setup.BlobOffset += (uint16_t)(new_max-offset);
                offset = new_max;
                if (smb->parms.setup.BlobLength - smb->parms.setup.BlobOffset == 0) {
                    offset--;
                    state = D_PADDING;
                }
            }
                break;
            case D_PADDING:
                /* If the blog length is odd, then there is no padding. Otherwise,
                 * there is one byte of padding */
                //if (smb->parms.setup.BlobLength & 1)
                    offset--;
                state = D_PADDING2;
                break;
            case D_PADDING2:
                if (smb->hdr.smb1.flags2 & 0x8000) {
                    state = D_OSU1;
                } else {
                    state = D_OSA1;
                }
                offset--;
                break;
            case D_OSA1:
                if (px[offset] == 0)
                    state = D_VERSIONA1;
                else {
                    banout_append(banout, PROTO_SMB, " os=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_OSA2;
                }
                break;
            case D_OSA2:
                if (px[offset] == 0)
                    state = D_VERSIONA1;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;
                
            case D_VERSIONA1:
                if (px[offset] == 0)
                    state = D_DOMAINA1;
                else {
                    banout_append(banout, PROTO_SMB, " ver=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_VERSIONA2;
                }
                break;
            case D_VERSIONA2:
                if (px[offset] == 0)
                    state = D_DOMAINA1;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;
            case D_DOMAINA1:
                if (px[offset] == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                    state = D_DOMAINA2;
                }
                break;
            case D_DOMAINA2:
                if (px[offset] == 0)
                    state = D_UNKNOWN;
                else
                    banout_append_char(banout, PROTO_SMB, px[offset]);
                break;
                
            case D_OSU1:
            case D_OSU3:
            case D_VERSION1:
            case D_VERSION3:
            case D_DOMAIN1:
            case D_DOMAIN3:
                smb->hdr.smb1.unicode_char = px[offset];
                state++;
                break;
                
            case D_OSU2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_VERSION1;
                else {
                    banout_append(banout, PROTO_SMB, " os=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_OSU3;
                }
                break;
                
            case D_OSU4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_VERSION1;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;
                
                
            case D_VERSION2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_DOMAIN1;
                else {
                    banout_append(banout, PROTO_SMB, " ver=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_VERSION3;
                }
                break;
                
            case D_VERSION4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_DOMAIN1;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;
                
            case D_DOMAIN2:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append(banout, PROTO_SMB, " domain=", AUTO_LEN);
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state = D_DOMAIN3;
                }
                break;
                
            case D_DOMAIN4:
                smb->hdr.smb1.unicode_char |= px[offset]<<8;
                if (smb->hdr.smb1.unicode_char == 0)
                    state = D_UNKNOWN;
                else {
                    banout_append_unicode(banout, PROTO_SMB, smb->hdr.smb1.unicode_char);
                    state--;
                }
                break;
            default:
                break;
        }
    }
    
    smb->hdr.smb1.byte_state = (unsigned short)state;
    smb->hdr.smb1.byte_offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static size_t
smb1_parse_negotiate2(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb1.byte_state;
    
    UNUSEDPARM(banout);

    if (max > offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset))
        max = offset + (smb->hdr.smb1.byte_count - smb->hdr.smb1.byte_offset);
    
    for (;offset<max; offset++)
        switch (state) {
            case 0:
                state = 1;
                break;
            default:
                break;
        }
    
    smb->hdr.smb1.byte_state = (unsigned short)state;
    smb->hdr.smb1.byte_offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}


/*****************************************************************************
 * A default parser for SMBv2 structs. The simplest implementation would be
 * to sipmly skip the "struct_length" bytes. However, we have all this
 * extra code to serve as a template for creating additional functions.
 *****************************************************************************/
static size_t
smb2_parse_response(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb2.state;
    
    UNUSEDPARM(banout);
    UNUSEDPARM(px);

    if (max > offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset))
        max = offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset);
    
    for (;offset<max; offset++)
        switch (state) {
            default:
                break;
        }
    
    smb->hdr.smb2.state = (unsigned short)state;
    smb->hdr.smb2.offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static size_t
smb2_parse_negotiate(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb2.state;
    
    enum {
        N_SECMOD1, N_SECMOD2,
        N_DIALECT1, N_DIALECT2,
        N_CONTEXTS1, N_CONTEXTS2,
        N_GUID01, N_GUID02, N_GUID03, N_GUID04,
        N_GUID05, N_GUID06, N_GUID07, N_GUID08,
        N_GUID09, N_GUID10, N_GUID11, N_GUID12,
        N_GUID13, N_GUID14, N_GUID15, N_GUID16,
        N_CAP1, N_CAP2, N_CAP3, N_CAP4,
        N_TRANSACTSIZE1, N_TRANSACTSIZE2, N_TRANSACTSIZE3, N_TRANSACTSIZE4,
        N_READSIZE1, N_READSIZE2, N_READSIZE3, N_READSIZE4,
        N_WRITESIZE1, N_WRITESIZE2, N_WRITESIZE3, N_WRITESIZE4,
        N_TIME1, N_TIME2, N_TIME3, N_TIME4,
        N_TIME5, N_TIME6, N_TIME7, N_TIME8,
        N_BOOT1, N_BOOT2, N_BOOT3, N_BOOT4,
        N_BOOT5, N_BOOT6, N_BOOT7, N_BOOT8,
        N_BLOB_OFFSET1, N_BLOB_OFFSET2,
        N_BLOB_LENGTH1, N_BLOB_LENGTH2,
    };
    /*
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Buffer Code          |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-+-+-+                                               +-+-+-+-+
    |                             Server                            |
    +-+-+-+-+                      GUID                     +-+-+-+-+
    |                                                               |
    +-+-+-+-+                                               +-+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-+-+-+                  Current Time                 +-+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-+-+-+                   Boot Time                   +-+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Sec Blob Offset        |        Sec Blob Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |               |               |               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Sec Blob  ANS.1/DER encoded blob containing supported authentication mechanisms
    +-+-+-+-+...
    */
    
    if (max > offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset))
        max = offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset);
    
    for (;offset<max; offset++)
        switch (state) {
            case N_SECMOD1: case N_SECMOD2:
            case N_DIALECT1: case N_DIALECT2:
            case N_CONTEXTS1:
                state++;
                break;
            case N_CONTEXTS2:
                if (!smb->is_printed_guid)
                    banout_append(banout, PROTO_SMB, " guid=", AUTO_LEN);
                state++;
                break;
            case N_GUID01:
            case N_GUID05:
            case N_GUID07:
                smb->hdr.smb2.number = px[offset];
                state++;
                break;
            case N_GUID02: case N_GUID03: case N_GUID04:
                smb->hdr.smb2.number |= px[offset] << (8*(state-N_GUID01));
                if (state == N_GUID04 && !smb->is_printed_guid) {
                    banout_append_hexint(banout, PROTO_SMB, smb->hdr.smb2.number, 8);
                    banout_append_char(banout, PROTO_SMB, '-');
                }
                state++;
                break;
            case N_GUID06:
            case N_GUID08:
                smb->hdr.smb2.number |= px[offset] << 8;
                if (!smb->is_printed_guid) {
                    banout_append_hexint(banout, PROTO_SMB, smb->hdr.smb2.number, 4);
                    banout_append_char(banout, PROTO_SMB, '-');
                }
                state++;
                break;
            case N_GUID10:
                if (!smb->is_printed_guid) {
                    banout_append_hexint(banout, PROTO_SMB, px[offset], 2);
                    banout_append_char(banout, PROTO_SMB, '-');
                }
                state++;
                break;
            case N_GUID09: case N_GUID11: case N_GUID12:
            case N_GUID13: case N_GUID14: case N_GUID15: case N_GUID16:
                if (!smb->is_printed_guid)
                    banout_append_hexint(banout, PROTO_SMB, px[offset], 2);
                if (state == N_GUID16)
                    smb->is_printed_guid = 1;
                state++;
                break;
            case N_CAP1: case N_CAP2: case N_CAP3: case N_CAP4:
            case N_TRANSACTSIZE1: case N_TRANSACTSIZE2: case N_TRANSACTSIZE3: case N_TRANSACTSIZE4:
            case N_READSIZE1: case N_READSIZE2: case N_READSIZE3: case N_READSIZE4:
            case N_WRITESIZE1: case N_WRITESIZE2: case N_WRITESIZE3: case N_WRITESIZE4:
                state++;
                break;
            case N_TIME1: case N_TIME2: case N_TIME3: case N_TIME4:
            case N_TIME5: case N_TIME6: case N_TIME7: case N_TIME8:
                smb->parms.negotiate2.current_time |= ((uint64_t)px[offset]<<(uint64_t)((state-N_TIME1)*8));
                if (state == N_TIME8 && !smb->is_printed_time) {
                    char str[64] = "(err)";
                    time_t timestamp = convert_windows_time(smb->parms.negotiate2.current_time);
                    struct tm tm = {0};
                    size_t len;
                    
                    gmtime_s(&tm, &timestamp);
                    len = strftime(str, sizeof(str), " time=%Y-%m-%d %H:%M:%S ", &tm);
                    banout_append(banout, PROTO_SMB, str, len);
                    smb->is_printed_time = 1;
                }
                state++;
                break;
            case N_BOOT1: case N_BOOT2: case N_BOOT3: case N_BOOT4:
            case N_BOOT5: case N_BOOT6: case N_BOOT7: case N_BOOT8:
                smb->parms.negotiate2.boot_time |= (px[offset]<<((state-N_BOOT1)*8));
                state++;
                break;
            case N_BLOB_OFFSET1:
                smb->hdr.smb2.blob_offset = px[offset];
                state++;
                break;
            case N_BLOB_OFFSET2:
                smb->hdr.smb2.blob_offset |= (px[offset]<<8);
                state++;
                break;
            case N_BLOB_LENGTH1:
                smb->hdr.smb2.blob_length = px[offset];
                state++;
                break;
            case N_BLOB_LENGTH2:
                smb->hdr.smb2.blob_length |= (px[offset]<<8);
                state++;
                break;
            default:
                break;
        }
    
    smb->hdr.smb2.state = (unsigned short)state;
    smb->hdr.smb2.offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static size_t
smb2_parse_setup(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb2.state;
    
    /*
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Buffer Code          |           Flags               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Sec Blob Offset        |        Sec Blob Length        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Sec Blob
     +-+-+-+-+...
     */
    enum {
        N_FLAGS1, N_FLAGS2,
        N_BLOB_OFFSET1, N_BLOB_OFFSET2,
        N_BLOB_LENGTH1, N_BLOB_LENGTH2,

    };

    UNUSEDPARM(banout);

    if (max > offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset))
        max = offset + (smb->hdr.smb2.struct_length - smb->hdr.smb2.offset);
    
    for (;offset<max; offset++)
        switch (state) {
            case N_FLAGS1: case N_FLAGS2:
                state++;
                break;
            case N_BLOB_OFFSET1:
                smb->hdr.smb2.blob_offset = px[offset];
                state++;
                break;
            case N_BLOB_OFFSET2:
                smb->hdr.smb2.blob_offset |= (px[offset]<<8);
                state++;
                break;
            case N_BLOB_LENGTH1:
                smb->hdr.smb2.blob_length = px[offset];
                state++;
                break;
            case N_BLOB_LENGTH2:
                smb->hdr.smb2.blob_length |= (px[offset]<<8);
                state++;
                break;
            default:
                break;
        }
    
    smb->hdr.smb2.state = (unsigned short)state;
    smb->hdr.smb2.offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}



/*****************************************************************************
 *****************************************************************************/
static size_t
smb2_parse_header(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->hdr.smb2.state;
    enum {
        SMB2_CRED_CHARGE1, SMB2_CRED_CHARG2,
        SMB2_STATUS1, SMB2_STATUS2, SMB2_STATUS3, SMB2_STATUS4,
        SMB2_OPCODE1, SMB2_OPCODE2,
        SMB2_CRED_GRANT1, SMB2_CRED_GRANT2,
        SMB2_FLAGS1, SMB2_FLAGS2, SMB2_FLAGS3, SMB2_FLAGS4,
        SMB2_CHAIN_OFFSET1, SMB2_CHAIN_OFFSET2,
        SMB2_CHAIN_OFFSET3, SMB2_CHAIN_OFFSET4,
        SMB2_MSGID1, SMB2_MSGID2, SMB2_MSGID3, SMB2_MSGID4,
        SMB2_MSGID5, SMB2_MSGID6, SMB2_MSGID7, SMB2_MSGID8,
        SMB2_PID1, SMB2_PID2, SMB2_PID3, SMB2_PID4,
        SMB2_TID1, SMB2_TID2, SMB2_TID3, SMB2_TID4,
        SMB2_SESSID1, SMB2_SESSID2, SMB2_SESSID3, SMB2_SESSID4,
        SMB2_SIG01, SMB2_SIG02, SMB2_SIG03, SMB2_SIG04,
        SMB2_SIG05, SMB2_SIG06, SMB2_SIG07, SMB2_SIG08,
        SMB2_SIG09, SMB2_SIG10, SMB2_SIG11, SMB2_SIG12,
        SMB2_SIG13, SMB2_SIG14, SMB2_SIG15, SMB2_SIG16,
        SMB2_ERROR
    };
    /*
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     0xFE      |      'S'      |      'M'      |      'B'      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Header Length        |           (padding)           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          NT_Status                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |            Opcode             |            (padding)          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |       :S:C:P:R|               |               |               |    Flags
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Chain Offset                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Command Sequence-                      |
     +-+-+-+-+-+-+                                     +-+-+-+-+-+-+-+
     |                             Number                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Process ID                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                            Tree ID                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +-+-+-+-+                    User ID                    +-+-+-+-+
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     +-+-+-+-+                                               +-+-+-+-+
     |                                                               |
     +-+-+-+-+                   Signature                   +-+-+-+-+
     |                                                               |
     +-+-+-+-+                                               +-+-+-+-+
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    
    if (max > offset + (smb->hdr.smb2.header_length - smb->hdr.smb2.offset))
        max = offset + (smb->hdr.smb2.header_length - smb->hdr.smb2.offset);
    
    for (;offset<max; offset++)
        switch (state) {
            case SMB2_CRED_CHARGE1: case SMB2_CRED_CHARG2:
                state++;
                break;
            case SMB2_STATUS1: case SMB2_STATUS2:
            case SMB2_STATUS3: case SMB2_STATUS4:
                smb->hdr.smb2.ntstatus |= (px[offset] << ((state - SMB2_STATUS1)*8));
                state++;
                break;
            case SMB2_OPCODE1: case SMB2_OPCODE2:
                smb->hdr.smb2.opcode |= (px[offset] << ((state - SMB2_OPCODE1)*8));
                state++;
                break;
            case SMB2_CRED_GRANT1: case SMB2_CRED_GRANT2:
                state++;
                break;
            case SMB2_FLAGS1:
                smb->hdr.smb2.flags = px[offset];
                if ((smb->hdr.smb2.flags & 1) == 0) {
                    banout_append(banout, PROTO_SMB, " PARSERROR[flags] ", AUTO_LEN);
                    state = SMB2_ERROR;
                } else
                    state++;
                break;
            case SMB2_FLAGS2: case SMB2_FLAGS3: case SMB2_FLAGS4:
            case SMB2_CHAIN_OFFSET1: case SMB2_CHAIN_OFFSET2:
            case SMB2_CHAIN_OFFSET3: case SMB2_CHAIN_OFFSET4:
                state++;
                break;
            case SMB2_MSGID1:
            case SMB2_MSGID2: case SMB2_MSGID3: case SMB2_MSGID4:
            case SMB2_MSGID5: case SMB2_MSGID6: case SMB2_MSGID7: case SMB2_MSGID8:
                smb->hdr.smb2.seqno |= (px[offset] << ((state - SMB2_MSGID1)*8));
                state++;
                break;
            case SMB2_PID1: case SMB2_PID2: case SMB2_PID3: case SMB2_PID4:
            case SMB2_TID1: case SMB2_TID2: case SMB2_TID3: case SMB2_TID4:
            case SMB2_SESSID1: case SMB2_SESSID2: case SMB2_SESSID3: case SMB2_SESSID4:
            case SMB2_SIG01: case SMB2_SIG02: case SMB2_SIG03: case SMB2_SIG04:
            case SMB2_SIG05: case SMB2_SIG06: case SMB2_SIG07: case SMB2_SIG08:
            case SMB2_SIG09: case SMB2_SIG10: case SMB2_SIG11: case SMB2_SIG12:
            case SMB2_SIG13: case SMB2_SIG14: case SMB2_SIG15: case SMB2_SIG16:
                state++;
                break;
                
            default:
                break;
        }
    
    smb->hdr.smb2.state = (unsigned short)state;
    smb->hdr.smb2.offset += (unsigned short)(offset - original_offset);
    return offset - original_offset;
}


/*****************************************************************************
 *****************************************************************************/
static size_t
smb_parse_smb(struct SMBSTUFF *smb, const unsigned char *px, size_t max, struct BannerOutput *banout,
                 struct InteractiveData *more)
{
    size_t len; /*scratch variables used in a couple places */
    unsigned state = smb->nbt_state;
    size_t i = 0;
    enum {
        SMB_VER,
        SMB1_VER_S, SMB1_VER_M, SMB1_VER_B,
        
        SMB1_CMD,
        SMB1_STATUS1, SMB1_STATUS2, SMB1_STATUS3, SMB1_STATUS4,
        SMB1_FLAGS1,
        SMB1_FLAGS2,
        SMB1_FLAGS3,
        SMB1_PID1, SMB1_PID2,
        SMB1_SIG1, SMB1_SIG2, SMB1_SIG3, SMB1_SIG4,
        SMB1_SIG5, SMB1_SIG6, SMB1_SIG7, SMB1_SIG8,
        SMB1_RSVD1,SMB1_RSVD2,
        SMB1_TID1, SMB1_TID2,
        SMB1_PID3, SMB1_PID4,
        SMB1_UID1, SMB1_UID2,
        SMB1_MID1, SMB1_MID2,
        SMB1_WORD_COUNT,
        SMB1_PARAMETERS,
        SMB1_BYTE_COUNT1,
        SMB1_BYTE_COUNT2,
        SMB1_DATA,
        SMB1_DATA_AFTER,
        /*
            UCHAR Protocol[4];
            UCHAR Command;
            SMB_ERROR Status;
            UCHAR Flags;
            USHORT Flags2;
            USHORT PIDHigh;
            UCHAR SecurityFeatures[8];
            USHORT Reserved;
            USHORT TID;
            USHORT PIDLow;
            USHORT UID;
            USHORT MID;
        */
        
        
        SMB2_VER_S, SMB2_VER_M, SMB2_VER_B,
        SMB2_HDR_LEN1, SMB2_HDR_LEN2,
        SMB2_PARSE_HEADER,
        SMB2_STRUCT_LEN1, SMB2_STRUCT_LEN2,
        SMB2_PARSE_STRUCT,
        SMB2_UNTIL_BLOB,
        SMB2_PARSE_BLOB,
        SMB2_PARSE_REMAINDER,
        
        SMB_ERROR,
     };
    
    if (max > i + smb->nbt_length)
        max = i + smb->nbt_length;

    
    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (; i<max; i++)
    switch (state) {
        case SMB_VER:
            switch (px[i]) {
                case 0xFF:
                    if (!smb->is_printed_ver)
                        banout_append(banout, PROTO_SMB, "SMBv1 ", AUTO_LEN);
                    smb->is_printed_ver = 1;
                    state = SMB1_VER_S;
                    break;
                case 0xFE:
                    if (!smb->is_printed_ver)
                        banout_append(banout, PROTO_SMB, "SMBv2 ", AUTO_LEN);
                    smb->is_printed_ver = 1;
                    state = SMB2_VER_S;
                    break;
                default:
                    if (!smb->is_printed_ver)
                        banout_append(banout, PROTO_SMB, "SMBv? ", AUTO_LEN);
                    smb->is_printed_ver = 1;
                    state = SMB_ERROR;
            }
            break;
        case SMB1_VER_S:
        case SMB2_VER_S:
            if (px[i] != 'S')
                state = SMB_ERROR;
            else
                state++;
            break;
        case SMB1_VER_M:
        case SMB2_VER_M:
            if (px[i] != 'M')
                state = SMB_ERROR;
            else
                state++;
            break;
        case SMB1_VER_B:
        case SMB2_VER_B:
            if (px[i] != 'B')
                state = SMB_ERROR;
            else
                state++;
            break;
            
        case SMB1_CMD:
            memset(&smb->hdr, 0, sizeof(smb->hdr));
            smb->hdr.smb1.command = px[i];
            state++;
            break;
        case SMB1_STATUS1: case SMB1_STATUS2: case SMB1_STATUS3: case SMB1_STATUS4:
            smb->hdr.smb1.status <<= 8;
            smb->hdr.smb1.status |= px[i];
            state++;
            break;
        case SMB1_FLAGS1:
            smb->hdr.smb1.flags1 = px[i];
            state++;
            break;
        case SMB1_FLAGS2:
            smb->hdr.smb1.flags2 = px[i];
            state++;
            break;
        case SMB1_FLAGS3:
            smb->hdr.smb1.flags2 |= px[i]<<8;
            state++;
            break;
        case SMB1_PID1: case SMB1_PID2:
            smb->hdr.smb1.pid <<= 8;
            smb->hdr.smb1.pid |= px[i];
            state++;
            break;
        case SMB1_SIG1: case SMB1_SIG2: case SMB1_SIG3: case SMB1_SIG4:
        case SMB1_SIG5: case SMB1_SIG6: case SMB1_SIG7: case SMB1_SIG8:
            state++;
            break;
        case SMB1_RSVD1:case SMB1_RSVD2:
            state++;
            break;
        case SMB1_TID1: case SMB1_TID2:
            smb->hdr.smb1.tid <<= 8;
            smb->hdr.smb1.tid |= px[i];
            state++;
            break;
        case SMB1_PID3: case SMB1_PID4:
            smb->hdr.smb1.pid <<= 8;
            smb->hdr.smb1.pid |= px[i];
            state++;
            break;
        case SMB1_UID1: case SMB1_UID2:
            smb->hdr.smb1.uid <<= 8;
            smb->hdr.smb1.uid |= px[i];
            state++;
            break;
        case SMB1_MID1: case SMB1_MID2:
            smb->hdr.smb1.mid <<= 8;
            smb->hdr.smb1.mid |= px[i];
            state++;
            break;
        case SMB1_WORD_COUNT:
            smb->hdr.smb1.param_length = px[i]*2;
            memset(&smb->parms, 0, sizeof(smb->parms));
            state++;
            break;
        case SMB1_PARAMETERS:
            /* Transfer control to a sub-parser, which may consume zero
             * or more bytes, up to the end of the parameters field
             * (meaning, up to word_count*2 bytes) */
            len = smb_params_parse(smb, px, i, max);
            i += len;
            if (smb->hdr.smb1.param_offset < smb->hdr.smb1.param_length)
                break;
            
            /* We've reached the end of the parameters field, so go onto 
             * read the byte-count/data field */
            state = SMB1_BYTE_COUNT1;
            
            /* Unconsume the next byte. The "word-count" field may have been
             * zero when we get to this state, so therefore the logic needs
             * to be written to handle this. That means when we loop around
             * again, we need to counter-act the fact that we will automatically
             * increment the index, so we substract one from it here. */
            i--;
            
            /* Process the parameter/word-count field according to what it
             * actually contained
             * TODO: I should make this a function, but I'm lazy 
             */
            switch (smb->hdr.smb1.command) {
                case 0x72:
                    if (!smb->is_printed_time) {
                        char str[64] = "(err)";
                        time_t timestamp = convert_windows_time(smb->parms.negotiate.SystemTime);
                        struct tm tm = {0};
                        
                        gmtime_s(&tm, &timestamp);
                        
                        len = strftime(str, sizeof(str), " time=%Y-%m-%d %H:%M:%S", &tm);
                        banout_append(banout, PROTO_SMB, str, len);
                        sprintf_s(str, sizeof(str), " TZ=%+d ", (short)smb->parms.negotiate.ServerTimeZone);
                        banout_append(banout, PROTO_SMB, str, AUTO_LEN);
                        
                        smb->is_printed_time = 1;
                    }
                    smb->hdr.smb1.byte_state = 0;
                    
                    if (smb->hdr.smb1.flags2 & 0x0800) {
                        tcp_transmit(more, smb1_null_session_setup_ex, sizeof(smb1_null_session_setup_ex), 0);
                    } else {
                        if (smb->parms.negotiate.SessionKey) {
                            unsigned char *buf;
                            
                            buf = tcp_transmit_alloc(more, sizeof(smb1_null_session_setup));
                            
                            memcpy(buf, smb1_null_session_setup, sizeof(smb1_null_session_setup));
                            buf[0x2f] = (unsigned char)(smb->parms.negotiate.SessionKey>> 0) & 0xFF;
                            buf[0x30] = (unsigned char)(smb->parms.negotiate.SessionKey>> 8) & 0xFF;
                            buf[0x31] = (unsigned char)(smb->parms.negotiate.SessionKey>>16) & 0xFF;
                            buf[0x32] = (unsigned char)(smb->parms.negotiate.SessionKey>>24) & 0xFF;
                            tcp_transmit(more, buf, sizeof(smb1_null_session_setup), TCPTRAN_DYNAMIC);
                            
                            /* NOTE: the following line is here to silence LLVM warnings about a potential
                             * memory leak. The 'tcp_transmit' function 'adopts' the pointer and will be
                             * responsible for freeing it after the packet gets successfully transmitted */
                            buf = 0;
                        } else {
                            tcp_transmit(more, smb1_null_session_setup, sizeof(smb1_null_session_setup), 0);
                        }
                    }
                
                    break;
                case 0x73: /* session setup and x */
                    break;
                default:
                    banout_append(banout, PROTO_SMB, " PARSERR(unknown-resonse) ", AUTO_LEN);
                    smb->hdr.smb1.byte_state = 0;
            }
            
            break;
            
        case SMB1_BYTE_COUNT1:
            smb->hdr.smb1.byte_count = px[i];
            state++;
            break;
        case SMB1_BYTE_COUNT2:
            smb->hdr.smb1.byte_count |= px[i]<<8;
            state++;
            break;
        case SMB1_DATA:
            switch (smb->hdr.smb1.command) {
                case 0x72:
                    if ((smb->hdr.smb1.flags2 & 0x0800) > 0 && smb->parms.negotiate.ChallengeLength == 0)
                        i += smb1_parse_negotiate2(smb, px, i, max, banout);
                    else
                        i += smb1_parse_negotiate1(smb, px, i, max, banout);
                    break;
                case 0x73: /* session setup and x */
                    if ((smb->hdr.smb1.flags2 & 0x0800) > 0 || smb->parms.setup.BlobLength)
                        i += smb1_parse_setup2(smb, px, i, max, banout);
                    else
                        i += smb1_parse_setup1(smb, px, i, max, banout);
                    break;
                default:
                    ;
            }
            if (smb->hdr.smb1.byte_offset >= smb->hdr.smb1.byte_count) {
                state = SMB1_DATA_AFTER;
                i--; /* unconsume byte because of auto-increment */
                
                /* close the connection, we've found all we can */
                if (smb->hdr.smb1.command == 0x73)
                    tcp_close(more);
            }
            break;
            
        case SMB1_DATA_AFTER:
            if (i < max) {
                ;
            } else {
                state = 0;
                i--;
            }
            break;
    
        case SMB2_HDR_LEN1:
            memset(&smb->hdr, 0, sizeof(smb->hdr));
            smb->hdr.smb2.header_length = px[i];
            state++;
            break;
            
        case SMB2_HDR_LEN2:
            smb->hdr.smb2.header_length |= (px[i]<<8);
            if (smb->hdr.smb2.header_length < 12) {
                banout_append(banout, PROTO_SMB, " PARSERROR[hdrlen] ", AUTO_LEN);
                state = SMB_ERROR;
            } else {
                smb->hdr.smb2.offset = 6;
                state++;
            }
            break;
            
        case SMB2_PARSE_HEADER:
            i += smb2_parse_header(smb, px, i, max, banout);
            if (smb->hdr.smb2.offset >= smb->hdr.smb2.header_length) {
                state++;
                i--;
            }
            break;
        case SMB2_STRUCT_LEN1:
            smb->hdr.smb2.struct_length = px[i];
            state++;
            break;
            
        case SMB2_STRUCT_LEN2:
            smb->hdr.smb2.struct_length |= (px[i]<<8);
            smb->hdr.smb2.is_dynamic = (smb->hdr.smb2.struct_length&1);
            smb->hdr.smb2.struct_length &= 0xFFFe;
            smb->hdr.smb2.state = 0;
            smb->hdr.smb2.offset = 2;
            memset(&smb->parms, 0, sizeof(smb->parms));
            if (smb->hdr.smb2.struct_length < 2) {
                banout_append(banout, PROTO_SMB, " PARSERROR[structlen] ", AUTO_LEN);
                state = SMB_ERROR;
            } else
                state++;
            break;
        case SMB2_PARSE_STRUCT:
            /*
             * Parse the data portion
             */
            switch (smb->hdr.smb2.opcode) {
                case 0x00: /* Negotiate Response */
                    i += smb2_parse_negotiate(smb, px, i, max, banout);
                    break;
                case 0x01: /* Session Setup */
                    i += smb2_parse_setup(smb, px, i, max, banout);
                    break;
                default:
                    i += smb2_parse_response(smb, px, i, max, banout);
                    break;
            }
            
            /*
             * Respond if necessary
             */
            if (smb->hdr.smb2.offset >= smb->hdr.smb2.struct_length) {
                switch (smb->hdr.smb2.opcode) {
                    case 0x00: /* negoiate response */
                        if (smb->hdr.smb2.seqno == 0) {
                            tcp_transmit(more, smb2_negotiate_request, sizeof(smb2_negotiate_request), 0);
                        } else if (smb->hdr.smb2.seqno == 1) {
                            tcp_transmit(more, smb2_null_session_setup, sizeof(smb2_null_session_setup), 0);
                        }
                        break;
                    default:
                        ;
                }
                i--;
                
                /*
                 * Process security blob
                 */
                if (smb->hdr.smb2.blob_length == 0)
                    state = SMB2_PARSE_REMAINDER;
                else if (smb->hdr.smb2.blob_offset < smb->hdr.smb2.header_length + smb->hdr.smb2.struct_length) {
                    printf("\n***** parse error *****\n");
                    state = SMB2_PARSE_REMAINDER;
                } else {
                    smb->hdr.smb2.blob_offset -= smb->hdr.smb2.header_length;
                    smb->hdr.smb2.blob_offset -= smb->hdr.smb2.struct_length;
                    state = SMB2_UNTIL_BLOB;
                }
                
            }
            break;
        case SMB2_UNTIL_BLOB:
            if (smb->hdr.smb2.blob_offset == 0) {
                spnego_decode_init(&smb->spnego, smb->hdr.smb2.blob_length);
                i--;
                state = SMB2_PARSE_BLOB;
            } else
                smb->hdr.smb2.blob_offset--;
            break;
        case SMB2_PARSE_BLOB:
        {
            size_t new_max = max;
            if (new_max > i + smb->hdr.smb2.blob_length)
                new_max = i + smb->hdr.smb2.blob_length;
            spnego_decode(&smb->spnego, px+i, new_max-i, banout);
            
            smb->hdr.smb2.blob_length -= (unsigned short)(new_max-i);
            i = new_max;
            if (smb->hdr.smb2.blob_length == 0) {
                i--;
                state = SMB2_PARSE_REMAINDER;
                
                /* Close the connection when we get a SessionSetup response */
                if (smb->hdr.smb2.opcode == 1)
                    tcp_close(more);
            }
        }
            break;
        case SMB2_PARSE_REMAINDER:
        case SMB_ERROR:
        default:
            break;
    }

    smb->nbt_length -= (unsigned)i;
    smb->nbt_state = state;
    return i;
}


/*****************************************************************************

 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |      TYPE     |     FLAGS     |            LENGTH             |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 /               TRAILER (Packet Type Dependent)                 /
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *****************************************************************************/
static void
smb_parse_record(
                 const struct Banner1 *banner1,
                 void *banner1_private,
                 struct ProtocolState *pstate,
                 const unsigned char *px, size_t max,
                 struct BannerOutput *banout,
                 struct InteractiveData *more)
{
    size_t i;
    unsigned state = pstate->state;
    struct SMBSTUFF *smb = &pstate->sub.smb;

    enum {
        NBT_TYPE,
        NBT_FLAGS,
        NBT_LEN1,
        NBT_LEN2,
        NBT_ERR,
        NBT_SMB,
        NBT_DRAIN,
        NBT_UNKNOWN,
    };

    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    for (i=0; i<max; i++)
        switch (state) {
            case NBT_TYPE:
                if (smb->spnego.ntlmssp.buf)
                    ntlmssp_cleanup(&smb->spnego.ntlmssp);
                smb->nbt_type = px[i];
                state++;
                break;
            case NBT_FLAGS:
                smb->nbt_flags = px[i] & 0xFE;
                smb->nbt_length = px[i] & 0x01;
                state++;
                break;
            case NBT_LEN1:
                smb->nbt_length <<= 8;
                smb->nbt_length |= px[i];
                state++;
                break;
            case NBT_LEN2:
                smb->nbt_length <<= 8;
                smb->nbt_length |= px[i];
                state++;
                
                
                
                /*
                 00 -  SESSION MESSAGE
                 81 -  SESSION REQUEST
                 82 -  POSITIVE SESSION RESPONSE
                 83 -  NEGATIVE SESSION RESPONSE
                 84 -  RETARGET SESSION RESPONSE
                 85 -  SESSION KEEP ALIVE
                 */
                switch (smb->nbt_type) {
                    case 0x00:
                        state = NBT_SMB;
                        smb->nbt_state = 0;
                        break;
                    case 0x81:
                        banout_append(banout, PROTO_SMB, " PARSERR(nbt-sess) ", AUTO_LEN);
                        state = NBT_UNKNOWN;
                        break;
                    case 0x82:
                        tcp_transmit(more, smb1_hello_template, sizeof(smb1_hello_template), 0);
                        state = NBT_DRAIN;
                        break;
                    case 0x85:
                        state = NBT_DRAIN;
                        break;
                    case 0x83:
                        state = NBT_ERR;
                        break;
                    case 0x84:
                        banout_append(banout, PROTO_SMB, " PARSERR(nbt-retarget) ", AUTO_LEN);
                        state = NBT_UNKNOWN;
                        break;
                    default:
                        banout_append(banout, PROTO_SMB, "ERR unknown response", AUTO_LEN);
                        break;
                }
                break;
            case NBT_ERR:
                smb->nbt_err = px[i];
                /*
                 80 -  Not listening on called name
                 81 -  Not listening for calling name
                 82 -  Called name not present
                 83 -  Called name present, but insufficient resources
                 8F -  Unspecified error
                 */
                switch (smb->nbt_err) {
                    case 0x80:
                        banout_append(banout, PROTO_SMB, "ERROR(Not listening on called name)", AUTO_LEN);
                        break;
                    case 0x81:
                        banout_append(banout, PROTO_SMB, "ERROR(Not listening for calling name)", AUTO_LEN);
                        break;
                    case 0x82:
                        banout_append(banout, PROTO_SMB, "ERROR(Called name not present)", AUTO_LEN);
                        break;
                    case 0x83:
                        banout_append(banout, PROTO_SMB, "ERROR(Called name present, but insufficient resources)", AUTO_LEN);
                        break;
                    case 0x8F:
                        banout_append(banout, PROTO_SMB, "ERROR(Unspecified error)", AUTO_LEN);
                        break;
                    default:
                        banout_append(banout, PROTO_SMB, "ERROR(UNKNOWN)", AUTO_LEN);
                        break;
                        
                }
                state = NBT_DRAIN;
                break;
                
            case NBT_SMB:
                i += smb_parse_smb(smb, px+i, max-i, banout, more);
                if (smb->nbt_length == 0) {
                    state = 0;
                    i--;
                }
                break;
            
            case NBT_DRAIN:
                if (smb->nbt_length == 0) {
                    state = 0;
                    i--;
                } else
                    smb->nbt_length--;
                break;
            case NBT_UNKNOWN:
            default:
                break;
        }
    
    pstate->state = state;
}

/*****************************************************************************
 *****************************************************************************/
#if 0
static int
negot_add_dialect(unsigned char *buf, size_t sizeof_buf, const char *dialect)
{
    size_t nbt_length;
    size_t dialect_length = strlen(dialect) + 1;
    size_t word_count;
    //size_t byte_count;
    
    /* Parse NetBIOS header */
    if (sizeof_buf < 4 || sizeof_buf + 4 < dialect_length)
        return -1;
    if (buf[0] != 0)
        return -1;
    nbt_length = buf[2]<<8 | buf[3];
    if (nbt_length <= 4 || nbt_length >= sizeof_buf - dialect_length)
        return -1;
    
    /* Parse SMB header */
    if (memcmp(buf+4, "\xFF" "SMB" "\x72", 5) != 0)
        return -1;
    if (nbt_length < 39)
        return -1;
    word_count = buf[36];
    if (word_count != 0)
        return -1;
    //byte_count = buf[37] | buf[38]<<8;
    
    
    
    return 0;
}
#endif

/*****************************************************************************
 *****************************************************************************/
static void *
smb_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}

/*****************************************************************************
 *****************************************************************************/

static const char
smb0_hello_template[] = {
    0x81, 0x00, 0x00, 0x44, 0x20, 0x43, 0x4b, 0x46,
    0x44, 0x45, 0x4e, 0x45, 0x43, 0x46, 0x44, 0x45,
    0x46, 0x46, 0x43, 0x46, 0x47, 0x45, 0x46, 0x46,
    0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
    0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 0x45,
    0x44, 0x46, 0x43, 0x45, 0x46, 0x45, 0x46, 0x45,
    0x44, 0x45, 0x49, 0x45, 0x46, 0x46, 0x43, 0x43,
    0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
    0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00,

    /*0x00, 0x00, 0x00, 0x45, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02,
    0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
    0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20,
    0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
    0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f,
    0x00*/
};



/*****************************************************************************
 * Do a single test of response packets
 *****************************************************************************/
static int
smb_do_test(const char *substring, const unsigned char *packet_bytes, size_t length)
{
    struct Banner1 *banner1;
    struct ProtocolState state[1];
    struct BannerOutput banout1[1];
    struct InteractiveData more;
    int x;
    
    banner1 = banner1_create();
    banout_init(banout1);
    memset(&state[0], 0, sizeof(state[0]));
    
    smb_parse_record(banner1,
                     0,
                     state,
                     packet_bytes,
                     length,
                     banout1,
                     &more);
    x = banout_is_contains(banout1, PROTO_SMB, substring);
    if (x == 0)
        printf("smb parser failure: %s\n", substring);
    banner1_destroy(banner1);
    banout_release(banout1);
    
    return x?0:1;
}

/*****************************************************************************
 *****************************************************************************/
static int
smb_selftest(void)
{
    int x = 0;

    /*****************************************************************************
     *****************************************************************************/
    {
        static const unsigned char packet_bytes[] = {
            0x00, 0x00, 0x00, 0x9f, 0xff, 0x53, 0x4d, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x88, 0x01, 0xc8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
            0xff, 0xff, 0x00, 0x00, 0x11, 0x00, 0x00, 0x03,
            0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x00, 0xad, 0xa0, 0x03, 0x0a,
            0x7c, 0xe0, 0x00, 0x80, 0x00, 0x1d, 0xbd, 0xd5,
            0xe2, 0x0f, 0xcf, 0x01, 0x00, 0x00, 0x00, 0x5a,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01,
            0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0,
            0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01,
            0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3,
            0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e,
            0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e,
            0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46,
            0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c,
            0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e,
            0x6f, 0x72, 0x65,
            
            0x00, 0x00, 0x01, 0x2a, 0xff, 0x53, 0x4d, 0x42,
            0x73, 0x16, 0x00, 0x00, 0xc0, 0x88, 0x01, 0xc0,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x04, 0xff, 0x00, 0x2a,
            0x01, 0x00, 0x00, 0xb3, 0x00, 0xff, 0x00, 0xa1,
            0x81, 0xb0, 0x30, 0x81, 0xad, 0xa0, 0x03, 0x0a,
            0x01, 0x01, 0xa1, 0x0c, 0x06, 0x0a, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
            0xa2, 0x81, 0x97, 0x04, 0x81, 0x94, 0x4e, 0x54,
            0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x12, 0x00, 0x12, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x31, 0x02, 0x89, 0xe0, 0x31, 0x6a,
            0x74, 0x8f, 0xb5, 0xf1, 0xe1, 0x56, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00,
            0x52, 0x00, 0x42, 0x00, 0x00, 0x00, 0x57, 0x00,
            0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, 0x47, 0x00,
            0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00,
            0x02, 0x00, 0x12, 0x00, 0x57, 0x00, 0x4f, 0x00,
            0x52, 0x00, 0x4b, 0x00, 0x47, 0x00, 0x52, 0x00,
            0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x01, 0x00,
            0x16, 0x00, 0x45, 0x00, 0x50, 0x00, 0x53, 0x00,
            0x4f, 0x00, 0x4e, 0x00, 0x38, 0x00, 0x38, 0x00,
            0x33, 0x00, 0x31, 0x00, 0x46, 0x00, 0x45, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x16, 0x00,
            0x45, 0x00, 0x50, 0x00, 0x53, 0x00, 0x4f, 0x00,
            0x4e, 0x00, 0x38, 0x00, 0x38, 0x00, 0x33, 0x00,
            0x31, 0x00, 0x46, 0x00, 0x45, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x45, 0x00, 0x50, 0x00, 0x53, 0x00,
            0x4f, 0x00, 0x4e, 0x00, 0x20, 0x00, 0x53, 0x00,
            0x74, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x61, 0x00,
            0x67, 0x00, 0x65, 0x00, 0x20, 0x00, 0x53, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x51, 0x00,
            0x20, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x32, 0x00,
            0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00,
            0x4b, 0x00, 0x47, 0x00, 0x52, 0x00, 0x4f, 0x00,
            0x55, 0x00, 0x50, 0x00, 0x00, 0x00
        };
        x += smb_do_test("os=EPSON", packet_bytes, sizeof(packet_bytes));
    }

    /*****************************************************************************
     *****************************************************************************/
    {
        static const unsigned char packet_bytes[] = {
            0x00, 0x00, 0x00, 0x56, 0xff, 0x53, 0x4d, 0x42,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x45, 0x60,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x07,
            0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x03,
            0x05, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0xa9, 0x00, 0x00, 0x00,
            0x1d, 0xc2, 0x00, 0x00, 0x00, 0x83, 0xa9, 0xe2,
            0x31, 0x02, 0xd4, 0x01, 0x00, 0x00, 0x08, 0x11,
            0x00, 0x77, 0x6d, 0x78, 0x8f, 0x06, 0x52, 0x8f,
            0xb8, 0x53, 0x36, 0x35, 0x39, 0x43, 0x32, 0x37,
            0x44, 0x00
        };
        x += smb_do_test("domain=S659C27D", packet_bytes, sizeof(packet_bytes));
    }
    
    
    if (x) {
        printf("smb parser failure: google.com\n");
        return 1;
    }
    
    return 0;

#if 0
    {
        struct Banner1 *banner1;
        struct ProtocolState state[1];
        struct BannerOutput banout1[1];
        struct InteractiveData more;
        size_t i;

        /*
         *  LET'S FUZZ THIS CRAP!!!
         *
         * We are going to re-parse the response packet as many times as needed,
         * each time flipping one bit in the packet. This should crash the
         * parser if it has such a bug that will crash it.
         */
        for (i=2; i< 5 && i<sizeof(packet_bytes); i++) {
            size_t j;
            
            for (j=0; j<8; j++) {
                size_t flip = 1<<j;
                
                packet_bytes[i] ^= flip;
                
                banner1 = banner1_create();
                banout_init(banout1);
                memset(&state[0], 0, sizeof(state[0]));
                
                smb_parse_record(banner1,
                                 0,
                                 state,
                                 packet_bytes,
                                 sizeof(packet_bytes),
                                 banout1,
                                 &more);
                banner1_destroy(banner1);
                banout_release(banout1);
                
                packet_bytes[i] ^= flip;
                
            }
        }
    }
    return 0;
#endif
}

/*****************************************************************************
 *****************************************************************************/
static void
smb_cleanup(struct ProtocolState *pstate)
{
    struct SMBSTUFF *smb = &pstate->sub.smb;
    if (smb->spnego.ntlmssp.buf)
        ntlmssp_cleanup(&smb->spnego.ntlmssp);
}

/*****************************************************************************
 * This is the 'plugin' structure that registers callbacks for this parser in
 * the main system.
 *****************************************************************************/
struct ProtocolParserStream banner_smb0 = {
    "smb", 139, smb0_hello_template, sizeof(smb0_hello_template), 0,
    smb_selftest,
    smb_init,
    smb_parse_record,
    smb_cleanup
};
struct ProtocolParserStream banner_smb1 = {
    "smb", 445, smb1_hello_template, sizeof(smb1_hello_template), 0,
    smb_selftest,
    smb_init,
    smb_parse_record,
    smb_cleanup
};

