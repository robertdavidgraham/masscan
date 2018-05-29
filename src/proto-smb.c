/*
    SMB parser
 
 */
#include "proto-smb.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "siphash24.h"
#include "string_s.h"
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
    //{0x72, 15,   4, IT_uint32, offsetof(struct Smb72_Negotiate, SessionKey)},
    {0x72, 19,   4, IT_uint32, offsetof(struct Smb72_Negotiate, Capabilities)},
    {0x72, 23,   8, IT_uint64, offsetof(struct Smb72_Negotiate, SystemTime)},
    {0x72, 31,   2, IT_uint16, offsetof(struct Smb72_Negotiate, ServerTimeZone)},
    {0x72, 33,   1, IT_uint8,  offsetof(struct Smb72_Negotiate, ChallengeLength)},
    
    {0xFF, 0,   65536, IT_uint0,  0},
    
};

#define memberat(t, s, offset) (t*)((char*)(s)+(offset))

static char smb1_null_session_setup[] = {
    0x00, 0x00, 0x00, 0xbe, 0xff, 0x53, 0x4d, 0x42,
    0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
    0x00, 0x00, 0x5d, 0xa8, 0x8f, 0x55, 0x48, 0x06,
    0xe8, 0xfc, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xca,
    0x00, 0x00, 0x00, 0x00, 0x0d, 0x75, 0x00, 0x84,
    0x00, 0x04, 0x11, 0x0a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x47,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00,
    0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
    0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x4e, 0x00,
    0x54, 0x00, 0x20, 0x00, 0x31, 0x00, 0x33, 0x00,
    0x38, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00,
    0x6f, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00,
    0x4e, 0x00, 0x54, 0x00, 0x20, 0x00, 0x34, 0x00,
    0x2e, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x2f, 0x00, 0x00, 0x5c, 0x00, 0x5c, 0x00,
    0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x32, 0x00,
    0x30, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x30, 0x00,
    0x2e, 0x00, 0x31, 0x00, 0x33, 0x00, 0x35, 0x00,
    0x5c, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00,
    0x24, 0x00, 0x00, 0x00, 0x3f, 0x3f, 0x3f, 0x3f,
    0x3f, 0x00
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
    
    if (max > offset + (smb->smb1.param_length - smb->smb1.param_offset))
        max = offset + (smb->smb1.param_length - smb->smb1.param_offset);
    
    //printf("\n max=%04x  \n", *(unsigned short*)(px+max));
    
    /* Find the correct header */
    for (c=0; params[c].command != smb->smb1.command && params[c].command != 0xFF; c++)
        ;
    
    for (; offset < max; offset++, smb->smb1.param_offset++) {
        again:
        
        //printf("\n%u/%u %u\n", (unsigned)smb->smb1.param_offset, (unsigned)smb->smb1.param_length, (unsigned)c);
        
        /* If we've gone past our header, just continue consuming bytes */
        if (params[c].command != smb->smb1.command)
            continue;
        
        /* If we've gone past the end of this field, goto next field */
        if (params[c].external_offset + params[c].external_length <= smb->smb1.param_offset) {
            c++;
            goto again;
        }
        /* Haven't reached the next field yet */
        if (params[c].external_offset > smb->smb1.param_offset)
            continue;
        
        //printf("\n%u/%u %u [%02x]\n", (unsigned)smb->smb1.param_offset, (unsigned)smb->smb1.param_length, (unsigned)c, px[offset]);
        
        /* Shift the type, because all fields little-endian */
        switch (params[c].internal_type) {
            case IT_uint0:
            default:
                break;
            case IT_uint8:
            {
                uint8_t *x = memberat(uint8_t, &smb->parms1, params[c].internal_offset);
                *x = px[offset];
            }
                break;
            case IT_uint16:
            {
                uint16_t *x = memberat(uint16_t, &smb->parms1, params[c].internal_offset);
                //*x <<= 8;
                *x |= px[offset] << ((smb->smb1.param_offset - params[c].external_offset)*8);
            }
                break;
            case IT_uint32:
            {
                uint32_t *x = memberat(uint32_t, &smb->parms1, params[c].internal_offset);
                //*x <<= 8;
                *x |= px[offset] << ((smb->smb1.param_offset - params[c].external_offset)*8);
            }
                break;
            case IT_uint64:
            {
                uint64_t *x = memberat(uint64_t, &smb->parms1, params[c].internal_offset);
                //*x <<= 8;
                *x |= (uint64_t)px[offset] << (uint64_t)((smb->smb1.param_offset - params[c].external_offset)*8);
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
enum {
    D_START,
    D_NEGOT_CHALLENGE,
    D_NEGOT_DOMAINA,
    D_NEGOT_NAMEA,
    D_NEGOT_DOMAIN1,
    D_NEGOT_DOMAIN2,
    D_NEGOT_NAME1,
    D_NEGOT_NAME2,
    D_NEGOT_END,
    
    D_UNKNOWN,
};

/*****************************************************************************
 *****************************************************************************/
static void
name_append_char(struct BannerOutput *banout, unsigned c)
{
    if (c & 0xFF80)
        banout_append_char(banout, PROTO_SMB, '.');
    else if (isalnum(c))
        banout_append_char(banout, PROTO_SMB, c);
    else switch (c) {
        case '-':
        case '_':
        case '$':
        case '*':
            banout_append_char(banout, PROTO_SMB, c);
            break;
        default:
            banout_append_char(banout, PROTO_SMB, '.');
            break;
            
    }
}
/*****************************************************************************
 *****************************************************************************/
static size_t
smb1_parse_data(struct SMBSTUFF *smb, const unsigned char *px, size_t offset, size_t max, struct BannerOutput *banout)
{
    size_t original_offset = offset;
    unsigned state = smb->smb1.byte_state;
    
    
    if (max > offset + (smb->smb1.byte_count - smb->smb1.byte_offset))
        max = offset + (smb->smb1.byte_count - smb->smb1.byte_offset);
    
    for (;offset<max; offset++)
    switch (state) {
        case D_START:
            state = D_UNKNOWN;
            break;
        case D_NEGOT_CHALLENGE:
            if (smb->parms1.negotiate.ChallengeLength == 0) {
                if (smb->smb1.flags2 & 0x0080) {
                    state = D_NEGOT_DOMAIN1;
                } else {
                    state = D_NEGOT_DOMAINA;
                }
                offset--;
            } else
                smb->parms1.negotiate.ChallengeLength--;
            break;
        case D_NEGOT_DOMAIN1:
        case D_NEGOT_NAME1:
            smb->smb1.unicode_char = px[offset];
            state++;
            break;
        case D_NEGOT_DOMAIN2:
        case D_NEGOT_DOMAINA:
        case D_NEGOT_NAME2:
        case D_NEGOT_NAMEA:
            smb->smb1.unicode_char |= px[offset] << 8;
            if (state == D_NEGOT_DOMAINA || state == D_NEGOT_NAMEA)
                smb->smb1.unicode_char >>= 8;
            if (smb->smb1.unicode_char == 0) {
                banout_append_char(banout, PROTO_SMB, ' ');
                state++;
            } else {
                name_append_char(banout, smb->smb1.unicode_char);
                state--;
            }
            break;
        default:
            break;
    }
    
    smb->smb1.byte_state = state;
    smb->smb1.byte_offset += (offset - original_offset);
    return offset - original_offset;
}

/*****************************************************************************
 *****************************************************************************/
static void
smb_parse_record(
                 const struct Banner1 *banner1,
                 void *banner1_private,
                 struct ProtocolState *pstate,
                 const unsigned char *px, size_t length,
                 struct BannerOutput *banout,
                 struct InteractiveData *more)
{
    size_t len; /*scratch variables used in a couple places */
    size_t max;
    unsigned state = pstate->state;
    struct SMBSTUFF *smb = &pstate->sub.smb;
    size_t i;
    enum {
        NBT_TYPE,
        NBT_FLAGS,
        NBT_LEN1,
        NBT_LEN2,
        NBT_ERR,
        NBT_DRAIN,
        
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
        NBT_UNKNOWN,
    };
    
    /*
     * On first run thourhg, the offset will be zero
     */
    i = 0;
    
again:
    
    /*
     * Make sure we don't go past the end of the NetBIOS header portion
     */
    max = length;
    if (state > NBT_LEN2) {
        if (max > i + smb->length)
            max = i + smb->length;
    }
    
    
    /*
     * `for all bytes in the segment`
     *   `do a state transition for that byte `
     */
    for (; i<max; i++)
    switch (state) {
            /*
             All session packets are of the following general structure:
             
             1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |      TYPE     |     FLAGS     |            LENGTH             |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             |                                                               |
             /               TRAILER (Packet Type Dependent)                 /
             |                                                               |
             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             */
        case NBT_TYPE:
            smb->nbt_type = px[i];
            state++;
            break;
        case NBT_FLAGS:
            smb->nbt_flags = px[i];
            smb->length = 0;
            state++;
            break;
        case NBT_LEN1:
            smb->length <<= 8;
            smb->length |= px[i];
            state++;
            break;
        case NBT_LEN2:
            smb->length <<= 8;
            smb->length |= px[i];
            if (max > i + smb->length)
                max = i + smb->length;
            
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
                    state = SMB_VER;
                    break;
                case 0x81:
                    banout_append(banout, PROTO_SMB, "ERR session request", AUTO_LEN);
                    state = NBT_UNKNOWN;
                    break;
                case 0x82:
                case 0x85:
                    state = NBT_DRAIN;
                    break;
                case 0x83:
                    state = NBT_ERR;
                    break;
                case 0x84:
                    banout_append(banout, PROTO_SMB, "ERR retarget", AUTO_LEN);
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
            
        case NBT_DRAIN:
            state = NBT_DRAIN;
            break;
            
        case SMB_VER:
            switch (px[i]) {
                case 0xFF:
                    banout_append(banout, PROTO_SMB, "SMBv1 ", AUTO_LEN);
                    state = SMB1_VER_S;
                    break;
                case 0xFE:
                    banout_append(banout, PROTO_SMB, "SMBv2 ", AUTO_LEN);
                    state = SMB2_VER_S;
                    break;
                default:
                    banout_append(banout, PROTO_SMB, "SMBv? ", AUTO_LEN);
                    state = NBT_UNKNOWN;
            }
            break;
        case SMB1_VER_S:
        case SMB2_VER_S:
            
            if (px[i] != 'S')
                state = NBT_UNKNOWN;
            else
                state++;
            break;
        case SMB1_VER_M:
        case SMB2_VER_M:
            if (px[i] != 'M')
                state = NBT_UNKNOWN;
            else
                state++;
            break;
        case SMB1_VER_B:
        case SMB2_VER_B:
            if (px[i] != 'B')
                state = NBT_UNKNOWN;
            else
                state++;
            break;
            
        case SMB1_CMD:
            memset(&smb->smb1, 0, sizeof(smb->smb1));
            smb->smb1.command = px[i];
            state++;
            break;
        case SMB1_STATUS1: case SMB1_STATUS2: case SMB1_STATUS3: case SMB1_STATUS4:
            smb->smb1.status <<= 8;
            smb->smb1.status |= px[i];
            state++;
            break;
        case SMB1_FLAGS1:
            smb->smb1.flags1 = px[i];
            state++;
            break;
        case SMB1_FLAGS2:
        case SMB1_FLAGS3:
            smb->smb1.flags2 <<= 8;
            smb->smb1.flags2 |= px[i];
            state++;
            break;
        case SMB1_PID1: case SMB1_PID2:
            smb->smb1.pid <<= 8;
            smb->smb1.pid |= px[i];
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
            smb->smb1.tid <<= 8;
            smb->smb1.tid |= px[i];
            state++;
            break;
        case SMB1_PID3: case SMB1_PID4:
            smb->smb1.pid <<= 8;
            smb->smb1.pid |= px[i];
            state++;
            break;
        case SMB1_UID1: case SMB1_UID2:
            smb->smb1.uid <<= 8;
            smb->smb1.uid |= px[i];
            state++;
            break;
        case SMB1_MID1: case SMB1_MID2:
            smb->smb1.mid <<= 8;
            smb->smb1.mid |= px[i];
            state++;
            break;
        case SMB1_WORD_COUNT:
            smb->smb1.param_length = px[i]*2;
            state++;
            break;
        case SMB1_PARAMETERS:
            /* Transfer control to a sub-parser, which may consume zero
             * or more bytes, up to the end of the parameters field
             * (meaning, up to word_count*2 bytes) */
            len = smb_params_parse(smb, px, i, max);
            i += len;
            if (smb->smb1.param_offset < smb->smb1.param_length)
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
            switch (smb->smb1.command) {
                case 0x72:
                {
                    char str[64] = "(err)";
                    time_t timestamp = convert_windows_time(smb->parms1.negotiate.SystemTime);
                    struct tm tm = {0};
                    
                    gmtime_s(&tm, &timestamp);
                    
                    len = strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S ", &tm);
                    banout_append(banout, PROTO_SMB, str, len);
                    sprintf_s(str, sizeof(str), "TZ%+d ", (short)smb->parms1.negotiate.ServerTimeZone);
                    banout_append(banout, PROTO_SMB, str, AUTO_LEN);
                    smb->smb1.byte_state = D_NEGOT_CHALLENGE;
                    
                    //more->payload = smb1_null_session_setup;
                    //more->length = sizeof(smb1_null_session_setup);
                    
                }
                    break;
                default:
                    banout_append(banout, PROTO_SMB, "-- ", AUTO_LEN);
                    smb->smb1.byte_state = D_UNKNOWN;
            }
            
            break;
            
        case SMB1_BYTE_COUNT1:
            smb->smb1.byte_count = px[i];
            state++;
            break;
        case SMB1_BYTE_COUNT2:
            smb->smb1.byte_count |= px[i]<<8;
            state++;
            break;
        case SMB1_DATA:
            i += smb1_parse_data(smb, px, i, max, banout);
            if (smb->smb1.byte_offset >= smb->smb1.byte_count) {
                state = SMB1_DATA_AFTER;
                i--; /* unconsume byte because of auto-increment */
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
    
        default:
            i = length;
            break;
    }
    
    /*
     * If there are multiple response packets, then
     * loop around and process the next one
     */
    if (i < length) {
        state = 0;
        goto again;
    }

    pstate->state = state;
}

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
smb1_hello_template[] = {
    0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
    0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc0, /* */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02,
    0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
    0x31, 0x32, 0x00
};

/*****************************************************************************
 *****************************************************************************/
static int
smb_selftest(void)
{
    struct Banner1 *banner1;
    struct ProtocolState state[1];
    struct BannerOutput banout1[1];
    struct InteractiveData more;
    int x;
    size_t i;

    unsigned char packet_bytes[] = {
        0x00, 0x00, 0x00, 0x69, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x88, 0x01, 0xc0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
        0xff, 0xff, 0x00, 0x00, 0x11, 0x00, 0x00, 0x03,
        0x10, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfc, 0xe3, 0x01, 0x00, 0x1f, 0xac, 0xe7, 0x7f,
        0x8a, 0xf0, 0xd3, 0x01, 0xf0, 0x00, 0x08, 0x24,
        0x00, 0xc2, 0xe5, 0x34, 0x10, 0xfd, 0x29, 0xa7,
        0x75, 0x42, 0x00, 0x4e, 0x00, 0x43, 0x00, 0x00,
        0x00, 0x53, 0x00, 0x48, 0x00, 0x49, 0x00, 0x50,
        0x00, 0x42, 0x00, 0x41, 0x00, 0x52, 0x00, 0x42,
        0x00, 0x4f, 0x00, 0x00, 0x00,

        /*0x00, 0x00, 0x00, 0x90, 0xff, 0x53, 0x4d, 0x42,
        0x73, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0x80,
        0x00, 0x00, 0x5d, 0xa8, 0x8f, 0x55, 0x48, 0x06,
        0xe8, 0xfc, 0x00, 0x00, 0x00, 0x08, 0xfe, 0xca,
        0x00, 0x08, 0x00, 0x00, 0x03, 0x75, 0x00, 0x81,
        0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x57, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x35, 0x00,
        0x2e, 0x00, 0x30, 0x00, 0x00, 0x00, 0x57, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32, 0x00,
        0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00,
        0x4c, 0x00, 0x41, 0x00, 0x4e, 0x00, 0x20, 0x00,
        0x4d, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x61, 0x00,
        0x67, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00,
        0x52, 0x00, 0x45, 0x00, 0x53, 0x00, 0x45, 0x00,
        0x41, 0x00, 0x55, 0x00, 0x00, 0x03, 0xff, 0x00,
        0x90, 0x00, 0x01, 0x00, 0x06, 0x00, 0x49, 0x50,
        0x43, 0x00, 0x00, 0x00*/

    };
    
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
    x = banout_is_contains(banout1, PROTO_SMB,
                           "SHIPBAR");
    if (!x) {
        printf("smb parser failure: google.com\n");
        return 1;
    }
    banner1_destroy(banner1);
    banout_release(banout1);
    
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
    return 0;
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
};
struct ProtocolParserStream banner_smb1 = {
    "smb", 445, smb1_hello_template, sizeof(smb1_hello_template), 0,
    smb_selftest,
    smb_init,
    smb_parse_record,
};

