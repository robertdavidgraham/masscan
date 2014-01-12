/*

    This is a state-machine parser for the X.509 protocol. When scanning
    SSL targets with the --banner option, this will extract information
    from the certificate, especially the "subject common name"
 */
#include "proto-x509.h"
#include "proto-banout.h"
#include "masscan-app.h"
#include "smack.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/****************************************************************************
 ****************************************************************************/
static struct SMACK *global_mib;

enum {
    Subject_Unknown,
    Subject_Common,
};

/****************************************************************************
 ****************************************************************************/
static struct SnmpOid {
    const char *oid;
    const char *name;
    int id;
} mib[] = {
    {"43.1006.51.341332", "selftest"}, /* for regression test */
    {"43", "iso.org"},
    {"43.6", "dod"},
    {"43.6.1", "inet"},
    {"43.6.1.2", "mgmt"},
    {"43.6.1.2.1", "mib2"},
    {"43.6.1.2.1.", "sys"},
    {"43.6.1.2.1.1.1", "sysDescr"},
    {"43.6.1.2.1.1.2", "sysObjectID"},
    {"43.6.1.2.1.1.3", "sysUpTime"},
    {"43.6.1.2.1.1.4", "sysContact"},
    {"43.6.1.2.1.1.5", "sysName"},
    {"43.6.1.2.1.1.6", "sysLocation"},
    {"43.6.1.2.1.1.7", "sysServices"},
    {"43.6.1.4", "priv"},
    {"43.6.1.4.1", "enterprise"},
    {"43.6.1.4.1.2001", "okidata"},
    {"42", "1.2"},
    {"42.840", "1.2.840"},
    {"42.840.52", "0"},
    {"42.840.113549", "1.2.840.113549"},
    {"42.840.113549.1", "1.2.840.113549.1"},
    {"42.840.113549.1.1", "1.2.840.113549.1.1"},
    {"42.840.113549.1.1.4", "md5WithRSAEncryption"},
    {"42.840.113549.1.1.5", "shaWithRSAEncryption"},
    {"42.840.113549.1.1.11", "sha256WithRSAEncryption"},
    {"42.840.113549.1.9", "1.2.840.113549.1.9"},
    {"42.840.113549.1.9.1", "email"},
    {"85", "2.5"},
    {"85.4", "2.5.4"},
    {"85.4.3", "common", Subject_Common},
    {"85.4.5", "serial"},
    {"85.4.6", "country"},
    {"85.4.7", "locality"},
    {"85.4.8", "state"},
    {"85.4.10", "organization"},
    {"85.4.11", "unit"},
    {"85.4.13", "description"},
    {"85.29", "2.5.29"},
    {"85.29.17", "altname", Subject_Common},
    {0,0},
};

#define TWO_BYTE       ((~0)<<7)
#define THREE_BYTE     ((~0)<<14)
#define FOUR_BYTE      ((~0)<<21)
#define FIVE_BYTE      ((~0)<<28)


/****************************************************************************
 ****************************************************************************/
static unsigned
id_prefix_count(unsigned id)
{
    if (id & FIVE_BYTE)
        return 4;
    if (id & FOUR_BYTE)
        return 3;
    if (id & THREE_BYTE)
        return 2;
    if (id & TWO_BYTE)
        return 1;
    return 0;
}

/****************************************************************************
 * Convert text OID to binary
 ****************************************************************************/
static unsigned
convert_oid(unsigned char *dst, size_t sizeof_dst, const char *src)
{
    size_t offset = 0;

    while (*src) {
        const char *next_src;
        unsigned long id;
        unsigned count;
        unsigned i;

        while (*src == '.')
            src++;

        id = strtoul(src, (char**)&next_src, 0);
        if (src == next_src)
            break;
        else
            src = next_src;

        count = id_prefix_count(id);
        for (i=count; i>0; i--) {
            if (offset < sizeof_dst)
                dst[offset++] = ((id>>(7*i)) & 0x7F) | 0x80;
        }
        if (offset < sizeof_dst)
            dst[offset++] = (id & 0x7F);


    }

    return (unsigned)offset;
}

/****************************************************************************
 * We need to initialize the OID/MIB parser
 * This should be called on program startup.
 * This is so that we can show short names, like "sysName", rather than
 * the entire OID.
 ****************************************************************************/
void
x509_init(void)
{
    unsigned i;

    /* We use an Aho-Corasick pattern matcher for this. Not necessarily
     * the most efficient, but also not bad */
    global_mib = smack_create("ssl-oids", 0);

    /* We just go through the table of OIDs and add them all one by
     * one */
    for (i=0; mib[i].name; i++) {
        unsigned char pattern[256];
        unsigned len;

        len = convert_oid(pattern, sizeof(pattern), mib[i].oid);

        smack_add_pattern(  global_mib,
                            pattern,
                            len,
                            i,
                            SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK
                            );
    }

    /* Now that we've added all the OIDs, we need to compile this into
     * an efficient data structure. Later, when we get packets, we'll
     * use this for searching */
    smack_compile(global_mib);

}



/****************************************************************************
 ****************************************************************************/
static void
push_remaining(struct CertDecode *x, unsigned next_state, uint64_t remaining)
{
    if ((remaining >> 16) != 0) {
        fprintf(stderr, "ASN.1 length field too big\n");
        x->state = 0xFFFFFFFF;
        return;
    }
    if (x->remainings_count >= sizeof(x->remainings)/sizeof(x->remainings[0])) {
        fprintf(stderr, "ASN.1 recursion too deep\n");
        x->state = 0xFFFFFFFF;
        return;
    }
    if (x->remainings_count) {
        if (remaining > x->remainings[0]) {
            fprintf(stderr, "ASN.1 inner object bigger than container\n");
            x->state = 0xFFFFFFFF;
            return;
        }
        x->remainings[0] = (unsigned short)(x->remainings[0] - remaining);
    }
    memmove(&x->remainings[1], &x->remainings[0], x->remainings_count * sizeof(x->remainings[0]));
    x->remainings[0] = (unsigned short)remaining;
    memmove(&x->states[1], &x->states[0], x->remainings_count * sizeof(x->states[0]));
    x->states[0] = (unsigned char)next_state;
    x->remainings_count++;
}
static unsigned
pop_remaining(struct CertDecode *x)
{
    unsigned next_state;
    next_state = x->states[0];
    x->remainings_count--;
    memmove(&x->remainings[0], &x->remainings[1], x->remainings_count * sizeof(x->remainings[0]));
    memmove(&x->states[0], &x->states[1], x->remainings_count * sizeof(x->states[0]));
    return next_state;
}

enum X509state {
    TAG0,           TAG0_LEN,       TAG0_LENLEN,
    TAG1,           TAG1_LEN,       TAG1_LENLEN,
    VERSION0_TAG,   VERSION0_LEN,   VERSION0_LENLEN,
    VERSION1_TAG,   VERSION1_LEN,   VERSION1_LENLEN,    VERSION_CONTENTS,
    SERIAL_TAG,     SERIAL_LEN,     SERIAL_LENLEN,      SERIAL_CONTENTS,
    SIG0_TAG,       SIG0_LEN,       SIG0_LENLEN,
    SIG1_TAG,       SIG1_LEN,       SIG1_LENLEN,        SIG1_CONTENTS0,SIG1_CONTENTS1,
    ISSUER0_TAG,    ISSUER0_LEN,    ISSUER0_LENLEN,
    ISSUER1_TAG,    ISSUER1_LEN,    ISSUER1_LENLEN,
    ISSUER2_TAG,    ISSUER2_LEN,    ISSUER2_LENLEN,
    ISSUERID_TAG,   ISSUERID_LEN,   ISSUERID_LENLEN,    ISSUERID_CONTENTS0, ISSUERID_CONTENTS1,
    ISSUERNAME_TAG, ISSUERNAME_LEN, ISSUERNAME_LENLEN,  ISSUERNAME_CONTENTS,
    VALIDITY_TAG,   VALIDITY_LEN,   VALIDITY_LENLEN,
    VNBEFORE_TAG,   VNBEFORE_LEN,   VNBEFORE_LENLEN,    VNBEFORE_CONTENTS,
    VNAFTER_TAG,    VNAFTER_LEN,    VNAFTER_LENLEN,     VNAFTER_CONTENTS,
    SUBJECT0_TAG,   SUBJECT0_LEN,   SUBJECT0_LENLEN,
    SUBJECT1_TAG,   SUBJECT1_LEN,   SUBJECT1_LENLEN,
    SUBJECT2_TAG,   SUBJECT2_LEN,   SUBJECT2_LENLEN,
    SUBJECTID_TAG,  SUBJECTID_LEN,  SUBJECTID_LENLEN,   SUBJECTID_CONTENTS0, SUBJECTID_CONTENTS1,
    SUBJECTNAME_TAG,SUBJECTNAME_LEN,SUBJECTNAME_LENLEN, SUBJECTNAME_CONTENTS,
    PUBKEY0_TAG,    PUBKEY0_LEN,    PUBKEY0_LENLEN,     PUBKEY0_CONTENTS,
    EXT0_TAG, EXT0_LEN, EXT0_LENLEN,
    EXT1_TAG, EXT1_LEN, EXT1_LENLEN,
    EXT2_TAG, EXT2_LEN, EXT2_LENLEN,
    EXTID_TAG, EXTID_LEN, EXTID_LENLEN, EXTID_CONTENTS0, EXTID_CONTENTS1,
    EXT_TAG, EXT_LEN, EXT_LENLEN, EXT_CONTENTS,
    ALGOID0_TAG,    ALGOID0_LEN,    ALGOID0_LENLEN,
    ALGOID1_TAG,    ALGOID1_LEN,    ALGOID1_LENLEN,     ALGOID1_CONTENTS0, ALGOID1_CONTENTS1,
    ENC_TAG,        ENC_LEN,        ENC_LENLEN,         ENC_CONTENTS,
    PADDING=254,
    ERROR=0xFFFFFFFF,
};

/****************************************************************************
 ****************************************************************************/
static unsigned
kludge_next(unsigned state)
{
    switch (state) {
    case TAG1_LEN:
        return ALGOID0_TAG;
    case ALGOID0_LEN:
        return ENC_TAG;
    case SERIAL_LEN:
        return SIG0_TAG;
    case VERSION0_LEN:
        return SERIAL_TAG;
    case SIG0_LEN:
        return ISSUER0_TAG;
    case ISSUER0_LEN:
        return VALIDITY_TAG;
    case SUBJECT0_LEN:
        return PUBKEY0_TAG;
    case ISSUER1_LEN:
        return ISSUER1_TAG;
    case SUBJECT1_LEN:
        return SUBJECT1_TAG;
    case ISSUERID_LEN:
        return ISSUERNAME_TAG;
    case EXTID_LEN:
        return EXT_TAG;
    case SUBJECTID_LEN:
        return SUBJECTNAME_TAG;
    case VALIDITY_LEN:
        return SUBJECT0_TAG;
    case VNBEFORE_LEN:
        return VNAFTER_TAG;
    case PUBKEY0_LEN:
        return EXT0_TAG;
    default:
        return PADDING;
    }
}
/****************************************************************************
 ****************************************************************************/
void
x509_decode(struct CertDecode *x, const unsigned char *px, size_t length, struct BannerOutput *banout)
{
    unsigned i;
    enum X509state state = x->state;


#define GOTO_ERROR(state, i, length) (state)=0xFFFFFFFF;(i)=(length);continue

    for (i=0; i<length; i++) {
        while (x->remainings[0] == 0) {
            if (x->remainings_count == 0)
                return;
            state = pop_remaining(x);
            //assert(((size_t)banout->next>>32) == 0);
        }
        x->remainings[0]--;

        switch (state) {
        case ENC_TAG:
            if (px[i] != 0x03) {
                state = ERROR;
                continue;
            }
            state++;
            break;
        case ISSUERNAME_TAG:
            if (px[i] != 0x13 && px[i] != 0x0c) {
                state++;
                continue;
            }
            //printf("issuer:");
            state++;
            break;
        case SUBJECTNAME_TAG:
            if (px[i] != 0x13 && px[i] != 0x0c) {
                state++;
                continue;
            }
            //printf("subject:");
            state++;
            break;
        case ISSUER1_TAG:
        case SUBJECT1_TAG:
            x->subject.type = 0;
            if (px[i] != 0x31) {
                state++;
                continue;
            }
            state++;
            break;
        case VNBEFORE_TAG:
        case VNAFTER_TAG:
            if (px[i] != 0x17) {
                state++;
                continue;
            }
            state++;
            break;
        case VERSION0_TAG:
            if (px[i] != 0xa0) {
                state = ERROR;
                continue;
            }
            state++;
            break;
        case SIG1_TAG:
        case ISSUERID_TAG:
        case SUBJECTID_TAG:
        case EXTID_TAG:
        case ALGOID1_TAG:
            if (px[i] != 0x06) {
                state = ERROR;
                continue;
            }
            state++;
            break;
        case VERSION1_TAG:
        case SERIAL_TAG:
            if (px[i] != 0x02) {
                state = ERROR;
                continue;
            }
            x->u.num = 0;
            state++;
            break;
        case ISSUERNAME_CONTENTS:
            //printf("%c", px[i]);
            //if (x->remainings[0] == 0)
            //    printf("\n");
            break;
        case SUBJECTNAME_CONTENTS:
        case EXT_CONTENTS:
            //printf("%c", px[i]);
            if (x->subject.type == Subject_Common)
                banout_append(banout, PROTO_SSL3, px+i, 1);
            //if (x->remainings[0] == 0)
            //    printf("\n");
            break;
        case VERSION_CONTENTS:
            x->u.num <<= 8;
            x->u.num |= px[i];
            if (x->remainings[0] == 0)
                state = PADDING;
            break;
        case ISSUERID_CONTENTS0:
        case SUBJECTID_CONTENTS0:
        case EXTID_CONTENTS0:
        case ALGOID1_CONTENTS0:
        case SIG1_CONTENTS0:
            memset(&x->u.oid, 0, sizeof(x->u.oid));
            state++;
        case ISSUERID_CONTENTS1:
        case SUBJECTID_CONTENTS1:
        case EXTID_CONTENTS1:
        case ALGOID1_CONTENTS1:
        case SIG1_CONTENTS1:
            {
                size_t id;
                unsigned offset = i;
                unsigned oid_state = x->u.oid.state;

                /* First, look it up */
                id = smack_search_next( global_mib,
                                        &oid_state,
                                        px,
                                        &offset,
                                        offset+1);
                x->u.oid.state = (unsigned short)oid_state;

                /* Do the multibyte numbers */
                x->u.oid.num <<= 7;
                x->u.oid.num |= px[i] & 0x7F;

                if (px[i] & 0x80) {
                    /* This is a multibyte number, don't do anything at
                     * this stage */
                } else {
                    if (id == SMACK_NOT_FOUND) {
                        if (x->u.oid.last_id) {
                            //printf("%s", mib[x->u.oid.last_id].name);
                            x->u.oid.last_id = 0;
                        }
                        //printf(".%u", (unsigned)x->u.oid.num);
                    } else {
                        //printf("%s [%u]\n", mib[x->u.oid.last_id].name, mib[x->u.oid.last_id].id);
                        x->subject.type = mib[id].id;
                        if (x->subject.type == Subject_Common && state == SUBJECTID_CONTENTS1)
                            banout_append(banout, PROTO_SSL3, ", ", 2);
                        if (x->subject.type == Subject_Common && state == EXTID_CONTENTS1)
                            banout_append(banout, PROTO_SSL3, ", ", 2);
                        x->u.oid.last_id = (unsigned char)id;
                    }
                    x->u.oid.num = 0;
                }
                if (x->remainings[0] == 0) {
                    if (x->u.oid.last_id) {
                        //printf("%s", mib[x->u.oid.last_id].name);
                        x->u.oid.last_id = 0;
                    }
                    state = PADDING;
                    //printf("\n");
                }
            }
            break;
        case SERIAL_CONTENTS:
            x->states[0] = (unsigned char)(state+1);
            x->u.num <<= 8;
            x->u.num |= px[i];
            if (x->remainings[0] == 0)
                state = PADDING;
            break;

        case TAG0:
        case TAG1:
        case SIG0_TAG:
        case ISSUER0_TAG:
        case ISSUER2_TAG:
        case SUBJECT0_TAG:
        case SUBJECT2_TAG:
        case VALIDITY_TAG:
        case PUBKEY0_TAG:
        case EXT1_TAG:
        case EXT2_TAG:
        case ALGOID0_TAG:
            if (px[i] != 0x30) {
                state = ERROR;
                continue;
            }
            state++;
            break;
        case EXT0_TAG:
            if (px[i] != 0xa3) {
                state = ERROR;
                continue;
            }
            state++;
            break;

        case EXT_TAG:
            /* can be anything */
            state++;
            break;


        case TAG0_LEN:
        case TAG1_LEN:
        case VERSION0_LEN:
        case VERSION1_LEN:
        case SERIAL_LEN:
        case SIG0_LEN:
        case SIG1_LEN:
        case ISSUER0_LEN:
        case ISSUER1_LEN:
        case ISSUER2_LEN:
        case ISSUERID_LEN:
        case ISSUERNAME_LEN:
        case VALIDITY_LEN:
        case VNBEFORE_LEN:
        case VNAFTER_LEN:
        case SUBJECT0_LEN:
        case SUBJECT1_LEN:
        case SUBJECT2_LEN:
        case SUBJECTID_LEN:
        case SUBJECTNAME_LEN:
        case EXT0_LEN:
        case EXT1_LEN:
        case EXT2_LEN:
        case EXTID_LEN:
        case EXT_LEN:
        case PUBKEY0_LEN:
        case ALGOID0_LEN:
        case ALGOID1_LEN:
        case ENC_LEN:
            if (px[i] & 0x80) {
                x->u.tag.length_of_length = px[i]&0x7F;
                x->u.tag.remaining = 0;
                state++;
                break;
            } else {
                x->u.tag.remaining = px[i];
                push_remaining(x, kludge_next(state), x->u.tag.remaining);
                state += 2;
                memset(&x->u, 0, sizeof(x->u));
                break;
            }

        case TAG0_LENLEN:
        case TAG1_LENLEN:
        case VERSION0_LENLEN:
        case VERSION1_LENLEN:
        case SERIAL_LENLEN:
        case SIG0_LENLEN:
        case SIG1_LENLEN:
        case ISSUER0_LENLEN:
        case ISSUER1_LENLEN:
        case ISSUER2_LENLEN:
        case ISSUERID_LENLEN:
        case ISSUERNAME_LENLEN:
        case VALIDITY_LENLEN:
        case VNBEFORE_LENLEN:
        case VNAFTER_LENLEN:
        case SUBJECT0_LENLEN:
        case SUBJECT1_LENLEN:
        case SUBJECT2_LENLEN:
        case SUBJECTID_LENLEN:
        case SUBJECTNAME_LENLEN:
        case PUBKEY0_LENLEN:
        case EXT0_LENLEN:
        case EXT1_LENLEN:
        case EXT2_LENLEN:
        case EXTID_LENLEN:
        case EXT_LENLEN:
        case ALGOID0_LENLEN:
        case ALGOID1_LENLEN:
        case ENC_LENLEN:
            x->u.tag.remaining = (x->u.tag.remaining)<<8 | px[i];
            x->u.tag.length_of_length--;
            if (x->u.tag.length_of_length)
                continue;
            push_remaining(x, kludge_next(state-1), x->u.tag.remaining);
            state++;
            memset(&x->u, 0, sizeof(x->u));
            break;

        case VNBEFORE_CONTENTS:
        case VNAFTER_CONTENTS:
            switch (x->u.timestamp.state) {
            case 0:
                x->u.timestamp.year = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 1:
                x->u.timestamp.year += (px[i] - '0');
                x->u.timestamp.state++;
                break;
            case 2:
                x->u.timestamp.month = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 3:
                x->u.timestamp.month += (px[i] - '0');
                x->u.timestamp.state++;
                break;
            case 4:
                x->u.timestamp.day = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 5:
                x->u.timestamp.day += (px[i] - '0');
                x->u.timestamp.state++;
                break;
            case 6:
                x->u.timestamp.hour = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 7:
                x->u.timestamp.hour += (px[i] - '0');
                x->u.timestamp.state++;
                break;
            case 8:
                x->u.timestamp.minute = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 9:
                x->u.timestamp.minute += (px[i] - '0');
                x->u.timestamp.state++;
                break;
            case 10:
                x->u.timestamp.second = (px[i] - '0') * 10;
                x->u.timestamp.state++;
                break;
            case 11:
                x->u.timestamp.second += (px[i] - '0');
                x->u.timestamp.state++;
                {
                    struct tm tm;
                    time_t now;

                    tm.tm_hour = x->u.timestamp.hour;
                    tm.tm_isdst = 0;
                    tm.tm_mday = x->u.timestamp.day;
                    tm.tm_min = x->u.timestamp.minute;
                    tm.tm_mon = x->u.timestamp.month - 1;
                    tm.tm_sec = x->u.timestamp.second;
                    tm.tm_wday = 0;
                    tm.tm_yday = 0;
                    tm.tm_year = 100 + x->u.timestamp.year;


                    now = mktime(&tm);

                    //tm = *localtime(&now);
                    if (state == VNBEFORE_CONTENTS)
                        x->prev = now;
                    else {
                        ;//printf("validity:%u-days\n", (now-x->prev)/(24*60*60));
                    }
                }
                break;
            case 12:
                break;
            }
            break;

        case PADDING:
            break;

        case PUBKEY0_CONTENTS:
        case ENC_CONTENTS:
            if (x->remainings[0]) {
                unsigned len = (unsigned)(length-i);

                if (len > x->remainings[0])
                    len = x->remainings[0];

                i += len;
                x->remainings[0] = (unsigned short)(x->remainings[0] - len);
            }
            break;

        case ERROR:
        default:
            if (x->remainings[0]) {
                unsigned len = (unsigned)(length-i);

                if (len > x->remainings[0])
                    len = x->remainings[0];

                i += len;
                x->remainings[0] = (unsigned short)(x->remainings[0] - len);
            }
            break;
        }
    }

    if (x->state != 0xFFFFFFFF)
    x->state = state;
}


void
x509_init_state(struct CertDecode *x, size_t length)
{
    memset(x, 0, sizeof(*x));
    push_remaining(x, 0xFFFFFFFF, length);
}
