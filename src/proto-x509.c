/*
    !!!!! BIZZARE CODE ALERT !!!!

    This module decodes X.509 public-key certificates using a
    "state-machine parser". If you are unfamiliar with such parsers,
    this will look very strange to you.

    The reason for such parsers is scalability. Certificates are so big
    that they typically cross packet boundaries. This requires some sort
    of "reassembly", which in term requires "memory allocation". This
    is done on a per-connection basis, resulting in running out of memory
    when dealing with millions of connections.
 
    With a state-machine parser, we don't need to reassemble certificates, or
    allocate memory. Instead, we maintain "state" between fragments. There
    is about 60 bytes of state that we must keep.
 
    If you are a code reviewer, you may care about looking into these common
    ASN.1 parsing errors. I've marked them with a [NAME] here, you can search
    these strings in the code to see how they are handled.
 
    [ASN1-CHILD-OVERFLOW]
        when the child length field causes it to exceed the length of
        its parent
    [ASN1-CHILD-UNDERFLOW]
        when there is padding after all the child fields within a larger
        parent field
    [ASN1-DER-LENGTH]
        when there are more bits used to encode a length field than necessary,
        such as using 0x82 0x00 0x12 instead of simply 0x12 as a length
    [ASN1-DER-NUMBER]
        When there are more bits than necessary to encode an integer, such
        as 0x00 0x00 0x00 0x20 rather than just 0x20.
        Since we don't deal with numbers, we don't check this.
    [ASN1-DER-SIGNED]
        issues with signed vs. unsigned numbers, where unsined 4 byte integers
        need an extra leading zero byte if their high-order bit is set
        Since we don't deal with numbers, we don't check this.
    [ASN1-DER-OID]
        Issues with inserting zeroes into OIDs.
        We explicitly deal with the opposite issue, allowing zeroes to be
        inserted. We should probably chainge that, and detect it as a DER
        error.

    CERTIFICATE FORMAT

    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }
TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }
   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
   CertificateSerialNumber  ::=  INTEGER
   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }
   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }
   UniqueIdentifier  ::=  BIT STRING
   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }
   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }
 */
#include "proto-x509.h"
#include "proto-spnego.h"
#include "proto-banout.h"
#include "masscan-app.h"
#include "smack.h"
#include "logger.h"
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/****************************************************************************
 * The X.509 certificates mark certain extensible fields with ASN.1
 * object-identifiers. Instead of copying these out of the certificate,
 * we match them using an Aho-Corasick DFA parser. These object-ids are
 * below. At program startup, the main() function must call x509_init()
 * to build the Aho-Corasick state-machine, which the main state-machine
 * will use to parse these object-ids.
 ****************************************************************************/
static struct SMACK *global_mib;


/****************************************************************************
 * Currently, the only field we extract is the "Common Name".
 ****************************************************************************/
enum {
    Subject_Unknown,
    Subject_Common,
};

/****************************************************************************
 * See "global_mib" above.
 ****************************************************************************/
static struct ObjectIdentifer {
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



/****************************************************************************
 * Used in converting text object-ids into their binary form.
 * @see convert_oid()
 ****************************************************************************/
static unsigned
id_prefix_count(unsigned id)
{
#define TWO_BYTE       ((unsigned long long)(~0)<<7)
#define THREE_BYTE     ((unsigned long long)(~0)<<14)
#define FOUR_BYTE      ((unsigned long long)(~0)<<21)
#define FIVE_BYTE      ((unsigned long long)(~0)<<28)
    
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
 * Convert text OID to binary. This is used when building a Aho-Corasick
 * table for matching object-identifiers: we type the object-ids in the 
 * source-code in human-readable format, but must compile them to binary
 * pattenrs to match within the X.509 certificates.
 * @see x509_init()
 ****************************************************************************/
static unsigned
convert_oid(unsigned char *dst, size_t sizeof_dst, const char *src)
{
    size_t offset = 0;

    /* 'for all text characters' */
    while (*src) {
        const char *next_src;
        unsigned id;
        unsigned count;
        unsigned i;

        /* skip to next number */
        while (*src == '.')
            src++;

        /* parse integer */
        id = (unsigned)strtoul(src, (char**)&next_src, 0);
        if (src == next_src)
            break; /* invalid integer, programming error */
        else
            src = next_src;

        /* find length of the integer */
        count = id_prefix_count(id);
        
        /* add binary integer to pattern */
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
     * an efficientdata structure. Later, when we get packets, we'll
     * use this for searching */
    smack_compile(global_mib);

}



/****************************************************************************
 * Since ASN.1 contains nested structures, each with their own length field,
 * we must maintain a small stack as we parse down the structure. Every time
 * we enter a field, this function "pushes" the ASN.1 "length" field onto
 * the stack. When we are done parsing the current field, we'll pop the
 * length back off the stack, and subtract from it the number of bytes
 * we've parsed.
 *
 * @param x
 *      The X.509 certificate parsing structure.
 * @param next_state
 *      Tells the parser the next field we'll be parsing after this field
 *      at the same level of the nested ASN.1 structure, or nothing if
 *      there are no more fields.
 * @param remaining
 *      The 'length' field. We call it 'remaining' instead of 'length'
 *      because as more bytes arrive, we decrement the length field until
 *      it reaches zero. Thus, at any point of time, it doesn't represent
 *      the length of the current ASN.1 field, but the remaining-length.
 ****************************************************************************/
static void
ASN1_push(struct CertDecode *x, unsigned next_state, uint64_t remaining)
{
    static const size_t STACK_DEPTH 
                            = sizeof(x->stack.remainings)
                                / sizeof(x->stack.remainings[0]);
    
    /* X.509 certificates can't be more than 64k in size. Therefore, to
     * conserve space (as we must store the state for millions of TCP
     * connections), we use the smallest number possible for the length,
     * meaning a 16-bit 'unsigned short'. If the certificate has a larger
     * length field, we need to reject it. */
    if ((remaining >> 16) != 0) {
        fprintf(stderr, "ASN.1 length field too big\n");
        x->state = 0xFFFFFFFF;
        return;
    }
    
    /* Make sure we don't recurse too deep, past the end of the stack. Note
     * that this condition checks a PRGRAMMING error not an INPUT error,
     * because we skip over fields we don't care about, and don't recurse
     * into them even if they have many levels deep */
    if (x->stack.depth >= STACK_DEPTH) {
        fprintf(stderr, "ASN.1 recursion too deep\n");
        x->state = 0xFFFFFFFF;
        return;
    }
    
    /* Subtract this length from it's parent.
     * 
     *[ASN1-CHILD-OVERFLOW]
     * It is here that we deal with the classic ASN.1 parsing problem in
     * which the child object claims a bigger length than its parent 
     * object. We could shrink the length field to fit, then continue
     * parsing, but instead we choose to instead cease parsing the certificate.
     * Note that this property is recursive: I don't need to redo the check
     * all the way up the stack, because I know my parent's length does
     * not exceed my grandparent's length.
     * I know certificates exist that trigger this error -- I need to track
     * them down and figure out why.
     */
    if (x->stack.depth) {
        if (remaining > x->stack.remainings[0]) {
            LOG(1, "ASN.1 inner object bigger than container [%u, %u]\n",
                next_state, x->stack.states[0]);
            x->state = 0xFFFFFFFF;
            return;
        }
        x->stack.remainings[0] = (unsigned short)
                                        (x->stack.remainings[0] - remaining);
    }
    
    /* Since 'remainings[0]' always represents the top of the stack, we
     * move all the bytes down one during the push operation. I suppose this
     * is more expensive than doing it the other way, where something
     * like "raminings[stack.depth]" reprents the top of the stack,
     * meaning no moves are necessary, but I prefer the cleanliness of the
     * code using [0] index instead */
    memmove(    &x->stack.remainings[1], 
                &x->stack.remainings[0], 
                x->stack.depth * sizeof(x->stack.remainings[0]));
    x->stack.remainings[0] = (unsigned short)remaining;
    
    memmove(    &x->stack.states[1], 
                &x->stack.states[0], 
                x->stack.depth * sizeof(x->stack.states[0]));
    x->stack.states[0] = (unsigned char)next_state;
    
    /* increment the count by one and exit */
    x->stack.depth++;
}


/****************************************************************************
 * This is the corresponding 'pop' operation to the ASN1_push() operation.
 * See that function for more details.
 * @see ASN1_push()
 ****************************************************************************/
static unsigned
ASN1_pop(struct CertDecode *x)
{
    unsigned next_state;
    next_state = x->stack.states[0];
    x->stack.depth--;
    memmove(    &x->stack.remainings[0], 
                &x->stack.remainings[1], 
                x->stack.depth * sizeof(x->stack.remainings[0]));
    memmove(    &x->stack.states[0], 
                &x->stack.states[1], 
                x->stack.depth * sizeof(x->stack.states[0]));
    return next_state;
}


/****************************************************************************
 * Called to skip the remainder of the ASN.1 field
 * @return
 *      1 if we've reached the end of the field
 *      0 otherwise
 ****************************************************************************/
static unsigned
ASN1_skip(struct CertDecode *x, unsigned *i, size_t length)
{
    unsigned len;

    if (x->stack.remainings[0] == 0)
        return 1;
    
    /* bytes remaining in packet */
    len = (unsigned)(length - (*i) - 1);

    /* bytes remaining in field */
    if (len > x->stack.remainings[0])
        len = x->stack.remainings[0];

    /* increment 'offset' by this length */
    (*i) += len;

    /* decrement 'remaining' by this length */
    x->stack.remainings[0] = (unsigned short)(x->stack.remainings[0] - len);

    return x->stack.remainings[0] == 0;
    
}


/****************************************************************************
 * The X.509 ASN.1 parser is done with a state-machine, where each byte of
 * the certificate has a corresponding state value. This massive enum
 * is for all those states.
 * DANGER NOTE NOTE NOTE NOTE DANGER NOTE DANGER NOTE
 *  These states are in a specific order. We'll just do 'state++' sometimes
 *  to go the next state. Therefore, you can't chane the order wihtout
 *  changing the code.
 ****************************************************************************/
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
    EXTENSIONS_A_TAG, EXTENSIONS_A_LEN, EXTENSIONS_A_LENLEN,
    EXTENSIONS_S_TAG, EXTENSIONS_S_LEN, EXTENSIONS_S_LENLEN,
    EXTENSION_TAG,    EXTENSION_LEN,    EXTENSION_LENLEN,
    EXTENSION_ID_TAG, EXTENSION_ID_LEN, EXTENSION_ID_LENLEN, EXTENSION_ID_CONTENTS0, EXTENSION_ID_CONTENTS1,
    EXTVALUE_TAG,   EXTVALUE_LEN,   EXTVALUE_LENLEN, 
    EXTVALUE2_TAG,  EXTVALUE2_LEN,  EXTVALUE2_LENLEN, 
    EXTVALUE3_TAG,  EXTVALUE3_LEN,  EXTVALUE3_LENLEN, 
        EXT_DNSNAME_TAG, EXT_DNSNAME_LEN, EXT_DNSNAME_LENLEN, EXT_DNSNAME_CONTENTS,
    ALGOID0_TAG,    ALGOID0_LEN,    ALGOID0_LENLEN,
    ALGOID1_TAG,    ALGOID1_LEN,    ALGOID1_LENLEN,     ALGOID1_CONTENTS0, ALGOID1_CONTENTS1,
    ENC_TAG,        ENC_LEN,        ENC_LENLEN,         ENC_CONTENTS,
    
    
    PADDING=254,
    ERROR=0xFFFFFFFF,
};

/****************************************************************************
 * My parser was kludged together in a couple of hours, and has this bug 
 * where I really don't know the next state like I should. Therefore, this
 * function patches it, converting the next state I think I want to the
 * next state that I really do want.
 * TODO: fix the parser so that this function is no longer necessary.
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
    case EXTENSION_LEN:
        return EXTENSION_TAG;
    case EXTENSION_ID_LEN:
        return EXTVALUE_TAG;
    case EXT_DNSNAME_LEN:
        return EXTVALUE3_TAG;
    case SUBJECTID_LEN:
        return SUBJECTNAME_TAG;
    case VALIDITY_LEN:
        return SUBJECT0_TAG;
    case VNBEFORE_LEN:
        return VNAFTER_TAG;
    case PUBKEY0_LEN:
        return EXTENSIONS_A_TAG;
    default:
        return PADDING;
    }
}




/****************************************************************************
 * This is a parser for X.509 certificates. It uses "state-machine"
 * technology, so that it accepts an in-order sequence of fragments. The
 * entire x.509 certificate does not need to be in memory -- you can start
 * calling this function when you have only the first fragment.
 *
 * It works by enumerating every possible state. In other words, every
 * byte of an X.509 certificate has an enumerated 'state' variable. As 
 * each byte arrives from the stream, we parse it, and change to the next
 * state. When we run out of input, we exit the function, saving the
 * current state-variable. When the next fragment arrives, we resume
 * at the same state where we left off.
 ****************************************************************************/
void
x509_decode(struct CertDecode *x, 
            const unsigned char *px, size_t length, 
            struct BannerOutput *banout)
{
    unsigned i;
    enum X509state state = x->state;


#define GOTO_ERROR(state, i, length) (state)=0xFFFFFFFF;(i)=(length);continue

    /* 'for all bytes in the current fragment ...'
     *   'process that byte, causing a state-transition ' 
     */
    for (i=0; i<length; i++) {
        
        
        /*
         * If we've reached the end of the current field, then we need to 
         * pop up the stack and resume parsing the parent field. Since we
         * reach the end of several levels simultaneously, we may need to
         * pop several levels at once
         */
        while (x->stack.remainings[0] == 0) {
            if (x->stack.depth == 0)
                return;
            state = ASN1_pop(x);
        }
        
        /*
         * Decrement the current 'remaining' length field.
         */
        x->stack.remainings[0]--;

        /*
         * Jump to the current current state
         */
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
            if (x->is_capture_issuer) {
                banout_append(banout, PROTO_SSL3, " issuer[", AUTO_LEN);
            }
            state++;
            break;
        case SUBJECTNAME_TAG:
            if (px[i] != 0x13 && px[i] != 0x0c) {
                state++;
                continue;
            }
            if (x->is_capture_subject) {
                banout_append(banout, PROTO_SSL3, " subject[", AUTO_LEN);
            }
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
        case EXTENSION_ID_TAG:
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
            if (x->is_capture_issuer) {
                banout_append(banout, PROTO_SSL3, px+i, 1);
                if (x->stack.remainings[0] == 0)
                    banout_append(banout, PROTO_SSL3, "]", 1);
            }
            break;
        case SUBJECTNAME_CONTENTS:
        case EXT_DNSNAME_CONTENTS:
            if (x->is_capture_subject) {
                banout_append(banout, PROTO_SSL3, px+i, 1);
                if (x->stack.remainings[0] == 0)
                    banout_append(banout, PROTO_SSL3, "]", 1);
            } else if (x->subject.type == Subject_Common)
                banout_append(banout, PROTO_SSL3, px+i, 1);
            break;
        case VERSION_CONTENTS:
            x->u.num <<= 8;
            x->u.num |= px[i];
            if (x->stack.remainings[0] == 0)
                state = PADDING;
            break;
        case ISSUERID_CONTENTS0:
        case SUBJECTID_CONTENTS0:
        case EXTENSION_ID_CONTENTS0:
        case ALGOID1_CONTENTS0:
        case SIG1_CONTENTS0:
            memset(&x->u.oid, 0, sizeof(x->u.oid));
            state++;
        case ISSUERID_CONTENTS1:
        case SUBJECTID_CONTENTS1:
        case EXTENSION_ID_CONTENTS1:
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
                                        offset + 1);
                x->u.oid.state = (unsigned short)oid_state;

                /* Do the multibyte numbers */
                x->u.oid.num <<= 7;
                x->u.oid.num |= px[i] & 0x7F;

                if (px[i] & 0x80) {
                    /* This is a multibyte number, don't do anything at
                     * this stage */
                    ;
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
                        if (x->subject.type == Subject_Common 
                                            && state == SUBJECTID_CONTENTS1) {
                            if (x->count <= 1) {
                                /* only handle first certificate in the chain */
                                banout_append(banout, PROTO_SSL3, ", ", 2);
                            } else {
                                x->subject.type = 0;
                            }

                            
                        }
                        //if (x->subject.type == Subject_Common 
                        //                    && state == EXTENSION_ID_CONTENTS1)
                        //    ; //banout_append(banout, PROTO_SSL3, ", ", 2);
                        x->u.oid.last_id = (unsigned char)id;
                    }
                    x->u.oid.num = 0;
                }
                if (x->stack.remainings[0] == 0) {
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
            x->stack.states[0] = (unsigned char)(state+1);
            x->u.num <<= 8;
            x->u.num |= px[i];
            if (x->stack.remainings[0] == 0)
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
        case EXTENSIONS_S_TAG:
        case EXTENSION_TAG:
        case EXTVALUE2_TAG:
        case ALGOID0_TAG:
            if (px[i] != 0x30) {
                state = ERROR;
                continue;
            }
            state++;
            break;
        case EXTENSIONS_A_TAG:
            if (px[i] != 0xa3) {
                state = ERROR;
                continue;
            }
            state++;
            break;

        /*
        GeneralName ::= CHOICE {
            otherName                       [0]     OtherName,
            rfc822Name                      [1]     IA5String,
            dNSName                         [2]     IA5String,
            x400Address                     [3]     ORAddress,
            directoryName                   [4]     Name,
            ediPartyName                    [5]     EDIPartyName,
            uniformResourceIdentifier       [6]     IA5String,
            iPAddress                       [7]     OCTET STRING,
            registeredID                    [8]     OBJECT IDENTIFIER }
        */
      
        case EXTVALUE3_TAG:
            if (x->subject.type == Subject_Common) {
                switch (px[i]) {
                case 0x82: /* dNSName */
                    banout_append(banout, PROTO_SSL3, ", ", 2);
                    state = EXT_DNSNAME_LEN;
                    break;
                default:
                    state = PADDING;
                    break;
                }
            } else {
                state = PADDING;
            }
            break;

        case EXTVALUE_TAG:
            /* can be anything */
            switch (px[i]) {
            default:
            case 2:
                state = PADDING;
                break;
            case 4:
                state++;
                break;
            }
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
        case EXTENSIONS_A_LEN:
        case EXTENSIONS_S_LEN:
        case EXTENSION_LEN:
        case EXTENSION_ID_LEN:
        case EXTVALUE_LEN:
        case EXTVALUE2_LEN:
        case EXTVALUE3_LEN:
        case EXT_DNSNAME_LEN:
        case PUBKEY0_LEN:
        case ALGOID0_LEN:
        case ALGOID1_LEN:
        case ENC_LEN:
            /* We do the same processing for all the various length fields.
             * There are three possible length fields:
             * 0x7F - for lengths 127 and below
             * 0x81 XX - for lengths 127 to 255
             * 0x82 XX XX - for length 256 to 65535
             * This state processes the first byte, and if it's an extended
             * field, switches to the correspondign xxx_LENLEN state
             */
            if (px[i] & 0x80) {
                x->u.tag.length_of_length = px[i]&0x7F;
                x->u.tag.remaining = 0;
                state++;
                break;
            } else {
                x->u.tag.remaining = px[i];
                ASN1_push(x, kludge_next(state), x->u.tag.remaining);
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
        case EXTENSIONS_A_LENLEN:
        case EXTENSIONS_S_LENLEN:
        case EXTENSION_LENLEN:
        case EXTENSION_ID_LENLEN:
        case EXTVALUE_LENLEN:
        case EXTVALUE2_LENLEN:
        case EXTVALUE3_LENLEN:
        case EXT_DNSNAME_LENLEN:
        case ALGOID0_LENLEN:
        case ALGOID1_LENLEN:
        case ENC_LENLEN:
            /* We process all multibyte lengths the same way in this
             * state.
             */
                
            /* [ASN1-DER-LENGTH]
             * Check for strict DER compliance, which says that there should
             * be no leading zero bytes */
            if (x->u.tag.remaining == 0 && px[i] == 0)
                x->is_der_failure = 1;
            
            /* parse this byte */
            x->u.tag.remaining = (x->u.tag.remaining)<<8 | px[i];
            x->u.tag.length_of_length--;
                
            /* If we aren't finished yet, loop around and grab the next */
            if (x->u.tag.length_of_length)
                continue;
                
            /* [ASN1-DER-LENGTH]
             * Check for strict DER compliance, which says that for lengths
             * 127 and below, we need only 1 byte to encode it, not many */
            if (x->u.tag.remaining < 128)
                x->is_der_failure = 1;

            /*
             * We have finished parsing the tag-length fields, and are now
             * ready to parse the 'value'. Push the current state on the 
             * stack, then decend into the child field.
             */
            ASN1_push(x, kludge_next(state-1), x->u.tag.remaining);
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
            /* [ASN1-CHILD-UNDERFLOW]
             * This state is reached when we've parsed everything inside an
             * ASN.1 field, yet there are still bytes left to parse. There
             * are TWO reasons why we reach this state.
             *  #1  there is a strict DER encoding problem, and we ought
             *      to flag the error
             *  #2  are parser is incomplete; we simply haven't added code
             *      for all fields yet, and therefore treat them as padding
             * We should flag the DER failure, but we can't, because the
             * existence of unparsed fields mean we'll falsely trigger DER
             * errors all the time.
             *
             * Note that due to the state-machine style parsing, we don't do
             * anything in this field. This problem naturally takes care of
             * itself.
             */
            break;

        case PUBKEY0_CONTENTS:
        case ENC_CONTENTS:
            ASN1_skip(x, &i, length);
            break;

        case ERROR:
        default:
            ASN1_skip(x, &i, length);
            break;
        }
    }

    /*
     * Save the state variable and exit
     */
    if (x->state != 0xFFFFFFFF)
        x->state = state;
}
void
spnego_decode(struct SpnegoDecode *spnego,
            const unsigned char *px, size_t length,
            struct BannerOutput *banout)
{
    struct CertDecode *x = spnego->x509;
    unsigned i;
    unsigned state = x->state;
    
    enum {
        /*NegotiationToken ::= CHOICE {
            negTokenInit    [0] NegTokenInit,
            negTokenResp    [1] NegTokenResp
        }*/
        NegotiationToken_tag, len, lenlen,
        
        NegTokenInit_tag,
        NegTokenInit_choice,
        NegTokenResp_tag,
        NegTokenResp_choice,
        mechType_tag,
        
        negState_tag,
        supportedMech_tag,
        responseToken_tag,
        mechListMIC_tag,
        
        mechTypes_tag,
        reqFlags_tag,
        mechToken_tag,
        
        mechToken_content,
        responseToken_content,
        mechToken_content2,
        responseToken_content2,

        UnknownContents,
        
        
    };
    
#define GOTO_ERROR(state, i, length) (state)=0xFFFFFFFF;(i)=(length);continue
    
    /* 'for all bytes in the current fragment ...'
     *   'process that byte, causing a state-transition '
     */
    for (i=0; i<length; i++) {
        
        
        /*
         * If we've reached the end of the current field, then we need to
         * pop up the stack and resume parsing the parent field. Since we
         * reach the end of several levels simultaneously, we may need to
         * pop several levels at once
         */
        while (x->stack.remainings[0] == 0) {
            if (x->stack.depth == 0)
                return;
            state = ASN1_pop(x);
        }
        
        /*
         * Decrement the current 'remaining' length field.
         */
        x->stack.remainings[0]--;
        
        /*
         * Jump to the current current state
         */
        switch (state) {
            case NegotiationToken_tag:
                x->brother_state = UnknownContents;
                switch (px[i]) {
                    case 0xa0:
                        x->child_state = NegTokenInit_tag;
                        break;
                    case 0xa1:
                        x->child_state = NegTokenResp_tag;
                        break;
                    case 0x60:
                        x->child_state = mechType_tag;
                        break;
                    default:
                        x->child_state = UnknownContents;
                        break;
                }
                state = len;
                break;
                
            case NegTokenResp_choice:
                /*
                 NegTokenResp ::= SEQUENCE {
                 negState       [0] ENUMERATED {
                    accept-completed    (0),
                    accept-incomplete   (1),
                    reject              (2),
                    request-mic         (3)
                    }                                 OPTIONAL,
                 -- REQUIRED in the first reply from the target
                 supportedMech   [1] MechType      OPTIONAL,
                 -- present only in the first reply from the target
                 responseToken   [2] OCTET STRING  OPTIONAL,
                 mechListMIC     [3] OCTET STRING  OPTIONAL,
                 ...
                 }*/
                x->brother_state = NegTokenResp_choice;
                switch (px[i]) {
                    case 0xa0:
                        x->child_state = negState_tag;
                        break;
                    case 0xa1:
                        x->child_state = supportedMech_tag;
                        break;
                    case 0xa2:
                        x->child_state = responseToken_tag;
                        break;
                    case 0xa3:
                        x->child_state = mechListMIC_tag;
                        break;
                    default:
                        x->child_state = UnknownContents;
                        break;
                }
                state = len;
                break;
                
            case NegTokenResp_tag:
                if (px[i] != 0x30) {
                    x->brother_state = UnknownContents;
                    x->child_state = UnknownContents;
                } else {
                    x->brother_state = UnknownContents;
                    x->child_state = NegTokenResp_choice;
                }
                state = len;
                break;
                
            case NegTokenInit_choice:
                /*
                 NegTokenInit ::= SEQUENCE {
                 mechTypes       [0] MechTypeList,
                 reqFlags        [1] ContextFlags  OPTIONAL,
                 -- inherited from RFC 2478 for backward compatibility,
                 -- RECOMMENDED to be left out
                 mechToken       [2] OCTET STRING  OPTIONAL,
                 mechListMIC     [3] OCTET STRING  OPTIONAL,
                 ...
                 }
                 }*/
                x->brother_state = NegTokenInit_choice;
                switch (px[i]) {
                    case 0xa0:
                        x->child_state = mechTypes_tag;
                        break;
                    case 0xa1:
                        x->child_state = reqFlags_tag;
                        break;
                    case 0xa2:
                        x->child_state = mechToken_tag;
                        break;
                    case 0xa3:
                        x->child_state = mechListMIC_tag;
                        break;
                    default:
                        x->child_state = UnknownContents;
                        break;
                }
                state = len;
                break;
            
            case NegTokenInit_tag:
                if (px[i] != 0x30) {
                    x->brother_state = UnknownContents;
                    x->child_state = UnknownContents;
                } else {
                    x->brother_state = UnknownContents;
                    x->child_state = NegTokenInit_choice;
                }
                state = len;
                break;

            case mechType_tag:
                if (px[i] == 0x06) {
                    x->brother_state = NegotiationToken_tag;
                    x->child_state = UnknownContents;
                } else {
                    x->brother_state = NegotiationToken_tag;
                    x->child_state = UnknownContents;
                }
                state = len;
                break;
            
            case negState_tag:
            case supportedMech_tag:
            case mechListMIC_tag:
            case mechTypes_tag:
            case reqFlags_tag:
                x->brother_state = UnknownContents;
                x->child_state = UnknownContents;
                state = len;
                break;
            
            case responseToken_tag:
                x->brother_state = UnknownContents;
                x->child_state = responseToken_content;
                state = len;
                break;
                
            case mechToken_tag:
                x->brother_state = UnknownContents;
                x->child_state = mechToken_content;
                state = len;
                break;
            
            case mechToken_content:
            case mechToken_content2:
                break;
             
                /************************************************************************
                 ************************************************************************
                 ************************************************************************
                 ************************************************************************
                 ************************************************************************
                 ************************************************************************
                 ************************************************************************
                 */
            case responseToken_content:
                ntlmssp_decode_init(&spnego->ntlmssp, x->stack.remainings[0] + 1);
                state = responseToken_content2;
                /* fall through */
            case responseToken_content2:
            {
                size_t new_max = length - i;
                
                if (new_max > x->stack.remainings[0] + 1U)
                    new_max = x->stack.remainings[0] + 1;
                
                ntlmssp_decode(&spnego->ntlmssp, px+i, new_max, banout);
                
                x->stack.remainings[0] -= (unsigned short)(new_max - 1);
                if (x->stack.remainings[0] == 0) {
                    if (spnego->ntlmssp.buf)
                        free(spnego->ntlmssp.buf);
                }
            }
                break;
                
            case len:
                /* We do the same processing for all the various length fields.
                 * There are three possible length fields:
                 * 0x7F - for lengths 127 and below
                 * 0x81 XX - for lengths 127 to 255
                 * 0x82 XX XX - for length 256 to 65535
                 * This state processes the first byte, and if it's an extended
                 * field, switches to the correspondign xxx_LENLEN state
                 */
                if (px[i] & 0x80) {
                    x->u.tag.length_of_length = px[i]&0x7F;
                    x->u.tag.remaining = 0;
                    state = lenlen;
                    break;
                } else {
                    x->u.tag.remaining = px[i];
                    ASN1_push(x, x->brother_state, x->u.tag.remaining);
                    state = x->child_state;
                    memset(&x->u, 0, sizeof(x->u));
                    break;
                }
                break;
            case lenlen:
                /* We process all multibyte lengths the same way in this
                 * state.
                 */
                
                /* [ASN1-DER-LENGTH]
                 * Check for strict DER compliance, which says that there should
                 * be no leading zero bytes */
                if (x->u.tag.remaining == 0 && px[i] == 0)
                    x->is_der_failure = 1;
                
                /* parse this byte */
                x->u.tag.remaining = (x->u.tag.remaining)<<8 | px[i];
                x->u.tag.length_of_length--;
                
                /* If we aren't finished yet, loop around and grab the next */
                if (x->u.tag.length_of_length)
                    continue;
                
                /* [ASN1-DER-LENGTH]
                 * Check for strict DER compliance, which says that for lengths
                 * 127 and below, we need only 1 byte to encode it, not many */
                if (x->u.tag.remaining < 128)
                    x->is_der_failure = 1;
                
                /*
                 * We have finished parsing the tag-length fields, and are now
                 * ready to parse the 'value'. Push the current state on the
                 * stack, then decend into the child field.
                 */
                ASN1_push(x, x->brother_state, x->u.tag.remaining);
                state = x->child_state;
                memset(&x->u, 0, sizeof(x->u));
                break;
            default:
                ;
        }
    }
}


/****************************************************************************
 * This function must be called to set the initial state.
 * @param length
 *      The size of the certificate. This is parsed from the SSL/TLS field.
 *      We know that if we exceed this number of bytes, then an overflow has
 *      occured.
 ****************************************************************************/
void
x509_decode_init(struct CertDecode *x, size_t length)
{
    memset(x, 0, sizeof(*x));
    ASN1_push(x, 0xFFFFFFFF, length);
}
void
spnego_decode_init(struct SpnegoDecode *x, size_t length)
{
    memset(x, 0, sizeof(*x));
    
    ASN1_push(x->x509, 0xFFFFFFFF, length);
}


