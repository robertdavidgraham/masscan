
#include "proto-tcp-rdp.h"
#include "proto-banner1.h"
#include "proto-interactive.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "util-malloc.h"
#include "assert.h"
#include <ctype.h>
#include <string.h>
#include "string_s.h"

/***************************************************************************
 * @param length
 *      Number of bytes remaining in this header, or bytes remaining in
 *      the packet, whichever is fewer.
 * @return the number of bytes processed
 ***************************************************************************/
static size_t
cc_parse(struct BannerOutput *banout, struct RDPSTUFF *rdp, const unsigned char *px, size_t length)
{
    size_t offset;
    unsigned state = rdp->cc.state;
    enum {
        TYPE, FLAGS, LENGTH, RESERVED, RESULT0, RESULT1, RESULT2, RESULT3, EXTRA, UNKNOWN_PROTOCOL
    };
    for (offset = 0; offset < length; offset++) {
        unsigned char c = px[offset];
        switch (state) {
            case TYPE:
                rdp->cc.type = c;
                state++;
                break;
            case FLAGS:
                rdp->cc.flags = c;
                state++;
                break;
            case LENGTH:
                rdp->cc.len = c;
                if (rdp->cc.len < 4) {
                    state = UNKNOWN_PROTOCOL;
                } else {
                    rdp->cc.len -= 4;
                    state++;
                }
                break;
            case RESERVED:
                switch (rdp->cc.type) {
                    case 2: /* negotiate success */
                    case 3: /* negotiate failure */
                        state = RESULT0;
                        rdp->cc.result = 0;
                        break;
                    default:
                        state = EXTRA;
                        break;
                }
                break;
            case RESULT0:
            case RESULT1:
            case RESULT2:
            case RESULT3:
                if (rdp->cc.len == 0)
                    state = EXTRA;
                else {
                    rdp->cc.len--;
                    rdp->cc.result = rdp->cc.result>>8 | (c << 24);
                    state++;
                    if (state == EXTRA) {
                        switch (rdp->cc.type) {
                            case 2:
                                if (rdp->cc.result & 2)
                                    banout_append(banout, PROTO_RDP, " NLA-supported", AUTO_LEN);
                                else
                                    banout_append(banout, PROTO_RDP, " NLA-unused", AUTO_LEN);
                                break;
                            case 3:
                                if (rdp->cc.result == 5)
                                    banout_append(banout, PROTO_RDP, " NLA-unsupported", AUTO_LEN);
                                else
                                    banout_append(banout, PROTO_RDP, " failure", AUTO_LEN);
                                break;
                            default:
                                banout_append(banout, PROTO_RDP, " unknown", AUTO_LEN);
                                break;
                        }
                    }
                }
                break;
                
            case EXTRA:
                offset = length;
                break;
            case UNKNOWN_PROTOCOL:
                banout_append(banout, PROTO_HEUR, px, length);
                offset = length;
                break;
        }
    }
    
    rdp->cc.state = state;
    return offset;
}

/***************************************************************************
 * @param length
 *      The number of bytes left in those received, or the number of bytes
 *      left in the COTP contents, whichever is less.
 * @return the number of bytes processed
 ***************************************************************************/
static size_t
cotp_parse(struct BannerOutput *banout, struct RDPSTUFF *rdp, const unsigned char *px, size_t length)
{
    size_t offset;
    unsigned state = rdp->cotp.state;
    enum {
        LENGTH, PDU_TYPE, DSTREF0, DSTREF1, SRCREF0, SRCREF1,
        FLAGS, CONTENT, UNKNOWN_PROTOCOL,
    };
    for (offset = 0; offset < length; offset++) {
        unsigned char c = px[offset];
        switch (state) {
            case LENGTH:
                rdp->cotp.len = c;
                if (rdp->cotp.len < 6) {
                    state = UNKNOWN_PROTOCOL;
                } else {
                    rdp->cotp.len -= 6;
                    state++;
                }
                break;
            case PDU_TYPE:
                rdp->cotp.type = c;
                rdp->cotp.srcref = 0;
                rdp->cotp.dstref = 0;
                state++;
                break;
            case DSTREF0:
            case DSTREF1:
                rdp->cotp.dstref = rdp->cotp.dstref<<8 | c;
                state++;
                break;
            case SRCREF0:
            case SRCREF1:
                rdp->cotp.dstref = rdp->cotp.dstref<<8 | c;
                state++;
                break;
            case FLAGS:
                rdp->cotp.flags = c;
                rdp->cc.state = 0;
                state++;
                break;
            case CONTENT:
                switch (rdp->cotp.type) {
                    case 0xd0: /* connect confirm */
                    {
                        size_t length2 = rdp->cotp.len;
                        size_t bytes_parsed;
                        
                        /* In case the TPKT length is more bytes than are in this packet */
                        if (length2 >= length - offset)
                            length2 = length - offset;
                        
                        bytes_parsed = cc_parse(banout, rdp, px + offset, length2);
                        
                        /* Track how many bytes the sub-parsers parsed, remembering
                         * that when the for-loop increments, it'll increment the offset
                         * by 1. */
                        assert(bytes_parsed != 0);
                        offset += bytes_parsed - 1;
                        rdp->cotp.len -= (unsigned char)bytes_parsed;
                        
                        /* If we have bytes left in the TPKT, then stay in this state,
                         * otherwise transition to the next TPKT */
                        if (rdp->cotp.len)
                            state = CONTENT;
                        else
                            state = UNKNOWN_PROTOCOL;

                    }
                        break;
                    default:
                        banout_append(banout, PROTO_RDP, " COTPPDU=unknown", AUTO_LEN);
                        offset = length;
                        break;
                }
                break;
            case UNKNOWN_PROTOCOL:
                banout_append(banout, PROTO_HEUR, px, length);
                offset = length;
                break;
        }
    }
    
    rdp->cotp.state = state;
    return offset;
}

/***************************************************************************
 ***************************************************************************/
static void
rdp_parse(  const struct Banner1 *banner1,
             void *banner1_private,
             struct ProtocolState *pstate,
             const unsigned char *px, size_t length,
             struct BannerOutput *banout,
             struct InteractiveData *more)
{
    unsigned state = pstate->state & 0xFFFFFF;
    struct RDPSTUFF *rdp = &pstate->sub.rdp;
    size_t offset;
    enum {
        TPKT_START,
        TPKT_RESERVED,
        TPKT_LENGTH0, TPKT_LENGTH1,
        TPKT_CONTENT,
        UNKNOWN_PROTOCOL,
    };
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);
    UNUSEDPARM(more);
    
    for (offset=0; offset<length; offset++) {
        unsigned char c = px[offset];
        switch (state & 0xF) {
            case TPKT_START:
                if (c != 3) { /* TPKT version=3 */
                    state = UNKNOWN_PROTOCOL;
                    offset--;
                } else {
                    rdp->tpkt_length = 0;
                    rdp->cotp.state = 0;
                    state = TPKT_RESERVED;
                }
                break;
            case TPKT_RESERVED:
                state++;
                break;
            case TPKT_LENGTH0:
                rdp->tpkt_length = rdp->tpkt_length;
                state++;
                break;
            case TPKT_LENGTH1:
                rdp->tpkt_length = rdp->tpkt_length<<8 | c;
                if (rdp->tpkt_length < 4) {
                    state = UNKNOWN_PROTOCOL;
                } else if (rdp->tpkt_length == 4) {
                    state = 0;
                } else {
                    rdp->tpkt_length -= 4;
                    state++;
                }
                break;
            case TPKT_CONTENT:
            {
                size_t length2 = rdp->tpkt_length;
                size_t bytes_parsed;
                
                /* In case the TPKT length is more bytes than are in this packet */
                if (length2 >= length - offset)
                    length2 = length - offset;
                
                bytes_parsed = cotp_parse(banout, rdp, px + offset, length2);
                
                /* Track how many bytes the sub-parsers parsed, remembering
                 * that when the for-loop increments, it'll increment the offset
                 * by 1. */
                assert(bytes_parsed != 0);
                offset += bytes_parsed - 1;
                rdp->tpkt_length -= (unsigned short)bytes_parsed;
                
                /* If we have bytes left in the TPKT, then stay in this state,
                 * otherwise transition to the next TPKT */
                if (rdp->tpkt_length)
                    state = TPKT_CONTENT;
                else
                    state = TPKT_START;
            }
                break;
            case UNKNOWN_PROTOCOL:
                banout_append(banout, PROTO_HEUR, px, length);
                offset = length;
                break;
            default:
                break;
        }
    }
    pstate->state = state;
}

/***************************************************************************
 ***************************************************************************/
static void *
rdp_init(struct Banner1 *banner1)
{
    UNUSEDPARM(banner1);
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int
rdp_selftest_item(const char *input, size_t length, const char *expect)
{
    struct Banner1 *banner1;
    struct ProtocolState pstate[1];
    struct BannerOutput banout1[1];
    struct InteractiveData more;
    int x;
    
    /*
     * Initiate a pseudo-environment for the parser
     */
    banner1 = banner1_create();
    banout_init(banout1);
    memset(&pstate[0], 0, sizeof(pstate[0]));
    
    /*
     * Parse the input payload
     */
    rdp_parse(banner1,
              0,
              pstate,
              (const unsigned char *)input,
              length,
              banout1,
              &more
              );
    
    /*
     * Verify that somewhere in the output is the string
     * we are looking for
     */
    x = banout_is_contains(banout1, PROTO_RDP, expect);
    if (x == 0)
        printf("RDP parser failure: %s\n", expect);
    
    banner1_destroy(banner1);
    banout_release(banout1);
    
    return (x?0:1);
}

/***************************************************************************
 ***************************************************************************/
static int
rdp_selftest(void)
{
    static const char test1[] =
        "\x03\x00\x00\x13"
        "\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x02\x00\x00\x00";
    static const char test2[] = "\x03\x00\x00\x13"
        "\x0e\xd0\x00\x00\x12\x34\x00\x03\x00\x08\x00\x05\x00\x00\x00";

    int result = 0;
    
    result += rdp_selftest_item(test1, sizeof(test1) - 1, "NLA-sup");
    result += rdp_selftest_item(test2, sizeof(test2) - 1, "NLA-unsup");

    return result;
}

    
/***************************************************************************
 ***************************************************************************/
static const char rdp_hello[] =
"\x03\x00\x00\x2d"
"\x28\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d" \
"\x73\x74\x73\x68\x61\x73\x68\x3d"  "masscan" "\x0d\x0a\x01\x00" \
"\x08\x00\x03\x00\x00\x00";


/***************************************************************************
 ***************************************************************************/
const struct ProtocolParserStream banner_rdp = {
    "telnet", 3389, rdp_hello, sizeof(rdp_hello)-1, 0,
    rdp_selftest,
    rdp_init,
    rdp_parse,
};
