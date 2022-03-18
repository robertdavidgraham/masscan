#include "proto-minecraft.h"
#include "unusedparm.h"

#define STATE_READ_PACKET_LENGTH 1
#define STATE_READ_PACKET_ID     2
#define STATE_READ_DATA_LENGTH   3
#define STATE_READ_DATA         4
#define STATE_MALFORMED          5

static const char minecraft_hello[] = {
    0x15, // length
    0x00, // packet ID (handshake)
    0xff, 0xff, 0xff, 0xff, 0x0f, // protocol version number (-1 for ping) 
    0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // hostname (we just use 'example.com')
    0xdd, 0x36, // port (stick with 25565)
    0x01, // next state (1 for querying server status)
    0x01, // length 
    00 // packet ID (request status)
};

static void minecraft_parse(const struct Banner1 *banner1,
                            void *banner1_private,
                            struct ProtocolState *stream_state,
                            const unsigned char *px, size_t length,
                            struct BannerOutput *banout,
                            struct InteractiveData *more) {
    
    unsigned state = stream_state->state; // assuming this starts out at zero
    struct MINECRAFTSTUFF *mc = &stream_state->sub.minecraft;
    
    UNUSEDPARM(banner1_private);
    UNUSEDPARM(banner1);

    // beware: the `bytes_read` field is reused
    for(size_t i = 0; i < length; i++) {
        switch(state) {
            
            // initial: set up some stuff
            case 0:
                mc->varint_accum = 0;
                mc->bytes_read = 0;
                state = STATE_READ_PACKET_LENGTH;
                // !!! fall through !!!

            // read varint
            // reuse same code for both varints
            case STATE_READ_PACKET_LENGTH:
            case STATE_READ_DATA_LENGTH:
                if(mc->bytes_read > 5) { // varint too long
                    state = STATE_MALFORMED;
                    break;
                }
                mc->varint_accum |= (unsigned)(px[i] & 0x7f) << (mc->bytes_read * 7);
                if(!(px[i] & 0x80)) { // msb indicates whether there are more bytes in the varint
                    if(state == STATE_READ_PACKET_LENGTH) {
                        state = STATE_READ_PACKET_ID;
                    } else {
                        mc->bytes_read = 0;
                        state = STATE_READ_DATA;
                    }
                }
                mc->bytes_read++;
                break;

            case STATE_READ_PACKET_ID:
                if(px[i] == 0x00) {
                    mc->varint_accum = 0;
                    mc->bytes_read = 0;
                    state = STATE_READ_DATA_LENGTH;
                } else {
                    state = STATE_MALFORMED;
                }
                break;

            case STATE_READ_DATA:
                if(mc->bytes_read == mc->varint_accum) {
                    state = STATE_MALFORMED;
                    break;
                } 
                banout_append_char(banout, PROTO_MINECRAFT, px[i]);
                mc->bytes_read++;
                break;
                
            // skip to the end if something went wrong
            default:
                i = (unsigned)length;

        }
    }

    stream_state->state = state;

}

static void *minecraft_init(struct Banner1 *banner1) {
    UNUSEDPARM(banner1);
    return 0;
}

// TODO
static int minecraft_selftest() {
    return 0; // TODO
}

const struct ProtocolParserStream banner_minecraft = {
    "minecraft", 25565, minecraft_hello, sizeof(minecraft_hello), 0, 
    minecraft_selftest,
    minecraft_init,
    minecraft_parse
};