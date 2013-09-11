#include "proto-banner1.h"
#include "smack.h"
#include <ctype.h>
#include <stdint.h>

enum {
    HTTPFIELD_INCOMPLETE,
    HTTPFIELD_SERVER,
    HTTPFIELD_UNKNOWN,
    HTTPFIELD_NEWLINE,
};
struct Patterns http_fields[] = {
    {"Server:",     7, HTTPFIELD_SERVER, SMACK_ANCHOR_BEGIN},
    {":",           1, HTTPFIELD_UNKNOWN, 0},
    {"\n",          1, HTTPFIELD_NEWLINE, 0}, 
    {0,0,0,0}
};




/***************************************************************************
 * BIZARRE CODE ALERT!
 *
 * This uses a "byte-by-byte state-machine" to parse the response HTTP
 * header. This is standard practice for high-performance network
 * devices, but is probably unfamiliar to the average network engineer.
 *
 * The way this works is that each byte of input causes a transition to
 * the next state. That means we can parse the response from a server
 * without having to buffer packets. The server can send the response
 * one byte at a time (one packet for each byte) or in one entire packet.
 * Either way, we don't. We don't need to buffer the entire response
 * header waiting for the final packet to arrive, but handle each packet
 * individually.
 * 
 * This is especially useful with our custom TCP stack, which simply
 * rejects out-of-order packets.
 ***************************************************************************/
unsigned
banner_http(  struct Banner1 *banner1,
        unsigned state,
        const unsigned char *px, size_t length,
        char *banner, unsigned *banner_offset, size_t banner_max)
{
    unsigned i;
    unsigned state2;
    size_t id;
    enum {
        FIELD_START = 9,
        FIELD_NAME,
        FIELD_COLON,
        FIELD_VALUE,

    };

    state2 = (state>>16) & 0xFFFF;
    id = (state>>8) & 0xFF;
    state = (state>>0) & 0xFF;

    for (i=0; i<length; i++)
    switch (state) {
    case 0: case 1: case 2: case 3: case 4:
        if (toupper(px[i]) != "HTTP/"[state])
            state = STATE_DONE;
        else
            state++;
        break;
    case 5:
        if (px[i] == '.')
            state++;
        else if (!isdigit(px[i]))
            state = STATE_DONE;
        break;
    case 6:
        if (isspace(px[i]))
            state++;
        else if (!isdigit(px[i]))
            state = STATE_DONE;
        break;
    case 7:
        /* TODO: look for 1xx response code */
        if (px[i] == '\n')
            state = FIELD_START;
        break;
    case FIELD_START:
        if (px[i] == '\r')
            break;
        else if (px[i] == '\n') {
            state = STATE_DONE;
            break;
        } else {
            state2 = 0;
            state = FIELD_NAME;
            /* drop down */
        }

    case FIELD_NAME:
        if (px[i] == '\r')
            break;
        id = smack_search_next(
                        banner1->http_fields,
                        &state2, 
                        px, &i, (unsigned)length);
        if (id == HTTPFIELD_NEWLINE) {
            state2 = 0;
            state = FIELD_START;
        } else if (id == SMACK_NOT_FOUND)
            ; /* continue here */
        else if (id == HTTPFIELD_UNKNOWN) {
            size_t id2;

            id2 = smack_next_match(banner1->http_fields, &state2);
            if (id2 != SMACK_NOT_FOUND)
                id = id2;
        
            state = FIELD_COLON;
        } else
            state = STATE_DONE;
        break;
    case FIELD_COLON:
        if (px[i] == '\n') {
            state = FIELD_START;
            break;
        } else if (isspace(px[i])) {
            break;
        } else {
            state = FIELD_VALUE;
            /* drop down */
        }

    case FIELD_VALUE:
        if (px[i] == '\r')
            break;
        else if (px[i] == '\n') {
            state = FIELD_START;
            break;
        }
        if (id == HTTPFIELD_SERVER) {
            if (*banner_offset < banner_max) {
                banner[(*banner_offset)++] = px[i];
            }
        }
        break;

    case STATE_DONE:
    default:
        i = (unsigned)length;
        break;
    }


    if (state == STATE_DONE)
        return state;
    else
        return (state2 & 0xFFFF) << 16
                | (id & 0xFF) << 8
                | (state & 0xFF);
}
