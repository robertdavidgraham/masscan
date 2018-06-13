#include "proto-interactive.h"
#include <stdlib.h>

/*
 * TODO: we need to track thie memory used for this better than with malloc(), such
 * as usuing a preallocated array of packet buffers. But for now, I'm just using
 * malloc() 'cause I'm a lazy programmer.
 */
unsigned char *
tcp_transmit_alloc(struct InteractiveData *more, size_t length)
{
    return malloc(length);
}


/*
 * This doesn't actually transmit right now. Instead, marks the payload as ready
 * to transmit, which will be transmitted later
 */
void
tcp_transmit(struct InteractiveData *more, const void *payload, size_t length, unsigned flags)
{
    more->m_payload = payload;
    more->m_length = (unsigned)length;
    
    if (flags & TCPTRAN_DYNAMIC)
        more->is_payload_dynamic = 1;
}
