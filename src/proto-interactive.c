#include "proto-interactive.h"

void
tcp_transmit(struct InteractiveData *more, const void *payload, size_t length, unsigned flags)
{
    more->m_payload = payload;
    more->m_length = (unsigned)length;
    
    if (flags & TCPTRAN_DYNAMIC)
        more->is_payload_dynamic = 1;
}
