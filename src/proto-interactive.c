#include "proto-interactive.h"

void
tcp_transmit(struct InteractiveData *more, const void *payload, size_t length)
{
    more->payload = payload;
    more->length = (unsigned)length;
}
