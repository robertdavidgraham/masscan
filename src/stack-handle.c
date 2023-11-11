#include "stack-handle.h"
#include "unusedparm.h"
#include "util-malloc.h"
#include <stdlib.h>

void
tcp_close(struct stack_handle_t *more)
{
    if (more == NULL)
        return;
    more->send(more->tcpcon, more->tcb, "", 0, TCP__static, true, more->secs, more->usecs);
}

/*
 * This doesn't actually transmit right now. Instead, marks the payload as ready
 * to transmit, which will be transmitted later
 */
void
tcp_transmit(struct stack_handle_t *more, const void *payload, size_t length, enum TCP__flags flags)
{
    more->send(more->tcpcon, more->tcb, payload, length, flags, more->is_closing, more->secs, more->usecs);
}
