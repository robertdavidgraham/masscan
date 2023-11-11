#ifndef STACK_HANDLE_H
#define STACK_HANDLE_H
#include <stdio.h>
#include "util-bool.h" /* <stdbool.h> */

enum TCP__flags {
    TCP__static,/* it's static data, so the send function can point to it */
    TCP__copy,  /* the send function must copy the data */
    TCP__adopt  /* the buffer was just allocated, so the send function can adopt the pointer */
};

typedef struct stack_handle_t {
    void *tcpcon;
    void *tcb;
    void (*send)(void *tcpcon, void *tcb, const void *buf, size_t length, enum TCP__flags flags, bool is_fin, unsigned secs, unsigned usecs);
    unsigned secs;
    unsigned usecs;
    unsigned is_closing:1;
} stack_handle_t;

/**
 * Called to 'transmit' TCP packet payload.
 */
void
tcp_transmit(struct stack_handle_t *more, const void *data, size_t length, enum TCP__flags flags);

/**
 * Called to close the connection
 */
void
tcp_close(struct stack_handle_t *more);


#endif
