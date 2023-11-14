#ifndef STACK_HANDLE_H
#define STACK_HANDLE_H
#include <stdio.h>
#include "util-bool.h" /* <stdbool.h> */

struct ProtocolParserStream;

enum TCP__flags {
    TCP__static,/* it's static data, so the send function can point to it */
    TCP__copy,  /* the send function must copy the data */
    TCP__adopt,  /* the buffer was just allocated, so the send function can adopt the pointer */
    TCP__close_fin /* close connection */
};

enum {
    SOCKERR_NONE=0, /* no error */
    SOCKERR_EBADF=10,  /* bad socket descriptor */
};

typedef struct stack_handle_t {
    void *tcpcon;
    void *tcb;
    unsigned secs;
    unsigned usecs;
} stack_handle_t;



/**
 * Set a new default timeout.
 */
int
tcpapi_set_timeout(struct stack_handle_t *socket,
                   unsigned secs,
                   unsigned usecs
                   );

/**
 * Change from the "send" state to the "receive" state.
 * Has no effect if in any state other than "send".
 * This is none-blocking, an event will be triggered
 * later that has the data.
 */
int
tcpapi_recv(struct stack_handle_t *socket);

int
tcpapi_send(struct stack_handle_t *socket,
            const void *buf, size_t length,
            enum TCP__flags flags);

/**
 * Re-connect to the target, same IP and port, creating a new connection
 * from a different port on this side.
 */
int
tcpapi_reconnect(struct stack_handle_t *old_socket,
                 struct ProtocolParserStream *new_stream,
                 unsigned new_app_state);

/**
 * The "app state" variable is stored opaquely in the `tcb` structure, so
 * to reset it, we need an access function.
 */
unsigned
tcpapi_change_app_state(struct stack_handle_t *socket, unsigned new_app_state);


/** Perform the sockets half-close function (calling `close()`). This
 * doesn't actually get rid of the socket, but only stops sending.
 * It sends a FIN packet to the other side, and transitions to the
 * TCP CLOSE-WAIT state.
 * The socket will continue to receive from the opposing side until they
 * give us a FIN packet. */
int
tcpapi_close(struct stack_handle_t *socket);



#endif
