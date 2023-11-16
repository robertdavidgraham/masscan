#ifndef STACK_TCP_APP_H
#define STACK_TCP_APP_H
#include <stdio.h>
#include "util-bool.h" /* <stdbool.h> */
struct stack_handle_t;
struct ProtocolParserStream;
struct Banner1;


enum App_Event {
    APP_CONNECTED,
    APP_RECV_TIMEOUT,
    APP_RECV_PAYLOAD,
    APP_SENDING,
    APP_SEND_SENT,
    APP_CLOSE /*FIN received */
};

/**
 * This is the interface between the underlying custom TCP/IP stack and
 * the rest of masscan. SCRIPTING will eventually go in here.
 */
unsigned
application_event(  struct stack_handle_t *socket,
                  unsigned state, enum App_Event event,
                  const struct ProtocolParserStream *stream,
                  struct Banner1 *banner1,
                  const void *payload, size_t payload_length
                  );

void
banner_set_sslhello(struct stack_handle_t *socket, bool is_true);

void
banner_set_small_window(struct stack_handle_t *socket, bool is_true);

bool
banner_is_heartbleed(const struct stack_handle_t *socket);

void
banner_flush(struct stack_handle_t *socket);

size_t
banner_parse(
             struct stack_handle_t *socket,
             const unsigned char *payload,
             size_t payload_length
             );

#endif

