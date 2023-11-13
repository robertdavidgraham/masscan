#include "stack-tcp-app.h"
#include "stack-tcp-api.h"
#include "proto-banner1.h"
#include "proto-ssl.h"
#include "unusedparm.h"
#include "util-malloc.h"
#include "util-logger.h"
#include <stdlib.h>


unsigned
application_event(  struct stack_handle_t *socket,
                  unsigned state, enum App_Event event,
                  const struct ProtocolParserStream *stream,
                  struct Banner1 *banner1,
                  const void *payload, size_t payload_length,
                  unsigned secs, unsigned usecs) {
    enum {
        App_Connect,
        App_ReceiveHello,
        App_ReceiveNext,
        App_SendFirst,
        App_SendNext,
        App_Close,
    };

again:
    switch (state) {
        case App_Connect:
            switch (event) {
                case APP_CONNECTED:
                    /* We have a receive a SYNACK here. If there are multiple handlers
                     * for this port, then attempt another connection using the
                     * other protocol handlers. For example, for SSL, we might want
                     * to try both TLSv1.0 and TLSv1.3 */
                    if (stream && stream->next) {
                        tcpapi_reconnect(socket, stream->next, App_Connect);
                    }

                    /*
                     * By default, wait for the "hello timeout" period
                     * receiving any packets they send us. If nothing is
                     * received in this period, then timeout will cause us
                     * to switch to sending
                     */
                    if (stream && (stream->flags & SF__nowait_hello) == 0) {
                        tcpapi_set_timeout(socket, 2 /*tcpcon->timeout_hello*/, 0);
                        tcpapi_recv(socket);
                        tcpapi_change_app_state(socket, App_ReceiveHello);
                    } else {
                        tcpapi_change_app_state(socket, App_SendFirst);
                        state = App_SendFirst;
                        goto again;
                    }
                    break;
                default:
                    LOG(1, "TCP.app: unknown state event\n");
                    break;
            }

            break;
        case App_ReceiveHello:
            switch (event) {
                case APP_RECV_TIMEOUT:
                    /* We've got no response from the initial connection,
                     * so switch from them being responsible for communications
                     * to us being responsible, and start sending */
                    if (stream) {
                        tcpapi_change_app_state(socket, App_SendFirst);
                        state = App_SendFirst;
                        goto again;
                    }
                    break;
                case APP_RECV_PAYLOAD:
                    /* We've receive some data from them, so wait for some more.
                     * This means we won't be transmitting anything to them. */
                    tcpapi_change_app_state(socket, App_ReceiveNext);
                    state = App_ReceiveNext;
                    goto again;
                default:
                    LOG(1, "TCP.app: unknown state event\n");
                    break;
            }
            break;

        case App_ReceiveNext:
            switch (event) {
                case APP_RECV_PAYLOAD:
                    /* [--banners]
                     * This is an important part of the system, where the TCP
                     * stack passes incoming packet payloads off to the application
                     * layer protocol parsers. This is where, in Sockets API, you
                     * might call the 'recv()' function.
                     */
                    banner_parse(socket,
                                 payload,
                                 payload_length
                                 );
                    break;
                case APP_CLOSE:
                    /* The other side has sent us a FIN, therefore, we need
                     * to likewise close our end. */
                    banner_flush(socket);
                    tcpapi_close(socket);
                    break;
                case APP_RECV_TIMEOUT:
                    break;
                default:
                    LOG(0, "TCP.app: unknown state event\n");
                    break;
            }
            break;

        case App_SendFirst:
            /* This isn't called from the outside, but from one of the
             * states internally whhen we transmit for the first time */
            if (stream == &banner_ssl || stream == &banner_ssl_12) {
                /*
                 * Kludge, extreme kludge
                 * I don't even know what this does any longer
                 */
                banner_set_sslhello(socket, true);
            }

            if (banner_is_heartbleed(socket)) {
                /*
                 * Kludge, extreme kludge
                 * I don't even know what this does any longer
                 */
                banner_set_small_window(socket, true);
            }

            /*
             * We either have a CALLBACK that will handle the
             * sending/receiving of packets, or we will send a fixed
             * "probe" string that will hopefull trigger a response.
             */
            if (stream && stream->transmit_hello) {
                /* We have a callback function for the protocol stream that will
                 * craft a packet, such as maybe generate an HTTP request containing
                 * valid "Host:" field. */
                stream->transmit_hello(banner1, socket);
            } else if (stream && stream->hello_length) {

                /* We just have a template to blindly copy some bytes onto the wire
                 * in order to trigger/probe for a response */
                tcpapi_send(socket, stream->hello, stream->hello_length, TCP__static);

                /* If specified, then send a FIN right after the hello data.
                 * This will complete a reponse faster from the server. */
                if ((stream->flags & SF__close) != 0)
                    tcpapi_close(socket);
            }
            tcpapi_change_app_state(socket, App_SendNext);
            break;
        case App_SendNext:
            switch (event) {
                case APP_SEND_SENT:
                    /* We've got an acknowledgement that all our data
                     * was sent. Therefore, change the receive state */
                    tcpapi_recv(socket);
                    tcpapi_change_app_state(socket, App_ReceiveNext);
                    break;
                default:
                    LOG(0, "TCP.app: unknown state=%u event=%u\n", state, event);
                    break;
            }
            break;
        default:
            LOG(0, "TCP state error\n");
            exit(1);
            break;
    }
    return 0;
}

