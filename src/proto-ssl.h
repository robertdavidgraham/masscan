#ifndef PROTO_SSL_H
#define PROTO_SSL_H
#include "proto-banner1.h"

extern struct ProtocolParserStream banner_ssl;

const char *ssl_hello_heartbeat;

unsigned ssl_hello_heartbeat_size;

#endif
