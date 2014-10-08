#ifndef PROTO_SSL_H
#define PROTO_SSL_H
#include "proto-banner1.h"

extern struct ProtocolParserStream banner_ssl;

const char *ssl_hello_heartbeat_template;

/**
 * Parse the SSL Hello template to find its size
 */
unsigned ssl_hello_size(const void *templ);

/**
 * Allocate memory and make a copy of the template, so that we can 
 * rewrite some fields, such as setting the correct timestamp
 */
char *ssl_hello(const void *templ);

#endif
