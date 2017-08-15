#ifndef PROTO_SSL_H
#define PROTO_SSL_H
#include "proto-banner1.h"

extern struct ProtocolParserStream banner_ssl;

extern const char *ssl_hello_heartbeat_template;
extern const char *ssl_hello_ticketbleed_template;
extern const char *ssl_hello_sslv3_template;

/**
 * Parse the SSL Hello template to find its size
 */
unsigned ssl_hello_size(const void *templ);

/**
 * Allocate memory and make a copy of the template, so that we can 
 * rewrite some fields, such as setting the correct timestamp
 */
char *ssl_hello(const void *templ);

/**
 * Add a cipher-spec.
 * There are many possible uses for this, but for now it's used for the POODLE
 * bug, appending TLS_FALLBACK_SCSV to the list. It may need to reallocate
 * the template.
 */
char *ssl_add_cipherspec(void *templ, unsigned cipher_spec, unsigned is_append);


#endif
