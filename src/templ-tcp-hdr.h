#ifndef TEMPL_TCP_H
#define TEMPL_TCP_H
#include "util-bool.h" /* <stdbool.h> */
#include <stdio.h>
struct TemplateOptions;

/**
 * Called during configuration, to apply all the various changes the
 * user asked for on the command-line, such as optioms like:
 * --tcp-mss 1460
 * --tcp-sackperm
 * --tcp-wscale 3
 */
void
templ_tcp_apply_options(unsigned char **inout_buf, size_t *inout_length,
                  const struct TemplateOptions *templ_opts);

/**
 * Conduct a selftest of all the functions that manipulate the TCP
 * header template.
 */
int
templ_tcp_selftest(void);

#endif
