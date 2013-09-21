#ifndef PROTO_SNMP_H
#define PROTO_SNMP_H
struct Output;
struct PreprocessedInfo;

/**
 * Need to call this on startup to compile the internal MIB.
 */
void snmp_init();

/**
 * Does a regression test.
 * @return
 *     0 if success, 1 if failure
 */
int snmp_selftest();

unsigned
handle_snmp(struct Output *out, const unsigned char *px, unsigned length, struct PreprocessedInfo *parsed);

#endif
