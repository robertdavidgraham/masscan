#ifndef PROTO_SMB_H
#define PROTO_SMB_H
#include "proto-banner1.h"

extern struct ProtocolParserStream banner_smb0;
extern struct ProtocolParserStream banner_smb1;

/**
 * Called when command line parameter:
 *   --hello smbv1
 * is set, in order to force negotiation down to SMBv1. This is because some machines
 * have faulty SMBv2 implementations. SMBv2, though, is the default negotiation
 * because Win10 disables SMBv1 by default.
 */
void smb_set_hello_v1(struct ProtocolParserStream *smb);

#endif
