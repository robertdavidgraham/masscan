#ifndef PROTO_SPNEGO_H
#define PROTO_SPNEGO_H

#include "proto-x509.h"
#include "proto-ntlmssp.h"

struct SpnegoDecode
{
    /*
     * ====== KLUDGE ALERT: there's no generic ASN.1 encoding, it's specific to
     * ====== x.509 parsing, so therefore we are just going to overload that
     * ====== a bit until we move the code out into it's own ASN.1 module
     */
    struct CertDecode x509[1];
    
    struct NtlmsspDecode ntlmssp;
};

void
spnego_decode_init(struct SpnegoDecode *x, size_t length);

void
spnego_decode(struct SpnegoDecode *x,
            const unsigned char *px, size_t length,
            struct BannerOutput *banout);

#endif

