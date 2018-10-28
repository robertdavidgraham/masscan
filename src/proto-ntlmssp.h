#ifndef PROTO_NTLMSSP_H
#define PROTO_NTLMSSP_H
#include <stdio.h>
struct BannerOutput;

struct NtlmsspDecode
{
    unsigned length;
    unsigned offset;
    unsigned char *buf;
};

void
ntlmssp_decode_init(struct NtlmsspDecode *x, size_t length);

void
ntlmssp_cleanup(struct NtlmsspDecode *x);

void
ntlmssp_decode(struct NtlmsspDecode *x,
              const unsigned char *px, size_t length,
              struct BannerOutput *banout);

#endif

