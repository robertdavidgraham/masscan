#ifndef CRYPTO_X25519_H
#define CRYPTO_X25519_H
#include <stdio.h>

int curve25519_donna(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

#endif
