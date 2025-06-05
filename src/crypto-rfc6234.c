/***************** See RFC 6234 for details. *******************/
/* Copyright (c) 2011 IETF Trust and the persons identified as */
/* authors of the code.  All rights reserved.                  */
/* See crypto-rfc2634.h for terms of use and redistribution.   */

/*
 * This is a concatenation of all the .c files included in
 * RFC6234: https://www.rfc-editor.org/rfc/rfc6234
 *
 * This implements most of the crypto required to compute the
 * various keys in TLS:
 * - TLS 1.1: SHA-1
 * - TLS 1.2: SHA-256/SHA-384
 * - TLS 1.3: SHA-384 + HKDF
 */

#include "crypto-rfc6234.h"
#include <string.h>
#include <stdlib.h>

/*****************************************************************/
/*****************************************************************/
/*****************************************************************/

#ifdef USE_32BIT_ONLY
/*
 * Define 64-bit arithmetic in terms of 32-bit arithmetic.
 * Each 64-bit number is represented in a 2-word array.
 * All macros are defined such that the result is the last parameter.
 */

/*
 * Define shift, rotate left, and rotate right functions
 */
#define SHA512_SHR(bits, word, ret) (                          \
    /* (((uint64_t)((word))) >> (bits)) */                     \
    (ret)[0] = (((bits) < 32) && ((bits) >= 0)) ?              \
      ((word)[0] >> (bits)) : 0,                               \
    (ret)[1] = ((bits) > 32) ? ((word)[0] >> ((bits) - 32)) :  \
      ((bits) == 32) ? (word)[0] :                             \
      ((bits) >= 0) ?                                          \
        (((word)[0] << (32 - (bits))) |                        \
        ((word)[1] >> (bits))) : 0 )

#define SHA512_SHL(bits, word, ret) (                          \
    /* (((uint64_t)(word)) << (bits)) */                       \
    (ret)[0] = ((bits) > 32) ? ((word)[1] << ((bits) - 32)) :  \
         ((bits) == 32) ? (word)[1] :                          \
         ((bits) >= 0) ?                                       \
           (((word)[0] << (bits)) |                            \
           ((word)[1] >> (32 - (bits)))) :                     \
         0,                                                    \
    (ret)[1] = (((bits) < 32) && ((bits) >= 0)) ?              \
        ((word)[1] << (bits)) : 0 )

/*
 * Define 64-bit OR
 */
#define SHA512_OR(word1, word2, ret) (                         \
    (ret)[0] = (word1)[0] | (word2)[0],                        \
    (ret)[1] = (word1)[1] | (word2)[1] )

/*
 * Define 64-bit XOR
 */
#define SHA512_XOR(word1, word2, ret) (                        \
    (ret)[0] = (word1)[0] ^ (word2)[0],                        \
    (ret)[1] = (word1)[1] ^ (word2)[1] )

/*
 * Define 64-bit AND
 */
#define SHA512_AND(word1, word2, ret) (                        \
    (ret)[0] = (word1)[0] & (word2)[0],                        \
    (ret)[1] = (word1)[1] & (word2)[1] )

/*
 * Define 64-bit TILDA
 */
#define SHA512_TILDA(word, ret)                                \
  ( (ret)[0] = ~(word)[0], (ret)[1] = ~(word)[1] )

/*
 * Define 64-bit ADD
 */
#define SHA512_ADD(word1, word2, ret) (                        \
    (ret)[1] = (word1)[1], (ret)[1] += (word2)[1],             \
    (ret)[0] = (word1)[0] + (word2)[0] + ((ret)[1] < (word1)[1]) )

/*
 * Add the 4word value in word2 to word1.
 */
static uint32_t ADDTO4_temp, ADDTO4_temp2;
#define SHA512_ADDTO4(word1, word2) (                          \
    ADDTO4_temp = (word1)[3],                                  \
    (word1)[3] += (word2)[3],                                  \
    ADDTO4_temp2 = (word1)[2],                                 \
    (word1)[2] += (word2)[2] + ((word1)[3] < ADDTO4_temp),     \
    ADDTO4_temp = (word1)[1],                                  \
    (word1)[1] += (word2)[1] + ((word1)[2] < ADDTO4_temp2),    \
    (word1)[0] += (word2)[0] + ((word1)[1] < ADDTO4_temp) )

/*
 * Add the 2word value in word2 to word1.
 */
static uint32_t ADDTO2_temp;
#define SHA512_ADDTO2(word1, word2) (                          \
    ADDTO2_temp = (word1)[1],                                  \
    (word1)[1] += (word2)[1],                                  \
    (word1)[0] += (word2)[0] + ((word1)[1] < ADDTO2_temp) )

/*
 * SHA rotate   ((word >> bits) | (word << (64-bits)))
 */
static uint32_t ROTR_temp1[2], ROTR_temp2[2];
#define SHA512_ROTR(bits, word, ret) (                         \
    SHA512_SHR((bits), (word), ROTR_temp1),                    \
    SHA512_SHL(64-(bits), (word), ROTR_temp2),                 \
    SHA512_OR(ROTR_temp1, ROTR_temp2, (ret)) )

/*
 * Define the SHA SIGMA and sigma macros
 *
 *  SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word)
 */
static uint32_t SIGMA0_temp1[2], SIGMA0_temp2[2],
  SIGMA0_temp3[2], SIGMA0_temp4[2];
#define SHA512_SIGMA0(word, ret) (                             \
    SHA512_ROTR(28, (word), SIGMA0_temp1),                     \
    SHA512_ROTR(34, (word), SIGMA0_temp2),                     \
    SHA512_ROTR(39, (word), SIGMA0_temp3),                     \
    SHA512_XOR(SIGMA0_temp2, SIGMA0_temp3, SIGMA0_temp4),      \
    SHA512_XOR(SIGMA0_temp1, SIGMA0_temp4, (ret)) )

/*
 * SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word)
 */
static uint32_t SIGMA1_temp1[2], SIGMA1_temp2[2],
  SIGMA1_temp3[2], SIGMA1_temp4[2];
#define SHA512_SIGMA1(word, ret) (                             \
    SHA512_ROTR(14, (word), SIGMA1_temp1),                     \
    SHA512_ROTR(18, (word), SIGMA1_temp2),                     \
    SHA512_ROTR(41, (word), SIGMA1_temp3),                     \
    SHA512_XOR(SIGMA1_temp2, SIGMA1_temp3, SIGMA1_temp4),      \
    SHA512_XOR(SIGMA1_temp1, SIGMA1_temp4, (ret)) )

/*
 * (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
 */
static uint32_t sigma0_temp1[2], sigma0_temp2[2],
  sigma0_temp3[2], sigma0_temp4[2];
#define SHA512_sigma0(word, ret) (                             \
    SHA512_ROTR( 1, (word), sigma0_temp1),                     \
    SHA512_ROTR( 8, (word), sigma0_temp2),                     \
    SHA512_SHR( 7, (word), sigma0_temp3),                      \
    SHA512_XOR(sigma0_temp2, sigma0_temp3, sigma0_temp4),      \
    SHA512_XOR(sigma0_temp1, sigma0_temp4, (ret)) )

/*
 * (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))
 */
static uint32_t sigma1_temp1[2], sigma1_temp2[2],
  sigma1_temp3[2], sigma1_temp4[2];
#define SHA512_sigma1(word, ret) (                             \
    SHA512_ROTR(19, (word), sigma1_temp1),                     \
    SHA512_ROTR(61, (word), sigma1_temp2),                     \
    SHA512_SHR( 6, (word), sigma1_temp3),                      \
    SHA512_XOR(sigma1_temp2, sigma1_temp3, sigma1_temp4),      \
    SHA512_XOR(sigma1_temp1, sigma1_temp4, (ret)) )

#ifndef USE_MODIFIED_MACROS
/*
 * These definitions are the ones used in FIPS 180-3, section 4.1.3
 *  Ch(x,y,z)   ((x & y) ^ (~x & z))
 */
static uint32_t Ch_temp1[2], Ch_temp2[2], Ch_temp3[2];
#define SHA_Ch(x, y, z, ret) (                                 \
    SHA512_AND(x, y, Ch_temp1),                                \
    SHA512_TILDA(x, Ch_temp2),                                 \
    SHA512_AND(Ch_temp2, z, Ch_temp3),                         \
    SHA512_XOR(Ch_temp1, Ch_temp3, (ret)) )

/*
 *  Maj(x,y,z)  (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
 */
static uint32_t Maj_temp1[2], Maj_temp2[2],
  Maj_temp3[2], Maj_temp4[2];
#define SHA_Maj(x, y, z, ret) (                                \
    SHA512_AND(x, y, Maj_temp1),                               \
    SHA512_AND(x, z, Maj_temp2),                               \
    SHA512_AND(y, z, Maj_temp3),                               \
    SHA512_XOR(Maj_temp2, Maj_temp3, Maj_temp4),               \
    SHA512_XOR(Maj_temp1, Maj_temp4, (ret)) )
#else /* !USE_MODIFIED_MACROS */
/*
 * These definitions are potentially faster equivalents for the ones
 * used in FIPS 180-3, section 4.1.3.
 *   ((x & y) ^ (~x & z)) becomes
 *   ((x & (y ^ z)) ^ z)
 */
#define SHA_Ch(x, y, z, ret) (                                 \
   (ret)[0] = (((x)[0] & ((y)[0] ^ (z)[0])) ^ (z)[0]),         \
   (ret)[1] = (((x)[1] & ((y)[1] ^ (z)[1])) ^ (z)[1]) )

/*
 *   ((x & y) ^ (x & z) ^ (y & z)) becomes
 *   ((x & (y | z)) | (y & z))
 */
#define SHA_Maj(x, y, z, ret) (                                 \
   ret[0] = (((x)[0] & ((y)[0] | (z)[0])) | ((y)[0] & (z)[0])), \
   ret[1] = (((x)[1] & ((y)[1] | (z)[1])) | ((y)[1] & (z)[1])) )
#endif /* USE_MODIFIED_MACROS */

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static uint32_t addTemp[4] = { 0, 0, 0, 0 };
#define SHA384_512AddLength(context, length) (                        \
    addTemp[3] = (length), SHA512_ADDTO4((context)->Length, addTemp), \
    (context)->Corrupted = (((context)->Length[3] < (length)) &&      \
       ((context)->Length[2] == 0) && ((context)->Length[1] == 0) &&  \
       ((context)->Length[0] == 0)) ? shaInputTooLong :               \
                                      (context)->Corrupted )

/* Local Function Prototypes */
static int SHA384_512Reset(SHA512Context *context,
                           uint32_t H0[SHA512HashSize/4]);
static void SHA384_512ProcessMessageBlock(SHA512Context *context);
static void SHA384_512Finalize(SHA512Context *context,
  uint8_t Pad_Byte);
static void SHA384_512PadMessage(SHA512Context *context,
  uint8_t Pad_Byte);
static int SHA384_512ResultN( SHA512Context *context,
  uint8_t Message_Digest[ ], int HashSize);

/* Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5 */
static uint32_t SHA384_H0[SHA512HashSize/4] = {
    0xCBBB9D5D, 0xC1059ED8, 0x629A292A, 0x367CD507, 0x9159015A,
    0x3070DD17, 0x152FECD8, 0xF70E5939, 0x67332667, 0xFFC00B31,
    0x8EB44A87, 0x68581511, 0xDB0C2E0D, 0x64F98FA7, 0x47B5481D,
    0xBEFA4FA4
};
static uint32_t SHA512_H0[SHA512HashSize/4] = {
    0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B, 0x3C6EF372,
    0xFE94F82B, 0xA54FF53A, 0x5F1D36F1, 0x510E527F, 0xADE682D1,
    0x9B05688C, 0x2B3E6C1F, 0x1F83D9AB, 0xFB41BD6B, 0x5BE0CD19,
    0x137E2179
};

#else /* !USE_32BIT_ONLY */

/*
 * These definitions are defined in FIPS 180-3, section 4.1.
 * Ch() and Maj() are defined identically in sections 4.1.1,
 * 4.1.2, and 4.1.3.
 *
 * The definitions used in FIPS 180-3 are as follows:
 */

#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#else /* USE_MODIFIED_MACROS */
/*
 * The following definitions are equivalent and potentially faster.
 */

#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))

#endif /* USE_MODIFIED_MACROS */

#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))

/* Define the SHA shift, rotate left and rotate right macros */
#define SHA512_SHR(bits,word)  (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits,word) ((((uint64_t)(word)) >> (bits)) | \
                                (((uint64_t)(word)) << (64-(bits))))

/*
 * Define the SHA SIGMA and sigma macros
 *
 *  SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word)
 */
#define SHA512_SIGMA0(word)   \
 (SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word))
#define SHA512_SIGMA1(word)   \
 (SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word))
#define SHA512_sigma0(word)   \
 (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
#define SHA512_sigma1(word)   \
 (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static unsigned int addTemp;
#define SHA384_512AddLength(context, length)                   \
   (addTemp = context->Length_Low, context->Corrupted =        \
    ((context->Length_Low += length) < addTemp) &&             \
    (++context->Length_High == 0) ? shaInputTooLong :          \
                                    (context)->Corrupted)

/* Local Function Prototypes */
static int SHA384_512Reset(SHA512Context *context,
                           uint64_t H0[SHA512HashSize/8]);
static void SHA384_512ProcessMessageBlock(SHA512Context *context);
static void SHA384_512Finalize(SHA512Context *context,
  uint8_t Pad_Byte);
static void SHA384_512PadMessage(SHA512Context *context,
  uint8_t Pad_Byte);
static int SHA384_512ResultN(SHA512Context *context,
  uint8_t Message_Digest[ ], int HashSize);

/* Initial Hash Values: FIPS 180-3 sections 5.3.4 and 5.3.5 */
static uint64_t SHA384_H0[ ] = {
    0xCBBB9D5DC1059ED8ll, 0x629A292A367CD507ll, 0x9159015A3070DD17ll,
    0x152FECD8F70E5939ll, 0x67332667FFC00B31ll, 0x8EB44A8768581511ll,
    0xDB0C2E0D64F98FA7ll, 0x47B5481DBEFA4FA4ll
};
static uint64_t SHA512_H0[ ] = {
    0x6A09E667F3BCC908ll, 0xBB67AE8584CAA73Bll, 0x3C6EF372FE94F82Bll,
    0xA54FF53A5F1D36F1ll, 0x510E527FADE682D1ll, 0x9B05688C2B3E6C1Fll,
    0x1F83D9ABFB41BD6Bll, 0x5BE0CD19137E2179ll
};

#endif /* USE_32BIT_ONLY */

/*
 * SHA384Reset
 *
 * Description:
 *   This function will initialize the SHA384Context in preparation
 *   for computing a new SHA384 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA384Reset(SHA384Context *context)
{
  return SHA384_512Reset(context, SHA384_H0);
}

/*
 * SHA384Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA384Input(SHA384Context *context,
    const uint8_t *message_array, unsigned int length)
{
  return SHA512Input(context, message_array, length);
}

/*
 * SHA384FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA384FinalBits(SHA384Context *context,
                    uint8_t message_bits, unsigned int length)
{
  return SHA512FinalBits(context, message_bits, length);
}

/*
 * SHA384Result
 *
 * Description:
 *   This function will return the 384-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 47.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA384Result(SHA384Context *context,
    uint8_t Message_Digest[SHA384HashSize])
{
  return SHA384_512ResultN(context, Message_Digest, SHA384HashSize);
}

/*
 * SHA512Reset
 *
 * Description:
 *   This function will initialize the SHA512Context in preparation
 *   for computing a new SHA512 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA512Reset(SHA512Context *context)
{
  return SHA384_512Reset(context, SHA512_H0);
}

/*
 * SHA512Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA512Input(SHA512Context *context,
        const uint8_t *message_array,
        unsigned int length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;

    if ((SHA384_512AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA512_Message_Block_Size))
      SHA384_512ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

/*
 * SHA512FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA512FinalBits(SHA512Context *context,
                    uint8_t message_bits, unsigned int length)
{
  static uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };
  static uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
  };

  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;

  SHA384_512AddLength(context, length);
  SHA384_512Finalize(context, (uint8_t)
    ((message_bits & masks[length]) | markbit[length]));

  return context->Corrupted;
}

/*
 * SHA512Result
 *
 * Description:
 *   This function will return the 512-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 63.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA512Result(SHA512Context *context,
    uint8_t Message_Digest[SHA512HashSize])
{
  return SHA384_512ResultN(context, Message_Digest, SHA512HashSize);
}

/*
 * SHA384_512Reset
 *
 * Description:
 *   This helper function will initialize the SHA512Context in
 *   preparation for computing a new SHA384 or SHA512 message
 *   digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *   H0[ ]: [in]
 *     The initial hash value array to use.
 *
 * Returns:
 *   sha Error Code.
 *
 */
#ifdef USE_32BIT_ONLY
static int SHA384_512Reset(SHA512Context *context,
                           uint32_t H0[SHA512HashSize/4])
#else /* !USE_32BIT_ONLY */
static int SHA384_512Reset(SHA512Context *context,
                           uint64_t H0[SHA512HashSize/8])
#endif /* USE_32BIT_ONLY */
{
  int i;
  if (!context) return shaNull;
  context->Message_Block_Index = 0;

#ifdef USE_32BIT_ONLY
  context->Length[0] = context->Length[1] =
  context->Length[2] = context->Length[3] = 0;

  for (i = 0; i < SHA512HashSize/4; i++)
    context->Intermediate_Hash[i] = H0[i];
#else /* !USE_32BIT_ONLY */
  context->Length_High = context->Length_Low = 0;

  for (i = 0; i < SHA512HashSize/8; i++)
    context->Intermediate_Hash[i] = H0[i];
#endif /* USE_32BIT_ONLY */

  context->Computed = 0;
  context->Corrupted = shaSuccess;

  return shaSuccess;
}

/*
 * SHA384_512ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 1024 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 *
 *
 */
static void SHA384_512ProcessMessageBlock(SHA512Context *context)
{
#ifdef USE_32BIT_ONLY
  /* Constants defined in FIPS 180-3, section 4.2.3 */
  static const uint32_t K[80*2] = {
      0x428A2F98, 0xD728AE22, 0x71374491, 0x23EF65CD, 0xB5C0FBCF,
      0xEC4D3B2F, 0xE9B5DBA5, 0x8189DBBC, 0x3956C25B, 0xF348B538,
      0x59F111F1, 0xB605D019, 0x923F82A4, 0xAF194F9B, 0xAB1C5ED5,
      0xDA6D8118, 0xD807AA98, 0xA3030242, 0x12835B01, 0x45706FBE,
      0x243185BE, 0x4EE4B28C, 0x550C7DC3, 0xD5FFB4E2, 0x72BE5D74,
      0xF27B896F, 0x80DEB1FE, 0x3B1696B1, 0x9BDC06A7, 0x25C71235,
      0xC19BF174, 0xCF692694, 0xE49B69C1, 0x9EF14AD2, 0xEFBE4786,
      0x384F25E3, 0x0FC19DC6, 0x8B8CD5B5, 0x240CA1CC, 0x77AC9C65,
      0x2DE92C6F, 0x592B0275, 0x4A7484AA, 0x6EA6E483, 0x5CB0A9DC,
      0xBD41FBD4, 0x76F988DA, 0x831153B5, 0x983E5152, 0xEE66DFAB,
      0xA831C66D, 0x2DB43210, 0xB00327C8, 0x98FB213F, 0xBF597FC7,
      0xBEEF0EE4, 0xC6E00BF3, 0x3DA88FC2, 0xD5A79147, 0x930AA725,
      0x06CA6351, 0xE003826F, 0x14292967, 0x0A0E6E70, 0x27B70A85,
      0x46D22FFC, 0x2E1B2138, 0x5C26C926, 0x4D2C6DFC, 0x5AC42AED,
      0x53380D13, 0x9D95B3DF, 0x650A7354, 0x8BAF63DE, 0x766A0ABB,
      0x3C77B2A8, 0x81C2C92E, 0x47EDAEE6, 0x92722C85, 0x1482353B,
      0xA2BFE8A1, 0x4CF10364, 0xA81A664B, 0xBC423001, 0xC24B8B70,
      0xD0F89791, 0xC76C51A3, 0x0654BE30, 0xD192E819, 0xD6EF5218,
      0xD6990624, 0x5565A910, 0xF40E3585, 0x5771202A, 0x106AA070,
      0x32BBD1B8, 0x19A4C116, 0xB8D2D0C8, 0x1E376C08, 0x5141AB53,
      0x2748774C, 0xDF8EEB99, 0x34B0BCB5, 0xE19B48A8, 0x391C0CB3,
      0xC5C95A63, 0x4ED8AA4A, 0xE3418ACB, 0x5B9CCA4F, 0x7763E373,
      0x682E6FF3, 0xD6B2B8A3, 0x748F82EE, 0x5DEFB2FC, 0x78A5636F,
      0x43172F60, 0x84C87814, 0xA1F0AB72, 0x8CC70208, 0x1A6439EC,
      0x90BEFFFA, 0x23631E28, 0xA4506CEB, 0xDE82BDE9, 0xBEF9A3F7,
      0xB2C67915, 0xC67178F2, 0xE372532B, 0xCA273ECE, 0xEA26619C,
      0xD186B8C7, 0x21C0C207, 0xEADA7DD6, 0xCDE0EB1E, 0xF57D4F7F,
      0xEE6ED178, 0x06F067AA, 0x72176FBA, 0x0A637DC5, 0xA2C898A6,
      0x113F9804, 0xBEF90DAE, 0x1B710B35, 0x131C471B, 0x28DB77F5,
      0x23047D84, 0x32CAAB7B, 0x40C72493, 0x3C9EBE0A, 0x15C9BEBC,
      0x431D67C4, 0x9C100D4C, 0x4CC5D4BE, 0xCB3E42B6, 0x597F299C,
      0xFC657E2A, 0x5FCB6FAB, 0x3AD6FAEC, 0x6C44198C, 0x4A475817
  };
  int     t, t2, t8;                  /* Loop counter */
  uint32_t  temp1[2], temp2[2],       /* Temporary word values */
        temp3[2], temp4[2], temp5[2];
  uint32_t  W[2*80];                  /* Word sequence */
  uint32_t  A[2], B[2], C[2], D[2],   /* Word buffers */
        E[2], F[2], G[2], H[2];

  /* Initialize the first 16 words in the array W */
  for (t = t2 = t8 = 0; t < 16; t++, t8 += 8) {
    W[t2++] = ((((uint32_t)context->Message_Block[t8    ])) << 24) |
              ((((uint32_t)context->Message_Block[t8 + 1])) << 16) |
              ((((uint32_t)context->Message_Block[t8 + 2])) << 8) |
              ((((uint32_t)context->Message_Block[t8 + 3])));
    W[t2++] = ((((uint32_t)context->Message_Block[t8 + 4])) << 24) |
              ((((uint32_t)context->Message_Block[t8 + 5])) << 16) |
              ((((uint32_t)context->Message_Block[t8 + 6])) << 8) |
              ((((uint32_t)context->Message_Block[t8 + 7])));
  }

  for (t = 16; t < 80; t++, t2 += 2) {
    /* W[t] = SHA512_sigma1(W[t-2]) + W[t-7] +
      SHA512_sigma0(W[t-15]) + W[t-16]; */
    uint32_t *Wt2 = &W[t2-2*2];
    uint32_t *Wt7 = &W[t2-7*2];
    uint32_t *Wt15 = &W[t2-15*2];
    uint32_t *Wt16 = &W[t2-16*2];
    SHA512_sigma1(Wt2, temp1);
    SHA512_ADD(temp1, Wt7, temp2);
    SHA512_sigma0(Wt15, temp1);
    SHA512_ADD(temp1, Wt16, temp3);
    SHA512_ADD(temp2, temp3, &W[t2]);
  }

  A[0] = context->Intermediate_Hash[0];
  A[1] = context->Intermediate_Hash[1];
  B[0] = context->Intermediate_Hash[2];
  B[1] = context->Intermediate_Hash[3];
  C[0] = context->Intermediate_Hash[4];
  C[1] = context->Intermediate_Hash[5];
  D[0] = context->Intermediate_Hash[6];
  D[1] = context->Intermediate_Hash[7];
  E[0] = context->Intermediate_Hash[8];
  E[1] = context->Intermediate_Hash[9];
  F[0] = context->Intermediate_Hash[10];
  F[1] = context->Intermediate_Hash[11];
  G[0] = context->Intermediate_Hash[12];
  G[1] = context->Intermediate_Hash[13];
  H[0] = context->Intermediate_Hash[14];
  H[1] = context->Intermediate_Hash[15];

  for (t = t2 = 0; t < 80; t++, t2 += 2) {
    /*
     * temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
     */
    SHA512_SIGMA1(E,temp1);
    SHA512_ADD(H, temp1, temp2);
    SHA_Ch(E,F,G,temp3);
    SHA512_ADD(temp2, temp3, temp4);
    SHA512_ADD(&K[t2], &W[t2], temp5);
    SHA512_ADD(temp4, temp5, temp1);
    /*
     * temp2 = SHA512_SIGMA0(A) + SHA_Maj(A,B,C);
     */
    SHA512_SIGMA0(A,temp3);
    SHA_Maj(A,B,C,temp4);
    SHA512_ADD(temp3, temp4, temp2);
    H[0] = G[0]; H[1] = G[1];
    G[0] = F[0]; G[1] = F[1];
    F[0] = E[0]; F[1] = E[1];
    SHA512_ADD(D, temp1, E);
    D[0] = C[0]; D[1] = C[1];
    C[0] = B[0]; C[1] = B[1];
    B[0] = A[0]; B[1] = A[1];
    SHA512_ADD(temp1, temp2, A);
  }

  SHA512_ADDTO2(&context->Intermediate_Hash[0], A);
  SHA512_ADDTO2(&context->Intermediate_Hash[2], B);
  SHA512_ADDTO2(&context->Intermediate_Hash[4], C);
  SHA512_ADDTO2(&context->Intermediate_Hash[6], D);
  SHA512_ADDTO2(&context->Intermediate_Hash[8], E);
  SHA512_ADDTO2(&context->Intermediate_Hash[10], F);
  SHA512_ADDTO2(&context->Intermediate_Hash[12], G);
  SHA512_ADDTO2(&context->Intermediate_Hash[14], H);

#else /* !USE_32BIT_ONLY */
  /* Constants defined in FIPS 180-3, section 4.2.3 */
  static const uint64_t K[80] = {
      0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
      0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
      0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
      0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
      0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
      0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
      0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
      0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
      0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
      0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
      0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
      0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
      0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
      0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
      0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
      0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
      0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
      0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
      0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
      0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
      0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
      0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
      0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
      0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
      0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
      0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
      0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll
  };
  int        t, t8;                   /* Loop counter */
  uint64_t   temp1, temp2;            /* Temporary word value */
  uint64_t   W[80];                   /* Word sequence */
  uint64_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t8 = 0; t < 16; t++, t8 += 8)
    W[t] = ((uint64_t)(context->Message_Block[t8  ]) << 56) |
           ((uint64_t)(context->Message_Block[t8 + 1]) << 48) |
           ((uint64_t)(context->Message_Block[t8 + 2]) << 40) |
           ((uint64_t)(context->Message_Block[t8 + 3]) << 32) |
           ((uint64_t)(context->Message_Block[t8 + 4]) << 24) |
           ((uint64_t)(context->Message_Block[t8 + 5]) << 16) |
           ((uint64_t)(context->Message_Block[t8 + 6]) << 8) |
           ((uint64_t)(context->Message_Block[t8 + 7]));

  for (t = 16; t < 80; t++)
    W[t] = SHA512_sigma1(W[t-2]) + W[t-7] +
        SHA512_sigma0(W[t-15]) + W[t-16];
  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 80; t++) {
    temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA512_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;
#endif /* USE_32BIT_ONLY */

  context->Message_Block_Index = 0;
}

/*
 * SHA384_512Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 *
 */
static void SHA384_512Finalize(SHA512Context *context,
    uint8_t Pad_Byte)
{
  int_least16_t i;
  SHA384_512PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (i = 0; i < SHA512_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
#ifdef USE_32BIT_ONLY    /* and clear length */
  context->Length[0] = context->Length[1] = 0;
  context->Length[2] = context->Length[3] = 0;
#else /* !USE_32BIT_ONLY */
  context->Length_High = context->Length_Low = 0;
#endif /* USE_32BIT_ONLY */
  context->Computed = 1;
}

/*
 * SHA384_512PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 1024 bits.  The first padding bit must be a '1'.
 *   The last 128 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will
 *   pad the message according to those rules by filling the
 *   Message_Block array accordingly.  When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 *
 */
static void SHA384_512PadMessage(SHA512Context *context,
    uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA512_Message_Block_Size-16)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA512_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA384_512ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA512_Message_Block_Size-16))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 16 octets
   */
#ifdef USE_32BIT_ONLY
  context->Message_Block[112] = (uint8_t)(context->Length[0] >> 24);
  context->Message_Block[113] = (uint8_t)(context->Length[0] >> 16);
  context->Message_Block[114] = (uint8_t)(context->Length[0] >> 8);
  context->Message_Block[115] = (uint8_t)(context->Length[0]);
  context->Message_Block[116] = (uint8_t)(context->Length[1] >> 24);
  context->Message_Block[117] = (uint8_t)(context->Length[1] >> 16);
  context->Message_Block[118] = (uint8_t)(context->Length[1] >> 8);
  context->Message_Block[119] = (uint8_t)(context->Length[1]);

  context->Message_Block[120] = (uint8_t)(context->Length[2] >> 24);
  context->Message_Block[121] = (uint8_t)(context->Length[2] >> 16);
  context->Message_Block[122] = (uint8_t)(context->Length[2] >> 8);
  context->Message_Block[123] = (uint8_t)(context->Length[2]);
  context->Message_Block[124] = (uint8_t)(context->Length[3] >> 24);
  context->Message_Block[125] = (uint8_t)(context->Length[3] >> 16);
  context->Message_Block[126] = (uint8_t)(context->Length[3] >> 8);
  context->Message_Block[127] = (uint8_t)(context->Length[3]);
#else /* !USE_32BIT_ONLY */
  context->Message_Block[112] = (uint8_t)(context->Length_High >> 56);
  context->Message_Block[113] = (uint8_t)(context->Length_High >> 48);
  context->Message_Block[114] = (uint8_t)(context->Length_High >> 40);
  context->Message_Block[115] = (uint8_t)(context->Length_High >> 32);
  context->Message_Block[116] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[117] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[118] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[119] = (uint8_t)(context->Length_High);

  context->Message_Block[120] = (uint8_t)(context->Length_Low >> 56);
  context->Message_Block[121] = (uint8_t)(context->Length_Low >> 48);
  context->Message_Block[122] = (uint8_t)(context->Length_Low >> 40);
  context->Message_Block[123] = (uint8_t)(context->Length_Low >> 32);
  context->Message_Block[124] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[125] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[126] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[127] = (uint8_t)(context->Length_Low);
#endif /* USE_32BIT_ONLY */

  SHA384_512ProcessMessageBlock(context);
}

/*
 * SHA384_512ResultN
 *
 * Description:
 *   This helper function will return the 384-bit or 512-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 47/63.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *   HashSize: [in]
 *     The size of the hash, either 48 or 64.
 *
 * Returns:
 *   sha Error Code.
 *
 */
static int SHA384_512ResultN(SHA512Context *context,
    uint8_t Message_Digest[ ], int HashSize)
{
  int i;
#ifdef USE_32BIT_ONLY
  int i2;
#endif /* USE_32BIT_ONLY */

  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA384_512Finalize(context, 0x80);

#ifdef USE_32BIT_ONLY
  for (i = i2 = 0; i < HashSize; ) {
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>24);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>16);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>8);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2++]);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>24);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>16);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2]>>8);
    Message_Digest[i++]=(uint8_t)(context->Intermediate_Hash[i2++]);
  }
#else /* !USE_32BIT_ONLY */
  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>3] >> 8 * ( 7 - ( i % 8 ) ));
#endif /* USE_32BIT_ONLY */

  return shaSuccess;
}

/*****************************************************************/
/*****************************************************************/
/*****************************************************************/

/* Define the SHA shift, rotate left, and rotate right macros */
#define SHA256_SHR(bits,word)      ((word) >> (bits))
#define SHA256_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (32-(bits))))
#define SHA256_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (32-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word)   \
  (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word)   \
  (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word)   \
  (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word)   \
  (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static unsigned int addTemp;
#define SHA224_256AddLength(context, length)               \
  (addTemp = (context)->Length_Low, (context)->Corrupted = \
    (((context)->Length_Low += (length)) < addTemp) &&     \
    (++(context)->Length_High == 0) ? shaInputTooLong :    \
                                      (context)->Corrupted )

/* Local Function Prototypes */
static int SHA224_256Reset(SHA256Context *context, uint32_t *H0);
static void SHA224_256ProcessMessageBlock(SHA256Context *context);
static void SHA224_256Finalize(SHA256Context *context,
  uint8_t Pad_Byte);
static void SHA224_256PadMessage(SHA256Context *context,
  uint8_t Pad_Byte);
static int SHA224_256ResultN(SHA256Context *context,
  uint8_t Message_Digest[ ], int HashSize);

/* Initial Hash Values: FIPS 180-3 section 5.3.2 */
static uint32_t SHA224_H0[SHA256HashSize/4] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

/* Initial Hash Values: FIPS 180-3 section 5.3.3 */
static uint32_t SHA256_H0[SHA256HashSize/4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/*
 * SHA224Reset
 *
 * Description:
 *   This function will initialize the SHA224Context in preparation
 *   for computing a new SHA224 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA224Reset(SHA224Context *context)
{
  return SHA224_256Reset(context, SHA224_H0);
}

/*
 * SHA224Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA224Input(SHA224Context *context, const uint8_t *message_array,
    unsigned int length)
{
  return SHA256Input(context, message_array, length);
}

/*
 * SHA224FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA224FinalBits(SHA224Context *context,
                    uint8_t message_bits, unsigned int length)
{
  return SHA256FinalBits(context, message_bits, length);
}

/*
 * SHA224Result
 *
 * Description:
 *   This function will return the 224-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 27.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA224Result(SHA224Context *context,
    uint8_t Message_Digest[SHA224HashSize])
{
  return SHA224_256ResultN(context, Message_Digest, SHA224HashSize);
}

/*
 * SHA256Reset
 *
 * Description:
 *   This function will initialize the SHA256Context in preparation
 *   for computing a new SHA256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Reset(SHA256Context *context)
{
  return SHA224_256Reset(context, SHA256_H0);
}

/*
 * SHA256Input
 *
 * Description:
 *   This function accepts an array of octets as the next portion
 *   of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_array[ ]: [in]
 *     An array of octets representing the next portion of
 *     the message.
 *   length: [in]
 *     The length of the message in message_array.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Input(SHA256Context *context, const uint8_t *message_array,
    unsigned int length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
            *message_array;

    if ((SHA224_256AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA256_Message_Block_Size))
      SHA224_256ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;

}

/*
 * SHA256FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256FinalBits(SHA256Context *context,
                    uint8_t message_bits, unsigned int length)
{
  static uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };
  static uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
  };

  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;

  SHA224_256AddLength(context, length);
  SHA224_256Finalize(context, (uint8_t)
    ((message_bits & masks[length]) | markbit[length]));

  return context->Corrupted;
}

/*
 * SHA256Result
 *
 * Description:
 *   This function will return the 256-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 31.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA256Result(SHA256Context *context,
                 uint8_t Message_Digest[SHA256HashSize])
{
  return SHA224_256ResultN(context, Message_Digest, SHA256HashSize);
}

/*
 * SHA224_256Reset
 *
 * Description:
 *   This helper function will initialize the SHA256Context in
 *   preparation for computing a new SHA-224 or SHA-256 message digest.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to reset.
 *   H0[ ]: [in]
 *     The initial hash value array to use.
 *
 * Returns:
 *   sha Error Code.
 */
static int SHA224_256Reset(SHA256Context *context, uint32_t *H0)
{
  if (!context) return shaNull;

  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0] = H0[0];
  context->Intermediate_Hash[1] = H0[1];
  context->Intermediate_Hash[2] = H0[2];
  context->Intermediate_Hash[3] = H0[3];
  context->Intermediate_Hash[4] = H0[4];
  context->Intermediate_Hash[5] = H0[5];
  context->Intermediate_Hash[6] = H0[6];
  context->Intermediate_Hash[7] = H0[7];

  context->Computed  = 0;
  context->Corrupted = shaSuccess;

  return shaSuccess;
}

/*
 * SHA224_256ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 512 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 */
static void SHA224_256ProcessMessageBlock(SHA256Context *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.2 */
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  int        t, t4;                   /* Loop counter */
  uint32_t   temp1, temp2;            /* Temporary word value */
  uint32_t   W[64];                   /* Word sequence */
  uint32_t   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = t4 = 0; t < 16; t++, t4 += 4)
    W[t] = (((uint32_t)context->Message_Block[t4]) << 24) |
           (((uint32_t)context->Message_Block[t4 + 1]) << 16) |
           (((uint32_t)context->Message_Block[t4 + 2]) << 8) |
           (((uint32_t)context->Message_Block[t4 + 3]));
  for (t = 16; t < 64; t++)
    W[t] = SHA256_sigma1(W[t-2]) + W[t-7] +
        SHA256_sigma0(W[t-15]) + W[t-16];

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];
  F = context->Intermediate_Hash[5];
  G = context->Intermediate_Hash[6];
  H = context->Intermediate_Hash[7];

  for (t = 0; t < 64; t++) {
    temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
    temp2 = SHA256_SIGMA0(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Intermediate_Hash[5] += F;
  context->Intermediate_Hash[6] += G;
  context->Intermediate_Hash[7] += H;

  context->Message_Block_Index = 0;
}

/*
 * SHA224_256Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 */
static void SHA224_256Finalize(SHA256Context *context,
    uint8_t Pad_Byte)
{
  int i;
  SHA224_256PadMessage(context, Pad_Byte);
  /* message may be sensitive, so clear it out */
  for (i = 0; i < SHA256_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;     /* and clear length */
  context->Length_Low = 0;
  context->Computed = 1;
}

/*
 * SHA224_256PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 512 bits.  The first padding bit must be a '1'.
 *   The last 64 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will pad
 *   the message according to those rules by filling the
 *   Message_Block array accordingly.  When it returns, it can be
 *   assumed that the message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 */
static void SHA224_256PadMessage(SHA256Context *context,
    uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA256_Message_Block_Size-8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA256_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;
    SHA224_256ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA256_Message_Block_Size-8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t)(context->Length_High);
  context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t)(context->Length_Low);

  SHA224_256ProcessMessageBlock(context);
}

/*
 * SHA224_256ResultN
 *
 * Description:
 *   This helper function will return the 224-bit or 256-bit message
 *   digest into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *    the last octet of hash in the element with index 27/31.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *   HashSize: [in]
 *     The size of the hash, either 28 or 32.
 *
 * Returns:
 *   sha Error Code.
 */
static int SHA224_256ResultN(SHA256Context *context,
    uint8_t Message_Digest[ ], int HashSize)
{
  int i;

  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA224_256Finalize(context, 0x80);

  for (i = 0; i < HashSize; ++i)
    Message_Digest[i] = (uint8_t)
      (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));

  return shaSuccess;
}

/*****************************************************************/
/*****************************************************************/
/*****************************************************************/

/*
 *  Define the SHA1 circular left shift macro
 */
#define SHA1_ROTL(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

/*
 * Add "length" to the length.
 * Set Corrupted when overflow has occurred.
 */
static unsigned int addTemp;
#define SHA1AddLength(context, length)                     \
    (addTemp = (context)->Length_Low,                      \
     (context)->Corrupted =                                \
        (((context)->Length_Low += (length)) < addTemp) && \
        (++(context)->Length_High == 0) ? shaInputTooLong  \
                                        : (context)->Corrupted )

/* Local Function Prototypes */
static void SHA1ProcessMessageBlock(SHA1Context *context);
static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte);
static void SHA1PadMessage(SHA1Context *context, uint8_t Pad_Byte);

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Reset(SHA1Context *context)
{
  if (!context) return shaNull;

  context->Length_High = context->Length_Low = 0;
  context->Message_Block_Index = 0;

  /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
  context->Intermediate_Hash[0]   = 0x67452301;
  context->Intermediate_Hash[1]   = 0xEFCDAB89;
  context->Intermediate_Hash[2]   = 0x98BADCFE;
  context->Intermediate_Hash[3]   = 0x10325476;
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;

  context->Computed   = 0;
  context->Corrupted  = shaSuccess;

  return shaSuccess;
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update.
 *      message_array[ ]: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Input(SHA1Context *context,
    const uint8_t *message_array, unsigned length)
{
  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (!message_array) return shaNull;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (context->Corrupted) return context->Corrupted;

  while (length--) {
    context->Message_Block[context->Message_Block_Index++] =
      *message_array;

    if ((SHA1AddLength(context, 8) == shaSuccess) &&
      (context->Message_Block_Index == SHA1_Message_Block_Size))
      SHA1ProcessMessageBlock(context);

    message_array++;
  }

  return context->Corrupted;
}

/*
 * SHA1FinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int SHA1FinalBits(SHA1Context *context, uint8_t message_bits,
    unsigned int length)
{
  static uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
  };

  static uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
  };

  if (!context) return shaNull;
  if (!length) return shaSuccess;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (length >= 8) return context->Corrupted = shaBadParam;

  SHA1AddLength(context, length);
  SHA1Finalize(context,
    (uint8_t) ((message_bits & masks[length]) | markbit[length]));

  return context->Corrupted;
}

/*
 * SHA1Result
 *
 * Description:
 *   This function will return the 160-bit message digest
 *   into the Message_Digest array provided by the caller.
 *   NOTE:
 *    The first octet of hash is stored in the element with index 0,
 *      the last octet of hash in the element with index 19.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA-1 hash.
 *   Message_Digest[ ]: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int SHA1Result(SHA1Context *context,
    uint8_t Message_Digest[SHA1HashSize])
{
  int i;

  if (!context) return shaNull;
  if (!Message_Digest) return shaNull;
  if (context->Corrupted) return context->Corrupted;

  if (!context->Computed)
    SHA1Finalize(context, 0x80);

  for (i = 0; i < SHA1HashSize; ++i)
    Message_Digest[i] = (uint8_t) (context->Intermediate_Hash[i>>2]
                                   >> (8 * ( 3 - ( i & 0x03 ) )));

  return shaSuccess;
}

/*
 * SHA1ProcessMessageBlock
 *
 * Description:
 *   This helper function will process the next 512 bits of the
 *   message stored in the Message_Block array.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *
 * Returns:
 *   Nothing.
 *
 * Comments:
 *   Many of the variable names in this code, especially the
 *   single character names, were used because those were the
 *   names used in the Secure Hash Standard.
 */
static void SHA1ProcessMessageBlock(SHA1Context *context)
{
  /* Constants defined in FIPS 180-3, section 4.2.1 */
  const uint32_t K[4] = {
      0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
  };

  int        t;               /* Loop counter */
  uint32_t   temp;            /* Temporary word value */
  uint32_t   W[80];           /* Word sequence */
  uint32_t   A, B, C, D, E;   /* Word buffers */

  /*
   * Initialize the first 16 words in the array W
   */
  for (t = 0; t < 16; t++) {
    W[t]  = ((uint32_t)context->Message_Block[t * 4]) << 24;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
    W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
  }

  for (t = 16; t < 80; t++)
    W[t] = SHA1_ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for (t = 0; t < 20; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Ch(B, C, D) + E + W[t] + K[0];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 20; t < 40; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 40; t < 60; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Maj(B, C, D) + E + W[t] + K[2];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  for (t = 60; t < 80; t++) {
    temp = SHA1_ROTL(5,A) + SHA_Parity(B, C, D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = SHA1_ROTL(30,B);
    B = A;
    A = temp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;
  context->Message_Block_Index = 0;
}

/*
 * SHA1Finalize
 *
 * Description:
 *   This helper function finishes off the digest calculations.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   sha Error Code.
 *
 */
static void SHA1Finalize(SHA1Context *context, uint8_t Pad_Byte)
{
  int i;
  SHA1PadMessage(context, Pad_Byte);
  /* message may be sensitive, clear it out */
  for (i = 0; i < SHA1_Message_Block_Size; ++i)
    context->Message_Block[i] = 0;
  context->Length_High = 0;     /* and clear length */
  context->Length_Low = 0;
  context->Computed = 1;
}

/*
 * SHA1PadMessage
 *
 * Description:
 *   According to the standard, the message must be padded to the next
 *   even multiple of 512 bits.  The first padding bit must be a '1'.
 *   The last 64 bits represent the length of the original message.
 *   All bits in between should be 0.  This helper function will pad
 *   the message according to those rules by filling the Message_Block
 *   array accordingly.  When it returns, it can be assumed that the
 *   message digest has been computed.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to pad.
 *   Pad_Byte: [in]
 *     The last byte to add to the message block before the 0-padding
 *     and length.  This will contain the last bits of the message
 *     followed by another single bit.  If the message was an
 *     exact multiple of 8-bits long, Pad_Byte will be 0x80.
 *
 * Returns:
 *   Nothing.
 */
static void SHA1PadMessage(SHA1Context *context, uint8_t Pad_Byte)
{
  /*
   * Check to see if the current message block is too small to hold
   * the initial padding bits and length.  If so, we will pad the
   * block, process it, and then continue padding into a second
   * block.
   */
  if (context->Message_Block_Index >= (SHA1_Message_Block_Size - 8)) {
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
    while (context->Message_Block_Index < SHA1_Message_Block_Size)
      context->Message_Block[context->Message_Block_Index++] = 0;

    SHA1ProcessMessageBlock(context);
  } else
    context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

  while (context->Message_Block_Index < (SHA1_Message_Block_Size - 8))
    context->Message_Block[context->Message_Block_Index++] = 0;

  /*
   * Store the message length as the last 8 octets
   */
  context->Message_Block[56] = (uint8_t) (context->Length_High >> 24);
  context->Message_Block[57] = (uint8_t) (context->Length_High >> 16);
  context->Message_Block[58] = (uint8_t) (context->Length_High >> 8);
  context->Message_Block[59] = (uint8_t) (context->Length_High);
  context->Message_Block[60] = (uint8_t) (context->Length_Low >> 24);
  context->Message_Block[61] = (uint8_t) (context->Length_Low >> 16);
  context->Message_Block[62] = (uint8_t) (context->Length_Low >> 8);
  context->Message_Block[63] = (uint8_t) (context->Length_Low);

  SHA1ProcessMessageBlock(context);
}

/*****************************************************************/
/*****************************************************************/
/*****************************************************************/

/*
 *  USHAReset
 *
 *  Description:
 *      This function will initialize the SHA Context in preparation
 *      for computing a new SHA message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          Selects which SHA reset to call
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int USHAReset(USHAContext *context, enum SHAversion whichSha)
{
  if (!context) return shaNull;
  context->whichSha = whichSha;
  switch (whichSha) {
    case SHA1:   return SHA1Reset((SHA1Context*)&context->ctx);
    case SHA224: return SHA224Reset((SHA224Context*)&context->ctx);
    case SHA256: return SHA256Reset((SHA256Context*)&context->ctx);
    case SHA384: return SHA384Reset((SHA384Context*)&context->ctx);
    case SHA512: return SHA512Reset((SHA512Context*)&context->ctx);
    default: return shaBadParam;
  }
}

/*
 *  USHAInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update.
 *      message_array: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int USHAInput(USHAContext *context,
              const uint8_t *bytes, unsigned int bytecount)
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA1:
      return SHA1Input((SHA1Context*)&context->ctx, bytes,
                       bytecount);
    case SHA224:
      return SHA224Input((SHA224Context*)&context->ctx, bytes,
          bytecount);
    case SHA256:
      return SHA256Input((SHA256Context*)&context->ctx, bytes,
          bytecount);
    case SHA384:
      return SHA384Input((SHA384Context*)&context->ctx, bytes,
          bytecount);
    case SHA512:
      return SHA512Input((SHA512Context*)&context->ctx, bytes,
          bytecount);
    default: return shaBadParam;
  }
}

/*
 * USHAFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The SHA context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int USHAFinalBits(USHAContext *context,
                  uint8_t bits, unsigned int bit_count)
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA1:
      return SHA1FinalBits((SHA1Context*)&context->ctx, bits,
                           bit_count);
    case SHA224:
      return SHA224FinalBits((SHA224Context*)&context->ctx, bits,
          bit_count);
    case SHA256:
      return SHA256FinalBits((SHA256Context*)&context->ctx, bits,
          bit_count);
    case SHA384:
      return SHA384FinalBits((SHA384Context*)&context->ctx, bits,
          bit_count);
    case SHA512:
      return SHA512FinalBits((SHA512Context*)&context->ctx, bits,
          bit_count);
    default: return shaBadParam;
  }
}

/*
 * USHAResult
 *
 * Description:
 *   This function will return the message digest of the appropriate
 *   bit size, as returned by USHAHashSizeBits(whichSHA) for the
 *   'whichSHA' value used in the preceeding call to USHAReset,
 *   into the Message_Digest array provided by the caller.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the SHA-1 hash.
 *   Message_Digest: [out]
 *     Where the digest is returned.
 *
 * Returns:
 *   sha Error Code.
 *
 */
int USHAResult(USHAContext *context,
               uint8_t Message_Digest[USHAMaxHashSize])
{
  if (!context) return shaNull;
  switch (context->whichSha) {
    case SHA1:
      return SHA1Result((SHA1Context*)&context->ctx, Message_Digest);
    case SHA224:
      return SHA224Result((SHA224Context*)&context->ctx,
                          Message_Digest);
    case SHA256:
      return SHA256Result((SHA256Context*)&context->ctx,
                          Message_Digest);
    case SHA384:
      return SHA384Result((SHA384Context*)&context->ctx,
                          Message_Digest);
    case SHA512:
      return SHA512Result((SHA512Context*)&context->ctx,
                          Message_Digest);
    default: return shaBadParam;
  }
}

/*
 * USHABlockSize
 *
 * Description:
 *   This function will return the blocksize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   block size
 *
 */
int USHABlockSize(enum SHAversion whichSha)
{
  switch (whichSha) {
    case SHA1:   return SHA1_Message_Block_Size;
    case SHA224: return SHA224_Message_Block_Size;
    case SHA256: return SHA256_Message_Block_Size;
    case SHA384: return SHA384_Message_Block_Size;
    default:
    case SHA512: return SHA512_Message_Block_Size;
  }
}

/*
 * USHAHashSize
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size
 *
 */
int USHAHashSize(enum SHAversion whichSha)
{
  switch (whichSha) {
    case SHA1:   return SHA1HashSize;
    case SHA224: return SHA224HashSize;
    case SHA256: return SHA256HashSize;
    case SHA384: return SHA384HashSize;
    default:
    case SHA512: return SHA512HashSize;
  }
}

/*
 * USHAHashSizeBits
 *
 * Description:
 *   This function will return the hashsize for the given SHA
 *   algorithm, expressed in bits.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   hash size in bits
 *
 */
int USHAHashSizeBits(enum SHAversion whichSha)
{
  switch (whichSha) {
    case SHA1:   return SHA1HashSizeBits;
    case SHA224: return SHA224HashSizeBits;
    case SHA256: return SHA256HashSizeBits;
    case SHA384: return SHA384HashSizeBits;
    default:
    case SHA512: return SHA512HashSizeBits;
  }
}

/*
 * USHAHashName
 *
 * Description:
 *   This function will return the name of the given SHA algorithm
 *   as a string.
 *
 * Parameters:
 *   whichSha:
 *     which SHA algorithm to query
 *
 * Returns:
 *   character string with the name in it
 *
 */
const char *USHAHashName(enum SHAversion whichSha)
{
  switch (whichSha) {
    case SHA1:   return "SHA1";
    case SHA224: return "SHA224";
    case SHA256: return "SHA256";
    case SHA384: return "SHA384";
    default:
    case SHA512: return "SHA512";
  }
}

/*****************************************************************/
/*****************************************************************/
/*****************************************************************/

/*
 *  hmac
 *
 *  Description:
 *      This function will compute an HMAC message digest.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      message_array[ ]: [in]
 *          An array of octets representing the message.
 *          Note: in RFC 2104, this parameter is known
 *          as 'text'.
 *      length: [in]
 *          The length of the message in message_array.
 *      key[ ]: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *      digest[ ]: [out]
 *          Where the digest is to be returned.
 *          NOTE: The length of the digest is determined by
 *              the value of whichSha.
 *
 *  Returns:
 *      sha Error Code.
 *
 */

int hmac(SHAversion whichSha,
    const unsigned char *message_array, int length,
    const unsigned char *key, int key_len,
    uint8_t digest[USHAMaxHashSize])
{
  HMACContext context;
  return hmacReset(&context, whichSha, key, key_len) ||
         hmacInput(&context, message_array, length) ||
         hmacResult(&context, digest);
}

/*
 *  hmacReset
 *
 *  Description:
 *      This function will initialize the hmacContext in preparation
 *      for computing a new HMAC message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      key[ ]: [in]
 *          The secret shared key.
 *      key_len: [in]
 *          The length of the secret shared key.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hmacReset(HMACContext *context, enum SHAversion whichSha,
    const unsigned char *key, int key_len)
{
  int i, blocksize, hashsize, ret;

  /* inner padding - key XORd with ipad */
  unsigned char k_ipad[USHA_Max_Message_Block_Size];

  /* temporary buffer when keylen > blocksize */
  unsigned char tempkey[USHAMaxHashSize];

  if (!context) return shaNull;
  context->Computed = 0;
  context->Corrupted = shaSuccess;

  blocksize = context->blockSize = USHABlockSize(whichSha);
  hashsize = context->hashSize = USHAHashSize(whichSha);
  context->whichSha = whichSha;

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > blocksize) {
    USHAContext tcontext;
    int err = USHAReset(&tcontext, whichSha) ||
              USHAInput(&tcontext, key, key_len) ||
              USHAResult(&tcontext, tempkey);
    if (err != shaSuccess) return err;

    key = tempkey;
    key_len = hashsize;
  }

  /*
   * The HMAC transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, text))
   *
   * where K is an n byte key, 0-padded to a total of blocksize bytes,
   * ipad is the byte 0x36 repeated blocksize times,
   * opad is the byte 0x5c repeated blocksize times,
   * and text is the data being protected.
   */

  /* store key into the pads, XOR'd with ipad and opad values */
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ 0x36;
    context->k_opad[i] = key[i] ^ 0x5c;
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < blocksize; i++) {
    k_ipad[i] = 0x36;
    context->k_opad[i] = 0x5c;
  }

  /* perform inner hash */
  /* init context for 1st pass */
  ret = USHAReset(&context->shaContext, whichSha) ||
        /* and start with inner pad */
        USHAInput(&context->shaContext, k_ipad, blocksize);
  return context->Corrupted = ret;
}

/*
 *  hmacInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.  It may be called multiple times.
 *
 *  Parameters:
 *      context: [in/out]
 *          The HMAC context to update.
 *      text[ ]: [in]
 *          An array of octets representing the next portion of
 *          the message.
 *      text_len: [in]
 *          The length of the message in text.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hmacInput(HMACContext *context, const unsigned char *text,
    int text_len)
{
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  /* then text of datagram */
  return context->Corrupted =
    USHAInput(&context->shaContext, text, text_len);
}

/*
 * hmacFinalBits
 *
 * Description:
 *   This function will add in any final bits of the message.
 *
 * Parameters:
 *   context: [in/out]
 *     The HMAC context to update.
 *   message_bits: [in]
 *     The final bits of the message, in the upper portion of the
 *     byte.  (Use 0b###00000 instead of 0b00000### to input the
 *     three bits ###.)
 *   length: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int hmacFinalBits(HMACContext *context,
    uint8_t bits, unsigned int bit_count)
{
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  /* then final bits of datagram */
  return context->Corrupted =
    USHAFinalBits(&context->shaContext, bits, bit_count);
}

/*
 * hmacResult
 *
 * Description:
 *   This function will return the N-byte message digest into the
 *   Message_Digest array provided by the caller.
 *
 * Parameters:
 *   context: [in/out]
 *     The context to use to calculate the HMAC hash.
 *   digest[ ]: [out]
 *     Where the digest is returned.
 *     NOTE 2: The length of the hash is determined by the value of
 *      whichSha that was passed to hmacReset().
 *
 * Returns:
 *   sha Error Code.
 *
 */
int hmacResult(HMACContext *context, uint8_t digest[USHAMaxHashSize])
{
  int ret;
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  ret =
    USHAResult(&context->shaContext, digest) ||

         /* perform outer SHA */
         /* init context for 2nd pass */
         USHAReset(&context->shaContext, context->whichSha) ||

         /* start with outer pad */
         USHAInput(&context->shaContext, context->k_opad,
                   context->blockSize) ||

         /* then results of 1st hash */
         USHAInput(&context->shaContext, digest, context->hashSize) ||
         /* finish up 2nd pass */
         USHAResult(&context->shaContext, digest);

  context->Computed = 1;
  return context->Corrupted = ret;
}

/*
 *  hkdf
 *
 *  Description:
 *      This function will generate keying material using HKDF.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Notes:
 *      Calls hkdfExtract() and hkdfExpand().
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hkdf(SHAversion whichSha,
    const unsigned char *salt, int salt_len,
    const unsigned char *ikm, int ikm_len,
    const unsigned char *info, int info_len,
    uint8_t okm[ ], int okm_len)
{
  uint8_t prk[USHAMaxHashSize];
  return hkdfExtract(whichSha, salt, salt_len, ikm, ikm_len, prk) ||
         hkdfExpand(whichSha, prk, USHAHashSize(whichSha), info,
                    info_len, okm, okm_len);
}

/*
 *  hkdfExtract
 *
 *  Description:
 *      This function will perform HKDF extraction.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      prk[ ]: [out]
 *          Array where the HKDF extraction is to be stored.
 *          Must be larger than USHAHashSize(whichSha);
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hkdfExtract(SHAversion whichSha,
    const unsigned char *salt, int salt_len,
    const unsigned char *ikm, int ikm_len,
    uint8_t prk[USHAMaxHashSize])
{
  unsigned char nullSalt[USHAMaxHashSize];
  if (salt == 0) {
    salt = nullSalt;
    salt_len = USHAHashSize(whichSha);
    memset(nullSalt, '\0', salt_len);
  } else if (salt_len < 0) {
    return shaBadParam;
  }
  return hmac(whichSha, ikm, ikm_len, salt, salt_len, prk);
}

/*
 *  hkdfExpand
 *
 *  Description:
 *      This function will perform HKDF expansion.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      prk[ ]: [in]
 *          The pseudo-random key to be expanded; either obtained
 *          directly from a cryptographically strong, uniformly
 *          distributed pseudo-random number generator, or as the
 *          output from hkdfExtract().
 *      prk_len: [in]
 *          The length of the pseudo-random key in prk;
 *          should at least be equal to USHAHashSize(whichSHA).
 *      info[ ]: [in]
 *          The optional context and application specific information.
 *          If info == NULL or a zero-length string, it is ignored.
 *      info_len: [in]
 *          The length of the optional context and application specific
 *          information.  (Ignored if info == NULL.)
 *      okm[ ]: [out]
 *          Where the HKDF is to be stored.
 *      okm_len: [in]
 *          The length of the buffer to hold okm.
 *          okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hkdfExpand(SHAversion whichSha, const uint8_t prk[ ], int prk_len,
    const unsigned char *info, int info_len,
    uint8_t okm[ ], int okm_len)
{
  int hash_len, N;
  unsigned char T[USHAMaxHashSize];
  int Tlen, where, i;

  if (info == 0) {
    info = (const unsigned char *)"";
    info_len = 0;
  } else if (info_len < 0) {
    return shaBadParam;
  }
  if (okm_len <= 0) return shaBadParam;
  if (!okm) return shaBadParam;

  hash_len = USHAHashSize(whichSha);
  if (prk_len < hash_len) return shaBadParam;
  N = okm_len / hash_len;
  if ((okm_len % hash_len) != 0) N++;
  if (N > 255) return shaBadParam;

  Tlen = 0;
  where = 0;
  for (i = 1; i <= N; i++) {
    HMACContext context;
    unsigned char c = i;
    int ret = hmacReset(&context, whichSha, prk, prk_len) ||
              hmacInput(&context, T, Tlen) ||
              hmacInput(&context, info, info_len) ||
              hmacInput(&context, &c, 1) ||
              hmacResult(&context, T);
    if (ret != shaSuccess) return ret;
    memcpy(okm + where, T,
           (i != N) ? hash_len : (okm_len - where));
    where += hash_len;
    Tlen = hash_len;
  }
  return shaSuccess;
}

/*
 *  hkdfReset
 *
 *  Description:
 *      This function will initialize the hkdfContext in preparation
 *      for key derivation using the modular HKDF interface for
 *      arbitrary length inputs.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hkdfReset(HKDFContext *context, enum SHAversion whichSha,
              const unsigned char *salt, int salt_len)
{
  unsigned char nullSalt[USHAMaxHashSize];
  if (!context) return shaNull;

  context->whichSha = whichSha;
  context->hashSize = USHAHashSize(whichSha);
  if (salt == 0) {
    salt = nullSalt;
    salt_len = context->hashSize;
    memset(nullSalt, '\0', salt_len);
  }

  return hmacReset(&context->hmacContext, whichSha, salt, salt_len);
}

/*
 *  hkdfInput
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the input keying material.  It may be called multiple times.
 *
 *  Parameters:
 *      context: [in/out]
 *          The HKDF context to update.
 *      ikm[ ]: [in]
 *          An array of octets representing the next portion of
 *          the input keying material.
 *      ikm_len: [in]
 *          The length of ikm.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int hkdfInput(HKDFContext *context, const unsigned char *ikm,
              int ikm_len)
{
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  return hmacInput(&context->hmacContext, ikm, ikm_len);
}

/*
 * hkdfFinalBits
 *
 * Description:
 *   This function will add in any final bits of the
 *   input keying material.
 *
 * Parameters:
 *   context: [in/out]
 *     The HKDF context to update
 *   ikm_bits: [in]
 *     The final bits of the input keying material, in the upper
 *     portion of the byte.  (Use 0b###00000 instead of 0b00000###
 *     to input the three bits ###.)
 *   ikm_bit_count: [in]
 *     The number of bits in message_bits, between 1 and 7.
 *
 * Returns:
 *   sha Error Code.
 */
int hkdfFinalBits(HKDFContext *context, uint8_t ikm_bits,
                  unsigned int ikm_bit_count)
{
  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  return hmacFinalBits(&context->hmacContext, ikm_bits, ikm_bit_count);
}

/*
 * hkdfResult
 *
 * Description:
 *   This function will finish the HKDF extraction and perform the
 *   final HKDF expansion.
 *
 * Parameters:
 *   context: [in/out]
 *     The HKDF context to use to calculate the HKDF hash.
 *   prk[ ]: [out]
 *     An optional location to store the HKDF extraction.
 *     Either NULL, or pointer to a buffer that must be
 *     larger than USHAHashSize(whichSha);
 *   info[ ]: [in]
 *     The optional context and application specific information.
 *     If info == NULL or a zero-length string, it is ignored.
 *   info_len: [in]
 *     The length of the optional context and application specific
 *     information.  (Ignored if info == NULL.)
 *   okm[ ]: [out]
 *     Where the HKDF is to be stored.
 *   okm_len: [in]
 *     The length of the buffer to hold okm.
 *     okm_len must be <= 255 * USHABlockSize(whichSha)
 *
 * Returns:
 *   sha Error Code.
 *
 */
int hkdfResult(HKDFContext *context,
               uint8_t prk[USHAMaxHashSize],
               const unsigned char *info, int info_len,
               uint8_t okm[USHAMaxHashSize], int okm_len)
{
  uint8_t prkbuf[USHAMaxHashSize];
  int ret;

  if (!context) return shaNull;
  if (context->Corrupted) return context->Corrupted;
  if (context->Computed) return context->Corrupted = shaStateError;
  if (!okm) return context->Corrupted = shaBadParam;
  if (!prk) prk = prkbuf;

  ret = hmacResult(&context->hmacContext, prk) ||
        hkdfExpand(context->whichSha, prk, context->hashSize, info,
                   info_len, okm, okm_len);
  context->Computed = 1;
  return context->Corrupted = ret;
}

