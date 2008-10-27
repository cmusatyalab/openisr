/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */

/* AES implementation by Tom St Denis
 *
 * Derived from the Public Domain source code by
 
---  
  * rijndael-alg-fst.c
  *
  * @version 3.0 (December 2000)
  *
  * Optimised ANSI C code for the Rijndael cipher (now AES)
  *
  * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
  * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
  * @author Paulo Barreto <paulo.barreto@terra.com.br>
---
 */

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"
#include "aes_tab.h"

static uint32_t setup_mix(uint32_t temp)
{
   return (Te4_3[byte(temp, 2)]) ^
          (Te4_2[byte(temp, 1)]) ^
          (Te4_1[byte(temp, 0)]) ^
          (Te4_0[byte(temp, 3)]);
}

 /**
    Initialize the AES (Rijndael) block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param skey The key in as scheduled by this function.
    @return ISRCRY_OK if successful
 */
enum isrcry_result isrcry_aes_init(const unsigned char *key, int keylen,
			struct isrcry_aes_key *skey)
{
    int i, j;
    uint32_t temp, *rk;
    uint32_t *rrk;
    
    if (key == NULL || skey == NULL)
	    return ISRCRY_INVALID_ARGUMENT;
    if (keylen != 16 && keylen != 24 && keylen != 32)
	    return ISRCRY_INVALID_ARGUMENT;
    
    skey->Nr = 10 + ((keylen/8)-2)*2;
        
    /* setup the forward key */
    i                 = 0;
    rk                = skey->eK;
    LOAD32H(rk[0], key     );
    LOAD32H(rk[1], key +  4);
    LOAD32H(rk[2], key +  8);
    LOAD32H(rk[3], key + 12);
    if (keylen == 16) {
        j = 44;
        for (;;) {
            temp  = rk[3];
            rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
               break;
            }
            rk += 4;
        }
    } else if (keylen == 24) {
        j = 52;   
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        for (;;) {
            temp = rk[5];
            rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                break;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    } else if (keylen == 32) {
        j = 60;
        LOAD32H(rk[4], key + 16);
        LOAD32H(rk[5], key + 20);
        LOAD32H(rk[6], key + 24);
        LOAD32H(rk[7], key + 28);
        for (;;) {
            temp = rk[7];
            rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                break;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^ setup_mix(RORc(temp, 8));
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            rk += 8;
        }
    } else {
       assert(0);
    }

    /* setup the inverse key now */
    rk   = skey->dK;
    rrk  = skey->eK + j - 4; 
    
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
    rk -= 3; rrk -= 3;
    
    for (i = 1; i < skey->Nr; i++) {
        rrk -= 4;
        rk  += 4;
        temp = rrk[0];
        rk[0] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[1];
        rk[1] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[2];
        rk[2] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
        temp = rrk[3];
        rk[3] =
            Tks0[byte(temp, 3)] ^
            Tks1[byte(temp, 2)] ^
            Tks2[byte(temp, 1)] ^
            Tks3[byte(temp, 0)];
    }

    /* copy last */
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;

    return ISRCRY_OK;   
}

/**
  Encrypts a block of text with AES
  @param in The input plaintext (16 bytes)
  @param out The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return ISRCRY_OK if successful
*/
enum isrcry_result _isrcry_aes_encrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;
    
    if (in == NULL || out == NULL || skey == NULL)
	    return ISRCRY_INVALID_ARGUMENT;
    
    Nr = skey->Nr;
    rk = skey->eK;
    
    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, in      ); s0 ^= rk[0];
    LOAD32H(s1, in  +  4); s1 ^= rk[1];
    LOAD32H(s2, in  +  8); s2 ^= rk[2];
    LOAD32H(s3, in  + 12); s3 ^= rk[3];

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {
        t0 =
            Te0[byte(s0, 3)] ^
            Te1[byte(s1, 2)] ^
            Te2[byte(s2, 1)] ^
            Te3[byte(s3, 0)] ^
            rk[4];
        t1 =
            Te0[byte(s1, 3)] ^
            Te1[byte(s2, 2)] ^
            Te2[byte(s3, 1)] ^
            Te3[byte(s0, 0)] ^
            rk[5];
        t2 =
            Te0[byte(s2, 3)] ^
            Te1[byte(s3, 2)] ^
            Te2[byte(s0, 1)] ^
            Te3[byte(s1, 0)] ^
            rk[6];
        t3 =
            Te0[byte(s3, 3)] ^
            Te1[byte(s0, 2)] ^
            Te2[byte(s1, 1)] ^
            Te3[byte(s2, 0)] ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }

        s0 =
            Te0[byte(t0, 3)] ^
            Te1[byte(t1, 2)] ^
            Te2[byte(t2, 1)] ^
            Te3[byte(t3, 0)] ^
            rk[0];
        s1 =
            Te0[byte(t1, 3)] ^
            Te1[byte(t2, 2)] ^
            Te2[byte(t3, 1)] ^
            Te3[byte(t0, 0)] ^
            rk[1];
        s2 =
            Te0[byte(t2, 3)] ^
            Te1[byte(t3, 2)] ^
            Te2[byte(t0, 1)] ^
            Te3[byte(t1, 0)] ^
            rk[2];
        s3 =
            Te0[byte(t3, 3)] ^
            Te1[byte(t0, 2)] ^
            Te2[byte(t1, 1)] ^
            Te3[byte(t2, 0)] ^
            rk[3];
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Te4_3[byte(t0, 3)]) ^
        (Te4_2[byte(t1, 2)]) ^
        (Te4_1[byte(t2, 1)]) ^
        (Te4_0[byte(t3, 0)]) ^
        rk[0];
    STORE32H(s0, out);
    s1 =
        (Te4_3[byte(t1, 3)]) ^
        (Te4_2[byte(t2, 2)]) ^
        (Te4_1[byte(t3, 1)]) ^
        (Te4_0[byte(t0, 0)]) ^
        rk[1];
    STORE32H(s1, out+4);
    s2 =
        (Te4_3[byte(t2, 3)]) ^
        (Te4_2[byte(t3, 2)]) ^
        (Te4_1[byte(t0, 1)]) ^
        (Te4_0[byte(t1, 0)]) ^
        rk[2];
    STORE32H(s2, out+8);
    s3 =
        (Te4_3[byte(t3, 3)]) ^
        (Te4_2[byte(t0, 2)]) ^
        (Te4_1[byte(t1, 1)]) ^
        (Te4_0[byte(t2, 0)]) ^ 
        rk[3];
    STORE32H(s3, out+12);

    return ISRCRY_OK;
}

#if 0
int ECB_ENC(const unsigned char *pt, unsigned char *ct, symmetric_key *skey) 
{
   int err = _rijndael_ecb_encrypt(pt, ct, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif

/**
  Decrypts a block of text with AES
  @param in The input ciphertext (16 bytes)
  @param out The output plaintext (16 bytes)
  @param skey The key as scheduled 
  @return ISRCRY_OK if successful
*/
enum isrcry_result _isrcry_aes_decrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey)
{
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;

    if (in == NULL || out == NULL || skey == NULL)
	    return ISRCRY_INVALID_ARGUMENT;
    
    Nr = skey->Nr;
    rk = skey->dK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, in      ); s0 ^= rk[0];
    LOAD32H(s1, in  +  4); s1 ^= rk[1];
    LOAD32H(s2, in  +  8); s2 ^= rk[2];
    LOAD32H(s3, in  + 12); s3 ^= rk[3];

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {

        t0 =
            Td0[byte(s0, 3)] ^
            Td1[byte(s3, 2)] ^
            Td2[byte(s2, 1)] ^
            Td3[byte(s1, 0)] ^
            rk[4];
        t1 =
            Td0[byte(s1, 3)] ^
            Td1[byte(s0, 2)] ^
            Td2[byte(s3, 1)] ^
            Td3[byte(s2, 0)] ^
            rk[5];
        t2 =
            Td0[byte(s2, 3)] ^
            Td1[byte(s1, 2)] ^
            Td2[byte(s0, 1)] ^
            Td3[byte(s3, 0)] ^
            rk[6];
        t3 =
            Td0[byte(s3, 3)] ^
            Td1[byte(s2, 2)] ^
            Td2[byte(s1, 1)] ^
            Td3[byte(s0, 0)] ^
            rk[7];

        rk += 8;
        if (--r == 0) {
            break;
        }


        s0 =
            Td0[byte(t0, 3)] ^
            Td1[byte(t3, 2)] ^
            Td2[byte(t2, 1)] ^
            Td3[byte(t1, 0)] ^
            rk[0];
        s1 =
            Td0[byte(t1, 3)] ^
            Td1[byte(t0, 2)] ^
            Td2[byte(t3, 1)] ^
            Td3[byte(t2, 0)] ^
            rk[1];
        s2 =
            Td0[byte(t2, 3)] ^
            Td1[byte(t1, 2)] ^
            Td2[byte(t0, 1)] ^
            Td3[byte(t3, 0)] ^
            rk[2];
        s3 =
            Td0[byte(t3, 3)] ^
            Td1[byte(t2, 2)] ^
            Td2[byte(t1, 1)] ^
            Td3[byte(t0, 0)] ^
            rk[3];
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
        (Td4[byte(t0, 3)] & 0xff000000) ^
        (Td4[byte(t3, 2)] & 0x00ff0000) ^
        (Td4[byte(t2, 1)] & 0x0000ff00) ^
        (Td4[byte(t1, 0)] & 0x000000ff) ^
        rk[0];
    STORE32H(s0, out);
    s1 =
        (Td4[byte(t1, 3)] & 0xff000000) ^
        (Td4[byte(t0, 2)] & 0x00ff0000) ^
        (Td4[byte(t3, 1)] & 0x0000ff00) ^
        (Td4[byte(t2, 0)] & 0x000000ff) ^
        rk[1];
    STORE32H(s1, out+4);
    s2 =
        (Td4[byte(t2, 3)] & 0xff000000) ^
        (Td4[byte(t1, 2)] & 0x00ff0000) ^
        (Td4[byte(t0, 1)] & 0x0000ff00) ^
        (Td4[byte(t3, 0)] & 0x000000ff) ^
        rk[2];
    STORE32H(s2, out+8);
    s3 =
        (Td4[byte(t3, 3)] & 0xff000000) ^
        (Td4[byte(t2, 2)] & 0x00ff0000) ^
        (Td4[byte(t1, 1)] & 0x0000ff00) ^
        (Td4[byte(t0, 0)] & 0x000000ff) ^
        rk[3];
    STORE32H(s3, out+12);

    return ISRCRY_OK;
}


#if 0
int ECB_DEC(const unsigned char *ct, unsigned char *pt, symmetric_key *skey) 
{
   int err = _rijndael_ecb_decrypt(ct, pt, skey);
   burn_stack(sizeof(unsigned long)*8 + sizeof(unsigned long*) + sizeof(int)*2);
   return err;
}
#endif
