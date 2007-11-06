/* 
 * Vulpes - support daemon for the OpenISR (R) system virtual disk
 * 
 * Copyright (C) 2002-2005 Intel Corporation
 * Copyright (C) 2005-2007 Carnegie Mellon University
 * 
 * This software is distributed under the terms of the Eclipse Public License, 
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE, 
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/blowfish.h>
#include "vulpes.h"
#include "crypto.h"
#include "log.h"
#include "util.h"


/* CORE ENCRYPTION/DECRYPTION Routines used by Vulpes */

/* Places 20 (HASH_LEN) bytes in @result */
void digest(const void *mesg, unsigned mesgLen, void *result)
{
    EVP_MD_CTX mdctx;

    /* In my copy of OpenSSL (0.9.8d), at least, none of these calls can
       actually fail */
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(&mdctx, mesg, mesgLen);
    EVP_DigestFinal_ex(&mdctx, result, NULL);
    EVP_MD_CTX_cleanup(&mdctx);
}

/* Nice things to remember about the BlowFish Cipher:
 * operates on 64 bit (8 byte) blocks of data
 * ivec must point at an 8 byte long initialization vector
 */

static const unsigned char iv[CIPHER_IV_SIZE] = {0};  /* A zero IV, same as SSH */

vulpes_err_t vulpes_encrypt(const void *inString, int inStringLength,
			    void **outString, int *outStringLength,
			    const void *key, int keyLen, int doPad)
{
    int tmplen;
    unsigned char *output;
    EVP_CIPHER_CTX ctx;

    output = malloc(inStringLength + CIPHER_BLOCK_SIZE);
    if (output == NULL) return VULPES_NOMEM;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, NULL, iv);
    if (!EVP_CIPHER_CTX_set_key_length(&ctx, keyLen))
        goto bad;
    EVP_CIPHER_CTX_set_padding(&ctx, doPad);
    EVP_EncryptInit_ex(&ctx, NULL, NULL, key, NULL);

    if (!EVP_EncryptUpdate(&ctx, output, outStringLength, inString,
      	    inStringLength))
        goto bad;
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_EncryptFinal_ex(&ctx, output + *outStringLength, &tmplen))
        goto bad;
    *outStringLength += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    *outString = output;
    return VULPES_SUCCESS;
    
bad:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return VULPES_INVALID;
}

vulpes_err_t vulpes_decrypt(const void *inString, int inStringLength,
			    void **outString, int *outStringLength,
			    const void *key, int keyLen, int doPad)
{
    int tmplen;
    unsigned char *output;
    EVP_CIPHER_CTX ctx;

    output = malloc(inStringLength + CIPHER_BLOCK_SIZE);
    if (output == NULL) return VULPES_NOMEM;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_bf_cbc(), NULL, NULL, iv);
    if (!EVP_CIPHER_CTX_set_key_length(&ctx, keyLen)) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return VULPES_INVALID;
    }
    EVP_CIPHER_CTX_set_padding(&ctx, doPad);
    EVP_DecryptInit_ex(&ctx, NULL, NULL, key, NULL);

    if (!EVP_DecryptUpdate(&ctx, output, outStringLength, inString,
      	    inStringLength)) {
    	vulpes_log(LOG_ERRORS,"DecryptUpdate failed");
    	EVP_CIPHER_CTX_cleanup(&ctx);
	return VULPES_BADFORMAT;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_DecryptFinal_ex(&ctx, output + *outStringLength, &tmplen)) {
	vulpes_log(LOG_ERRORS,"DecryptFinal failed");
	EVP_CIPHER_CTX_cleanup(&ctx);
	return VULPES_BADFORMAT;
    }
    *outStringLength += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    *outString = output;
    return VULPES_SUCCESS;
}
