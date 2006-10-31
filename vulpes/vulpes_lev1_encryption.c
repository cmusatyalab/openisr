/*
                               Fauxide

		      A virtual disk drive tool
 
               Copyright (c) 2002-2004, Intel Corporation
                          All Rights Reserved

This software is distributed under the terms of the Eclipse Public License, 
Version 1.0 which can be found in the file named LICENSE.  ANY USE, 
REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
ACCEPTANCE OF THIS AGREEMENT

*/

#include "vulpes_lev1_encryption.h"
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
#include "vulpes_log.h"
#include "vulpes_util.h"


/* LOCAL VARIABLES */
static const char digestName[] = "sha1";

/* CORE ENCRYPTION/DECRYPTION Routines used by Vulpes */

/* REM : For a SHA1 digest, the digest is 20 bytes long
 */
unsigned char *digest(const unsigned char *mesg, unsigned mesgLen)
{
    EVP_MD_CTX mdctx;
    const EVP_MD *md;
    unsigned char *md_value;

    int md_len;

    md_value = (unsigned char *) malloc(EVP_MAX_MD_SIZE);
    if (md_value == NULL) return NULL;

    OpenSSL_add_all_digests();


    md = EVP_get_digestbyname(digestName);

    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, mesg, mesgLen);
    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);

    return md_value;
}

/* Nice things to remember about the BlowFish Cipher:
 * operates on 64 bit (8 byte) blocks of data
 * ivec must point at an 8 byte long initialization vector
 */

static unsigned const char iv[] = { 0, 0, 0, 0, 0, 0, 0, 0 };	/* A zero IV, same as SSH */


int vulpes_encrypt(const unsigned char *const inString, 
		   const int inStringLength,
		   unsigned char **outString, int *outStringLength,
		   const unsigned char *const key, const int keyLen)
{
    int tmplen;
    unsigned char *output;

    output = (unsigned char *) malloc(inStringLength * 2);
    if (output == NULL) return 0;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv);

    if (!EVP_EncryptUpdate
	(&ctx, output, outStringLength, inString, inStringLength)) {
	/* Error */
	return 0;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_EncryptFinal_ex(&ctx, output + *outStringLength, &tmplen)) {
	/* Error */
	return 0;
    }
    *outStringLength += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    *outString = output;
    output = NULL;
    return 1;
}

int vulpes_decrypt(const unsigned char *const inString, 
		   const int inStringLength,
		   unsigned char **outString, int *outStringLength,
		   const unsigned char *const key, const int keyLen)
{
    int tmplen;
    unsigned char *output;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv);

    output =
	(unsigned char *) malloc((int) ((float) inStringLength * 1.2));
	 /* 1.2 is a random size - wnted it to be big enough to avoid overflow */
    if (output == NULL) return 0;

    if (!EVP_DecryptUpdate
	(&ctx, output, outStringLength, inString, inStringLength)) {
	printf("vulpes_decrypt failed at EVP_DecryptUpdate\n");
	/* Error */
	return 0;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
     * encrypted to avoid overwriting it.
     */
    if (!EVP_DecryptFinal_ex(&ctx, output + *outStringLength, &tmplen)) {
	/* Error */
	printf("vulpes_decrypt failed at EVP_DecryptFinal_ex\n");
	return 0;
    }
    *outStringLength += tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    *outString = output;
    output = NULL;
    return 1;
}
