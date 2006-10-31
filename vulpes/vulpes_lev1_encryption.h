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

#ifndef VULPES_LEV1_ENCRYPT
#define VULPES_LEV1_ENCRYPT

#include "vulpes.h"

/*
 * TYPEDEFS
 */
struct keyring_entry {
    unsigned char tag[20];/* was called as o2 earlier */
    unsigned char key[20];/* was called as o1 earlier */
};

struct keyring {
  struct keyring_entry *keyRing;
  int numKeys;
};

unsigned char *digest(const unsigned char *mesg, unsigned mesgLen);
int vulpes_encrypt(const unsigned char *const inString, 
		   const int inStringLength,
		   unsigned char **outString, int *outStringLength,
		   const unsigned char *const key, const int keyLen);
int vulpes_decrypt(const unsigned char *const inString,
		   const int inStringLength,
		   unsigned char **outString, int *outStringLength,
		   const unsigned char *const key, const int keyLen);

#endif
