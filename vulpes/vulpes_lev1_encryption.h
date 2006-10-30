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

/*
 * TYPEDEFS
 */
struct keyring_entry {
    unsigned char tag[20];/* was called as o2 earlier */
    unsigned char key[20];/* was called as o1 earlier */
};

struct keyring {
  char keyRingFileName[256];
  struct keyring_entry *keyRing;
  int numKeys;
};

typedef int lev1_encrypt_ret_t;

/* lev1_encrypt_ret_t values */
#define LEV1_ENCRYPT_SUCCESS             0
#define LEV1_ENCRYPT_E_KEY_NO_EXIST      -1
#define LEV1_ENCRYPT_E_NO_TAG_MATCH      -2
#define LEV1_ENCRYPT_E_NO_ENCRY          -3

struct keyring* lev1_initEncryption(char *keyring_name);	
int lev1_cleanupKeys(struct keyring *kr, char *keyring_name); 

lev1_encrypt_ret_t lev1_get_tag(struct keyring *kr, int keyNum, unsigned char **tag);
lev1_encrypt_ret_t lev1_check_tag(struct keyring *kr, int keyNum, const unsigned char *tag);
lev1_encrypt_ret_t lev1_get_key(struct keyring *kr, int keyNum, unsigned char **key);
void lev1_updateKey(struct keyring *kr, unsigned char new_key[20], unsigned char new_tag[20],
		    int keyNum); 

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
