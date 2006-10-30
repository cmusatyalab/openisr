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


/* REM: Never use any string functions on the input
 * or the output strings, because they are binary
 * data and may not be null terminated and may have
 * embedded null characters in them.
 */
int vulpes_encrypt(const unsigned char *const inString, 
		   const int inStringLength,
		   unsigned char **outString, int *outStringLength,
		   const unsigned char *const key, const int keyLen)
{
    int tmplen;
    unsigned char *output;

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv);

    output = (unsigned char *) malloc(inStringLength * 2);

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
    /* REM: Need binary mode for fopen because encrypted data is
     * binary data. Also cannot use strlen() on it because
     * it wont be null terminated and may contain embedded
     * nulls.
     */
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
    /* REM: Need binary mode for fopen because encrypted data is
     * binary data. Also cannot use strlen() on it because
     * it wont be null terminated and may contain embedded
     * nulls.
     */
    *outString = output;
    output = NULL;
    return 1;
}

/* Routines to read and write from the keyring file */

/* reads the hex file, converts to binary and returns pointer */
static unsigned char* 
vulpes_read_hex_keyring(int fd, int *keysRead)
{
	int lineNumber, charNumber, val, howManyKeys;
	off_t fLength;
	unsigned char *hexFile, *binaryFile, *readPtr ,*writePtr ;
	                                                        /* one char each for the space bet O2 O1,the LF and NULL 
																			     and one more "for the road!" */
	val=lseek(fd,0,SEEK_SET);
	if (val==(off_t)-1) {
		return NULL;
	}
	if ((fLength = lseek(fd,0,SEEK_END)) < 0) {
		perror("lseek:");
		return NULL;
	}
	val=lseek(fd,0,SEEK_SET);
	hexFile = (unsigned char*) malloc(fLength);
	if(read(fd,hexFile,fLength)!=fLength)
	{
		free(hexFile);
		return NULL;
	};

	/* Each line in hex file has O2,O1 and a line-feed character : so each line has 81 bytes */
	if (fLength%82)
	{
		free(hexFile);
		return NULL;
	};
	howManyKeys = fLength/82;
	binaryFile = (unsigned char*)malloc(howManyKeys*40);
	readPtr=hexFile;
	writePtr=binaryFile;
	/*readFormat[0]='\0';
	for(charNumber=0;charNumber<20;charNumber++)
		strcat(readFormat,"%02X");

	temp[0]='\0';
	strcat(temp,readFormat);
	strcat(temp,"\n");
	strcat(readFormat," ");
	strcat(readFormat,temp);*/
	
	for(lineNumber=0;lineNumber<howManyKeys;lineNumber++)
	{
		for(charNumber=0;charNumber<20;charNumber++,writePtr++,readPtr+=2)
		{
			*writePtr=hexToBin(readPtr);
			/* sscanf(readPtr,"%02X",writePtr);*/
		}
		readPtr++;
		for(charNumber=0;charNumber<20;charNumber++,writePtr++,readPtr+=2)
		{
			*writePtr=hexToBin(readPtr);
			/* sscanf(readPtr,"%02X",writePtr);*/
		}
		readPtr++;
	}
	/*printf("Done reading\n");*/
	vulpes_log(LOG_KEYS,"READ_HEX_KEYRING","");
	free(hexFile);
	*keysRead = howManyKeys;
	return binaryFile;
}

/* converts to hex, writes */
/* returns 0 on error and 1 on success */
static int 
vulpes_write_hex_keyring(int fd, unsigned char* binaryKeyring, int howManyKeys)
{
	int lineNumber, charNumber, val, fLength;
	unsigned char *hexFile,  *readPtr ,*writePtr;

	val=ftruncate(fd,0);
	if (val==-1)
		return 0;
	fLength = howManyKeys*82;
	hexFile = (unsigned char*) malloc(fLength);
	readPtr=binaryKeyring;
	writePtr=hexFile;

	for(lineNumber=0;lineNumber<howManyKeys;lineNumber++)
	{
		for(charNumber=0;charNumber<20;charNumber++,readPtr++,writePtr+=2)
		{
			binToHex(readPtr,writePtr);
			/* sprintf(writePtr,"%02X",*readPtr); */
		}
		*writePtr = ' ';
		writePtr++;
		for(charNumber=0;charNumber<20;charNumber++,readPtr++,writePtr+=2)
		{
			binToHex(readPtr,writePtr);
			/* sprintf(writePtr,"%02X",*readPtr); */
		}
		*writePtr = '\n';
		writePtr++;
	}
	if(write(fd,hexFile,fLength)!=fLength)
	{
		free(hexFile);
		return 0;
	}
	free(hexFile);
	return 1;
}

/* Higher level functions */
/*
 * This is called only on chunk-file close  
 */
void lev1_updateKey(struct keyring *kr, unsigned char new_key[20], unsigned char new_tag[20],
		    int keyNum)
{
  unsigned char old_tag_log[41], tag_log[41];
  unsigned char *readPtr ,*writePtr;
  int i;

  if(kr == NULL) {
    vulpes_log(LOG_ERRORS,"lev1_updateKey","cannot be here - no encryption in place");
  }

  writePtr=old_tag_log; readPtr=kr->keyRing[keyNum].tag;

  for(i=0;i<20;i++,readPtr++,writePtr+=2)
    binToHex(readPtr,writePtr);
  *writePtr='\0';

  writePtr=tag_log; readPtr=new_tag;
  for(i=0;i<20;i++,readPtr++,writePtr+=2)
    binToHex(readPtr,writePtr);
  *writePtr='\0';

  if (strcmp(old_tag_log,tag_log)!=0)
    vulpes_log(LOG_KEYS,"LEV1_UPDATEKEY","%d %s %s",keyNum,old_tag_log,tag_log);
  
  memcpy(kr->keyRing[keyNum].tag, new_tag, 20);
  memcpy(kr->keyRing[keyNum].key, new_key, 20);
}

vulpes_err_t lev1_get_tag(struct keyring *kr, int keyNum, unsigned char **tag)
{
  /* set tag to NULL in case of error */
  *tag=NULL;
  
  if (kr == NULL) {
      return VULPES_INVALID;
  }

  if (keyNum > kr->numKeys) {
      return VULPES_NOKEY;
  }

  /* no error -- set tag */
  *tag = kr->keyRing[keyNum].tag;

  return VULPES_SUCCESS;
}

vulpes_err_t lev1_get_key(struct keyring *kr, int keyNum, unsigned char **key)
{
  /* set key to NULL in case of error */
  *key=NULL;
  
  if (kr == NULL) {
      return VULPES_INVALID;
  }

  if (keyNum > kr->numKeys) {
      return VULPES_NOKEY;
  }

  /* no error -- set key */
  *key = kr->keyRing[keyNum].key;

  return VULPES_SUCCESS;
}

vulpes_err_t 
lev1_check_tag(struct keyring *kr, int keyNum, const unsigned char *tag)
{
  if (kr == NULL) {
      return VULPES_INVALID;
  }

  if (keyNum > kr->numKeys) {
      return VULPES_NOKEY;
  }

  return ((memcmp(kr->keyRing[keyNum].tag, tag, 20) == 0) 
	  ? VULPES_SUCCESS : VULPES_TAGFAIL);
}

/* Called with 
*  userpath=path to keyring file
*  user_key: if the keyring is encrypted, then this is the key to decrypt the keyring
*  userKeyLen: length of above key
*  a of now: keyring is not encrypted, so the second parm is NULL, and third is zero
*  Returns 1 on success, 0 otherwise
*/  
static int lev1_getKeyRingFile(struct keyring *kr, char *userPath, char *user_key, int userKeyLen)
{
  int fdes;
  char fname[256];
  
  if (kr == NULL) {
    printf("Cannot use this function: no encryption in place\n");
    return 0;
  }

  if (!userKeyLen) {
    fname[0] = '\0'; /* as of now: keyring is not encrypted */
    if (userPath)
      strcat(fname, userPath);
    if (!user_key) {
      if (kr->keyRingFileName)
	strcat(fname, kr->keyRingFileName);
    } else if (user_key)
      strcat(fname, user_key);
    /*printf("Opening keyring file: %s\n", fname);*/
    fdes = open(fname, O_RDONLY);
    if (fdes < 0)
      {
	vulpes_log(LOG_ERRORS,"LEV1_GETKEYRING","could not open keyring: %s",fname);
	return 0;
      }
    kr->keyRing = (struct keyring_entry *)  vulpes_read_hex_keyring(fdes,&(kr->numKeys));
    if (!kr->keyRing)
      return 0;
    close(fdes);
    vulpes_log(LOG_BASIC,"LEV1_GETKEYRING","read keyring %s: %d keys",fname,kr->numKeys);
    
    return 1;
  }
 
 vulpes_log(LOG_ERRORS,"LEV1_GETKEYRING","UNTESTED CODE: using encrypted keyring");
			
 /* printf("WARNING: Using an ENCRYPTED(?) keyring. Running UNTESTED CODE\n");*/
 return 0;/* DISABLE THIS PATH , call the vulpes_read_hex_keyring if ENABLED someday*/
 
 /*
   int fsize, tmp;
   unsigned char *fileContent, *decrypted = NULL;
   fname[0] = '\0';
   strcat(fname, userPath);
   strcat(fname, kr->keyRingFileName);
   fdes = open(fname, O_RDONLY);
   fsize = lseek(fdes, 0, SEEK_END);
   fileContent = (unsigned char *) malloc(fsize);
   lseek(fdes, 0, SEEK_SET);
   read(fdes, fileContent, fsize);
   close(fdes);
   vulpes_decrypt(fileContent, fsize, &decrypted, &tmp, user_key,
   userKeyLen);
   
   kr->numKeys = fsize / sizeof(struct keyring_entry);
   kr->keyRing = (struct keyring_entry *) malloc(fsize);
   memcpy(kr->keyRing, decrypted, tmp);
   free(decrypted);
   decrypted = NULL;
 */
}


/* returns -1 on error or 0 otherwise on success */
static int writeKeyRingFile(struct keyring *kr, char *userPath, char *user_key,
			    int userKeyLen)
{
  int fdes, tmp ;
  char fname[256];
  
  if (kr == NULL) {
    printf("Cannot use this function: no encryption in place\n");
    return -1;
  }
  
  if (!userKeyLen) {		/* as of now: keyring is not encrypted */
    fname[0] = '\0';
    if (userPath)
      strcat(fname, userPath);
    if (!user_key) {
      if (kr->keyRingFileName)
	strcat(fname, kr->keyRingFileName);
    } else if (user_key)
      strcat(fname, user_key);

    /*printf("\nOpening this file as the keyring to write to %s\n", fname);*/
    fdes = open(fname, O_WRONLY|O_TRUNC, 0600);
    if (fdes < 0) {
	vulpes_log(LOG_ERRORS,"WRITEKEYRINGFILE","could not open keyring file for writeback: %s", fname);
	return -1;
    }
    tmp = ftruncate(fdes,0);
    
    /* NOT REQUIRED ANYMORE
       write(fdes, (void *) keyRing, numKeys * (sizeof(struct keyring_entry)));  */
    if (tmp==-1) {
      vulpes_log(LOG_ERRORS,"WRITEKEYRINGFILE","could not truncate keyring file for writeback: %s", fname);
      return -1;
    }
    tmp = vulpes_write_hex_keyring(fdes, (void *)(kr->keyRing), kr->numKeys);  /* converts to hex and writes */
    if (tmp==0) {
      vulpes_log(LOG_ERRORS,"WRITEKEYRINGFILE","failed in vulpes_write_hex_keyring: %s", fname);
      return -1;
    }
    close(fdes);
    vulpes_log(LOG_BASIC,"WRITEKEYRINGFILE","wrote keyring %s: %d keys",fname,kr->numKeys);
    /* debugHash(); */
    return 0;
  }
  
  /* BUGGY CODE FOLLOWS */
  printf("warning: running UNSUPPORTED CODE in vulpes_lev1_encryption.c: bailing out\n");
  return -1;
  /* comment out code below - its unsupported
     vulpes_encrypt((unsigned char *) keyRing, numKeys * sizeof(struct keyring_entry),
     &decrypted, &tmp, user_key, userKeyLen);
     
     fname[0] = '\0';
     strcat(fname, userPath);
     strcat(fname, keyRingFileName);
     fdes = open(fname, O_WRONLY | O_TRUNC, 0600);
     write(fdes, decrypted, tmp);
     close(fdes);
     free(decrypted);
     decrypted = NULL;*/
}

/* returns a new struct keyring */
struct keyring *lev1_initEncryption(char *keyring_name)
{
  struct keyring *kr = NULL;

  if(keyring_name == NULL)
    return NULL;

  kr = malloc(sizeof(struct keyring));
  if(kr == NULL) return NULL;

  kr->keyRingFileName[0] = '\0';

  if(lev1_getKeyRingFile(kr, NULL, keyring_name, 0))
    return kr;
  
  /* else */
  free(kr);

  return NULL;
}

/* returns -1 on error or 0 on success */
int lev1_cleanupKeys(struct keyring *kr, char *keyring_name)
{
  int i;
  
  if (kr == NULL) return 0;

  if (!keyring_name) {
    vulpes_log(LOG_ERRORS,"LEV1_CLEANUPKEYS","keyring name is null");
    /*i= writeKeyRingFile("/home/nath/", NULL, 0);
      free(keyRing);*/
    return -1;
  } 

  /* else */
  i=writeKeyRingFile(kr, NULL, keyring_name, 0);
  free(kr->keyRing);
  free(kr);
  return i;
}
