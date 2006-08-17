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

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <zlib.h>
#include <string.h>
#include <stdlib.h>

#include "vulpes_lev1_encryption.h"

const int KEYLENGTH=20;

int keyprint(FILE* f, const unsigned char *key)
{
  int i;
  u_int8_t byte;

  for(i=0; i<KEYLENGTH; i++) {
    byte = key[i];
    if (fprintf(f, "%02X", byte) != 2) {
      printf("error in keyprint()\n");
      return i;
    }
  }

  return i;
}

void usage(const char *progname)
{
  printf("usage: %s <input-file> <output-file> <keyring-file>\n", progname);
  printf("    Compress and encrypt input file, saving O2 and O1 to keyring.\n");
  exit(-1);
}

int main(int argc, char *argv[])
{
  FILE *keyring_file;
  int input_fd, output_fd, tmp;
  unsigned long size1, size2, size3;
  unsigned char *inputFile, *compressedInput, *outputFile, *key1,
    *key2;
  int result;

  /* Check the command line */
  if (argc != 4) {
    usage(argv[0]);
  };
  
  /* Open the input file */
  if( (input_fd = open(argv[1], O_RDONLY)) < 1) {
    printf("Couldnt open input file : %s\n", argv[1]);
    exit(-1);
  };
  
  /* Get the size of the input file */
  size1 = lseek(input_fd, 0, SEEK_END);
  lseek(input_fd, 0, SEEK_SET);
  
  /* Allocate memory arrays */
  if( (inputFile = (unsigned char *) malloc(size1)) == NULL) {
    printf("unable to allocate the input array.\n");
    exit(-1);
  }
  if( (compressedInput = (unsigned char *) malloc(size1)) == NULL) {
    printf("unable to allocate the compression buffer.\n");
    exit(-1);
  }
  
  /* Read the input file into memory */
  read(input_fd, inputFile, size1);
  close(input_fd);
  
  /* Compress the input file */
  size2=size1;
  if( (result=compress2(compressedInput, &size2, inputFile, size1, 9)) 
      != Z_OK) {
    printf("error compressing input file (%d)\n", result);
    exit(-1);
  }
  free(inputFile);
  /* printf("Compressed size: %d", size2); */
  
  /* Derive the encryption key (O1) */
  key1 = digest(compressedInput, size2);
  
  /* Encrypt the input */
  vulpes_encrypt(compressedInput, size2, &outputFile, &tmp, key1, 20);
  size3 = tmp;
  
  /* Write the output file */
  if( (output_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 1) {
    printf("Couldnt create ouput file\n");
    exit(-1);
  };
  if( (result=write(output_fd, outputFile, size3)) != size3) {
    printf("error writing output (%d)\n", result);
    exit(-1);
  }	
  close(output_fd);
  
  /* Determine the lookup key */
  key2 = digest(outputFile, size3);
  
  /* Free the output arrays */
  free(compressedInput);
  free(outputFile);
  
  /* Open keyring in append mode */
  if( (keyring_file = fopen(argv[3], "a+")) == NULL) {
    printf("Couldnt open to the keyring file\n");
    exit(-1);
  };
  
  /* Write keyring values */
  if(keyprint(keyring_file, key2) != KEYLENGTH) {
    printf("error writing keyring\n");
    exit(-1);
  }
  fprintf(keyring_file, " ");
  if(keyprint(keyring_file, key1) != KEYLENGTH) {
    printf("error writing keyring\n");
    exit(-1);
  }
  fprintf(keyring_file, "\n");
  
  /* Clean up */
  fclose(keyring_file);
  free(key1);
  free(key2);
  
  exit(0);
}
