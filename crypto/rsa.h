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

#define LTC_MP_LT   -1
#define LTC_MP_EQ    0
#define LTC_MP_GT    1

#define LTC_MP_NO    0
#define LTC_MP_YES   1

enum {
   PK_PUBLIC=0,
   PK_PRIVATE=1
};

int rand_prime(void *N, long len, prng_state *prng, int wprng);

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096

/** RSA PKCS style key */
typedef struct Rsa_key {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;
    /** The public exponent */
    void *e; 
    /** The private exponent */
    void *d; 
    /** The modulus */
    void *N; 
    /** The p factor of N */
    void *p; 
    /** The q factor of N */
    void *q; 
    /** The 1/q mod p CRT param */
    void *qP; 
    /** The d mod (p - 1) CRT param */
    void *dP; 
    /** The d mod (q - 1) CRT param */
    void *dQ;
} rsa_key;

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key);

void rsa_free(rsa_key *key);

int rsa_sign_hash_ex(const unsigned char *in,       unsigned long  inlen,
                           unsigned char *out,      unsigned long *outlen,
                           prng_state    *prng,     int            prng_idx,
                           int            hash_idx, unsigned long  saltlen,
                           rsa_key *key);

int rsa_verify_hash_ex(const unsigned char *sig,      unsigned long siglen,
                       const unsigned char *hash,     unsigned long hashlen,
                             int            hash_idx, unsigned long saltlen,
                             int           *stat,     rsa_key      *key);

int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key);
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key);

enum {
 LTC_ASN1_EOL,
 LTC_ASN1_INTEGER,
 LTC_ASN1_SHORT_INTEGER,
 LTC_ASN1_BIT_STRING,
 LTC_ASN1_OCTET_STRING,
 LTC_ASN1_OBJECT_IDENTIFIER,
 LTC_ASN1_SEQUENCE,
};

/** A LTC ASN.1 list type */
typedef struct ltc_asn1_list_ {
   /** The LTC ASN.1 enumerated type identifier */
   int           type;
   /** The data to encode or place for decoding */
   void         *data;
   /** The size of the input or resulting output */
   unsigned long size;
   /** The used flag, this is used by the CHOICE ASN.1 type to indicate which choice was made */
   int           used;
   /** prev/next entry in the list */
   struct ltc_asn1_list_ *prev, *next, *child, *parent;
} ltc_asn1_list;

#define LTC_SET_ASN1(list, index, Type, Data, Size)  \
   do {                                              \
      int LTC_MACRO_temp            = (index);       \
      ltc_asn1_list *LTC_MACRO_list = (list);        \
      LTC_MACRO_list[LTC_MACRO_temp].type = (Type);  \
      LTC_MACRO_list[LTC_MACRO_temp].data = (void*)(Data);  \
      LTC_MACRO_list[LTC_MACRO_temp].size = (Size);  \
      LTC_MACRO_list[LTC_MACRO_temp].used = 0;       \
   } while (0);

/* SEQUENCE */
int der_encode_sequence_ex(ltc_asn1_list *list, unsigned long inlen,
                           unsigned char *out,  unsigned long *outlen, int type_of);
                          
#define der_encode_sequence(list, inlen, out, outlen) der_encode_sequence_ex(list, inlen, out, outlen, LTC_ASN1_SEQUENCE)                        

int der_decode_sequence_ex(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *list,     unsigned long  outlen, int ordered);
                              
#define der_decode_sequence(in, inlen, list, outlen) der_decode_sequence_ex(in, inlen, list, outlen, 1)

int der_length_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned long *outlen);

/* VA list handy helpers with triplets of <type, size, data> */
int der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...);

int pkcs_1_i2osp(void *n, unsigned long modulus_len, unsigned char *out);
int pkcs_1_os2ip(void *n, unsigned char *in, unsigned long inlen);

int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  prng_state   *prng,     
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen);

int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res);


