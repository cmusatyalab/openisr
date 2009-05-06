/** math functions **/

#define LTC_MP_LT   -1
#define LTC_MP_EQ    0
#define LTC_MP_GT    1

#define LTC_MP_NO    0
#define LTC_MP_YES   1

int ltc_init_multi(void **a, ...);
void ltc_deinit_multi(void *a, ...);

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_math.h,v $ */
/* $Revision: 1.43 $ */
/* $Date: 2006/12/02 19:23:13 $ */
