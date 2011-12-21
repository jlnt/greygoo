/* Copyright 2011 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Julien Tinnes
 *
 * Crypto interface. We have two implementations, OpenSSL and cryptolib.
 */
#ifndef GG_CRYPTO_H
#define GG_CRYPTO_H
#include "gg-utils.h"

#define DH_KEY_MAX_LEN (1024/8)

#define HMAC_KEY_MAX_LEN 20

typedef struct GG_crypt_impl GG_crypt;

/* crypto_global_init() and crypto_state2_init must both be called before using
 * any crypto.
 *
 * The crypto is seeded at the second stage, so if using multiple processes,
 * crypto_global_init can be called in the parent and stage2 in each child
 *
 * This will compute the private Diffie-Hellman exponent
 *
 */
GG_crypt *crypto_global_init(void);
int crypto_stage2_init(GG_crypt *ggc);

/* set the hmac key used for all future HMAC operations */
int crypto_set_hmac_key(GG_crypt *ggc, const void *key, size_t key_len);

/* standard HMAC stuff. hmac_final writes the hmac to md, of maximum length len */
int crypto_hmac_init(GG_crypt *ggc);
int crypto_hmac_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len);
int crypto_hmac_final(GG_crypt *ggc, const GG_ptr *md, unsigned int len);

/* set remote DH key to gcc internal state */
int crypto_set_remote_key(GG_crypt *ggc, const unsigned char *remote_pubkey,
                          size_t len);
/* compute the g^xy of the DH exchange */
int crypto_compute_shared_key(GG_crypt *ggc);
/* compute the shared key and sets it as the internal HMAC key in ggc */
int crypto_set_shared_key_to_hmac(GG_crypt *ggc);

/* Getter to get the Diffie-Hellman key in a format that can be wired */
unsigned char *crypto_get_dh_pubkey_bin(GG_crypt *ggc);
size_t crypto_get_dh_pubkey_len(GG_crypt *ggc);

enum keyindex { KEYIDX_ROOT, KEYIDX_TEST };

/* Set the RSA key that will be used for signature verification
 *
 * rsakey = NULL and len = KEYIDX_ROOT means: use internally baked root key
 * rsakey = NULL and len = KEYIDX_TEST means: use internally baked test key
 */
int crypto_verify_setkey(GG_crypt *ggc, void *rsakey, size_t len);
/* classic MAC interface to signature verification */
int crypto_verify_init(GG_crypt *ggc);
int crypto_verify_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len);
int crypto_verify_final(GG_crypt *ggc, GG_ptr *sigret, size_t siglen);


/* classic MAC interface to signature generation
 * only our OpenSSL implementation supports those */
int crypto_sign_setkey(GG_crypt *ggc, void *rsakey, size_t len);
int crypto_sign_init(GG_crypt *ggc);
int crypto_sign_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len);
int crypto_sign_final(GG_crypt *ggc, GG_ptr *sigret, size_t *siglen);

#endif                          /* GG_CRYPTO_H */
