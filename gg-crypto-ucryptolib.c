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
 * ucryptolib implementation of the Crypto interface.
 * Lacks RSA sign, so can't be used for the client
 */
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "gg-crypto.h"
#include "gg-utils.h"
#include "report.h"
#include "ucryptolib/cryptolib.h"

typedef struct {
  char key[HMAC_KEY_MAX_LEN];
  size_t len;
} GG_key;

struct GG_crypt_impl {
  int dev_urandom;
  clBignumModulus myDH;
  clHMAC_CTX hmac_ctx;
  clPRNG_CTX prng;
  /* my diffie-hellman public key, in wire-compatible format */
  uint8_t *pubkey_bin;
  int pubkey_bin_len;
  /* diffie-hellman private key */
  uint8_t x[DH_KEY_MAX_LEN];
  GG_key hmac_key;
  uint8_t *dh_shared_secret;
  int dh_shared_secret_size;
  /* the remote public diffie-hellman key */
  uint8_t *remote_key;
  size_t remote_key_len;
  /* for RSA signature / verification */
  clBignumModulus myRSA;
  clHASH_CTX rsaHash;
};

extern clBignumModulus precomputed_dh;

/*
 * Allocate and initialize a GG_crypt structure
 * Return NULL on failure
 *
 * There are two stages, global and worker, this is the first one.
 */
GG_crypt *crypto_global_init(void) {
  GG_crypt *ggc;
  int dev_urandom;

  /* pre-open urandom so that we can use it later */
  dev_urandom = open("/dev/urandom", O_RDONLY);
  if (dev_urandom == -1) {
    REPORT_ERRNO("Could not open /dev/urandom");
    return NULL;
  }

  ggc = xmalloc(sizeof(GG_crypt));

  *ggc = (GG_crypt) {
    .dev_urandom = dev_urandom,
    .pubkey_bin_len = 0,
    .dh_shared_secret = NULL,
    .remote_key = NULL,
  };

  /* TODO: replace myDH with pointer */
  ggc->myDH = (clBignumModulus) precomputed_dh;

  /* allocate memory for the result of DH_compute_key */
  ggc->dh_shared_secret = xmalloc(ggc->myDH.size);
  ggc->dh_shared_secret_size = ggc->myDH.size;

  /* cryptolib */
  ggc->pubkey_bin = xmalloc(ggc->myDH.size);
  ggc->pubkey_bin_len = ggc->myDH.size;

  ggc->remote_key = xmalloc(ggc->myDH.size);
  ggc->remote_key_len = ggc->myDH.size;

  return ggc;
}

/* returns -1 on failure, 0 on success */
int crypto_set_hmac_key(GG_crypt *ggc, const void *key, size_t key_len) {
  if (key_len > HMAC_KEY_MAX_LEN) {
    REPORT_ERROR("KEY too large");
    return -1;
  }
  memcpy(ggc->hmac_key.key, key, key_len);
  ggc->hmac_key.len = key_len;

  if (!crypto_hmac_init(ggc))
    return 0;
  else
    return 1;
}

/* returns 0 on success */
int crypto_hmac_init(GG_crypt *ggc) {
  clHMAC_SHA1_init(&ggc->hmac_ctx, ggc->hmac_key.key, ggc->hmac_key.len);
  return 0;
}

/* returns 0 on success */
int crypto_hmac_update(GG_crypt *ggc, const GG_ptr* ggpp, size_t len) {
  assert_ggp_size(ggpp, len);
  clHMAC_update(&ggc->hmac_ctx, ggpp->ptr, len);
  return 0;
}

/* returns 0 on success */
int crypto_hmac_final(GG_crypt *ggc, const GG_ptr *md, unsigned int len) {
  const unsigned char *digest;
  if (len < (unsigned int) clHMAC_size(&ggc->hmac_ctx))
    return -1;

  digest = clHMAC_final(&ggc->hmac_ctx);
  ggp_memcpy(md, digest, len);

  return 0;
}

#define SEED_NUMBYTES 16
/*
 * This is the second stage of the initialization
 * Return 0 on failure
 */
int crypto_stage2_init(GG_crypt *ggc) {
  static char buf[SEED_NUMBYTES];
  GG_ptr rand = ggp_init(buf, SEED_NUMBYTES);

  if (!ggc)
    return 0;

  if (ggp_full_read(ggc->dev_urandom, &rand, SEED_NUMBYTES) != SEED_NUMBYTES) {
    REPORT_ERROR("Could not read dev_urandom");
    return 0;
  }

  /*
   * Seed the cryptolib
   * This is not very high quality entropy, but should be good enough
   */
  clPRNG_init(&ggc->prng, buf, SEED_NUMBYTES);

  close(ggc->dev_urandom);

  /* Loop until we draw a proper private key. This will never loop in practice */
  do {
    clPRNG_draw(&ggc->prng, ggc->x, sizeof(ggc->x));
  } while (clDHgenerate(&ggc->myDH, ggc->x, sizeof(ggc->x), ggc->pubkey_bin) !=
           1);

  DEBUG(2, "worker %d: generated DH key\n", getpid());

  return 1;
}

/* ggc->dh_shared_secret must be (ggc->myDH.size) bytes large
 * return 0 on success -1 on failure
 */
int crypto_compute_shared_key(GG_crypt *ggc) {
  int ret;

  ret =
      clDHcompute(&ggc->myDH, ggc->remote_key, ggc->remote_key_len, ggc->x,
                  sizeof(ggc->x), ggc->dh_shared_secret);

  if (ret != 1) {
    DEBUG(2, "crypto_compute_shared_key: clDHcompute failed\n");
    return -1;
  } else {
    ggc->dh_shared_secret_size = ggc->myDH.size;
    DEBUG(2, "crypto_compute_shared_key: success %X, size: %d\n",
          ((uint32_t *) ggc->dh_shared_secret)[0], ggc->dh_shared_secret_size);
    return 0;
  }
}

/* put the shared DH key into the HMAC */
/* -1 on failure 0 on success */
int crypto_set_shared_key_to_hmac(GG_crypt *ggc) {

  static uint8_t md[clSHA1_DIGEST_SIZE];
  const uint8_t *ret;
  ret = clSHA1(ggc->dh_shared_secret, ggc->dh_shared_secret_size, md);

  return crypto_set_hmac_key(ggc, ret, clSHA1_DIGEST_SIZE);
}

/* Set remote DH key */
/* return 0 on success -1 on failure */
int crypto_set_remote_key(GG_crypt *ggc, const unsigned char *remote_pubkey,
                          size_t len) {

  if (len != ggc->remote_key_len) {
    DEBUG(1, "Remote DH key has the wrong size %zi\n", len);
    return -1;
  }

  memcpy(ggc->remote_key, remote_pubkey, len);

  return 0;
}

extern clBignumModulus precomputed_rsa_root;
extern clBignumModulus precomputed_rsa_test;

/* Initializes internal pointers
 * rsakey must be NULL and len must be 0 to indicate the root key
 * or 1 to indicate the testing key.
 *
 * Return 0 on success -1 on failure */
int crypto_verify_setkey(GG_crypt *ggc, void *rsakey, size_t len) {

  /* this implementation only supports pre-initialized keys */
  if (rsakey != NULL)
    return -1;

  /* use the test key ? */
  switch (len) {
    case KEYIDX_TEST:
      ggc->myRSA = (clBignumModulus) precomputed_rsa_test;
      return 0;
    case KEYIDX_ROOT:
      ggc->myRSA = (clBignumModulus) precomputed_rsa_root;
      return 0;
    default:
      return -1;
  }
}

/* return 0 on succes, something else on failure */
static int crypto_sha_init(clHASH_CTX *ctx) {
  clSHA1_init(ctx);
  return 0;
}

static int crypto_sha_update(clHASH_CTX *ctx, const GG_ptr *ggpp, size_t len) {
  assert_ggp_size(ggpp, len);
  clHASH_update(ctx, ggpp->ptr, len);
  return 0;
}

int crypto_verify_init(GG_crypt *ggc) {
  return crypto_sha_init(&ggc->rsaHash);
}

int crypto_verify_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len) {
  return crypto_sha_update(&ggc->rsaHash, ggpp, len);
}

/*
 * Verify a RSA signature
 *
 * Returns -1 on failure, 0 on success
 */
int crypto_verify_final(GG_crypt *ggc, GG_ptr *sigret, size_t siglen) {
  int ret;

  assert_ggp_size(sigret, siglen);

  if (siglen != (unsigned int) ggc->myRSA.size)
    return -1;

  ret = clRSA2K_verify(&ggc->myRSA, sigret->ptr, siglen, &ggc->rsaHash);

  if (ret == 1) {
    return 0;
  } else {
    DEBUG(2, "RSA verification failed\n");
    return -1;
  }
}

/* simple getter for ggc->pubkey_bin_len */
size_t crypto_get_dh_pubkey_len(GG_crypt *ggc) {
  return ggc->pubkey_bin_len;
}

unsigned char *crypto_get_dh_pubkey_bin(GG_crypt *ggc) {
  return ggc->pubkey_bin;
}
