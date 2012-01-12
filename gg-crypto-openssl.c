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
 * OpenSSL implementation of Grey Goo crypto interface
 */

#include <unistd.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "gg-crypto.h"
#include "gg-utils.h"
#include "gg-password.h"
#include "report.h"

typedef struct {
  char key[HMAC_KEY_MAX_LEN];
  size_t len;
} GG_key;

struct GG_crypt_impl {
  int dev_urandom;
  DH *dh;
  BIGNUM *dh_p_minus_1;    /* pre-computed p-1 for DH remote parameter check */
  HMAC_CTX hmac_ctx;
  /* my diffie-hellman public key, in wire-compatible format */
  unsigned char pubkey_bin[DH_KEY_MAX_LEN];
  int pubkey_bin_len;
  GG_key hmac_key;
  unsigned char *dh_shared_secret;
  int dh_shared_secret_size;
  /* the remote public diffie-hellman key, in big number format */
  BIGNUM *remote_key;
  /* for RSA signature / verification */
  BIO *rsa_pub_bio;
  BIO *rsa_priv_bio;
  RSA *rsa_pub;
  EVP_PKEY *rsa_priv;
  /* for signature verification */
  SHA_CTX sigctx;
  /* for signature generation */
  EVP_MD_CTX sign_ctx;
  unsigned char shasigdigest[SHA_DIGEST_LENGTH];
};

static int crypto_sha_init(SHA_CTX *ctx);
static int crypto_sha_update(SHA_CTX *ctx, const GG_ptr *ggpp, size_t len);
static int crypto_sha_final(unsigned char *md, SHA_CTX *ctx);

/* We will link the dh parameters */
extern const unsigned char _binary_public_keys_dh_parameters_der_start[];
extern const unsigned char _binary_public_keys_dh_parameters_der_end[];

/*
 * Allocate and initialize a GG_crypt structure
 * Return NULL on failure
 *
 * There are two stages, global and worker, this is the first one.
 */
GG_crypt *crypto_global_init(void) {
  GG_crypt *ggc;
  int dev_urandom;
  const unsigned char *dh_params = _binary_public_keys_dh_parameters_der_start;
  const long dh_params_len = _binary_public_keys_dh_parameters_der_end -
                             _binary_public_keys_dh_parameters_der_start;

  /* pre-open urandom so that we can use it later */
  dev_urandom = open("/dev/urandom", O_RDONLY);
  if (dev_urandom == -1) {
    REPORT_ERRNO("Could not open /dev/urandom");
    return NULL;
  }

  ggc = xmalloc(sizeof(GG_crypt));

  *ggc = (GG_crypt) {
    .dev_urandom = dev_urandom,
    .dh = NULL,
    .pubkey_bin_len = 0,
    .dh_shared_secret = NULL,
    .remote_key = NULL,
    .rsa_pub_bio = NULL,
    .rsa_priv_bio = NULL,
    .rsa_pub = NULL,
    .rsa_priv = NULL,
  };

  ggc->dh = d2i_DHparams(NULL, &dh_params, dh_params_len);
  if (!ggc->dh) {
    REPORT_ERROR("Getting DH parameters failed");
    xfree(ggc);
    return NULL;
  }

  /* allocate memory for the result of DH_compute_key */
  ggc->dh_shared_secret = xmalloc(DH_size(ggc->dh));

  ggc->remote_key = BN_new();
  ggc->dh_p_minus_1 = BN_new();

  if (!ggc->remote_key || !ggc->dh_p_minus_1) {
    REPORT_ERROR("Could not allocate number\n");
    return NULL;
  }

  /* Pre-compute p-1 for later use at shared key computation time */
  if (!BN_sub(ggc->dh_p_minus_1, ggc->dh->p, BN_value_one())) {
    REPORT_ERROR("Could not compute p-1\n");
    return NULL;
  }

  /* This function cannot fail */
  HMAC_CTX_init(&ggc->hmac_ctx);

  /* Initialize the context so that we can call it with only the key later
   *
   * Note: My headers declare HMAC_Init_ex as returning void, even though the
   * documentation states otherwise
   */
  HMAC_Init_ex(&ggc->hmac_ctx, "Grey Goo", 8, EVP_sha1(), NULL);

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
  /* Note: my headers declare this as returning void ? */
  HMAC_Init_ex(&ggc->hmac_ctx, ggc->hmac_key.key, ggc->hmac_key.len, NULL,
               NULL);
  return 0;
}

/* returns 0 on success */
int crypto_hmac_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len) {

  assert_ggp_size(ggpp, len);
  HMAC_Update(&ggc->hmac_ctx, (const unsigned char *) ggpp->ptr, len);
  return 0;
}

/* returns 0 on success */
int crypto_hmac_final(GG_crypt *ggc, const GG_ptr *md, unsigned int len) {
  unsigned int lencpy = 0;
  assert_ggp_size(md, (size_t) len);
  HMAC_Final(&ggc->hmac_ctx, (unsigned char *) md->ptr, &lencpy);
  if (lencpy != len)
    return -1;
  return 0;
}

/* Zero pad a big endian bignum of size num_size to occupy the whole space in
 * a buffer buf of size buf_size.
 * Return 0 on success, -1 on error
 */
static int normalize_bignum(unsigned char *buf, size_t buf_size,
                            size_t num_size) {
  if (buf_size < num_size)
    return -1;
  memmove(buf + buf_size - num_size, buf, num_size);
  while (num_size < buf_size) {
    *buf++ = 0;
    num_size++;
  }
  return 0;
}

#define SEED_NUMBYTES 16
/*
 * This is the second stage of the initialization
 * Return 0 on failure
 */
int crypto_stage2_init(GG_crypt *ggc) {
  BIGNUM *pubkey;
  static char buf[SEED_NUMBYTES];
  int ossl_len;
  GG_ptr rand = ggp_init(buf, SEED_NUMBYTES);

  if (!ggc)
    return 0;

  if (ggp_full_read(ggc->dev_urandom, &rand, SEED_NUMBYTES) != SEED_NUMBYTES) {
    REPORT_ERROR("Could not read dev_urandom");
    return 0;
  }

  /*
   * Seed OpenSSL - OpenSSL would do this transparently later otherwise
   * This is not very high quality entropy, but should be good enough
   */
  RAND_add(buf, SEED_NUMBYTES, SEED_NUMBYTES);

  close(ggc->dev_urandom);

  if (!DH_generate_key(ggc->dh)) {
    REPORT_ERROR("crypto_worker_init: DH_generate_key failed");
    return 0;
  }
  /*
   * Note: we use OpenSSL structure. In theory this could fail if an engine is
   * used but OpenSSL provides nothing better
   * OpenSSH seems to do the same :(
   */
  pubkey = ggc->dh->pub_key;

  if ((unsigned int) BN_num_bytes(pubkey) > sizeof(ggc->pubkey_bin)) {
    REPORT_ERROR("crypto_worker_init: Pubkey buffer too small\n");
    return 0;
  }

  ossl_len = BN_bn2bin(pubkey, ggc->pubkey_bin);

  /* OpenSSL doesn't provide a good way to check for errors */
  if (ossl_len <= 0 ||
      (unsigned int) DH_size(ggc->dh) > sizeof(ggc->pubkey_bin) ||
      ossl_len > DH_size(ggc->dh)) {
    REPORT_ERROR("crypto_worker_init: BN_bn2bin error");
    return 0;
  }

  /* OpenSSL wire format tries to optimize the size by striping leading zeros
   * We stipulate that we should always wire DH_size() bytes
   */
  if (normalize_bignum(ggc->pubkey_bin, DH_size(ggc->dh), ossl_len))
    return 0;
  ggc->pubkey_bin_len = DH_size(ggc->dh);

  DEBUG(2, "worker %d: generated DH key\n", getpid());

  return 1;
}

/* ggc->dh_shared_secret must be DH_size(ggc->dh) bytes large
 * return 0 on success -1 on failure
 */
int crypto_compute_shared_key(GG_crypt *ggc) {
  int ret;
  ret = DH_compute_key(ggc->dh_shared_secret, ggc->remote_key, ggc->dh);

  if (ret == -1) {
    return -1;
  } else {
    ggc->dh_shared_secret_size = ret;
    DEBUG(2, "crypto_compute_shared_key: success %X, size: %d\n",
          ((uint32_t *) ggc->dh_shared_secret)[0], ret);
    return 0;
  }
}

/* put the shared DH key into the HMAC */
/* -1 on failure 0 on success */
int crypto_set_shared_key_to_hmac(GG_crypt *ggc) {

  static unsigned char md[SHA_DIGEST_LENGTH];
  unsigned char *ret;
  ret = SHA1(ggc->dh_shared_secret, ggc->dh_shared_secret_size, md);

  return crypto_set_hmac_key(ggc, ret, SHA_DIGEST_LENGTH);
}

/* Set remote DH key */
/* return 0 on success -1 on failure */
int crypto_set_remote_key(GG_crypt *ggc, const unsigned char *remote_pubkey,
                          size_t len) {

  if (len != (unsigned int) DH_size(ggc->dh)) {
    DEBUG(1, "Remote DH key has the wrong size: %zi\n", len);
    return -1;
  }

  /* This could result in dynamic memory allocation */
  ggc->remote_key = BN_bin2bn(remote_pubkey, len, ggc->remote_key);
  if (!ggc->remote_key) {
    DEBUG(2, "crypto_compute_shared_key: BN_bin2bn failed\n");
    return -1;
  }

  /* We want to make sure that g^y != +-1 mod p and g^y != 0 mod p
   * We go farther and check: 1 < g^y < p-1
   * OpenSSH does something similar in dh.c
   *
   * We check successively that:
   *  - g^y != 0
   *  - g^y >= 0
   *  - g^y < p-1
   *  - g^y > 1
   *
   * The two first checks should be covered by the two last checks, but we are
   * paranoid when using OpenSSL.
   */
  if (BN_is_zero(ggc->remote_key) ||
      BN_is_negative(ggc->remote_key) ||
      BN_cmp(ggc->remote_key, ggc->dh_p_minus_1) != -1 ||
      BN_cmp(ggc->remote_key, BN_value_one()) != 1) {
    REPORT_INFO("Invalid remote DH proposal\n");
    return -1;
  }

  return 0;
}

/* Initializes internal pointers */
/* return 0 on success -1 on failure */
int crypto_verify_setkey(GG_crypt *ggc, void *rsakey, size_t len) {

  ggc->rsa_pub_bio = BIO_new_mem_buf(rsakey, len);
  if (!ggc->rsa_pub_bio) {
    DEBUG(2, "could not get new BIO from mem buffer");
    return -1;
  }

  /* PEM_read_bio_RSA_PublicKey does not accept raw public keys so we use
   * PEM_read_bio_RSA_PUBKEY instead */
  ggc->rsa_pub = PEM_read_bio_RSAPublicKey(ggc->rsa_pub_bio, NULL, NULL, NULL);
  if (!ggc->rsa_pub) {
    //DEBUG(2,"Could not read public key: %s\n", ERR_error_string(ERR_get_error(),
    // NULL));
    return -1;
  }
  return 0;
}

int crypto_verify_init(GG_crypt *ggc) {
  return crypto_sha_init(&ggc->sigctx);
}

int crypto_verify_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len) {
  return crypto_sha_update(&ggc->sigctx, ggpp, len);
}

/*
 * Verify a RSA signature
 *
 * Returns -1 on failure, 0 on success
 */
int crypto_verify_final(GG_crypt *ggc, GG_ptr *sigret, size_t siglen) {
  int ret;
  assert_ggp_size(sigret, siglen);

  ret = crypto_sha_final(ggc->shasigdigest, &ggc->sigctx);
  if (ret) {
    DEBUG(2, "SHA1_Final failed\n");
    return -1;
  }

  /* Our protocol states that the RSA signature should be zero padded to modulus
     size */
  if (siglen != (unsigned int) RSA_size(ggc->rsa_pub))
    return -1;

  ret = RSA_verify(NID_sha1, ggc->shasigdigest, SHA_DIGEST_LENGTH, sigret->ptr,
                   siglen, ggc->rsa_pub);

  /* "RSA_verify() returns 1 on successful verification, 0 otherwise." */
  if (ret == 1) {
    return 0;
  } else {
    DEBUG(2, "RSA_verify failed\n");
    return -1;
  }
}

/* Initializes internal pointers */
/* return 0 on success -1 on failure */
int crypto_sign_setkey(GG_crypt *ggc, void *rsakey, size_t len) {

  ggc->rsa_priv_bio = BIO_new_mem_buf(rsakey, len);
  if (!ggc->rsa_priv_bio) {
    DEBUG(2, "could not get new BIO from mem buffer");
    return -1;
  }
  /* Add all algorithms to the OpenSSL internal table */
  OpenSSL_add_all_algorithms();
  ggc->rsa_priv = PEM_read_bio_PrivateKey(ggc->rsa_priv_bio, NULL,
                                          gg_pass_cb, NULL);
  /* remove algorithms from OpenSSL internal table */
  EVP_cleanup();
  if (!ggc->rsa_priv) {
    DEBUG(2, "Could not read private key\n");
    return -1;
  }
  return 0;
}

/* return 0 on succes, something else on failure */
static int crypto_sha_init(SHA_CTX *ctx) {
  /* We use a different return value convention that OpenSSL */
  return !SHA1_Init(ctx);
}

static int crypto_sha_update(SHA_CTX *ctx, const GG_ptr *ggpp, size_t len) {
  assert_ggp_size(ggpp, len);
  return !SHA1_Update(ctx, ggpp->ptr, len);
}

static int crypto_sha_final(unsigned char *md, SHA_CTX *ctx) {
  return !SHA1_Final(md, ctx);
}

/* 0 on success, something else on failure */
int crypto_sign_init(GG_crypt *ggc) {
  EVP_SignInit(&ggc->sign_ctx, EVP_sha1());
  return 0;
}

int crypto_sign_update(GG_crypt *ggc, const GG_ptr *ggpp, size_t len) {
  return !EVP_SignUpdate(&ggc->sign_ctx, ggpp->ptr, len);
}

/* buffer sigret must have *siglen bytes available
 * siglen will contain the length of the signature
 * -1 fail, return 0 if ok
 */
int crypto_sign_final(GG_crypt *ggc, GG_ptr *sigret, size_t *siglen) {
  unsigned int retlen = 0;
  int ret;
  const int target_size = EVP_PKEY_size(ggc->rsa_priv);

  if (!siglen || *siglen < (unsigned int) target_size || target_size < 0) {
    DEBUG(2, "sig buffer length is too small\n");
    return -1;
  }
  assert_ggp_size(sigret, *siglen);

  ret = EVP_SignFinal(&ggc->sign_ctx, sigret->ptr, &retlen, ggc->rsa_priv);
  if (ret == 1) {
    /* We normalize the RSA signature to a fixed size */
    if (normalize_bignum(sigret->ptr, target_size, retlen))
      return -1;
    *siglen = target_size;
    return 0;
  } else {
    DEBUG(2, "RSA_Sign failed\n");
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
