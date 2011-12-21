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
 */
#include <ucryptolib/cryptolib.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

/* From cryptolib test.c */

#define CHECK(a) do { if (!(a)){ \
                   fprintf(stderr, "FAIL %s(%d) : %s\n", \
                           __FILE__, __LINE__, #a); \
                   abort(); \
                 }} while(0)


// Print precomputed public key as C initializer.
static void cprint(FILE * f, const clBignumModulus * mod) {
  int i;
  fprintf(f, "{\n%d, %d, 0x%08x,\n", mod->size, mod->nwords, mod->n0inv);
  fprintf(f, "{\n");
  for (i = 0; i < mod->nwords; ++i) {
    fprintf(f, "0x%08x,", mod->n[i]);
    if ((i & 3) == 3)
      fprintf(f, "\n");
  }
  fprintf(f, "},\n{\n");
  for (i = 0; i < mod->nwords; ++i) {
    fprintf(f, "0x%08x,", mod->rr[i]);
    if ((i & 3) == 3)
      fprintf(f, "\n");
  }
  fprintf(f, "}}\n");
}

// Compute bignum structure for simple C bignum code.
static void precomputeModulus(const BIGNUM * n, clBignumModulus * mod) {
  int size = BN_num_bytes(n);
  int nwords = size / 4;        // bytes to dwords
  int i;

  // assert n is positive, odd, and multiple of 32 bits.
  CHECK(!BN_is_negative(n));
  CHECK((BN_num_bits(n) & 31) == 0);
  CHECK(BN_is_odd(n));

  memset(mod, 0, sizeof *mod);

  {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *R = BN_new();
    BIGNUM *RR = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *N = BN_new();
    BIGNUM *N0inv = BN_new();

    BN_set_bit(r, 32);          // 2^32
    BN_copy(N, n);              // modulus
    BN_set_bit(R, nwords * 32);
    BN_mod_sqr(RR, R, N, ctx);

    BN_div(NULL, rem, N, r, ctx);
    BN_mod_inverse(N0inv, rem, r, ctx);

    mod->size = size;
    mod->nwords = nwords;
    mod->n0inv = 0 - BN_get_word(N0inv);
    for (i = 0; i < nwords; ++i) {
      BN_div(RR, rem, RR, r, ctx);
      mod->rr[i] = BN_get_word(rem);
      BN_div(N, rem, N, r, ctx);
      mod->n[i] = BN_get_word(rem);
    }

    BN_free(N0inv);
    BN_free(N);
    BN_free(rem);
    BN_free(r);
    BN_free(RR);
    BN_free(R);
    BN_CTX_free(ctx);
  }
}

int precompute_rsa(char *rsa_file_precomp, char *rsa_file_pem,
                   char *variable_name) {
  FILE *rsa_precomp_c;
  BIO *bio;
  RSA *rsa_pub;
  clBignumModulus rsa_precompute;


  bio = BIO_new_file(rsa_file_pem, "r");

  if (!bio) {
    printf("Could not open %s properly\n", rsa_file_pem);
    return -1;
  }

  rsa_pub = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);

  if (!rsa_pub) {
    printf("Error while reading RSA public key from %s\n", rsa_file_pem);
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!(rsa_precomp_c = fopen(rsa_file_precomp, "w+"))) {
    printf("Error opening %s\n", rsa_file_precomp);
    return -1;
  }

  precomputeModulus(rsa_pub->n, &rsa_precompute);
  fprintf(rsa_precomp_c,
          "#include <ucryptolib/cryptolib.h>\n\n"
          "clBignumModulus %s =\n", variable_name);

  cprint(rsa_precomp_c, &rsa_precompute);
  fprintf(rsa_precomp_c, ";\n");
  fclose(rsa_precomp_c);

  return 0;
}

int precompute_dh(char *dh_file_precomp, char *dh_file_der,
                  char *variable_name) {
  FILE *dh_precomp_c;
  FILE *dh_der;
  DH *dh;
  clBignumModulus dh_precompute;
  size_t dh_params_len;
  unsigned char dh_params_buffer[2048];
  const unsigned char *dh_params = dh_params_buffer;

  if (!(dh_der = fopen(dh_file_der, "r"))) {
    printf("Error opening %s\n", dh_file_der);
    return -1;
  }

  /* Try to read up to sizeof(dh_params) bytes */
  dh_params_len = fread(dh_params_buffer, 1, sizeof(dh_params_buffer), dh_der);

  if (!feof(dh_der)) {
    printf("Error reading %s or file too big\n", dh_file_der);
    return -1;
  }

  dh = d2i_DHparams(NULL, &dh_params, dh_params_len);
  if (!dh) {
    printf("Error while reading DH parameters from %s\n", dh_file_der);
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!BN_is_word(dh->g, 2)) {
    printf("Error precomputing DH key, generator needs to be 2\n");
    return -1;
  }

  if (!(dh_precomp_c = fopen(dh_file_precomp, "w+"))) {
    printf("Error opening %s\n", dh_file_precomp);
    return -1;
  }

  precomputeModulus(dh->p, &dh_precompute);

  fprintf(dh_precomp_c,
          "#include <ucryptolib/cryptolib.h>\n\n"
          "clBignumModulus %s =\n", variable_name);

  cprint(dh_precomp_c, &dh_precompute);
  fprintf(dh_precomp_c, ";\n");
  fclose(dh_precomp_c);

  return 0;

}

int main(int argc, char *argv[]) {
  if (argc < 5) {
    printf
        ("Usage %s -r rsa_public_precomp.c rsa_public.pem variable_name | %s -d dh_params_precom.c dh_parameters.der variable_name\n",
         argv[0], argv[0]);
    return -1;
  }

  if (!strcmp(argv[1], "-r")) {
    return precompute_rsa(argv[2], argv[3], argv[4]);
  } else if (!strcmp(argv[1], "-d")) {
    return precompute_dh(argv[2], argv[3], argv[4]);
  } else {
    return -1;
  }
}
