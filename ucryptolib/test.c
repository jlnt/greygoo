// Copyright 2011 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: Marius Schilder
//
// Test driver and sample invocation code for cryptolib.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

// Works with openssl-0.9x or openssl-1x
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "cryptolib.h"

#define CHECK(a) do { if (!(a)){ \
                   fprintf(stderr, "FAIL %s(%d) : %s\n", \
                           __FILE__, __LINE__, #a); \
                   abort(); \
                 }} while(0)

// Test key, generated with 'openssl genrsa 2048'.
static const char kPrivateKey[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEA27sPhY+JHh2g8M9aqqwiYQR25MI0kdwBgOx3RCudqNKhQS83\n"
"8IV9FvF00XD5VkG7DqD4FDjSQRb1VfO5Jbq3sJtMwbsxF1OlUU2qXoMjj+HJeg+D\n"
"GI1BSyX9Vo0nZqIOQkMTCErc6VmANCIhQvOijt6Lnia3wfbPDJ4g1Qrf6kvoesyg\n"
"6bbRRNdkBwG/WtjxAmXxWl6KT+V1BIzgEbKw1G2XwAewevpeTmIMqpxrUV98OlfC\n"
"xY4wCevm/SphUc/dksTC4MFDYkf/v51xAdSueMHDLv5mcGYLuFfb/QrD2arcPIzi\n"
"f5mth5yF4ynw2Khne1nWKzLlvMdmKQC9GuFfpwIDAQABAoIBAAkFtk5ypVuyNcCN\n"
"kxh89vBq4YLlIol2si0cCI2pCNE8zNhDWxWqNYeypGxRKjvLeSXRoD4cUy3PBoXf\n"
"+xM8hnxe9BjkWdCuY5RiDwPQeK5YxBAaAPUKH8s5JRzfsOV69ADuhiKKCGYgga4i\n"
"VKFOJbeeFbeJuXPicYAAIjL9PlJ9dfOuykLW/1UW8Vm+Hq7ZlPYxzmNje/slQWcV\n"
"9JrbC7kgmNhbJDorhwKB7EcxGqycxsXmI/owMyp3i5xAKFVaBZDzVYgtKeeYOqJh\n"
"IZrpa/7oRGRp9gegCl3pH0zytMQePw1bOofkW2rcdW33jZvlSzfARlhK/YQXm+bK\n"
"ejclWCECgYEA8ukZUuJb3la5SfPDE4OqrVoNil3Rj8cU6POrcQRKuoqLOzb38CXs\n"
"VVSTQvBMbCeGPVFzVt9jRwjwLWY3Oioh2r7bRBzM4f3FE4nY5OaqsUCvnvdAQucP\n"
"ZGC6sHReNfWXwWsMaKPABAicNbilx0Is2t5kc5Hdw/TNKrG5Dx23txECgYEA55Iz\n"
"W5Kak2jPxDNzJMGPgczNjKPmXhPgAGE7pfYhy3Z4e3UuI1W+fNfaIQxHo0sBvDq2\n"
"xRn/ZrRt+JYdnxFilEmBL0gfLp17k2ThX6znT3oRQb0t4GmnItP//fWBGy20n1/7\n"
"lmMLGevYC3C5qrv5TYlQgyzZqz0rCRplK4D2WzcCgYEAjYYfufml+sFeTObXxjvV\n"
"KhCoiPAmU3VzClJFlaAhhdOIUSSyidkee4y+C6cDb5QLkxgscfXO2qkrfdfq31mC\n"
"xfaiu2loOVboBn0uwBZgZstARwbZCuGiRyJQQtRZu2huVUNwRFr7WZ5GnMoK1DAL\n"
"AC3IKslWgn/TNUe8gUEYM3ECgYAPApMBpIcQdwLAnPUhtMowh63rJ9SO1Ir4e1T6\n"
"dPHL1moI1pefArfOL8+bxMf/9aSvJr8iF4VOivN14YUaAm55XipZfjtHMj4IV8mk\n"
"AfkcVbU4paKLoU2MHGHDfF5Z/KRwkDAml1To4TinxS7Dult2gygM2KNjThu0A1n7\n"
"b+iIEQKBgQC6ZLGo+440K0yFYZeEGCW1ZwXvxhcjxPcAwhIFWpiDauAe4mlA1WoP\n"
"RwsiTjM7m1YB6wA7HtFTzeOF7E0/LGR0IhVj8sGXcBFy1v0ddeBwvTRVGSE6NStA\n"
"0hgEnuvf4yUkT3k80Kh8GVbRoU0jRv8z69fNJ7qc0itqTI21hYkNDA==\n"
"-----END RSA PRIVATE KEY-----\n";

// Test DH params, generated with 'openssl gendh 1024'.
static const char kDHParams[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIGHAoGBALG7ycTIexYRQvVWaL+Aq+NtT29ckFvKYhBRvMgWdbbSZYNhl4V1igZJ\n"
"swlqLhADsPuSvTvUBmZo6HSKNYcyLokTqmFU8jG4GodQtxiSTTlbFbPf/m/MWsy8\n"
"47t+8V729dTA6FPQJXeWtQu3Qc532b4erhCabqKnrYeX0Yo877JrAgEC\n"
"-----END DH PARAMETERS-----\n";

static EVP_PKEY* parseKey(const char* keyStr) {
  BIO* bio = BIO_new_mem_buf((char*)keyStr, strlen(keyStr));
  OpenSSL_add_all_algorithms();
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  EVP_cleanup();
  BIO_vfree(bio);
  return key;
}

static void freeKey(EVP_PKEY* key) { EVP_PKEY_free(key); }

static DH* parseDH(const char* dhStr) {
  BIO* bio = BIO_new_mem_buf((char*)dhStr, strlen(dhStr));
  DH* dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_vfree(bio);
  return dh;
}

static void freeDH(DH* dh) { DH_free(dh); }

// Compute bignum structure for simple C bignum code.
static void precomputeModulus(const BIGNUM* n, clBignumModulus* mod) {
  int size = BN_num_bytes(n);
  int nwords = size / 4;  // bytes to dwords
  int i;

  // assert n is positive, odd, and multiple of 32 bits.
  CHECK(!BN_is_negative(n));
  CHECK((BN_num_bits(n) & 31) == 0);
  CHECK(BN_is_odd(n));

  memset(mod, 0, sizeof *mod);

  {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* R = BN_new();
    BIGNUM* RR = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM* N = BN_new();
    BIGNUM* N0inv = BN_new();

    BN_set_bit(r, 32);  // 2^32
    BN_copy(N, n);  // modulus
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

static void precomputeRSA(EVP_PKEY* key, clBignumModulus* mod) {
  RSA* rsa = EVP_PKEY_get1_RSA(key);
  precomputeModulus(rsa->n, mod);
  RSA_free(rsa);
}

static void precomputeDH(DH* dh, clBignumModulus* mod) {
  precomputeModulus(dh->p, mod);
  // assert generator is 2.
  CHECK(BN_is_word(dh->g, 2));
}

// Print precomputed public key as C initializer.
static void cprint(const clBignumModulus* mod) {
  int i;
  printf("{\n%d, %d, 0x%08x,\n", mod->size, mod->nwords, mod->n0inv);
  printf("{\n");
  for (i = 0; i < mod->nwords; ++i) {
    printf("0x%08x,", mod->n[i]);
    if ((i & 3) == 3) printf("\n");
  }
  printf("},\n{\n");
  for (i = 0; i < mod->nwords; ++i) {
    printf("0x%08x,", mod->rr[i]);
    if ((i & 3) == 3) printf("\n");
  }
  printf("}}\n");
}

// SHA256 using openssl.
// md needs to hold SHA256_DIGEST_LENGTH bytes.
static void ossl_sha256(const void* in, int in_size, unsigned char* md) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, in, in_size);
  SHA256_Final(md, &ctx);
}

// Sign a message with openssl using RSA private key and specified digest.
// Returns 1 if OK.
static int ossl_sign(EVP_PKEY* signing_key,
                     const EVP_MD* hash,
                     const void* msg,
                     size_t msglen,
                     unsigned char **sig,
                     size_t* siglen) {
  EVP_MD_CTX *ctx = NULL;
  int result = 0;
  unsigned int tmplen = EVP_PKEY_size(signing_key);

  *sig = NULL;
  *siglen = 0;

  ctx = EVP_MD_CTX_create();
  if (!ctx) goto error;

  EVP_MD_CTX_init(ctx);
  EVP_DigestInit(ctx, hash);
  EVP_DigestUpdate(ctx, msg, msglen);

  *sig = (unsigned char*)malloc(tmplen);
  result = EVP_SignFinal(ctx, *sig, &tmplen, signing_key);
  *siglen = tmplen;

error:
  if (result != 1) {
    free(*sig);
  }
  if (ctx) EVP_MD_CTX_destroy(ctx);
  return result;
}

static void printHex(const char* tag, const void* data, int len) {
  const uint8_t* p = (const uint8_t*)data;
  int i;
  if (*tag) printf("%s", tag);
  for (i = 0; i < len; ++i)
    printf("%02x", p[i]);
  if (*tag) printf("\n");
}


// Simple known answer test for HMAC-SHA256 and HMAC-SHA1.
static void testHMAC() {
  static const uint8_t KAT256[] = {
    0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,
    0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
    0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,
    0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
  };
  static const uint8_t KAT1[] = {
    0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,0xd2,0x74,
    0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79
  };
  const unsigned char* digest;
  clHMAC_CTX hmac;

  // HMAC-SHA256
  clHMAC_SHA256_init(&hmac, "Jefe", 4);
  clHMAC_update(&hmac, "what do ya want for nothing?", 28);
  digest = clHMAC_final(&hmac);
  printHex("hmac:", digest, clHMAC_size(&hmac));
  CHECK(clEqual(digest, clHMAC_size(&hmac), KAT256, sizeof KAT256) == 0);

  // HMAC-SHA1
  clHMAC_SHA1_init(&hmac, "Jefe", 4);
  clHMAC_update(&hmac, "what do ya want for nothing?", 28);
  digest = clHMAC_final(&hmac);
  printHex("hmac:", digest, clHMAC_size(&hmac));
  CHECK(clEqual(digest, clHMAC_size(&hmac), KAT1, sizeof KAT1) == 0);
}


// Sign random test message with openssl, verify using simple C code.
static void testRSA() {
  EVP_PKEY* key = parseKey(kPrivateKey);
  unsigned char* sig;
  size_t siglen;
  unsigned char msg[1024];
  int msg_size;
  clBignumModulus myKey;
  clHASH_CTX myHash;

  // Compute key representation for cryptolib.
  precomputeRSA(key, &myKey);
  cprint(&myKey);

  // Construct random message.
  msg_size = rand() & 1023;
  RAND_bytes(msg, msg_size);

  printHex("msg:  ", msg, msg_size);

  // Check pkcs15-sha256 =========================
  CHECK(ossl_sign(key, EVP_sha256(), msg, msg_size, &sig, &siglen) == 1);

  printHex("sig:  ", sig, siglen);

  // Check signature matches hash.
  clSHA256_init(&myHash);
  clHASH_update(&myHash, msg, msg_size);
  CHECK(clRSA2K_verify(&myKey, sig, siglen, &myHash) == 1);

  // Flip evil bit in sig.
  sig[0] ^= 1;

  // Check fail.
  clSHA256_init(&myHash);
  clHASH_update(&myHash, msg, msg_size);
  CHECK(clRSA2K_verify(&myKey, sig, siglen, &myHash) == 0);

  free(sig);

  // Check pkcs15-sha1 ============================
  CHECK(ossl_sign(key, EVP_sha1(), msg, msg_size, &sig, &siglen) == 1);

  printHex("sig:  ", sig, siglen);

  // Check signature matches hash.
  clSHA1_init(&myHash);
  clHASH_update(&myHash, msg, msg_size);
  CHECK(clRSA2K_verify(&myKey, sig, siglen, &myHash) == 1);

  // Flip evil bit in sig.
  sig[0] ^= 1;

  // Check fail.
  clSHA1_init(&myHash);
  clHASH_update(&myHash, msg, msg_size);
  CHECK(clRSA2K_verify(&myKey, sig, siglen, &myHash) == 0);

  free(sig);

  freeKey(key);
}


// ossl *2bin functions drop leading zeros.
// Move and add leading zeros if needed.
static int ossl_normalize(uint8_t* inout, int in_size, int out_size) {
  if (in_size != out_size) {
    CHECK(in_size < out_size);
    memmove(inout + out_size - in_size, inout, in_size);
    for( ; in_size < out_size; ++in_size) *inout++ = 0;
  }
  return out_size;
}


static void testDH() {
  DH* dh = parseDH(kDHParams);
  clBignumModulus myDH;
  uint8_t gx[clBIGNUMBYTES];
  uint8_t x[clBIGNUMBYTES];
  uint8_t myGx[clBIGNUMBYTES];
  uint8_t gxy[clBIGNUMBYTES];
  uint8_t myGxy[clBIGNUMBYTES];
  int size_gx, size_x, size_gxy;
  BIGNUM* gy = BN_new();

  CHECK(dh != NULL);

  precomputeDH(dh, &myDH);
  cprint(&myDH);

  // Phase 1 of DH: make up random priv_key and compute 2 ** priv_key.
  CHECK(DH_generate_key(dh) == 1);
  size_gx = BN_bn2bin(dh->pub_key, gx);
  CHECK(size_gx > 0);

  size_gx = ossl_normalize(gx, size_gx, myDH.size);

  size_x = BN_bn2bin(dh->priv_key, x);
  CHECK(size_x > 0);

  printHex("x    :", x, size_x);
  printHex("gx   :", gx, size_gx);

  // Feed same priv_key to clDHgenerate, should match output.
  CHECK(clDHgenerate(&myDH, x, size_x, myGx) == 1);
  printHex("myGx :", myGx, myDH.size);

  // Phase 2: pretend this gx was other party's input.
  // We're thus computing 2 ** (priv_key * priv_key) but doesn't matter.
  BN_bin2bn(myGx, myDH.size, gy);

  size_gxy = DH_compute_key(gxy, gy, dh);
  size_gxy = ossl_normalize(gxy, size_gxy, myDH.size);

  printHex("gxy  :", gxy, size_gxy);

  CHECK(clDHcompute(&myDH, gx, size_gx, x, size_x, myGxy) == 1);
  printHex("myGxy:", myGxy, myDH.size);

  CHECK(clEqual(gxy, size_gxy, myGxy, myDH.size) == 0);

  {
    uint8_t a[SHA256_DIGEST_LENGTH];
    uint8_t b[clSHA256_DIGEST_SIZE];

    ossl_sha256(gxy, myDH.size, a);
    clSHA256(myGxy, myDH.size, b);
    CHECK(clEqual(a, sizeof a, b, sizeof b) == 0);
  }

  // Some negative testing on clDHgenerate()
  memset(x, 0, sizeof x);
  CHECK(clDHgenerate(&myDH, x, 0, myGx) == 0);  // 0 exponent not cool.
  CHECK(clDHgenerate(&myDH, x, 1, myGx) == 0);  // 0 exponent not cool.
  CHECK(clDHgenerate(&myDH, x, sizeof x, myGx) == 0);  // 0 exponent not cool.

  size_x = BN_bn2bin(dh->p, x);
  CHECK(clDHgenerate(&myDH, x, size_x, myGx) == 1);  // x^p mod p == x

  x[size_x - 1]--;  // compute p-1
  CHECK(clDHgenerate(&myDH, x, size_x, myGx) == 0);  // x^(p-1) mod p == 1

  freeDH(dh);
  BN_free(gy);
}

static void testPRNG() {
  clPRNG_CTX prng;
  uint8_t block[128];

  clPRNG_init(&prng, "abc", 3);
  printHex("prng:", &prng, sizeof prng);

  clPRNG_draw(&prng, block, sizeof block);
  printHex("prng:", &prng, sizeof prng);
  printHex("out :", block, sizeof block);

  clPRNG_draw(&prng, block, sizeof block);
  printHex("prng:", &prng, sizeof prng);
  printHex("out :", block, sizeof block);
}

static void testPBKDF2() {
  uint8_t key[20];
  static const uint8_t kExpected[] = {
    0x4b,0x00,0x79,0x01,0xb7,0x65,0x48,0x9a,0xbe,0xad,
    0x49,0xd9,0x26,0xf7,0x21,0xd0,0x65,0xa4,0x29,0xc1
  };
  CHECK(PKCS5_PBKDF2_HMAC_SHA1("password", 8,
                               (unsigned char*)"salt", 4,
                               4096, sizeof key, key) == 1);
  CHECK(clEqual(key, sizeof key, kExpected, sizeof kExpected) == 0);
}

int main(int argc, char* argv[]) {
  testHMAC();
  testRSA();
  testDH();
  testPRNG();
  testPBKDF2();
  return 0;
}
