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
 * Generate RSA key pair and encrypt it with user supplied password
 */
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "gg-password.h"
#include "gg-utils.h"

#define SEED_NUMBYTES 32
static int generate_rsa(char *private_file, char *public_file,
                        pem_password_cb *cb) {
  RSA *rsa = NULL;
  FILE *priv = NULL;
  FILE *pub = NULL;
  const EVP_CIPHER *enc;
  int ret, num_read = 0;
  int return_value = 0;
  int dev_random = -1;
  char seed[SEED_NUMBYTES];

  /* First make sure we seed OpenSSL properly */
  dev_random = open("/dev/random", O_RDONLY);
  if (dev_random < 0) {
    return_value = -1;
    goto out;
  }

  printf("Getting random data, this may take a while\n");
  while (num_read < SEED_NUMBYTES) {
    ret = read(dev_random, seed + num_read, sizeof(seed) - num_read);
    /* /dev/random should never return EOF so we consider it an error */
    if (ret <= 0) {
      return_value = -1;
      goto out;
    } else {
      num_read += ret;
    }
  }

  /* Seed OpenSSL */
  RAND_add(seed, sizeof(seed), sizeof(seed));

  bzero(seed, sizeof(seed));

  enc = EVP_aes_128_cbc();

  if (!enc) {
    fprintf(stderr, "AES not available\n");
    return_value = -1;
    goto out;
  }

  priv = fopen(private_file, "w");
  if (!priv) {
    fprintf(stderr, "Could not open %s for writing\n", private_file);
    return_value = -1;
    goto out;
  }

  pub = fopen(public_file, "w");
  if (!pub) {
    fprintf(stderr, "Could not open %s for writing\n", public_file);
    return_value = -1;
    goto out;
  }

  rsa = RSA_generate_key(2048, 65537, NULL, NULL);

  if (!rsa) {
    fprintf(stderr, "Could not generate RSA key\n");
    return_value = -1;
    goto out;
  }

  /* This in unfortunately not a standard PKCS#8 EncryptedPrivateKeyInfo
   *
   * This is not available in current OpenSSL
   *
   * You can take a look at the key with.
   * openssl rsa -inform PEM -outform PEM -pubout -in <file>
   */
  if (!cb) {
    /* Do not encrypt the private key */
    ret = PEM_write_RSAPrivateKey(priv, rsa, NULL, NULL, 0, NULL, NULL);
  } else {
    ret = PEM_write_RSAPrivateKey(priv, rsa, enc, NULL, 0, cb, NULL);
  }

  if (!ret) {
    fprintf(stderr, "Error writing private key\n");
    return_value = -1;
    goto out;
  }

  ret = PEM_write_RSAPublicKey(pub, rsa);

  if (!ret) {
    fprintf(stderr, "Error writing public key\n");
    return_value = -1;
    goto out;
  }

out:

  if (dev_random != -1 && close(dev_random))
    return_value = -1;
  if (pub && fclose(pub))
    return_value = -1;
  if (priv && fclose(priv))
    return_value = -1;
  if(rsa)
    RSA_free(rsa);

  return return_value;
}

void usage(const char* a0) {
    fprintf(stderr, "Usage: %s private_key_file public_key_file\n", a0);
}

int main(int argc, char *argv[]) {
  char buf[1024];
  int ret;
  char ch;
  char nopassword = 0;

  /* Test key derivation implementation before use */
  if (password_testall()) {
    fprintf(stderr, "Internal tests failed\n");
    return -1;
  }

  /* No swap, no core dumps */
  if (protect_address_space()) {
    fprintf(stderr, "Could not protect the address space adequately. The keys "
            "could leak to swap. Check 'ulimit -l'. Continue? [Y/N]\n");
    *buf = 0;
    if ((read(STDIN_FILENO, buf, 1) != 1) || *buf != 'Y')
      return -1;
  }

  fprintf(stderr, "Warning: never run this from a virtual machine as the key "
          "may leak to persistent storage\n\n");

  while ((ch = getopt(argc, argv, ":nt")) != -1) {
    switch (ch) {
    case 'n':
      nopassword = 1;
      break;
    case 't':
      /* Undocumented option -t prints out the derived key for direct usage with
       * OpenSSL
       */
      ret = gg_getkey(buf, sizeof(buf));
      if (ret) return -1;
      fprintf(stdout, "%s\n", buf);
      return 0;
    default:
      usage(argv[0]);
      return -1;
    }
  }

  if (argc - optind != 2) {
    usage(argv[0]);
    return -1;
  }

  if (generate_rsa(argv[optind], argv[optind+1],
                   nopassword ? NULL : gg_pass_cb))
    return -1;

  printf("RSA keys generated successfuly\n");
  return 0;
}
