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
 * Read a password from standard input and slowly derive a hex encoded
 * passkey.
 */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>
#include <unistd.h>

/* Number of hash iterations */
#define GG_HASH_ITERS (1<<17)

static int a_to_b16(const unsigned char *in, uint32_t inlen,
                    unsigned char *out, uint32_t outlen);
int password_to_key(char *pass, size_t pass_len,
                    unsigned char *key, size_t max_keylen);
static ssize_t read_passkey(unsigned char *key, size_t max_keylen);

/* OpenSSL compliant password callback function
 *
 * Return number of bytes on success, 0 on error
 */
int gg_pass_cb(char *buf, int size, int rwflag, void *u) {
  int ret;

  ret = read_passkey((unsigned char*)buf, size);
  if (ret <= 0) return 0;

  ret = password_to_key(buf, ret, (unsigned char*)buf, size);

  if (ret) return 0;

  return strlen(buf);
}

/* Read password from stdin
 *
 * PBKDF2 hash it and return the hex encoded result in buf
 *
 * Return 0 on succes, -1 otherwise
 */
int gg_getkey(char *buf, int size) {
  int ret;

  ret = gg_pass_cb(buf, size, 0, NULL);

  if (!ret)
    return -1;
  else
    return 0;
}

/* Will return a HEX (NUL terminated) encoded PKCS5#2.0 derived key
 * using SHA-1 as a hash function with GG_HASH_ITERS iterations
 *
 * key must accomodate HEX NUL terminated SHA-1, so be at least 41 bytes long
 *
 * It's ok to provide the same buffer for pass and key (input and output)
 *
 * Return 0 on succes, -1 on failure
 */
int password_to_key(char *pass, size_t pass_len,
                    unsigned char *key, size_t max_keylen) {
  const size_t md_size = SHA_DIGEST_LENGTH;
  unsigned char hash[md_size];
  int ret;
  /* dd if=/dev/random bs=20 count=1 | uuencode -m -
     http://xkcd.com/221/ */
  static const unsigned char salt[] = "eP9VfEvqP7vMC3T3rXC6zOvzVOA=";

  /* Size check for NUL terminated */
  if (max_keylen < md_size*2 + 1)
    return -1;

  /* FIXME: use something better than PBKDF2 */

  PKCS5_PBKDF2_HMAC_SHA1(pass, pass_len, salt, sizeof(salt), GG_HASH_ITERS,
                         md_size, hash);

  ret = a_to_b16(hash, md_size, key, max_keylen);

  /* make a best effort to not keep the password on the stack even though
   * we have no guarantee from PKCS5_PBKDF2_HMAC
   */
  bzero(hash, sizeof(hash));

  return ret;
}

/* Read a password without local echo.
 * The password will be NUL terminated.
 *
 * Returns: the password size (without NUL) on success
 *          -1 on failure
 */
static ssize_t read_passkey(unsigned char *key, size_t max_keylen) {
  struct termios orig, noecho;
  ssize_t ret = -1;
  FILE *ftty = NULL;
  int tty;

  ftty = fopen("/dev/tty", "r+");
  /* We probably don't have a tty */
  if (!ftty) goto out;
  tty = fileno(ftty);

  if (tcgetattr(tty, &orig)) goto out;

  /* disable local echo and use canonical mode */
  noecho = orig;
  noecho.c_lflag &= ~ECHO;
  noecho.c_lflag |= ICANON;

  fprintf(ftty, "Grey Goo password: ");
  fflush(ftty);
  if (tcsetattr(tty, TCSAFLUSH, &noecho)) goto out;

  /* read until EOF, full or error */
  ret = read(tty, key, max_keylen);
  fprintf(ftty, "\n");

  if (ret > 0 && key[ret-1] == '\n')
    key[--ret] = '\0';
  else
    /* maybe the password was too long or something else is wrong */
    ret = -1;

  if (tcsetattr(tty, TCSAFLUSH, &orig))
    ret = -1;
out:
  if (ftty && fclose(ftty))
    ret = -1;
  if (ret == -1)
    bzero(key, max_keylen);
  return ret;
}

/* Base 16 encoding. Returns a NUL terminated string for convenience.
 */
static int a_to_b16(const unsigned char *in, uint32_t inlen,
                    unsigned char *out, uint32_t outlen) {
  static const char b16[]="0123456789ABCDEF";
  int i;

  if (inlen > UINT16_MAX || outlen < inlen*2 + 1)
    return -1;

  for (i = 0; i < inlen; ++i) {
    *out++ = b16[in[i]>>4];
    *out++ = b16[in[i]&0xF];
  }

  *out = '\0';
  return 0;
}

/* tests password_to_key.
 * This is a regression test, not a correctness test
 *
 * Returns -1 on error 0 on success */
int password_testall(void) {
  unsigned char  out[1024];
  char *test_vect[][2] = {
    {"test", "60A92A4C499497A6A50CC02F09A07054482B07F2"},
    {"longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong"
     "longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong"
     "longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong",
     "A0FECE50949C2B79CC3158A5A616EB2A11B42D92"},
    {"GreyGoo", "C935B7591066C8DA29EB9A1A81E6B724647FEEF4"},
  };
  int i;

  for (i = 0; i < sizeof(test_vect)/sizeof(test_vect[0]); ++i) {
    if (password_to_key(test_vect[i][0], strlen(test_vect[i][0]),
                        out, sizeof(out)) ||
        strcmp(test_vect[i][1], (char *) out)) {
      return -1;
    }
  }
  return 0;
}
