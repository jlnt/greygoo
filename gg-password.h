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
#include <unistd.h>
#ifndef GG_PASSWORD_H
#define GG_PASSWORD_H

/* OpenSSL compliant password callback function
 *
 * Return the number of bytes on succes, 0 on error
 *
 * rwflag and u are ignored
 */
int gg_pass_cb(char *buf, int size, int rwflag, void *u);

/* Read password from stdin
 *
 * PBKDF2 hash it and return the hex encoded result in buf
 *
 * Return 0 on succes, -1 otherwise
 */
int gg_getkey(char *buf, int size);

/* Perform internal tests
 *
 * Returns 0 on success, -1 on failure
 */
int password_testall(void);

#ifdef GG_TESTS
int password_to_key(char *pass, size_t pass_len,
                    unsigned char *key, size_t max_keylen);
#endif                          /* GG_TESTS */
#endif                          /* GG_PASSWORD_H */
