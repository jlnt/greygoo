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
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "report.h"
#include "gg-utils.h"
#include "tools/gg-tests.h"

static void ggp_init_nullptr(void) {
  GG_ptr ptr;
  ptr = ggp_init((void *) NULL, 11);
}

static int ggp_equal_tests(void) {
  char a_buf[] = "AAAAAAAAAA";
  char b_buf[] = "AAAAAAAAAB";
  char c_buf[] = "CAAAAAAAAA";
  GG_ptr a, b, c;
  int test_ok = 1;

  a = ggp_init(a_buf, 10);
  b = ggp_init(b_buf, 10);
  c = ggp_init(c_buf, 10);
  test_ok &= (ggp_equal(&a, &b, 10) != 0);
  test_ok &= (ggp_equal(&a, &b, 9) == 0);
  test_ok &= (ggp_equal(&a, &c, 1) != 0);
  test_ok &= (ggp_equal(&a, &c, 0) == 0);
  return !test_ok;
}

/* pointer below range */
static void ggp_check_1(void) {
  char buf[] = "0123456789";
  GG_ptr a;

  a = ggp_init(buf, 10);
  a.ptr -= 1;
  assert_ggp_size(&a, 1);
}

/* pointer above range */
static void ggp_check_2(void) {
  char buf[] = "0123456789";
  GG_ptr a;

  a = ggp_init(buf, 10);
  a.ptr += 10;
  assert_ggp_size(&a, 1);
}

/* size is too big */
static void ggp_check_3(void) {
  char buf[] = "0123456789";
  GG_ptr a;

  a = ggp_init(buf, 10);
  a.ptr += 5;
  assert_ggp_size(&a, 6);
}

/* size is just ok, should not FATAL() */
static int ggp_check_4(void) {
  char buf[] = "0123456789";
  GG_ptr a;

  a = ggp_init(buf, 10);
  a.ptr += 5;
  assert_ggp_size(&a, 5);
  return 0;
}

/* pointer overflow */
static void ggp_check_5(void) {
  char buf[] = "0123456789";
  GG_ptr a;

  a = ggp_init(buf, 10);
  a.ptr += 5;
  assert_ggp_size(&a, SIZE_MAX);
}

static int ggp_check_tests(void) {
  return expect_fatal(ggp_check_1) || expect_fatal(ggp_check_2) ||
         expect_fatal(ggp_check_3) || ggp_check_4() ||
         expect_fatal(ggp_check_5);
}

/* should be ok to use encode_uint32 at the edge of the
   buffer */
static int encode_uint32_1(void) {
  char buf[sizeof(uint32_t)];
  /* intermediate pointer is needed to bypass gcc's strict aliasing check */
  void *ptr = buf;
  GG_ptr a;
  a = ggp_init(buf, sizeof(buf));
  encode_uint32(&a, 0xABCDEF);
  if (htonl(*((uint32_t* ) ptr)) == 0xABCDEF)
    return 0;
  else
    return -1;
}

/* encode in too small a buffer, should FATAL() */
static void encode_uint32_2(void) {
  char buf[sizeof(uint32_t) + 10];
  GG_ptr a;
  a = ggp_init(buf, sizeof(buf));
  a.ptr += 11;
  encode_uint32(&a, 0xABCDEF);
}

static int encode_uint32_tests(void) {
  return encode_uint32_1() || expect_fatal(encode_uint32_2);
}

static int code_string_tests(void) {
  char string1[] = "1";
  char string2[] = "striiing2";
  char string3[] = "string3";
  char buf1[sizeof(string1) + sizeof(string2) + sizeof(string3)];
  char buf2[sizeof(buf1)];
  GG_ptr ptr;

  bzero(buf2, sizeof(buf2));
  memcpy(buf1, string1, sizeof(string1));
  memcpy(buf1 + sizeof(string1), string2, sizeof(string2));
  memcpy(buf1 + sizeof(string1) + sizeof(string2), string3, sizeof(string3));

  ptr = ggp_init(buf2, sizeof(buf2));
  if (encode_string(&ptr, string1, sizeof(string1)) != sizeof(string1) ||
      encode_string(&ptr, string2, sizeof(string2) - 1) != -1 ||
      encode_string(&ptr, string2, sizeof(string2)) != sizeof(string2) ||
      encode_string(&ptr, string2, sizeof(string3)) != -1 ||
      encode_string(&ptr, string3, sizeof(string3)) != sizeof(string3) ||
      encode_string(&ptr, string1, 0) != -1)
    return -1;
  /* re-init the buffer and parse the string */
  ptr = ggp_init(buf2, sizeof(buf2));
  if (parse_string(&ptr, sizeof(buf1)) != sizeof(string1) ||
      parse_string(&ptr, sizeof(string2) - 1) != -1 ||
      parse_string(&ptr, sizeof(string2)) != sizeof(string2) ||
      parse_string(&ptr, sizeof(string3)) != sizeof(string3))
    return -1;

  return (memcmp(buf1, buf2, sizeof(buf2)));
}

/* This should FATAL because the value is out of range */
static void oom_score_adj_conversion_1(void) {
  (void) oom_adj_to_oom_score_adj(16);
}

/* This should FATAL because the value is out of range */
static void oom_score_adj_conversion_2(void) {
  (void) oom_adj_to_oom_score_adj(-18);
}

static int oom_score_adj_conversion_value_tests(void) {
  /* test maximum and minimum range values */
  return oom_adj_to_oom_score_adj(15) != 1000 ||
         oom_adj_to_oom_score_adj(-17) != -1000;
}

static int oom_score_adj_conversion_tests(void) {
  return expect_fatal(oom_score_adj_conversion_1) ||
         expect_fatal(oom_score_adj_conversion_2) ||
         oom_score_adj_conversion_value_tests();
}

DEFINE_TEST(utils_testall) {
  return expect_fatal(ggp_init_nullptr) ||
         ggp_equal_tests() ||
         ggp_check_tests() ||
         encode_uint32_tests() ||
         code_string_tests() ||
         oom_score_adj_conversion_tests();
}
