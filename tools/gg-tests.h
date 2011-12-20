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
#ifndef GG_TESTS_H
#define GG_TESTS_H
#ifdef GG_TESTS

/* 'DEFINE_TEST(test_function) { code }' will automatically register a test */
#define DEFINE_TEST(test)                                                \
static int test (void);                                                  \
__attribute__ ((constructor)) static void test ## _auto_register(void) { \
  register_test(test, __FILE__ "(" #test ")");                           \
}                                                                        \
                                                                         \
static int test (void)                                                   \

/* add a new test to a global linked list of tests
 * test() should return 0 on success and -1 on failure
 */
void register_test(int (*test)(void), char *name);

/* Launches a test in a new process.
 *
 * Returns:
 * - 0 if the test resulted in the process exiting with EXIT_FAILURE
 * - -1 if the test returned or there was a problem running the test
 */
int expect_fatal(void (*test)());
#endif /* GG_TESTS */
#endif /* GG_TESTS_H */
