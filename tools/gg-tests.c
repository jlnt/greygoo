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
 * Various tests that will be done after compiling
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "report.h"
#include "gg-password.h"

static struct gg_test {
  int (*run)(void);
  char *name;
  struct gg_test *next;
} *test_list = NULL;

/* register a new test by adding it to the head of the test_list */
void register_test(int (*test)(void), char *name) {
  struct gg_test *newtest;
  newtest = malloc(sizeof(struct gg_test));
  if (!newtest) {
    fprintf(stderr, "Could not initialize testing framework\n");
    exit(EXIT_FAILURE);
  }
  newtest->run = test;
  newtest->name = name;
  newtest->next = test_list;
  test_list = newtest;
}

static void destroy_test_list(void) {
  struct gg_test *elem;
  while (test_list != NULL) {
    elem = test_list;
    test_list = test_list->next;
    free(elem);
  }
  test_list = NULL;
}

/* fork() and launch the test in a new process, expecting FATAL() */
int expect_fatal(void (*test)()) {
  pid_t p;
  int status, ret;
  if (!test)
    return -1;

  switch (p = fork()) {
    case -1:
      REPORT_ERRNO("Fork failed");
      return -1;
    case 0:
      /* Disable stderr and syslog */
      disable_stderr();
      disable_syslog();
      /* child, run the test */
      test();
      /* get killed by a signal if test() returns */
      abort();
    default:
      /* parent, wait for the child. Return if child stopped (and we would
       * return -2) */
      if ((waitpid(p, &status, WUNTRACED) == p) && WIFEXITED(status)) {
        ret = WEXITSTATUS(status);
        if (ret == EXIT_FAILURE)
          return 0;
      }
      return -1;
  }
}

int main(int argc __attribute__((unused)),
         char *argv[] __attribute__((unused))) {
  struct gg_test *test = test_list;
  int is_failure = 0;
  printf("Starting Grey Goo unit tests:\n");
  if (!test_list) {
    fprintf(stderr, "No test registered\n");
    return 0;
  }
  while (test && test->run != NULL && test->name != NULL) {
    if (test->run()) {
      printf("  %s: FAILED\n", test->name);
      is_failure = 1;
    } else {
      printf("  %s: OK\n", test->name);
    }
    test = test->next;
  }

  destroy_test_list();

  if (is_failure) {
    printf("Tests failed\n");
    return -1;
  } else {
    printf("All tests ok\n");
    return 0;
  }
}
