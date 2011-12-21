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
 * Reporting/logging helpers
 */
#include <stdio.h>
#include <stdarg.h>
#include "report.h"
#include "gg-syslog.h"

static int stderr_disabled = 0;

void disable_stderr(void) {
  stderr_disabled = 1;
}

static int syslog_disabled = 0;

void disable_syslog(void) {
  syslog_disabled = 1;
}

int report_init(void) {
  if (gg_loginit() < 0)
    return -1;
  else
    return 0;
}

 /*
  * Our generic report function. va_start and va_copy may allocate memory on
  * some systems.
  *
  * We support "%m" for errno.
  */
void report(const char *fmt, int type, ...) {
  va_list log_args;
  va_list print_args;
  int ret = 0;

  va_start(log_args, type);

  if (!stderr_disabled) {
    va_copy(print_args, log_args);
    ret = vfprintf(stderr, fmt, print_args);
  }

  if (!syslog_disabled)
    gg_vsyslog(LOG_DAEMON | LOG_ERR, fmt, log_args);

  if (!stderr_disabled)
    va_end(print_args);

  /* Disable stderr if vfprintf failed */
  if (ret < 0)
    stderr_disabled = 1;

  va_end(log_args);
}

static int debuglevel = 0;

void debug_setlevel(int level) {
  debuglevel = level;
}

#ifdef GG_DEBUG
void debug(int level, const char *fmt, const char *file, int line,
           const char *func, ...) {
  va_list print_args;

  if (!stderr_disabled && level <= debuglevel) {
    va_start(print_args, func);

    if ((fprintf(stderr, "%s:%d - %s(): ", file, line, func) < 0) ||
        (vfprintf(stderr, fmt, print_args) < 0)) {
      stderr_disabled = 1;
    }
    va_end(print_args);
  }
}
#endif                          /* GG_DEBUG */
