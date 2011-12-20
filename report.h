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
#ifndef GG_REPORT_H
#define GG_REPORT_H
#include <stdlib.h>

/* Initialize reporting / logging. Not mandatory, but the only way
 * to make sure that we have a proper socket.
 *
 * Returns 0 on success, -1 on failure.
 */
int report_init(void);

/* Send a message to syslog (LOG_DAEMON) and to stderr at the same time */
void report(const char *fmt, int type, ...)
    __attribute__ ((format(printf, 1, 3)));

#ifdef GG_DEBUG
/* Print message to stderr */
void debug(int level, const char *fmt, const char *file, int line,
           const char *func, ...) __attribute__ ((format(printf, 2, 6)));
#endif

/* set the debug level of the process. If debug() is u sed with a lesser level
 * the message will be ignored */
void debug_setlevel(int level);

/* disable reporting errors to stderr or syslog */
void disable_stderr(void);
void disable_syslog(void);

#define REPORT_INFO(format, ...) report(format, 0, ## __VA_ARGS__)

#define REPORT_ERROR(message) report("%s:%d:%s %s\n", 0,\
                                     __FILE__, __LINE__, __func__, message)
#define REPORT_ERRNO(message) report("%s:%d:%s %s : %m\n", 0, __FILE__,\
                                     __LINE__, __func__, message)

#ifdef GG_DEBUG
#define DEBUG(level, format, ...) debug(level, format, __FILE__, __LINE__,\
                                        __func__, ## __VA_ARGS__)
#else
#define DEBUG(...) ({ })
#endif

#define FATAL(message) ({                                           \
    report("%s:%d %s\n", 0, __FILE__, __LINE__, message);           \
    exit(EXIT_FAILURE);                                             \
})

#define FATAL_ERRNO(message) ({                                     \
    report("%s:%d %s : %m\n", 0, __FILE__, __LINE__, message);      \
    exit(EXIT_FAILURE);                                             \
})

#endif                          /* GG_REPORT_H */
