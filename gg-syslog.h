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
 * Grey Goo's own non-blocking replacement for syslog(3).
 *
 * This is mono-thread only.
 * If we can't send a message to syslog without blocking, it's discarded.
 * If the message is too long for the pre-allocated space, it's truncated.
 */
#ifndef GG_SYSLOG_H
#define GG_SYSLOG_H

#include <syslog.h>

/* open the socket to communicate with a syslog daemon. gg_vsyslog would open
 * this automatically, but since it doesn't return errors, a caller may want to
 * call gg_loginit() at initialization time and act on the return value.
 *
 * Return -1 on error, a fd on success
 */
int gg_loginit(void);

/* Like vsyslog(3) */
void gg_vsyslog(int priority, const char *format, va_list ap);

#endif /* GG_SYSLOG_H */
