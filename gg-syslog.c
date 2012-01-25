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
 * If we can't send a message to syslog without blocking, it's discarded.
 * If the message is too long for the pre-allocated space, it's truncated.
 *
 * RFC5424 seems pretty much ignored. Well formated time actually seems to
 * trigger a bug in syslog-ng.
 * RFC3164 (the old BSD version) is a bit better.
 *
 * We generate: '<PRI>TAG: CONTENT'. No timestamp or hostname.
 * RFC3164, section 4.3.2 says that a syslog daemon MUST cope with this and
 * add the timestamp and hostname for us.
 */
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include "gg-syslog.h"
#include "report.h"

#define MAX_PROC_NAME 16
/* This should not be longer than MAX_PROC_NAME */
#define DEFAULT_PROC_NAME "greygoo"
static char proc_name[MAX_PROC_NAME+1] = DEFAULT_PROC_NAME;

/* Get a DGRAM socket to send messages to the syslog daemon
 * Make it non blocking and automatically closed on execve()
 * Also initialize the global variable proc_name;
 *
 * Returns -1 on error and the socket fd on success.
 *
 * We cache the existing open fd. If sucessful, the initialization process will
 * only run once.
 */
int gg_loginit(void) {
  static int logfd = -1;
  int ret;

  if (logfd >= 0)
    return logfd;

  /* Note: we specify SOCK_NONBLOCK | SOCK_CLOEXEC but it's a relatively new
   * feature in Linux, so we will use fcntl() instead
   */
  logfd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (logfd < 0)
    return -1;

  /* Close the socket automatically on execve() and make it non blocking */
  if (fcntl(logfd, F_SETFD, FD_CLOEXEC) || fcntl(logfd, F_SETFL, O_NONBLOCK)) {
    close(logfd);
    logfd = -1;
    return -1;
  }
  ret = prctl(PR_GET_NAME, proc_name, 0, 0, 0);
  proc_name[MAX_PROC_NAME] = '\0';
  if (ret) {
    strncpy(proc_name, DEFAULT_PROC_NAME, MAX_PROC_NAME);
  }

  return logfd;
}

static void sendlog(int logfd, char *message, size_t len) {
  struct sockaddr_un log_sa;
  ssize_t sent;

  log_sa = (struct sockaddr_un) {
    .sun_family = AF_UNIX,
    .sun_path = "/dev/log",
  };

  /* FIXME: should we do some sanitization before sending attacker-controlled
   * strings to syslogd ? */
  /* Note: MSG_NOSIGNAL is not necessary for a SOCK_DGRAM socket
   */
  sent = sendto(logfd, message, len, MSG_NOSIGNAL,
                (const struct sockaddr *) &log_sa, sizeof(log_sa));

  if (sent < 0) {
    /* This could be EWOULDBLOCK */
    DEBUG(1, "Could not send message of size %zi to logger: %m\n", len);
    return;
  }

  /* If we got truncated, we don't do anything about it */
  if ((size_t) sent != len)
    DEBUG(1, "Message of length %zi was truncated to %zi\n", len, sent);
}

/* Simple, non blocking replacement for vsyslog(3) */
void gg_vsyslog(int priority, const char *format, va_list ap) {
  static char buffer[4096];
  int len1, len2, totalsize, logfd;

  logfd = gg_loginit();

  if (logfd < 0) {
    return;
  }

  /* See the top of file for an explanation of this simplified format */
  len1 = snprintf(buffer, sizeof(buffer), "<%u>%s: ", priority, proc_name);
  if (len1 < 0 || (size_t) len1 >= sizeof(buffer))
    return;

  len2 = vsnprintf(buffer + len1, sizeof(buffer) - len1, format, ap);
  /* We only consider real errors, we continue silently if the output was
   * truncated */
  if (len2 < 0)
    return;

  totalsize = len1 + len2;
  /* The previous addition might overflow */
  if (totalsize < 0 || (unsigned int) totalsize > sizeof(buffer))
    totalsize = sizeof(buffer);

  sendlog( logfd, buffer, totalsize);
}
