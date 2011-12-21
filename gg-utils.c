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
 */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include "report.h"
#include "gg-utils.h"

/* OpenSSH-style x* functions
 *
 * Call FATAL() if any allocation or free fails.
 */

void *xmalloc(size_t size) {
  void *pt;

  if (size == 0) {
    FATAL("xmalloc: size == 0");
  }

  pt = malloc(size);

  if (pt == NULL) {
    FATAL("xmalloc: failed to alloc");
  }

  return pt;
}

void xfree(void *ptr) {
  if (ptr == NULL)
    FATAL("xfree: ptr == NULL)");

  free(ptr);
}

GG_ptr ggp_init(char *buf, size_t size) {
  GG_ptr ret;
  if (!buf || size > SIZE_MAX || buf + size < buf)
    FATAL("ggp_init: potential memory corruption");
  ret._start = buf;
  ret._size = size;
  ret.ptr = buf;
  return ret;
}

/* check if a GG_ptr has obvious memory corruption issue.
 * Terminate with FATAL if so
 */
static void assert_ggp_valid(const GG_ptr *ggp) {
  /* 1. Obvious checks
   * 2. Overflow check for (3)
   * 3. Check that ptr is in the permitted range
   */
  if (!ggp || !ggp->ptr || !ggp->_start || ggp->_size > SIZE_MAX ||
      ggp->_start + ggp->_size < ggp->_start ||
      ggp->_start > ggp->ptr || ggp->_start + ggp->_size < ggp->ptr)
    FATAL("potential memory corruption");
}

/* Check if a GG_ptr can accomodate size in its current state
 *
 * Terminate with FATAL if not so
 */
void assert_ggp_size(const GG_ptr *ggp, size_t size) {
  assert_ggp_valid(ggp);
  if (size > SIZE_MAX || size > ggp->_size ||
      ggp->ptr + size < ggp->ptr ||
      ggp->_start > ggp->ptr + size ||
      ggp->_start + ggp->_size < ggp->ptr + size)
    FATAL("potential memory corruption");
}

/* consider this a pointer copy */
GG_ptr ggp_clone(const GG_ptr *ggp) {
  GG_ptr ret;

  assert_ggp_valid(ggp);
  ret._start = ggp->_start;
  ret._size = ggp->_size;
  ret.ptr = ggp->ptr;
  return ret;
}

/* add "offset" to a GG_ptr */
static void ggp_seek(GG_ptr *ggp, size_t offset) {
  /* we don't add a assert_ggp_size there. The caller should be free to seek
   * up to an invalid location, as long as the pointer is not
   * used. (For instance parse_string).
   */
  if (offset > SIZE_MAX)
    FATAL("ggp_seek: potential memory correction");
  ggp->ptr += offset;
}

/* use like read(), except ggp->ptr is the destination */
ssize_t ggp_read(int socket, const GG_ptr *ggp, size_t size) {
  ssize_t ret;

  assert_ggp_size(ggp, size);
  if (size > SSIZE_MAX) {
    FATAL("FATAL: ggp_read");
  }

  ret = read(socket, ggp->ptr, size);

  return ret;
}

/* use like read(), except ggp->ptr is the destination */
ssize_t ggp_write(int socket, const GG_ptr *ggp, size_t size) {
  ssize_t ret;

  assert_ggp_size(ggp, size);
  if (size > SSIZE_MAX) {
    FATAL("FATAL: ggp_write");
  }

  ret = write(socket, ggp->ptr, size);

  return ret;
}

ssize_t ggp_full_read(int socket, const GG_ptr *ggp, size_t size) {

  ssize_t nread = 0;
  ssize_t ret = 0;
  GG_ptr buf;
  buf = *ggp;

  while (nread < size) {
    ret = ggp_read(socket, &buf, size - nread);
    if (ret <= 0)
      return ret;
    nread += ret;
    buf.ptr += ret;
  }

  return nread;
}

ssize_t ggp_full_write(int socket, const GG_ptr *ggp, size_t size) {

  ssize_t nread = 0;
  ssize_t ret = 0;
  GG_ptr buf;
  buf = *ggp;

  while (nread < size) {
    ret = ggp_write(socket, &buf, size - nread);
    if (ret <= 0)
      return ret;
    nread += ret;
    buf.ptr += ret;
  }

  return nread;
}

/* fixed timing comparison return 0 if equal, something else otherwise */
int ggp_equal(const GG_ptr *s1, const GG_ptr *s2, size_t n) {
  int i, ret;
  char *v1;
  char *v2;
  assert_ggp_size(s1, n);
  assert_ggp_size(s2, n);

  v1 = (char *) s1->ptr;
  v2 = (char *) s2->ptr;

  for (i = 0, ret = 0; i < n; ++i) {
    ret |= v1[i] ^ v2[i];
  }

  return ret;
}

int ggp_memcmp(const GG_ptr *ggpp, const void *s2, size_t n) {
  assert_ggp_size(ggpp, n);
  return memcmp(ggpp->ptr, s2, n);
}

void *ggp_memcpy(const GG_ptr *dest, const void *src, size_t n) {
  assert_ggp_size(dest, n);
  return memcpy(dest->ptr, src, n);
}

void gg_bzero(const GG_ptr *s, size_t n) {
  assert_ggp_size(s, n);
  bzero(s->ptr, n);
}

uint32_t ggp_get_uint32(const GG_ptr *ggpp) {
  assert_ggp_size(ggpp, sizeof(uint32_t));
  return ntohl(*((uint32_t *) ggpp->ptr));
}

uint16_t ggp_get_uint16(const GG_ptr *ggpp) {
  assert_ggp_size(ggpp, sizeof(uint16_t));
  return ntohs(*((uint16_t *) ggpp->ptr));
}

void ggp_put_uint32(const GG_ptr *ggpp, uint32_t num) {
  assert_ggp_size(ggpp, sizeof(uint32_t));
  *((uint32_t *) ggpp->ptr) = htonl(num);
}

void ggp_put_uint16(const GG_ptr *ggpp, uint16_t num) {
  assert_ggp_size(ggpp, sizeof(uint16_t));
  *((uint16_t *) ggpp->ptr) = htons(num);
}

/* helpers for parsing / encoding stuff */

/* read a 32 bits integer in network order
 * and increase the pointer
 */
uint32_t parse_uint32(GG_ptr *ggpp) {
  uint32_t ret;
  ret = ggp_get_uint32(ggpp);
  ggp_seek(ggpp, sizeof(uint32_t));
  return ret;
}

uint16_t parse_uint16(GG_ptr *ggpp) {
  uint16_t ret;
  ret = ggp_get_uint16(ggpp);
  ggp_seek(ggpp, sizeof(uint16_t));
  return ret;
}

ssize_t parse_string(GG_ptr *ggpp, size_t maxlen) {
  size_t ret;
  char *cp = ggpp->ptr;
  if (maxlen < 1 || maxlen > SSIZE_MAX)
    return -1;
  assert_ggp_size(ggpp, maxlen);

  for (ret = 0; ret < maxlen; cp++, ret++)
    if (*cp == 0) {
      ggp_seek(ggpp, ret + 1);
      return (ret + 1);
    }

  return -1;
}

/* maxlen: max size of the buffer */
ssize_t encode_string(GG_ptr *ggpp, char *string, size_t maxlen) {
  size_t len;
  /* we need to account for the NUL byte */
  if (maxlen <= 1 || (len = strlen(string)) > maxlen - 1)
    return -1;
  assert_ggp_size(ggpp, maxlen);

  /* account for the NUL byte */
  len++;

  ggp_memcpy(ggpp, string, len);
  ggp_seek(ggpp, len);

  return len;
}

ssize_t encode_uint32(GG_ptr *ggpp, uint32_t num) {
  ggp_put_uint32(ggpp, num);
  ggp_seek(ggpp, sizeof(uint32_t));
  return sizeof(uint32_t);
}

ssize_t encode_uint16(GG_ptr *ggpp, uint16_t num) {
  ggp_put_uint16(ggpp, num);
  ggp_seek(ggpp, sizeof(uint16_t));
  return sizeof(uint16_t);
}

int adjust_oom_score(const char *oom_score) {
  FILE *oom_adj = NULL;
  size_t n;
  int ret = -1;

  if (!oom_score)
    goto out;

  oom_adj = fopen("/proc/self/oom_adj", "a+");
  if (!oom_adj)
    goto out;

  n = fwrite(oom_score, strlen(oom_score), 1, oom_adj);
  if (n != 1)
    goto out;

  /* all good */
  ret = 0;
out:
  if (oom_adj && fclose(oom_adj))
    ret = -1;
  return ret;
}

int become_bullet_proof(int prio) {
  int ret = 0;

  /* commit all the pages we might need to memory. We don't use MCL_FUTURE
   * since that could cause things to fail. Also this is not inherited on
   * fork(), which is what we want.
   * Most pages of the virtual address space should be shared anyway, so
   * workers will have their code commited to memory.
   */
  if (mlockall(MCL_CURRENT)) {
    DEBUG(1, "Could not lock all memory(): %m\n");
    ret = -1;
  }

  /* -17 gives complete immunity. Inherited on fork(). */
  if (adjust_oom_score("-17")) {
    DEBUG(1, "Could not get OOM immunity\n");
    ret = -1;
  }

  /* Set priority for the current process group. Inherited on fork() */
  if (setpriority(PRIO_PGRP, 0, prio)) {
    DEBUG(1, "Could not set priority: %d\n", prio);
    ret = -1;
  }

  return ret;
}

int protect_address_space(void) {
  int ret = 0;
  const struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

  /* Get unlimited locked memory space if we can */
  if (setrlimit(RLIMIT_MEMLOCK, &rl)) ret = -1;

  /* no core dumps */
  if (prctl(PR_SET_DUMPABLE, 0, -1, -1, -1)) ret = -1;

  /* No swap */
  if (mlockall(MCL_CURRENT | MCL_FUTURE)) ret = -1;

  return ret;
}

/* FIXME: fixup for OLD libc that don't support ppoll */
/* we know the system call number for Linux i386 */
#if (!SYS_ppoll && __WORDSIZE == 32 && i386 && linux)
#define SYS_ppoll 309
#endif

/*
 * ppoll is only supported since glibc 2.4 (~2006)
 * The system call is present since Linux 2.6.16
 * We accomodate old libcs
 */
int old_libc_compatible_ppoll(struct pollfd *fds, nfds_t nfds,
                    const struct timespec *timeout, const sigset_t *sigmask) {
  struct timespec ts;
  int ret;
  /* Point timeout to a modifiable copy (glibc guarantees timeout won't be
   * modified)
   */
  if (timeout) {
    ts = *timeout;
    timeout = &ts;
  }

  ret = syscall(SYS_ppoll, fds, nfds, timeout, sigmask, _NSIG / 8);
  if ((ret == -1) && (errno == ENOSYS))
    FATAL("This system does not support ppoll\n");
  return ret;
}
