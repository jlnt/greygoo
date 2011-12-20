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
#ifndef GG_UTILS_H
#define GG_UTILS_H
#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

void *xmalloc(size_t size);
void xfree(void *ptr);

/*
 * should be initialized with gg_buf_init
 * ptr should be used as a regular pointer, the rest should be opaque to the
 * user.
 */
typedef struct {
  void *_start;
  void *ptr;
  size_t _size;
} GG_ptr;

/*
 * A GG_ptr is a safer pointer representation for buffers with implicit valid
 * range representation.
 *
 * Use a GG_ptr like you would use a pointer, and a GG_ptr* like a pointer on
 * a pointer.
 *
 * A GG_ptr should be initialized by gg_buf_init or can be assigned
 * from an existing GG_ptr.
 */
GG_ptr ggp_init(char *buf, size_t size);
/* Consider this a pointer copy */
GG_ptr ggp_clone(const GG_ptr *ggp);

/* exit with FATAL() if ggp cannot hold size */
void assert_ggp_size(const GG_ptr *ggp, size_t size);

/* Like read(2), but ggpp is the destination */
ssize_t ggp_read(int socket, const GG_ptr *ggpp, size_t size);
/* call ggp_read successively until size has been read
 * return values are similar to read
 */
ssize_t ggp_full_read(int socket, const GG_ptr *ggp, size_t size);
/* see ggp_read* counterparts */
ssize_t ggp_write(int socket, const GG_ptr *ggpp, size_t size);
ssize_t ggp_full_write(int socket, const GG_ptr *ggp, size_t size);

/* Fixed timing comparison between the first n bytes of s1 and s2
 * Returns 0 if equal, something else otherwise
 */
int ggp_equal(const GG_ptr *s1, const GG_ptr *s2, size_t n);
/* Like memcmp() but with a GG_ptr */
int ggp_memcmp(const GG_ptr *ggpp, const void *s2, size_t n);
/* Like memcpy() but with a GG_ptr */
void *ggp_memcpy(const GG_ptr *dest, const void *src, size_t n);
/* Like bzero() but with a GG_ptr */
void gg_bzero(const GG_ptr *s, size_t n);

/* Get uintXXt from ggpp in network order */
uint32_t ggp_get_uint32(const GG_ptr *ggpp);
uint16_t ggp_get_uint16(const GG_ptr *ggpp);
/* Write uintXXt at ggpp in network order */
void ggp_put_uint32(const GG_ptr *ggpp, uint32_t num);
void ggp_put_uint16(const GG_ptr *ggpp, uint16_t num);

/* read an unsigned XX bits integer in network order and make ggpp point
 * past that */
uint32_t parse_uint32(GG_ptr *ggpp);
uint16_t parse_uint16(GG_ptr *ggpp);
/* return the size of the string (including the NUL character) or -1 on error
 * we consider anything with a NUL byte of len >= 1 a string
 *
 * we update the pointer to point after the string which may make it invalid
 * i.e. using it would trigger FATAL()
 */
ssize_t parse_string(GG_ptr *ggpp, size_t maxlen);

/* copy a NUL terminated string of maximum length maxlen to ggpp
 * return -1 on error or the size of the string (accounting for NUL)
 *
 * we update the pointer to point after the string which may make it invalid
 * i.e. using it would trigger FATAL()
 */
ssize_t encode_string(GG_ptr *ggpp, char *string, size_t maxlen);
/* write an unsigned XX bits integer in network order and make ggpp point past
 * that (possibly rendiring it invalid)
 */
ssize_t encode_uint32(GG_ptr *ggpp, uint32_t num);
ssize_t encode_uint16(GG_ptr *ggpp, uint16_t num);

/* Adjust the (inheritable) OOM score.
 * The score must be the ascii base 10 representation of an integer between
 * -17 and 16.
 *
 * Return -1 on error, 0 on success
 */
int adjust_oom_score(const char *oom_score);

/* This function does 3 things:
 * 1. Commit all the pages in the virtual address space to memory
 * 2. Give the process complete immunity to the OOM killer
 * 3. Give the current process group priority prio
 *
 * Note that (2) and (3) are inherited, and the caller may want to
 * reduce the priority of its child after a fork() or remove the OOM
 * killer immunity (see adjust_oom_score above).
 *
 * Return 0 on success, -1 if something failed
 */
int become_bullet_proof(int prio);

/* Get a "protected" address space
 *  - No core dumps
 *  - mlock all memory to prevent swapping
 *
 * Returns -1 on error 0 on success
 */
int protect_address_space(void);

/* like ppoll(2) */
int old_libc_compatible_ppoll(struct pollfd *fds, nfds_t nfds,
                    const struct timespec *timeout, const sigset_t *sigmask);
#ifdef GG_TESTS
void ggp_seek(GG_ptr *ggp, size_t offset);
#endif

#endif                          /* GG_UTILS_H */
