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
#ifndef GG_SERVER_H
#define GG_SERVER_H
#include <sys/socket.h>
#include <netinet/in.h>
#include "gg-packet.h"

/* Handle a connection that has been accept-ed and initialized */
int do_handle_connection(GG_cnx *cnx);

/*
 * Setup our signal mask and actions for a ppoll() or pselect() loop.
 *
 * Block the signals we want to watch and return a signal set with them
 * unblocked in "oldmask", readily usable in ppoll or pselect.
 *
 * For now we only care about SIGCHLD:
 *
 * 1. Block SIGCHLD in the calling thread
 * 2. Return the current signal mask, but with SIGCHLD unblocked, in oldmask
 * 3. Set the signal handler for SIGCHLD to a handler that sets the reap_child
 *    global variable when a signal is caught.
 *
 * return -1 on error, 0 on success
 */
int setup_sigchld_watcher(sigset_t *oldmask);

/* global variable set by the SIGCHLD signal handlder when SIGCHLD is caught */
extern int reap_child;

#endif                          /* GG_SERVER_H */
