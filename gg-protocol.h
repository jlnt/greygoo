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
 * Start a session as server or client
 */
#ifndef GG_PROTOCOL_H
#define GG_PROTOCOL_H
#include "gg-packet.h"

#define xstr(s) str(s)
#define str(s) #s

#define GG_PORT_STRING xstr(GG_PORT)

/* Everything returns 0 on success and -1 on error */

/* Start a session as the server:
 *
 * - Negociate Diffie-Hellman session
 * - Authenticate the client
 */
int do_start_session_server(GG_cnx *cnx, GG_packet *pkt);

/* Start a session as the client:
 *
 * - Negociate a Diffie-Hellman session
 * - Send a signature of the session identifier
 */
int do_start_session_client(GG_cnx *cnx, GG_packet *pkt);

/* Forward everything on input to the connection and everything from the
 * connection to output
 */
int do_fw_in_out(GG_cnx *cnx, int input, int output, sigset_t *sigmsk,
                 int (*signal_cb)(int), int cb_arg);

/*
 * Get the next packet and expect it to contain the remote g^y DH offer
 * Save it in our connection context
 */
int get_remote_dh_key(GG_cnx *cnx, GG_packet *pkt);

/*
 * Send our DH g^x offer in a new packet over the connection
 */
int send_our_dh_key(GG_cnx *cnx, GG_packet *pkt);

/* Compute the shared session key g^xy and set it as the internal HMAC key
 * used for the connection
 */
int do_handshake_crypto(GG_cnx *cnx, GG_packet *pkt);


#endif                          /* GG_PROTOCOL_H */
