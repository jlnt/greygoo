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
 * Start a server session
 */
#include <string.h>
#include "gg-protocol.h"
#include "report.h"

/* Start a session as the server
 *
 * Negociate a Diffie-Hellman session and authenticate the client
 *
 * Returns:
 *  0: success
 * -1: error
 */
int do_start_session_server(GG_cnx *cnx, GG_packet *pkt) {
  ssize_t ret;
  size_t payload_len;

  /* we use a well-known, shared HMAC key at first */
  crypto_set_hmac_key(cnx->ggc, "This is not a secret", 20);

  /* initialize RSA signature verification */
  crypto_verify_init(cnx->ggc);

  /* get the first packet: remote DH public key */
  if (get_remote_dh_key(cnx, pkt))
    return -1;

  /* RSA signature verification (1): include first packet's HMAC */
  if (crypto_verify_update(cnx->ggc, &pkt->hmac, GG_PKT_HMAC_LEN)) {
    DEBUG(2, "Sign update failed\n");
    return -1;
  }

  /* send the second packet: our DH public key */
  if ((ret = send_our_dh_key(cnx, pkt)))
    return -1;

  /* RSA signature verification (2): include second packet's HMAC */
  if (crypto_verify_update(cnx->ggc, &pkt->hmac, GG_PKT_HMAC_LEN)) {
    DEBUG(2, "crypto error\n");
    return -1;
  }

  /* Compute the shared key for the session */
  if (do_handshake_crypto(cnx)) {
    DEBUG(2, "Could not compute shared key\n");
    return -1;
  }

  /* Get the third packet: RSA signature */
  ret = gg_packet_get_full(cnx, pkt);
  if (ret == 0) {
    DEBUG(2, "connection closed by peer\n");
    return -1;
  }
  if (ret < 0)
    return -1;

  /* RSA signature verification (3): now check the signature */
  if (crypto_verify_final(cnx->ggc, &pkt->payload, pkt->payload_size)) {
    DEBUG(2, "crypto_verify_final failed \n");
    return -1;
  } else {
    DEBUG(2, "RSA Signature successful 0x%X - PEER IS AUTHENTICATED!! \n",
          ((uint32_t *) (pkt->payload.ptr))[0]);
  }

  /* now we need to send our server_id out as a confirmation */
  if (cnx->our_id
      && ((payload_len = strlen(cnx->our_id)) <= GG_SERVER_ID_MAX_LEN - 1)
      && (payload_len < pkt->max_payload_size)) {

    /* include NUL in the size */
    payload_len++;

    ggp_memcpy(&pkt->payload, cnx->our_id, payload_len);

  } else {
    payload_len = 0;
  }

  if (gg_packet_set_payload(pkt, GG_PAYLOAD_PRESENT_ID, payload_len) ||
      (gg_packet_put_full(cnx, pkt) <= 0)) {
    DEBUG(0, "could not send our own ID out\n");
    return -1;
  }

  return 0;
}
