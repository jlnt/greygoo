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
 * Start a client session
 */
#include "gg-protocol.h"
#include "report.h"

int do_start_session_client(GG_cnx *cnx, GG_packet *pkt) {
  size_t sig_size, id_size;
  GG_ptr payload = ggp_clone(&pkt->payload);
  int ret;

  /* we use a well-known, shared HMAC key at first */
  crypto_set_hmac_key(cnx->ggc, "This is not a secret", 20);

  /* initialize RSA signature */
  crypto_sign_init(cnx->ggc);

  /* send the first packet: our DH public key */
  if (send_our_dh_key(cnx, pkt))
    return -1;

  /* RSA signature (1): include first packet's HMAC */
  if (crypto_sign_update(cnx->ggc, &pkt->hmac, GG_PKT_HMAC_LEN)) {
    DEBUG(2, "Sign update error\n");
    return -1;
  }

  /* get the second packet: remote DH public key */
  if (get_remote_dh_key(cnx, pkt))
    return -1;

  /* RSA signature (2): include second packet's HMAC */
  if (crypto_sign_update(cnx->ggc, &pkt->hmac, GG_PKT_HMAC_LEN)) {
    DEBUG(2, "Sign update error\n");
    return -1;
  }

  /* Compute the shared key for the session */
  if (do_handshake_crypto(cnx, pkt))
    return -1;

  sig_size = pkt->max_payload_size;
  /* RSA signature (3): calculate the signature */
  ret = crypto_sign_final(cnx->ggc, &pkt->payload, &sig_size);
  if (ret) {
    DEBUG(2, "crypto sign final failed\n");
    return -1;
  }

  ret = gg_packet_set_payload(pkt, GG_RSA_SIGNATURE_SESSION, sig_size);
  if (ret)
    return -1;

  /* Send the third packet with the RSA signature */
  ret = gg_packet_put_full(cnx, pkt);
  if (ret <= 0) {
    return -1;
  }

  /* now get a confirmation that we are authenticated, and what name the server
   * pretends to have */

  ret = gg_packet_get_full(cnx, pkt);
  if (ret <= 0) {
    DEBUG(2, "could not get confirmation packet from server\n");
    return -1;
  }

  if (pkt->payload_type != GG_PAYLOAD_PRESENT_ID) {
    DEBUG(2, "Did not receive the server ID\n");
    return -1;
  }

  /* parse_string modifies the pointer */
  id_size = parse_string(&payload, pkt->payload_size);
  if (id_size > 0) {
    gg_cnx_set_strongid(cnx, pkt->payload.ptr, id_size);
  }

  DEBUG(2, "We are authenticated to the server (pretends to be %s)!\n",
        cnx->remote_strong_id);

  return 0;
}
