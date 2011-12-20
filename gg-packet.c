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
 * Grey Goo packet handling. See gg-packet.h for some documentation
 */
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "gg-packet.h"
#include "gg-crypto.h"
#include "report.h"

static int gg_packet_setsize(GG_packet *pkt, size_t size);

static int gg_packet_forge(GG_cnx *cnx, GG_packet *pkt);
static int gg_packet_encode(GG_packet *pkt, GG_crypt *ggc);
static int gg_packet_calc_hmac(GG_packet *pkt, GG_crypt *ggc, GG_ptr *hmac);

static int gg_packet_verify(GG_packet *pkt, GG_cnx *cnx);
static int gg_packet_decode_header(GG_packet *pkt);
static int gg_packet_verify_hmac(GG_packet *pkt, GG_crypt *ggc);

void gg_cnx_init(GG_cnx *cnx, int socket, char *our_id, char *remote_id,
                 GG_crypt *ggc, int isserver) {

  *cnx = (GG_cnx) {
    .socket = socket,
    .our_id = our_id,
    .remote_id = remote_id,
    .l_seq = 0,
    .r_seq = 0,
    .ggc = ggc,
    .state = 0,
    .isserver = isserver,
  };
}

/* set remote_strong_id to NULL or something meaningful */
void gg_cnx_set_strongid(GG_cnx *cnx, char *remote_id, size_t len) {
  GG_ptr ptr;

  if (!cnx || !remote_id || len > GG_SERVER_ID_MAX_LEN) {
    cnx->remote_strong_id = NULL;
    return;
  }

  ptr = ggp_init(cnx->strong_id_buffer, GG_SERVER_ID_MAX_LEN);

  ggp_memcpy(&ptr, remote_id, len);

  cnx->remote_strong_id = cnx->strong_id_buffer;

}

/*
 * Initialize a GG_packet structure 
 * to use a specified underlying buffer.
 *
 * It's possible to rebind a GG_packet structure to use a new buffer with this
 * function.
 *
 * This buffer should be at least GG_PKT_MAX_SIZE large
 *
 * Returns 0 on success, -1 on error
 */
int gg_packet_init(GG_packet *pkt, const GG_ptr *buffer, size_t buf_size) {

  if (buf_size < GG_PKT_MIN_SIZE)
    return -1;
  /* "truncate" our view of the buffer */
  if (buf_size > GG_PKT_MAX_SIZE)
    buf_size = GG_PKT_MAX_SIZE;

  pkt->full_packet = *buffer;

  pkt->buffer_size = buf_size;
  /* GG_PKT_HEADER_SIZE + GG_PKT_HMAC_LEN is guaranteed <= GG_PKT_MIN_SIZE */
  pkt->max_payload_size = buf_size - GG_PKT_HEADER_SIZE - GG_PKT_HMAC_LEN;

  /* reset transmitted and is_full_and_verified */
  gg_packet_reset(pkt);

  /* FIXME: create ggp_shrink(size) */

  pkt->hdr = ggp_init(pkt->full_packet.ptr, GG_PKT_HEADER_SIZE);

  pkt->hmac = ggp_init(pkt->hdr.ptr + GG_PKT_HEADER_SIZE, GG_PKT_HMAC_LEN);

  pkt->payload = ggp_init(pkt->hmac.ptr + GG_PKT_HMAC_LEN,
                          pkt->max_payload_size);

  if (gg_packet_setsize(pkt, buf_size))
    return -1;

  return 0;
}

/*
 * Reset a GG_packet so that it can be used to get or send a new packet
 *
 * This has been introduced to prevent/detect logic errors
 */
void gg_packet_reset(GG_packet *pkt) {

  pkt->transmitted = 0;
  pkt->is_full_and_verified = 0;
}

ssize_t gg_packet_put(GG_cnx *cnx, GG_packet *pkt) {
  GG_ptr buf;
  ssize_t ret = -1;

  DEBUG(2, "start\n");

  if (!cnx || !pkt)
    return -2;

  /* do we really need to resume sending this packet ? */
  if (pkt->is_full_and_verified) {
    DEBUG(0, "called on a full and verified packet!\n");
    return -2;
  }

  /*
   * if nothing has been transmitted yet, we need to bind the packet to the
   * connection and encode it
   */
  if (!pkt->transmitted) {
    ret = gg_packet_forge(cnx, pkt);
    if (ret)
      return -2;

    ret = gg_packet_encode(pkt, cnx->ggc);
    if (ret)
      return -2;
  }

  buf = pkt->full_packet;
  buf.ptr += pkt->transmitted;

  if (pkt->transmitted >= GG_PKT_MAX_SIZE ||
      pkt->transmitted >= pkt->buffer_size ||
      pkt->transmitted >= pkt->size) {
    DEBUG(2, "pkt->transmitted is not consistent\n");
    return -2;
  }
  // FIXME stress test
  ret = ggp_write(cnx->socket, &buf, pkt->size - pkt->transmitted);
  //ret = ggp_write(cnx->socket, &buf,
  //                (pkt->size - pkt->transmitted) > 5
  //                ? 5 : (pkt->size - pkt->transmitted) );

  if (ret > 0) {
    if (!pkt->transmitted) {
      /* increment the sequence number for outbound packets if we finally
       * transmitted something */
      DEBUG(2, "incrementing cnx->l_seq from %d, pkt has: %d\n", cnx->l_seq,
            pkt->seq);
      cnx->l_seq += 1;
    }
    pkt->transmitted += ret;
    pkt->is_full_and_verified = pkt->transmitted == pkt->size ? 1 : 0;
  }

  return ret;
}

/*
 * Wire a packet in full. Block until done.
 *
 * Returns the number of bytes read in total or an error
 * See gg_packet_put for errors
 */
ssize_t gg_packet_put_full(GG_cnx *cnx, GG_packet *pkt) {

  ssize_t ret;
  ssize_t nwrit = 0;

  DEBUG(2, "start\n");

  if (!cnx || !pkt)
    return -2;

  gg_packet_reset(pkt);

  /* read and process until there is an error or we're done */
  do {
    ret = gg_packet_put(cnx, pkt);
    if (ret <= 0)
      break;
    nwrit += ret;
  } while (!pkt->is_full_and_verified);

  if (ret > 0)
    /* we finished writing the packet */
    ret = nwrit;

  DEBUG(2, "returning %zi full size %d\n", ret, pkt->size);
  return ret;
}

/*
 * Declare that a new payload is ready in pkt->payload. Prepare and encode the
 * packet to be wired
 *
 * Returns -1 on error, 0 on success
 */
int gg_packet_set_payload(GG_packet *pkt, uint16_t payload_type,
                          size_t payload_size) {
  if (!pkt || payload_size > pkt->max_payload_size)
    return -1;

  /* HEADER_SIZE + HMAC_LEN + MAX_PAYLOAD_SIZE is guaranteed to not int overflow */
  if (gg_packet_setsize
      (pkt, GG_PKT_HEADER_SIZE + GG_PKT_HMAC_LEN + payload_size))
    return -1;

  pkt->payload_type = payload_type;

  /* this packet was not sent out at all yet */
  gg_packet_reset(pkt);

  return 0;
}

/*
 * Set the total size of a packet.
 *
 * Set both payload_size and (packet) size
 *
 * pkt->payload and pkt->full_packet must both
 * be properly initialized.
 *
 * Return -1 on error, 0 on success
 */
static int gg_packet_setsize(GG_packet *pkt, size_t size) {

  if (size > GG_PKT_MAX_SIZE || size > pkt->buffer_size
      || size < GG_PKT_MIN_SIZE) {
    DEBUG(2,
          "tried to set an incorrect packet size: %zi - buffer_size is %zi\n",
          size, pkt->buffer_size);
    return -1;
  }

  pkt->size = size;
  assert_ggp_size(&pkt->full_packet, pkt->size);

  pkt->payload_size = size - (GG_PKT_HEADER_SIZE + GG_PKT_HMAC_LEN);
  assert_ggp_size(&pkt->payload, pkt->payload_size);

  return 0;
}

/*
 * Forge a packet for a connection
 *
 * "Forging" currently means setting the sequence number and the client
 * to server bit.
 *
 * Return 0 on success -1 on failure
 */
static int gg_packet_forge(GG_cnx *cnx, GG_packet *pkt) {

  if (!cnx || !pkt)
    return -1;

  if (cnx->l_seq >= GG_MAX_SEQUENCE_NUMBER) {
    REPORT_ERROR("sequence number too large");
    return -1;
  }

  pkt->seq = cnx->l_seq + 1;
  /* we will increment cnx->l_seq later, after the first bytes have been
   * transmitted */

  /* Is this packet sent from the client to the server ? */
  pkt->client_to_server = cnx->isserver ? 0 : 1;

  return 0;
}

/*
 * Make a packet ready for gg_packet_put by encoding all the field
 * into the buffer so that the packet can be wired.
 *
 * Encode the header, calculates the HMAC
 *
 * Returns 0 on success, -1 on failure
 */
static int gg_packet_encode(GG_packet *pkt, GG_crypt *ggc) {
  GG_ptr hdr = pkt->hdr;

  ggp_memcpy(&hdr, "GG01", 4);
  hdr.ptr += 4;

  encode_uint16(&hdr, pkt->size);

  encode_uint32(&hdr, pkt->seq);
  /* The next field combines the payload type and a flag */
  encode_uint16(&hdr,
                pkt->payload_type |
                (pkt->client_to_server ? GG_CLIENT_TO_SERVER_FLAG
                                       : 0));

  /* Calculate the HMAC and encode it in the packet */
  if (gg_packet_calc_hmac(pkt, ggc, &pkt->hmac))
    return -1;

  return 0;
}

/*
 * Calculate the HMAC of a packet and put it in hmac
 *
 * It's ok to use pkt->hmac as hmac when encoding a packet
 *
 * hmac must be GG_PKT_HMAC_LEN large
 *
 * Returns -1 on error, 0 on success
 */
static int gg_packet_calc_hmac(GG_packet *pkt, GG_crypt *ggc, GG_ptr *hmac) {

  /* we calculate the HMAC of header + payload */
  if (crypto_hmac_init(ggc) ||
      crypto_hmac_update(ggc, &pkt->hdr, GG_PKT_HEADER_SIZE) ||
      crypto_hmac_update(ggc, &pkt->payload, pkt->payload_size) ||
      crypto_hmac_final(ggc, hmac, GG_PKT_HMAC_LEN)) {
    return -1;
  } else {
    return 0;
  }
}

/* FIXME URGENT refactor this FIXME */

/*
 * Resume or start reading a packet. The packet contains an internal
 * "is_full_and_verified" state that will be updated by this function.
 *
 * The return values are similar to "read" with the addition of "-2"
 *
 * If the packet has been read fully, it'll be entirely decoded and
 * pkt->is_full_and_verified will be 1
 *
 * The caller must call gg_packet_init or gg_packet_reset to reset the internal
 * state before expecting to read a new packet. This is done to make sure
 * the caller epects to be reading a new packet and detect logic errors.
 *
 * Returns:
 *  -2: Packet is invalid. Not a valid GG packet or wrong HMAC for instance
 *  -1: read() error. errno is set
 *   0: EOF as returned by read()
 *  number of bytes: number of bytes read
 *
 * For security, the important part is is_full_and_verified
 */
ssize_t gg_packet_get(GG_cnx *cnx, GG_packet *pkt) {
  GG_ptr buf;
  ssize_t ret = -1;

  if (!cnx || !pkt)
    return -2;

  DEBUG(2, "start is_full_and_verified: %d, transmitted: %zi\n",
        pkt->is_full_and_verified, pkt->transmitted);

  buf = pkt->full_packet;
  buf.ptr += pkt->transmitted;

  if (pkt->is_full_and_verified) {
    /* caller probably forgot packet_reset or there is a logic error */
    DEBUG(2, "pkt->is_full_and_verified is 1!");
    return -2;
  }

  /* Do we still need to read the mandatory part of the packet ? */
  if (pkt->transmitted < GG_PKT_MIN_SIZE) {
    ret = ggp_read(cnx->socket, &buf, GG_PKT_MIN_SIZE - pkt->transmitted);
    // FIXME stress test
    //ret = ggp_read(cnx->socket, &buf, GG_PKT_MIN_SIZE - pkt->transmitted > 3
    //               3 : GG_PKT_MIN_SIZE - pkt->transmitted);
    if (ret <= 0)
      return ret;

    /* we have read something */
    DEBUG(2, "We have read %zi bytes\n", ret);
    pkt->transmitted += ret;
    if (pkt->transmitted < GG_PKT_MIN_SIZE) {
      /* if we still don't have the minimum size, we can't do anything more for
         now */
      return ret;
    } else {
      /* we have the full header, we can get the packet length etc */
      if (gg_packet_decode_header(pkt)) {
        DEBUG(2, "Got a non compliant packet\n");
        return -2;
      }

      /* Will we need to read more from this packet ? */
      if (pkt->size > pkt->transmitted) {
        pkt->is_full_and_verified = 0;
        return ret;
      } else {
        /* our packet is full let's continue */
        if (gg_packet_verify(pkt, cnx)) {
          REPORT_INFO("gg_packet_verify failed\n");
          return -2;
        }
        pkt->is_full_and_verified = 1;
        return ret;
      }
    }
  } else {
    /* Sanity check */
    if (pkt->transmitted >= GG_PKT_MAX_SIZE ||
        pkt->transmitted >= pkt->buffer_size ||
        pkt->transmitted >= pkt->size) {
      DEBUG(2, "pkt->transmitted is inconsistent: got %zi and size is %d\n",
            pkt->transmitted, pkt->size);
      return -2;
    }

    ret = ggp_read(cnx->socket, &buf, pkt->size - pkt->transmitted);
    // FIXME
    //ret = ggp_read(cnx->socket, &buf, pkt->size - pkt->transmitted > 2 ?
    //               2 : pkt->size - pkt->transmitted);

    if (ret <= 0) {
      return ret;
    }

    pkt->transmitted += ret;

    if (pkt->transmitted == pkt->size) {

      /* verify HMAC, sequence number, etc.. */
      if (gg_packet_verify(pkt, cnx)) {
        REPORT_INFO("gg_packet_verify failed\n");
        return -2;
      }
      pkt->is_full_and_verified = 1;
      DEBUG(2, "Got packet - Type %d - HMAC verification passed!\n\n",
            pkt->payload_type);
    }

    /* all good, we report how many bytes we've read */
    return ret;
  }
}

/*
 * Read an incoming packet in full and decodes it
 *
 * Returns the number of bytes read in total or an error
 * See gg_packet_get for errors
 */
ssize_t gg_packet_get_full(GG_cnx *cnx, GG_packet *pkt) {

  ssize_t ret;
  ssize_t nread = 0;

  DEBUG(2, "start\n");

  if (!cnx || !pkt)
    return -2;

  gg_packet_reset(pkt);

  /* read and process until there is an error or we're done */
  do {
    ret = gg_packet_get(cnx, pkt);
    if (ret <= 0)
      break;
    nread += ret;
  } while (!pkt->is_full_and_verified);

  if (ret > 0)
    /* we finished reading the packet */
    ret = nread;

  DEBUG(1, "returning %zi\n", ret);
  return ret;
}

int gg_can_read(GG_cnx *cnx, int timeout) {
  struct pollfd pfd;

  pfd = (struct pollfd) {
    .fd = cnx->socket,
    .events = POLLIN,
    .revents = 0,
  };

  return poll(&pfd, 1, timeout);
}

/*
 * verify a packet pkt is correct, given a connection cnx
 *
 * This will verify the HMAC of the packet, the sequence number
 * and the client_to_server flag
 *
 * Returns -1 on error, 0 on succcess
 */
static int gg_packet_verify(GG_packet *pkt, GG_cnx *cnx) {

  /* verify sequence number */
  if (cnx->r_seq >= SSIZE_MAX) {
    REPORT_ERROR("sequence number is too large");
    return -1;
  }

  if (pkt->seq != cnx->r_seq + 1) {
    REPORT_ERROR("invalid sequence number");
    DEBUG(0, "invalid sequence number: got %d expected %d\n", pkt->seq,
          cnx->r_seq + 1);
    return -1;
  } else {
    DEBUG(2, "got valid sequence number: %d\n", pkt->seq);
  }
  /* the sequence number is ok */

  /* Now check the client_to_server flag */
  if ((pkt->client_to_server && !cnx->isserver)
      || (!pkt->client_to_server && cnx->isserver)) {
    REPORT_ERROR("invalid client or server flag");
    return -1;
  }

  /* now verify the HMAC */
  if (gg_packet_verify_hmac(pkt, cnx->ggc)) {
    REPORT_ERROR("Hmac verification failed");
    return -1;
  }

  /* all ok increment our internal sequence number for the remote end */

  cnx->r_seq++;

  return 0;
}

/*
 * Decode a "raw packet" in a buffer to a packet structure
 *
 * Returns -1 on error, 0 on success
 */
static int gg_packet_decode_header(GG_packet *pkt) {
  GG_ptr buf;
  uint16_t pyld;

  buf = pkt->hdr;

  /* FIXME */
  if (ggp_memcmp(&buf, "GG01", 4)) {
    DEBUG(2, "Got a non compliant packet\n");
    return -1;
  }
  buf.ptr += 4;

  if (gg_packet_setsize(pkt, parse_uint16(&buf)))
    return -1;

  pkt->seq = parse_uint32(&buf);

  /* The next field combines the payload type and a flag */
  pyld = parse_uint16(&buf);
  pkt->payload_type = pyld & GG_PAYLOAD_MASK;
  pkt->client_to_server = pyld & GG_CLIENT_TO_SERVER_FLAG;

  return 0;
}

/*
 * Verifies the HMAC of a given packet with a crypto context ggc
 *
 * Returns -1 on error, 0 on success
 *
 */
static int gg_packet_verify_hmac(GG_packet *pkt, GG_crypt *ggc) {
  static char md[GG_PKT_HMAC_LEN];
  GG_ptr local_hmac;
  local_hmac = ggp_init(md, sizeof(md));

  /* useless */
  gg_bzero(&local_hmac, GG_PKT_HMAC_LEN);

  if (gg_packet_calc_hmac(pkt, ggc, &local_hmac)
      || ggp_equal(&pkt->hmac, &local_hmac, GG_PKT_HMAC_LEN)) {
    //if (gg_packet_calc_hmac(pkt, ggc, &local_hmac) ||
    //    memcmp(pkt->hmac.ptr, local_hmac.ptr, GG_PKT_HMAC_LEN)) {
    /*
     * if anything goes wrong, we make sure the HMAC is incorrect so that we
     * don't re-use the HMAC we calculated ourselves in case of a logic error
     * somewhere
     */
    DEBUG(2,
          "HMAC WRONG: valid: \\x%02hhx\\x%02hhx - got: \\x%02hhx\\x%02hhx\n",
          ((unsigned char *) (pkt->hmac.ptr))[0],
          ((unsigned char *) (pkt->hmac.ptr))[1], md[0], md[1]);
    gg_bzero(&pkt->hmac, GG_PKT_HMAC_LEN);
    return -1;
  }
  DEBUG(2, "HMAC OK: valid %x%x%x%x\n", md[0], md[1], md[2], md[3]);
  return 0;
}
