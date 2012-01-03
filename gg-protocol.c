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
 * Helpers for starting a session as server or client
 */
#include <errno.h>
#include <string.h>
#include "gg-protocol.h"
#include "report.h"

/*
 * Get the remote DH key and sets it in cnx
 *
 * Return:
 *  -1: error
 *   0: success
 */
int get_remote_dh_key(GG_cnx *cnx, GG_packet *pkt) {
  ssize_t ret;

  ret = gg_packet_get_full(cnx, pkt);
  switch (ret) {
  case -2:
    DEBUG(2, "Got invalid packet\n");
    return -1;
  case -1:
    DEBUG(2, "read error: %m\n");
    return -1;
  case 0:
    DEBUG(2, "connection closed by peer\n");
    return -1;
  }

  /* Check the type of the payload */
  if (pkt->payload_type != GG_PAYLOAD_DH) {
    DEBUG(2, "Incorrect payload type\n");
    return -1;
  }

  /* set the DH remote key from the payload */
  ret = crypto_set_remote_key(cnx->ggc, pkt->payload.ptr, pkt->payload_size);
  if (ret) {
    DEBUG(2, "Could not set remote key\n");
    return -1;
  }
  return 0;
}

/* Send our DH key
 *
 * Return:
 *  -1: error
 *   0: success
 */
int send_our_dh_key(GG_cnx *cnx, GG_packet *pkt) {
  ssize_t ret;
  const size_t pubkey_bin_len = crypto_get_dh_pubkey_len(cnx->ggc);
  const unsigned char *pubkey_bin = crypto_get_dh_pubkey_bin(cnx->ggc);

  /* put our own DH key a payload in a new packet */
  if (pubkey_bin_len > pkt->max_payload_size) {
    DEBUG(2, "pubkey is too long");
    return -1;
  }
  ggp_memcpy(&pkt->payload, pubkey_bin, pubkey_bin_len);
  DEBUG(2, "---- sending pubkey: 0x%X with size %zi\n",
        ((uint32_t *) pkt->payload.ptr)[0], pubkey_bin_len);
  ret = gg_packet_set_payload(pkt, GG_PAYLOAD_DH, pubkey_bin_len);

  if (ret) {
    DEBUG(2, "gg_packet_set_payload failed\n");
    return -1;
  }

  /* wire that packet */
  ret = gg_packet_put_full(cnx, pkt);
  switch (ret) {
  case 0:
    DEBUG(2, "connection closed by peer\n");
    return -1;
  case -1:
    DEBUG(2, "write error :%m\n");
    return -1;
  case -2:
    DEBUG(2, "error crafting packet\n");
    return -1;
  default:
    return 0;
  }
}

/* Compute the shared session key
 *
 * Return:
 *  -1: error
 *   0: success
 */
int do_handshake_crypto(GG_cnx *cnx) {

  if (
       /* Update our signature context with the hmac of the second packet */
       /* compute the DH shared key */
       crypto_compute_shared_key(cnx->ggc) ||
       /* set the shared key as the hmac key */
       crypto_set_shared_key_to_hmac(cnx->ggc)
      ) {
    DEBUG(2, "crypto error\n");
    return -1;
  }
  return 0;
}


/*
 * FIXME: needs refactoring and probably rewriting to make less simple and
 * forward closed stuff to the other end.
 *
 * Pretty limited forwarder. Anything read on input is sent to the connection,
 * anything read on the connection is sent to output.
 *
 * We stop reading input on the connection before we can fully output it to
 * output. Moreover, we stop reading input on input before we can fully output
 * it through the connection.
 *
 * The caller should make sure any "interesting" signal is currently blocked
 * and pass a signal set in sigmsk with those unblocked (in a similar way to
 * how ppoll and pselect work).
 *
 * If we catch a signal, signal_cb() will be called with cb_arg and we will
 * return 0 if signal_cb() returns 1.
 *
 * Return 0 on connection closed (or if signal_cb returned 1), -1 on error
 *
 */
int do_fw_in_out(GG_cnx *cnx, int input, int output, sigset_t *sigmsk,
                 int (*signal_cb)(int), int cb_arg) {
  static char input_buf[GG_PKT_MAX_SIZE];
  GG_packet pkt_input;
  GG_ptr in_buf;
  static char output_buf[GG_PKT_MAX_SIZE];
  GG_packet pkt_output;
  GG_ptr out_buf;
  enum pf_fds {cnx_fd, in_fd, out_fd};
  struct pollfd pf[3];          /* cnx, input, output */
  GG_packet *pkt_in, *pkt_out;
  int p;
  ssize_t input_read, output_written, ret;
  int input_closed = 0;
  int output_closed = 0;

  if (!cnx)
    return -1;

  in_buf = ggp_init(input_buf, sizeof(input_buf));
  out_buf = ggp_init(output_buf, sizeof(output_buf));

  pkt_in = &pkt_input;
  pkt_out = &pkt_output;

  if (gg_packet_init(pkt_in, &in_buf, sizeof(input_buf)) ||
      gg_packet_init(pkt_out, &out_buf, sizeof(output_buf)))
    return -1;

  /* Initial state: watch for input only */
  pf[cnx_fd].fd = cnx->socket;
  pf[cnx_fd].events = POLLIN;

  pf[in_fd].fd = input;
  pf[in_fd].events = POLLIN;

  pf[out_fd].fd = -1;
  pf[out_fd].events = POLLOUT;

  input_read = 0;
  output_written = 0;

  /*
   * we are watching two inputs (the connection and "input") and two outputs
   * the connection and output, we call them cnx_in, input, cnx_out and output
   * respectively in the comments.
   *
   * At any given time we will watch at most two of them:
   * cnx_in and output are mutually exclusive
   * cnx_out and input are mutually exclusive
   *
   * Mutual exclusion exists because we will finish writing to output before we
   * start reading from cnx_in again for instance.
   *
   * To stop watching input or output we switch their fd to -1. To stop
   * watching cnx_in or cnx_out, we change the events flag only. This is a
   * simplification that can exist because while input/output are under the
   * control of the user or of a command, cnx_in and cnx_out are regulated by
   * the Grey Goo protocol that states that closing any side of the connection
   * means everything is over.
   *
   * Returns:
   *  0: connection closed or signal callback returned 1
   * -1: error
   */

  /* -1 is an error, except when errno is EINTR which means we caught a
     signal */
  while ((p = old_libc_compatible_ppoll(pf, 3, NULL, sigmsk)) != -1 || errno == EINTR) {
    DEBUG(2, "poll returned: %d (pid %d)\n)\n", p, getpid());
    DEBUG(2, "cnx has events %d\n", pf[cnx_fd].revents);
    DEBUG(2, "input has events %d\n", pf[in_fd].revents);
    DEBUG(2, "output has events %d\n", pf[out_fd].revents);

    if (sigmsk && p == -1 && signal_cb) {
      /* we  have caught a signal, call our callback */
      ret = signal_cb(cb_arg);
      if (ret)
        return 0;
      else
        continue;
    }

    /* we have p events to handle */
    if (pf[cnx_fd].revents) {

      /* input from cnx */
      if (pf[cnx_fd].revents & POLLIN) {
        DEBUG(2, "cnx POLLIN\n");

        /* now resume reading our (new or not) packet */
        ret = gg_packet_get(cnx, pkt_in);
        if (ret <= 0) {
          switch (ret) {
          case -2:
          case -1:
            DEBUG(2, "Error when reading packet\n");
            return -1;
          case 0:
            DEBUG(2, "Connection closed while reading\n");
            return 0;
          }
        }
        if (pkt_in->is_full_and_verified) {
          /* we have a full packet ready */

          /* check the payload type, return if streaming stopped */
          if (pkt_in->payload_type != GG_PAYLOAD_STREAM) {
            return 0;
          }
          /* it's time to write to output */
          pf[cnx_fd].events &= ~POLLIN;
          pf[out_fd].fd = output;
          output_written = 0;
        }
      }

      /* output from cnx */
      if (pf[cnx_fd].revents & POLLOUT) {
        DEBUG(2, "cnx POLLOUT\n");

        /* now resume sending out our packet */
        ret = gg_packet_put(cnx, pkt_out);
        if (ret <= 0) {
          switch (ret) {
          case -2:
          case -1:
            DEBUG(2, "Error when sending packet\n");
            return -1;
          case 0:
            DEBUG(2, "Connection closed for writing\n");
            return 0;
          }
        }

        if (pkt_out->is_full_and_verified) {
          /* our packet was fully sent, we can resume polling input */
          pf[cnx_fd].events &= ~POLLOUT;
          pf[in_fd].fd = input;
          input_read = 0;
        }
      }

      /* We received one of the "implicit" events: POLLERR, POLLHUP, POLLNVAL */
      if (pf[cnx_fd].revents & ~POLLIN & ~POLLOUT) {
        DEBUG(2, "cnx: received error: %d\n", pf[cnx_fd].revents);
        return -1;
      }
    }

    if (pf[in_fd].revents) {
      DEBUG(2, "got event on input\n");
      if (pf[in_fd].revents & (POLLIN | POLLHUP)) {
        /* read as much as we can and prepare a packet for output */
        input_read =
            ggp_read(input, &pkt_out->payload, pkt_out->max_payload_size);
        if (input_read > 0) {
          DEBUG(2, "read %zi on input\n", input_read);
          gg_packet_set_payload(pkt_out, GG_PAYLOAD_STREAM, input_read);

          /* we have a packet prepared, we should send it out */
          pf[in_fd].fd = -1;
          pf[cnx_fd].events |= POLLOUT;
        } else {
          input_closed = 1;
          /* let the "we can't read anything more" code below handle this */
        }
      }
      if (input_closed || (pf[in_fd].revents & ~(POLLIN | POLLHUP))) {
        /* We received one of the "implicit" events: POLLERR or POLLNVAL
         * or ggp_read() said we're done reading on input
         */
        DEBUG(2, "input: got error %d\n", pf[in_fd].revents);
        input_closed = 1;
        /* we stop polling the input forever */
        pf[in_fd].fd = -1;
        if (output_closed) {
          /* if the output is closed as well, we are done */
          DEBUG(2, "both input and output are closed\n");
          return 0;
        }
      }
    }

    if (pf[out_fd].revents) {
      DEBUG(2, "got event on output\n");
      if (pf[out_fd].revents & (POLLOUT | POLLHUP)) {
        GG_ptr cur_out;
        if (output_written >= pkt_in->payload_size) {
          DEBUG(2,
                "logic error: POLLOUT event on output and nothing to write:"
                " output_written: %zi\n",
                output_written);
          return -1;
        }

        cur_out =
            ggp_init(pkt_in->payload.ptr + output_written,
                     pkt_in->payload_size - output_written);

        ret =
            ggp_write(output, &cur_out, pkt_in->payload_size - output_written);
        if (ret > 0) {
          DEBUG(2, "wrote %zi on output\n", ret);
          output_written += ret;

          if (output_written == pkt_in->payload_size) {
            /* we're done, resume polling cnx for input instead */
            pf[out_fd].fd = -1;
            pf[cnx_fd].events |= POLLIN;

            /* it'll need to start fresh, with a new packet */
            gg_packet_reset(pkt_in);
          }
        } else {
          output_closed = 1;
          /* let the "we can't write anything more" code below handle this */
        }
      }
      if (output_closed || (pf[out_fd].revents & ~(POLLOUT | POLLHUP))) {
        /* We received one of the "implicit" events: POLLERR or POLLNVAL
         * or ggp_write() said we're done writing on output
         */
        DEBUG(2, "output: got error %d\n", pf[out_fd].revents);
        output_closed = 1;
        /* we stop polling the output forever */
        pf[out_fd].fd = -1;
        if (input_closed) {
          DEBUG(2, "output: both input and output are closed\n");
          return 0;
        }
      }
    }
  }
  return 0;
}
