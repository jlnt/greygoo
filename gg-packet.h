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
 * Grey Goo packet handling.
 */
#ifndef GG_PACKET_H
#define GG_PACKET_H
#include <sys/socket.h>
#include <netinet/in.h>
#include "gg-utils.h"
#include "gg-crypto.h"


typedef struct GG_packet_impl GG_packet;
typedef struct GG_cnx_impl GG_cnx;

/* Initialize a connection context cnx
 *
 * our_id and remote_id are NUL terminated identifiers (e.g. hostnames)
 * ggc is an initialized crypto context
 * isserver must be 1 if we are the server, 0 otherwise
 */
void gg_cnx_init(GG_cnx *cnx, int socket, char *our_id, char *remote_id,
                 GG_crypt *ggc, int isserver);

/*
 * Set a "strong ID" (sent over a channel with integrity) that the remote party
 * claims to be to the connection context
 */
void gg_cnx_set_strongid(GG_cnx *cnx, char *remote_id, size_t len);

/*
 * gg_packet_init binds a packet with a buffer
 * This buffer should be larger than GG_PKT_MAX_SIZE.
 *
 * (Note: this could easily be relaxed to GG_PKT_MIN_SIZE instead, but
 * the GG_packet should only be use to send packets, not receive them. Don't
 * use this for now.)
 */
int gg_packet_init(GG_packet *pkt, const GG_ptr *buffer, size_t buf_size);
/*
 * A GG_packet structure can be re-used to receive a new packet if it has been
 * reset.
 */
void gg_packet_reset(GG_packet *pkt);

/*
 * A GG_pkt can be used to send and receive packet. A GG_packet will always
 * point to a buffer of size at least GG_PKT_MAX_SIZE.
 * This behaviour could be changed but makes everything easier.
 *
 * gg_packet_init() must be used to bind a GG_packet with a buffer.
 *
 * To send a packet:
 *  1. Write payload data to pkt->payload
 *  2. Use gg_packet_set_payload() to bind the payload type and length.
 *  3. Use either gg_packet_put_full (once, can block) or gg_packet_put
 *    repeatedly until pkt->is_full_and_verified becomes true
 *
 * To get a packet:
 *  1. Use a new bound GG_pkt or a packet that has been reset by gg_packet_reset
 *    (this step exists to prevent logic errors)
 *  2. Use either gg_packet_get_full (once, can block) or gg_packet_get until
 *    pkt->is_full_and_verified becomes true
 */

/* return values are similar to those of gg_packet_get() */
ssize_t gg_packet_put(GG_cnx *cnx, GG_packet *pkt);
ssize_t gg_packet_put_full(GG_cnx *cnx, GG_packet *pkt);

/* Sets the packet payload size and type.
 * The actual payload is in pkt->payload
 *
 * Returns -1 on error, 0 on success
 */
int gg_packet_set_payload(GG_packet *pkt, uint16_t payload_type,
                          size_t payload_size);

/* Start or resume reading a packet
 *
 * The return values are similar to "read" with the addition of "-2"
 *
 * pkt must be bound (gg_packet_init) to a buffer of size at least
 * GG_PKT_MAX_SIZE
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
 */
ssize_t gg_packet_get(GG_cnx *cnx, GG_packet *pkt);

/*
 * gg_packet_get_full is similar to gg_get_packet but will block
 * if the full packet has not been read yet.
 * Should be used to read a brand new packet only. (i.e. don't use it
 * to finish reading a packet already received partially with gg_packet_get())
 */
ssize_t gg_packet_get_full(GG_cnx *cnx, GG_packet *pkt);

/*
 * Poll the connection until we can read() without blocking or a timeout
 * (in ms) is reached.
 * Returns -1 on error (errno is set), 0 if the timeout is reached, 1 if
 * there is something to read.
 */
int gg_can_read(GG_cnx *cnx, int timeout);

#define GG_PORT 1986 /* Publication date of "Engines of Creation" */

#define GG_PKT_HEADER_SIZE 12
#define GG_PKT_HMAC_LEN 20
#define GG_PKT_MAX_SIZE 32768 /* cannot be more than 65535 */
#define GG_PKT_MIN_SIZE (GG_PKT_HEADER_SIZE + GG_PKT_HMAC_LEN)
/* we guarantee that GG_PKT_MAX_PAYLOAD_SIZE is less than SSIZE_MAX */
#define GG_PKT_MAX_PAYLOAD_SIZE (GG_PKT_MAX_SIZE - GG_PKT_HEADER_SIZE \
                                 - GG_PKT_HMAC_LEN)

/* The most significant bit of the payload type  is a flag (see PROTOCOL) */
#define GG_PAYLOAD_PING 1
#define GG_PAYLOAD_PONG 2
#define GG_PAYLOAD_DH 3
#define GG_RSA_SIGNATURE_SESSION 4
#define GG_PAYLOAD_STREAM 5
#define GG_PAYLOAD_PRESENT_ID 6
#define GG_PAYLOAD_CMD_FORK_EXECVE 7
#define GG_PAYLOAD_CMD_REBOOT 8
#define GG_PAYLOAD_STRING 9
#define GG_PAYLOAD_INT 10
#define GG_PAYLOAD_CMD_WRITE_FILE 11
#define GG_PAYLOAD_CMD_DMESG 12
#define GG_PAYLOAD_DATA 13
#define GG_PAYLOAD_CMD_DIRECT_EXECVE 14

#define GG_PAYLOAD_MASK 0x7FFF
#define GG_CLIENT_TO_SERVER_FLAG 0x8000

/* FIXME */
#define GG_MAX_SEQUENCE_NUMBER SSIZE_MAX

/* guaranteed < GG_PKT_MAX_PAYLOAD_SIZE */
#define GG_SERVER_ID_MAX_LEN 1024

/* guaranteed to fit in a uint32_t */
#define GG_CMD_MAX_ARGC 2048

/* We have to fully define our types here so that instances can be
 * pre-allocated easily without constructors
 */

struct GG_packet_impl {
  GG_ptr full_packet;
  size_t transmitted;           /* how much of the packet did we already read
                                   or write from / to the write ? */
  int is_full_and_verified;     /* partially transmitted (read or write) */
  size_t buffer_size;           /* full size of the buffer pointed to by
                                   full_packet
                                   (there is a 1:1 mapping with max_payload_size
                                    and both will be modified together)
                                 */
  uint16_t size;                /* packet size as advertised in the header */
  uint32_t seq;                 /* sequence number */
  // GG_HMAC hmac;
  GG_ptr hmac;
  /* HMAC size is fixed at GG_PKT_HMAC_LEN */
  uint16_t payload_type;
  int client_to_server;         /* is this a packet from the client to the
                                   server? */
  GG_ptr hdr;
  /* Header size is fixed at GG_PKT_HEADER_SIZE */
  GG_ptr payload;
  size_t max_payload_size;      /* size of the payload buffer
                                   (there is a 1:1 mapping with buffer_size
                                    and both will be modified together)
                                 */
  uint16_t payload_size;
};

struct GG_cnx_impl {
  int socket;
  char *our_id;
  char *remote_id;
  char *remote_strong_id;
  char strong_id_buffer[GG_SERVER_ID_MAX_LEN];
  uint32_t l_seq;               /* local us -> remote sequence number */
  uint32_t r_seq;               /* remote -> local (us) sequence number */
  GG_crypt *ggc;                /* crypto context */
  uint32_t state;               /* general state */
  int isserver;                 /* Are we the server ? */
};

#endif                          /* GG_PACKET_H */
