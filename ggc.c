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
 * Grey Goo client
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "report.h"
#include "gg-protocol.h"
#include <openssl/pem.h>

/* We will link the root private key */
extern unsigned char _binary_private_keys_rsa_private_root_pem_start[];
extern unsigned char _binary_private_keys_rsa_private_root_pem_end[];

/* We will link the test private key */
extern unsigned char _binary_private_keys_rsa_private_test_pem_start[];
extern unsigned char _binary_private_keys_rsa_private_test_pem_end[];


struct cmdline_parsed {
  char *target_ip;
  char *target_port;
  char *opt_sysrq_command;  /* sysrq command key */
  char **target_argv;
  int  target_argc;
  enum {CMD_DEFAULT, CMD_FORK_EXEC, CMD_DIRECT_EXEC, CMD_REBOOT, CMD_SYSRQ,
        CMD_DMESG}
       command_to_run;
  int use_test_key;
};

static int connect_to_remote(char *hostname, char *port);
static int connect_and_init_session(GG_cnx *cnx, GG_crypt *ggc,
                                    char *target_ip, char *target_port);
static int remote_cmd_reboot(GG_cnx *cnx);
static int remote_cmd_execve(GG_cnx *cnx, int argc, char *argv[], int cmd_type);
static int remote_cmd_sysrq(GG_cnx *cnx, char command);
static int remote_cmd_dmesg(GG_cnx *cnx);
void parse_command_line(struct cmdline_parsed *cmd, int argc, char *argv[]);
__attribute__((noreturn)) static void usage(char *name);

int main(int argc, char *argv[]) {
  GG_crypt *ggc;
  int ret;
  struct cmdline_parsed cmd;

  GG_cnx cnx;

  fprintf(stderr, "Grey Goo client\n\n");

  /* Get a protected address space: no core dump, no swapping */
  if (protect_address_space())
    fprintf(stderr, "Could not protect the address space adequately. "
                    "Check 'ulimit -l'. You should abort.\n");

  parse_command_line(&cmd, argc, argv);

  /* Initialize crypto */
  if (!(ggc = crypto_global_init()) || !crypto_stage2_init(ggc)) {
    REPORT_ERROR("Could not init crypto");
    return -1;
  }

  if (cmd.use_test_key) {
    ret =
      crypto_sign_setkey(ggc,
          (void *) _binary_private_keys_rsa_private_test_pem_start,
          _binary_private_keys_rsa_private_test_pem_end -
          _binary_private_keys_rsa_private_test_pem_start);
  } else {
    ret =
      crypto_sign_setkey(ggc,
          (void *) _binary_private_keys_rsa_private_root_pem_start,
          _binary_private_keys_rsa_private_root_pem_end -
          _binary_private_keys_rsa_private_root_pem_start);
  }

  if (ret) {
    REPORT_ERROR("Could not set RSA private keys\n");
    return -1;
  }

  /* Establish a session with the client, be ready to send a command */
  ret = connect_and_init_session(&cnx, ggc, cmd.target_ip, cmd.target_port);
  if (ret)
    return -1;

  /* Now send the actual command */
  switch (cmd.command_to_run) {

  case (CMD_REBOOT):
    return remote_cmd_reboot(&cnx);

  case (CMD_SYSRQ):
    return remote_cmd_sysrq(&cnx, cmd.opt_sysrq_command[0]);

  case (CMD_DMESG):
    return remote_cmd_dmesg(&cnx);

  case (CMD_DIRECT_EXEC):
    return remote_cmd_execve(&cnx, cmd.target_argc, cmd.target_argv,
                             CMD_DIRECT_EXEC);
  case (CMD_FORK_EXEC):
  default:
    return remote_cmd_execve(&cnx, cmd.target_argc, cmd.target_argv,
                             CMD_FORK_EXEC);
  }

  /* should not be reached */
  return -1;
}

__attribute__((noreturn)) static void usage(char *name) {
  fprintf(stderr, "Usage:\n\n"

          "%s -e [options] [-- /path/to/command [arg0 [arg1] ...]\n"
          "%s -c [options] [\"shell command\"]\n"
          "%s <-k|-r> [options]\n"
          "%s -s <key> [options]\n"
          "%s <hostname> [\"shell command\"] "
          "(equivalent to -h <hostname> -c command)\n\n"

          "Command descriptions:\n"
          "  -e              execute a program via execve()\n"
          "  -c              execute shell command via \"/bin/sh -c\" "
            "(e.g. 'cat <file> | grep test')\n"
          "  -k              write last %d bytes of the kernel "
            "ring buffer on stderr\n"
          "  -r              reboot\n"
          "  -s <key>        sysrq request <key>\n\n"

          "Execve command options (for -e or -c):\n"
          "  -x (avoid!)     simple/plain rexec mode. No crypto after "
          "authentication!\n"
          "                  stdin will be disabled\n\n"

          "General options:\n"
          "  -h <hostname>   target hostname/ipv4/ipv6\n"
          "  -p <port>       target port\n"
          "  -t              use the alternative (test mode) key\n\n"

          "If no command is specified, an interactive shell is run.\n\n",
          name, name, name, name, name, GG_PKT_MAX_PAYLOAD_SIZE);

  exit(EXIT_FAILURE);
}

void parse_command_line(struct cmdline_parsed *cmd, int argc, char *argv[]) {
  int ch;
  static char *default_argv[] = { "/bin/sh", "-i", NULL };
  static char *bin_sh_c_argv[] = { "/bin/sh", "-c", "id", NULL };
  enum { FLAG_NONE, FLAG_C, FLAG_E, FLAG_K, FLAG_R, FLAG_S } exclusive_flag = 0;
  int do_direct_exec = 0; /* -x */

  *cmd = (struct cmdline_parsed) {
    .target_ip = NULL,
    .target_port = GG_PORT_STRING,
    .opt_sysrq_command = NULL,
    .target_argv = NULL,
    .target_argc = 0,
    .command_to_run = CMD_DEFAULT,
    .use_test_key = 0,
  };

  while ((ch = getopt(argc, argv, ":ceh:p:d:rs:ktx")) != -1) {
    switch (ch) {
    case 'c':
      if (exclusive_flag)
        usage(argv[0]);
      exclusive_flag = FLAG_C;
      break;
    case 'e':
      if (exclusive_flag)
        usage(argv[0]);
      exclusive_flag = FLAG_E;
      break;
    case 'h':
      cmd->target_ip = optarg;
      break;
    case 'p':
      cmd->target_port = optarg;
      break;
    case 'd':
      debug_setlevel(atoi(optarg));
      break;
    case 'k':
      if (exclusive_flag)
        usage(argv[0]);
      exclusive_flag = FLAG_K;
      break;
    case 'r':
      if (exclusive_flag)
        usage(argv[0]);
      exclusive_flag = FLAG_R;
      break;
    case 's':
      /* check also that the sysrq command is one single character */
      if (exclusive_flag || strlen(optarg) != 1) {
        usage(argv[0]);
      } else {
        exclusive_flag = FLAG_S;
        cmd->opt_sysrq_command = optarg;
      }
      break;
    case 't':
      cmd->use_test_key = 1;
      break;
    case 'x':
      do_direct_exec = 1;
      break;
    default:
      usage(argv[0]);
    }
  }

  /* This should no happen */
  if (optind > argc) {
    FATAL("getopt");
  }

  /* if the user did not specify anything, we assume -c */
  if (!exclusive_flag)
    exclusive_flag = FLAG_C;

  /* Which command should we run ? */
  switch(exclusive_flag) {
    case FLAG_K:
      cmd->command_to_run = CMD_DMESG;
      break;
    case FLAG_R:
      cmd->command_to_run = CMD_REBOOT;
      break;
    case FLAG_S:
      cmd->command_to_run = CMD_SYSRQ;
      break;
    case FLAG_C:
    case FLAG_E:
      if (do_direct_exec)
        cmd->command_to_run = CMD_DIRECT_EXEC;
      else
        cmd->command_to_run = CMD_FORK_EXEC;
      break;
    default:
      FATAL("exclusive_flag");
  }

  /* Make sure we have a target hostname */
  if (!cmd->target_ip) {
    /* Hack: try to use the first extra argument as a hostname otherwise */
    if (optind < argc) {
      cmd->target_ip = argv[optind];
      ++optind;
    } else {
      fprintf(stderr, "Make sure you specify a hostname!\n\n");
      usage(argv[0]);
    }
  }

  /* Make sure command line had correct syntax */
  switch (cmd->command_to_run) {
    case CMD_REBOOT:
    case CMD_SYSRQ:
    case CMD_DMESG:
      /* for any of those commands, there should be no extra argument on the
         command line */
      if (optind != argc)
        usage(argv[0]);
      break;
    case CMD_FORK_EXEC:
    case CMD_DIRECT_EXEC:
    case CMD_DEFAULT:
      if (optind == argc) {
        /* Nothing on the command line, just run a shell */
        cmd->target_argv = default_argv;
        cmd->target_argc = 2;
      } else if (exclusive_flag == FLAG_C) {
        if ((argc - optind) == 1) {
          bin_sh_c_argv[2] = argv[optind];
          cmd->target_argv = bin_sh_c_argv;
          cmd->target_argc = 3;
          ++optind;
        } else {
          fprintf(stderr, "-c only accepts one shell command. "
                          "Make sure you use quotes!\n\n");
          usage(argv[0]);
        }
      } else if (exclusive_flag == FLAG_E) {
        /* an execve command has been specified */
        cmd->target_argc = argc - optind;
        cmd->target_argv = argv + optind;
      } else {
        /* wrong number of arguments */
        usage(argv[0]);
      }
  }
}

static ssize_t serialize_command(GG_ptr *payload, size_t maxlen, int argc,
                                 char *argv[]) {
  /* get our own copy of the payload pointer */
  GG_ptr buf = ggp_clone(payload);
  size_t len = 0;
  ssize_t ret;
  int i;

  if (argc > GG_CMD_MAX_ARGC || argc < 1) {
    REPORT_INFO("Too many arguments in your command: %d\n", argc);
    return -1;
  }

  if (maxlen < sizeof(uint32_t) || maxlen > SSIZE_MAX)
    return -1;

  encode_uint32(&buf, argc);
  len += sizeof(uint32_t);

  for (i = 0; i < argc; i++) {

    ret = encode_string(&buf, argv[i], maxlen - len);
    if (ret < 0) {
      REPORT_INFO("Could not encode arguments, command line may be too long\n");
      return -1;
    }
    /* encode_string will return something smaller than maxlen - len, so len
     * will stay smaller than maxlen
     */
    len += ret;
  }

  DEBUG(2, "serialized command %s, total length: %zi\n", argv[0], len);

  return (ssize_t) len;
}

static int connect_and_init_session(GG_cnx *cnx, GG_crypt *ggc,
                                    char *target_ip, char *target_port) {
  char buffer[GG_PKT_MAX_SIZE];
  int tcp_sock;
  GG_ptr buf = ggp_init(buffer, sizeof(buffer));
  GG_packet pkt;
  int ret;

  tcp_sock = connect_to_remote(target_ip, target_port);
  if (tcp_sock < 0)
    return -1;

  gg_cnx_init(cnx, tcp_sock, "some-gg-client", target_ip, ggc, 0);

  if (gg_packet_init(&pkt, &buf, sizeof(buffer)))
    return -1;

  ret = do_start_session_client(cnx, &pkt);
  if (ret) {
    REPORT_INFO("Could not authenticate to the server\n");
    return -1;
  }

  DEBUG(2, "CLIENT: started session correctly!\n");
  if (cnx->remote_strong_id) {
    REPORT_INFO
      ("Successfully authenticated to a server pretending to be %s\n",
       cnx->remote_strong_id);
  } else {
    REPORT_INFO
      ("Successfully authenticated to a server that didn't send an identity\n");
  }

  return 0;
}

/*
 * Send a request to fork/execve (and then act as a forwarder for stdin/stdout)
 * or to direct execve() (and then read()/write() the socket to stdout)
 * depending on cmd_type
 *
 * Return 0 on success, -1 on any error
 */
static int remote_cmd_execve(GG_cnx *cnx, int argc, char *argv[], int cmd_type) {
  char buffer[GG_PKT_MAX_SIZE];
  GG_ptr buf = ggp_init(buffer, sizeof(buffer));
  GG_packet pkt;
  ssize_t size;
  int ret;
  int payload_type;

  switch (cmd_type) {
    case CMD_FORK_EXEC:
      payload_type = GG_PAYLOAD_CMD_FORK_EXECVE;
      break;
    case CMD_DIRECT_EXEC:
      fprintf(stderr, "*Warning*: integrity of packets will not "
                      "be guaranteed!\n");
      payload_type = GG_PAYLOAD_CMD_DIRECT_EXECVE;
      break;
    default:
      return -1;
  }

  if (gg_packet_init(&pkt, &buf, sizeof(buffer)))
    return -1;

  size = serialize_command(&pkt.payload, pkt.max_payload_size, argc, argv);
  if (size <= 0)
    return -1;

  REPORT_INFO("Sending command %s with %d other argument(s)\n", argv[0],
              argc - 1);

  if (gg_packet_set_payload(&pkt, payload_type, size) ||
      gg_packet_put_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not send command request\n");
    return -1;
  }

  switch (cmd_type) {
    case CMD_FORK_EXEC:
      return do_fw_in_out(cnx, STDIN_FILENO, STDOUT_FILENO, NULL, NULL, 0);
    case CMD_DIRECT_EXEC:
      /* loop until read or write fails */
      do {
        ret = ggp_read(cnx->socket, &buf, sizeof(buffer));
        if (ret > 0) {
          ret = ggp_full_write(STDOUT_FILENO, &buf, ret);
        }
      } while (ret > 0);

      /* the socket was probably closed or there was an error reading */
      return ret;
    default:
      return -1;
  }
}

/* Read a big endian int32_t in a packet and report it
 *
 * Returns 0 on success, -1 on error
 */
static int report_server_code(GG_packet *pkt) {
  int32_t ret;

  if (pkt->payload_size != 4) {
    REPORT_INFO("Server returned a malformed error\n");
    return -1;
  } else {
    ret = ggp_get_uint32(&pkt->payload);
    REPORT_INFO("Server returned error %d\n", ret);
    return 0;
  }
}

static int remote_cmd_sysrq(GG_cnx *cnx, char command) {
  char buffer[GG_PKT_MAX_SIZE];
  const char sysrq[] = "/proc/sysrq-trigger";
  GG_ptr buf = ggp_init(buffer, sizeof(buffer));
  GG_packet pkt;

  if (gg_packet_init(&pkt, &buf, sizeof(buffer)))
    return -1;

  /* We need to wire the string + the char */
  if (sizeof(sysrq) + 1 > pkt.max_payload_size)
    return -1;

  /* Copy the string to the payload and then the command */
  ggp_memcpy(&pkt.payload, sysrq, sizeof(sysrq));
  ((char *)pkt.payload.ptr)[sizeof(sysrq)] = command;

  REPORT_INFO("Sending sysrq command %c\n", command);

  if (gg_packet_set_payload(&pkt, GG_PAYLOAD_CMD_WRITE_FILE,
                            sizeof(sysrq) + 1) ||
      gg_packet_put_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not send command request\n");
    return -1;
  }

  /* FIXME: add timeout */
  if (gg_packet_get_full(cnx, &pkt) <= 0) {
    /* Some sysrq will never return */
    REPORT_INFO("Could not read answer from server, this could be expected\n");
    return 0;
  } else {
    report_server_code(&pkt);
    return -1;
  }
}

static int remote_cmd_dmesg(GG_cnx *cnx) {
  char buffer[GG_PKT_MAX_SIZE];
  GG_ptr buf = ggp_init(buffer, sizeof(buffer));
  GG_packet pkt;

  if (gg_packet_init(&pkt, &buf, sizeof(buffer)))
    return -1;
  REPORT_INFO("Sending dmesg command\n");

  if (gg_packet_set_payload(&pkt, GG_PAYLOAD_CMD_DMESG, 0) ||
      gg_packet_put_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not send command request\n");
    return -1;
  }

  if (gg_packet_get_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not read answer from server\n");
    return -1;
  }

  switch (pkt.payload_type) {
    case GG_PAYLOAD_INT:
      /* The server returned an error, report it */
      report_server_code(&pkt);
      return -1;
    case GG_PAYLOAD_DATA:
      /* write dmesg output to stdout, don't handle errors */
      fwrite(pkt.payload.ptr, pkt.payload_size, 1, stdout);
      return 0;
    default:
      return -1;
  }
}

static int remote_cmd_reboot(GG_cnx *cnx) {
  char buffer[GG_PKT_MAX_SIZE];
  GG_ptr buf = ggp_init(buffer, sizeof(buffer));
  GG_packet pkt;
  int ret;

  if (gg_packet_init(&pkt, &buf, sizeof(buffer)))
    return -1;
  REPORT_INFO("Sending reboot command\n");

  if (gg_packet_set_payload(&pkt, GG_PAYLOAD_CMD_REBOOT, 0) ||
      gg_packet_put_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not send command request\n");
    return -1;
  }

  /* poll the connection for 1s */
  switch (ret = gg_can_read(cnx, 1000)) {
    default:
    case -1:
      DEBUG(1, "gg_can_read returned -1: %m\n");
      return -1;
    case 0:
      REPORT_INFO("Timed out while waiting for the server to answer. This is "
                  "expected.\n");
      return 0;
    case 1:
      /* We know that gg_packet_get() wouldn't block, but we have no indication
       * about gg_packet_get_full. However in practice a non adversarial server
       * won't make us block.
       */
      if (gg_packet_get_full(cnx, &pkt) <= 0) {
        /* In the server, reboot() will never return */
        REPORT_INFO("Could not read answer from server, this is expected\n");
        return 0;
      } else {
        report_server_code(&pkt);
        return -1;
      }
  }
}

static int connect_to_remote(char *remote_host, char *remote_port) {
  int tcp_sock;
  int ret;
  struct addrinfo hints;
  struct addrinfo *result;
  struct sockaddr_in6 client_socket;
  socklen_t client_socket_sl = sizeof(client_socket);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints = (struct addrinfo) {
    .ai_family = AF_INET6,
    .ai_socktype = SOCK_STREAM,
    .ai_flags = AI_NUMERICSERV | AI_CANONNAME | AI_V4MAPPED,
    .ai_protocol = 0,
  };

  ret = getaddrinfo(remote_host, remote_port, &hints, &result);

  if (ret) {
    REPORT_INFO("Invalid IP address or could not resolve hostname: %s\n",
                remote_host);
    return -1;
  }

  REPORT_INFO("Connecting to %s [%s]\n", result->ai_canonname, remote_host);

  tcp_sock =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (tcp_sock == -1) {
    REPORT_ERRNO("Could not create socket");
    freeaddrinfo(result);
    return -1;
  }

  ret = connect(tcp_sock, result->ai_addr, result->ai_addrlen);

  if (ret) {
    REPORT_ERRNO("Could not connect");
    freeaddrinfo(result);
    return -1;
  }

  ret = getsockname(tcp_sock, (struct sockaddr *) &client_socket,
                    &client_socket_sl);
  if (ret) {
    REPORT_ERRNO("Could not get local socket information");
    freeaddrinfo(result);
    return -1;
  }

  REPORT_INFO("Connected to %s [%s] from port %d\n", result->ai_canonname,
              remote_host, (int) ntohs(client_socket.sin6_port));

  freeaddrinfo(result);
  return tcp_sock;
}
