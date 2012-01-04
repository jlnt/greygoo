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

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/klog.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "gg-packet.h"
#include "gg-server.h"
#include "gg-protocol.h"
#include "report.h"

static int do_process_packets(GG_cnx *cnx);
static int cmd_fork_execve(GG_cnx *cnx, GG_packet *cmd_pkt);
__attribute__((noreturn)) static void cmd_direct_exec(GG_cnx *cnx,
                                                      GG_packet *cmd_pkt);
static int cmd_reboot(GG_cnx *cnx, GG_packet *cmd_pkt);
static int cmd_write_file(GG_cnx *cnx, GG_packet *cmd_pkt);
static int cmd_dmesg(GG_cnx *cnx, GG_packet *cmd_pkt);

/*
 * Entry point for the server
 *
 * We have a new connection to handle, in a process of our own.
 *
 * When we return, the process will exit(). It's also ok to just execve()
 * something.
 */
int do_handle_connection(GG_cnx *cnx) {
  int ret;

  //ret = write(socket, "hello!\n\n", 8);

  ret = do_process_packets(cnx);

  if (ret == 0)
    REPORT_INFO("Connection with %s closed, pid %d exiting\n", cnx->remote_id,
                getpid());
  else
    REPORT_INFO("Protocol error with %s, pid %d exiting\n", cnx->remote_id,
                getpid());

  close(cnx->socket);
  return 0;
}

/*
 * Deserialize a GG_PAYLOAD_RUN_COMMAND payload
 *
 * Returns -1 on error or the number of argument (argc) on success
 */
static int parse_execve_payload(GG_ptr *payload, size_t totallen,
                                 char *argv[], int maxargc) {
  size_t parsed = 0;
  ssize_t ret;
  int argc;
  int i;
  GG_ptr commands;

  if (!payload || maxargc < 1 || totallen < sizeof(uint32_t))
    return -1;

  /* clone the gg pointer */
  commands = ggp_clone(payload);

  argc = parse_uint32(&commands);
  parsed += sizeof(uint32_t);

  DEBUG(2, "Decoding %d arguments\n", argc);

  /* maxargc - 1 because we need one slot for NULL */
  if (argc < 0 || argc > maxargc - 1)
    return -1;

  for (i = 0; i < argc; i++) {
    if ((ret = parse_string(&commands, totallen - parsed)) <= 0)
      return -1;
    /* start at the end of the previous string */
    argv[i] = payload->ptr + parsed;
    DEBUG(2, "stacked new arguments: %s\n", argv[i]);
    /* ret is <= totallen - parsed, to parsed will stay <= totallen */
    parsed += ret;
  }

  /* NULL terminate argv */
  argv[argc] = NULL;

  return argc;
}

extern char **environ;

static char *const minimal_env[] = {
  "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
  "PS1=GG (\\s-\\v\\$) ",
  NULL
};

/*
 * Start processing packets to and from the client.
 *
 * We will first authenticate the client, then we will process the commands and
 * requests they send to us.
 *
 * Returns -1 on protocol error, 0 otherwise
 *
 * FIXME: we allocate an extra buffer here, rationalize this so that we don't
 *  waste space.
 */
static int do_process_packets(GG_cnx *cnx) {
  static char buffer[GG_PKT_MAX_SIZE];
  GG_ptr packet_buffer;
  GG_packet pkt;
  int ret;

  packet_buffer = ggp_init(buffer, sizeof(buffer));

  /* initialize our pkt structure */
  if (gg_packet_init(&pkt, &packet_buffer, sizeof(buffer)))
      return -1;

  /* try to start a session and authenticate the client */
  ret = do_start_session_server(cnx, &pkt);

  if (ret) {
    REPORT_INFO("Error occured while trying to authenticate %s\n",
                cnx->remote_id);
    return -1;
  }

  REPORT_INFO("Remote %s authenticated successfully!\n", cnx->remote_id);

  if (gg_packet_get_full(cnx, &pkt) <= 0) {
    REPORT_INFO("Could not get command request\n");
    return -1;
  }

  /* Switch between all the commands we support */
  switch (pkt.payload_type) {
    case GG_PAYLOAD_CMD_DIRECT_EXECVE:
      cmd_direct_exec(cnx, &pkt);
      /* This is dead code */
      exit(EXIT_FAILURE);
    case GG_PAYLOAD_CMD_FORK_EXECVE:
      ret = cmd_fork_execve(cnx, &pkt);
      return ret;
    case GG_PAYLOAD_CMD_REBOOT:
      ret = cmd_reboot(cnx, &pkt);
      return ret;
    case GG_PAYLOAD_CMD_WRITE_FILE:
      ret = cmd_write_file(cnx, &pkt);
      return ret;
    case GG_PAYLOAD_CMD_DMESG:
      ret = cmd_dmesg(cnx, &pkt);
      return ret;
    default:
      REPORT_INFO("Unknown command request\n");
      return -1;
  }
}

/* Read the kernel ring buffer. We only read the last bytes, up to the size of
 * the payload.
 * Unfortunately we couldn't iterate to send the whole ring buffer in multiple
 * packets because the kernel doesn't allow doing that without allocating a
 * giant temporary buffer.
 *
 * Return -1 on protocol error, 0 otherwise
 */
static int cmd_dmesg(GG_cnx *cnx, GG_packet *cmd_pkt) {
  int len;

  REPORT_INFO("Got a request to send the kernel ring buffer\n");
  /* execute the syslog(SYSLOG_ACTION_READ_ALL, buf, len) system call via the
   * libc wrapper
   */
  len = klogctl(3, cmd_pkt->payload.ptr, cmd_pkt->max_payload_size);

  /* Did the kernel return an error ? */
  if (len < 0 || (unsigned int) len > cmd_pkt->max_payload_size) {
    /* return -1 as a 32 bits uint in network order */
    ggp_put_uint32(&cmd_pkt->payload, -1);
    if (gg_packet_set_payload(cmd_pkt, GG_PAYLOAD_INT, sizeof(uint32_t)) ||
        gg_packet_put_full(cnx, cmd_pkt) <= 0)
      return -1;
    else
      return 0;
  } else {
    /* return the ring buffer in the payload */
    if (gg_packet_set_payload(cmd_pkt, GG_PAYLOAD_DATA, len) ||
        gg_packet_put_full(cnx, cmd_pkt) <= 0)
      return -1;
    else
      return 0;
  }
}

/* Open a file in append mode, write to it, possibly blocking and close it
 *
 * Returns -1 on error, 0 on success
 */
static int do_open_write(const char *file, const GG_ptr *data, size_t size) {
  int fd;
  int ret = 0;
  if (size > SSIZE_MAX)
    return -1;

  fd = open(file, O_WRONLY, O_APPEND);
  if (fd < 0) return -1;

  if (ggp_full_write(fd, data, size) != (ssize_t) size)
    ret = -1;

  if (close(fd))
    ret = -1;

  return ret;
}

/*
 * Append data to a file
 *
 * Decode a string from the payload for the filename and consider
 * the remaining part of the payload as data to write.
 *
 * Report any error to the client (this is not considered a protocol error)
 *
 * cmd_pkt must be a packet structure with max_payload_size big enough for
 * our reply (4 bytes)
 *
 * Return -1 on protocol error, 0 otherwise
 */
static int cmd_write_file(GG_cnx *cnx, GG_packet *cmd_pkt) {
  ssize_t ret;
  GG_ptr unparsed = ggp_clone(&cmd_pkt->payload);

  ret = parse_string(&unparsed, cmd_pkt->payload_size);

  /* Make sure we did find a string and there is actual data to write */
  if (ret < 0 || ret >= cmd_pkt->payload_size)
    return -1;

  /* the payload points to the start of our file name, unparsed to the extra
   * data to write
   */
  REPORT_INFO("Write request to %s\n", (char *) cmd_pkt->payload.ptr );
  ret = do_open_write(cmd_pkt->payload.ptr, &unparsed,
        cmd_pkt->payload_size - ret);

  if (cmd_pkt->max_payload_size < sizeof(uint32_t))
    return -1;

  /* return ret encoded as a 32 bits uint in network order */
  ggp_put_uint32(&cmd_pkt->payload, ret);
  if (gg_packet_set_payload(cmd_pkt, GG_PAYLOAD_INT, sizeof(uint32_t)) ||
      gg_packet_put_full(cnx, cmd_pkt) <= 0)
    return -1;

  return 0;
}

/* Reboot the system via the reboot() system call.
 *
 * Notify the client if it fails and we have enough space
 * in the packet buffer.
 *
 * - Does not return if reboot sucessful
 * - Returns 0 if reboot not successful but client was notified
 * - Returns -1 on protocol error
 *
 * Note that if reboot() itself fails, it's not a protocol
 * error
 */
static int cmd_reboot(GG_cnx *cnx, GG_packet *cmd_pkt) {
  int ret;

  REPORT_INFO("Got a request to reboot\n");
  ret = reboot(RB_AUTOBOOT);

  /* If reboot() returns, it's an error, notify the client */
  REPORT_INFO("reboot() system call failed\n");
  if (cmd_pkt->max_payload_size < sizeof(uint32_t))
    return -1;

  ggp_put_uint32(&cmd_pkt->payload, ret);

  if (gg_packet_set_payload(cmd_pkt, GG_PAYLOAD_INT, sizeof(uint32_t)) ||
      gg_packet_put_full(cnx, cmd_pkt) <= 0)
    return -1;

  return 0;
}

/*
 * Direct exec without fork. The executed command will have /dev/null as stdin
 * and will have its output / stderr directly connected to the socket.
 *
 * Hence, there will be no packet integrity at all with this command
 *
 * This is a fail-safe command and should be avoided if possible.
 *
 * There is nothing that would prevent this command from running forever.
 *
 * This function does not return
 */
__attribute__((noreturn)) static void cmd_direct_exec(GG_cnx *cnx,
                                                      GG_packet *cmd_pkt) {
  char *argv[GG_CMD_MAX_ARGC + 1];
  int argc;
  int dev_null;

  /* We have a request to run a command */
  REPORT_INFO("Got a request to fast-execve\n");

  argc =
      parse_execve_payload(&cmd_pkt->payload, cmd_pkt->payload_size, argv,
                            GG_CMD_MAX_ARGC + 1);

  if (argc < 1) {
    REPORT_INFO("Could not parse the remote command\n");
  } else {
    REPORT_INFO("Executing command %s with %d other argument(s)\n", argv[0],
                argc - 1);

    dev_null = open("/dev/null", O_RDONLY);

    if (dev_null > -1) {
      /* STDOUT and STDERR only, no STDIN */
      dup2(dev_null, STDIN_FILENO);
      dup2(cnx->socket, STDOUT_FILENO);
      dup2(cnx->socket, STDERR_FILENO);
      close(cnx->socket);
      close(dev_null);

      execve(argv[0], argv, minimal_env);
      fprintf(stderr, "Could not run command: %m\n");
    }
  }

  _exit(EXIT_FAILURE);
}

/* reap_child is a global variable set by the SIGCHLD signal handler */
int reap_child;

/* It's good pratice to have the signal handler just set a global variable
 * so that we don't have to worry about re-entrant functions.
 *
 * Functions that check for reap_child should be called with SIGCHLD blocked
 * and should reset it to 0 after the check;
 */
static void sigchld_handler(int signal __attribute__((unused))) {
  reap_child = 1;
}

/*
 * Setup our signal mask and actions for a ppoll() or pselect() loop.
 * See header file.
 */
int setup_sigchld_watcher(sigset_t *oldmask) {
  struct sigaction sa;
  sigset_t sigchld;

  /* Block SIGCHLD in the calling thread (1) */
  if (sigemptyset(&sigchld) || sigaddset(&sigchld, SIGCHLD) ||
      sigprocmask(SIG_BLOCK, &sigchld, oldmask)) {
    REPORT_ERRNO("Error generating sigset or setting signal mask");
    return -1;
  }

  /* Set the signal handler for SIGCHLD and make sure we don't block SIGCHLD
   * in oldmsk even if we were previously (2)
   */
  sa = (struct sigaction) {
    .sa_handler = sigchld_handler,
    .sa_mask = sigchld,
    .sa_flags = SA_NOCLDSTOP,
  };

  if (sigaction(SIGCHLD, &sa, NULL) || sigdelset(oldmask, SIGCHLD)) {
    REPORT_ERRNO("Sigaction failed or error generating sigset");
    return -1;
  }

  return 0;
}

/* wait() for pid if global variable "reap_child" is set
 * Never blocks.
 * resets reap_child to 0
 * Should be called with SIGCHLD blocked
 *
 * Returns 1 if pid was reaped, 0 otherwise
 */
static int handle_sigchld_wait_for_pid(pid_t pid) {
  int ret;

  ret = reap_child;
  /* reset reap_child no matter what */
  reap_child = 0;

  if (ret) {
    ret = waitpid(pid, NULL, WNOHANG);

    if (ret == pid)
      return 1;
  }
  return 0;
}

/*
 * fork() and execve() in interactive mode
 * This is used, for instance to run a shell
 */
static int cmd_fork_execve(GG_cnx *cnx, GG_packet *cmd_pkt) {
  int sv[2];
  int argc, ret;
  pid_t pid;
  sigset_t sigmsk;
  /* keep an additional space for NULL */
  char *argv[GG_CMD_MAX_ARGC + 1];

  /* We have a request to run a command */
  REPORT_INFO("Got a request to fork/execve\n");

  argc =
      parse_execve_payload(&cmd_pkt->payload, cmd_pkt->payload_size, argv,
                            GG_CMD_MAX_ARGC + 1);

  if (argc < 1) {
    REPORT_INFO("Could not parse the remote command\n");
    return -1;
  } else {
    REPORT_INFO("Executing command %s with %d other argument(s)\n", argv[0],
                argc - 1);
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
    DEBUG(0, "Could not get a socket pair\n");
    return -1;
  }

  switch (pid = fork()) {
  case -1:
    DEBUG(0, "Could not fork\n");
    return -1;
  case 0:
    dup2(sv[1], STDIN_FILENO);
    dup2(sv[1], STDOUT_FILENO);
    dup2(sv[1], STDERR_FILENO);
    close(cnx->socket);
    /* close both ends of the socket pair. The end we care about is dup2-ed
       already */
    close(sv[0]);
    close(sv[1]);
    execve(argv[0], argv, minimal_env);
    fprintf(stderr, "Could not run command: %m\n");
    _exit(EXIT_FAILURE);
  default:
    close(sv[1]);
    if (setup_sigchld_watcher(&sigmsk))
      return -1;

    ret = do_fw_in_out(cnx, sv[0], sv[0], &sigmsk,
                       handle_sigchld_wait_for_pid, pid);
    break;
  }

  return ret;
}
