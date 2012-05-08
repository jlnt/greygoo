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
 * Grey Goo server daemon
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "report.h"
#include "gg-crypto.h"
#include "gg-server.h"
#include "gg-utils.h"

/* Number of pre-forked workers */
#define DEFAULT_GG_WORKERS 2

/* This value must be kept reasonable and will be used as a second argument to
 * ppoll(2)
 */
#define GG_MAX_WORKERS 32

/* Don't create a PID file by default */
#define DEFAULT_GG_PID_FILE NULL

/* Magic string to pass to -t to enable the test key */
#define ENABLE_TESTKEY_MAGIC "enable_test_key"

GG_crypt *bind_keys_and_init_crypto(int use_test_key);
static void do_gg_factory(int tcp_sock, unsigned int gg_workers,
                          GG_crypt *ggc, char *server_id);

__attribute__ ((noreturn))
static void do_gg_worker(int tcp_sock, int notifier, GG_crypt *ggc,
                         char *server_id);
static int listen_on_port(in_port_t port);
static void usage(char *name);
static int daemonize(void);
static int get_server_id(char *buf, size_t len);
static int create_pid_file(char *path);

int main(int argc, char *argv[]) {
  int tcp_sock;
  int ch;
  in_port_t port = GG_PORT;
  int priority = -1;
  /* command line arguments: force background or foreground? */
  int arg_force_bg = 0;
  int arg_force_fg = 0;
  int arg_use_test_key = 0;
  int arg_num_workers = DEFAULT_GG_WORKERS;
  char *arg_pid_file = DEFAULT_GG_PID_FILE;
  GG_crypt *ggc = NULL;

  char server_id[GG_SERVER_ID_MAX_LEN];

  printf("Grey Goo server\n\n");

  if (report_init()) {
    fprintf(stderr, "Cannot initialize error reporting\n");
    return EXIT_FAILURE;
  }
  debug_setlevel(0);

  while ((ch = getopt(argc, argv, ":bfp:d:n:t:i:w:")) != -1) {
    switch (ch) {
    case 'b':
      arg_force_bg = 1;
      break;
    case 'f':
      arg_force_fg = 1;
      break;
    case 'p':
      port = (in_port_t) atoi(optarg);
      break;
    case 'd':
      debug_setlevel(atoi(optarg));
      break;
    case 'n':
      priority = atoi(optarg);
      if (priority > 0)
        fprintf(stderr, "Warning: you're giving Grey Goo *less* priority\n");
      break;
    case 't':
      if (strcmp(optarg, ENABLE_TESTKEY_MAGIC)) {
        fprintf(stderr,
                "The magic string to enable the test key was incorrect\n");
        usage(argv[0]);
        return EXIT_FAILURE;
      } else {
        arg_use_test_key = 1;
      }
      break;
    case 'i':
      if (*optarg == '/') {
        arg_pid_file = optarg;
      } else {
        fprintf(stderr, "PID file needs to be an absolute path\n");
        return EXIT_FAILURE;
      }
      break;
    case 'w':
      arg_num_workers = atoi(optarg);
      if (arg_num_workers < 1 || arg_num_workers > GG_MAX_WORKERS) {
        fprintf(stderr, "Invalid number of workers (should be in [1-%d])\n",
                GG_MAX_WORKERS);
        return EXIT_FAILURE;
      }
      break;
    default:
      usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  /*
   * No extra arguments on the command line. FG and BG are mutually
   * exclusive
   */
  if (argc != optind || (arg_force_bg && arg_force_fg)) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  tcp_sock = listen_on_port(port);
  if (tcp_sock == -1)
    return EXIT_FAILURE;
  else
    REPORT_INFO("Grey Goo starting on port %hu\n", port);

  if (get_server_id(server_id, sizeof(server_id))) {
    REPORT_INFO("Could not get any server id\n");
    return EXIT_FAILURE;
  }
#ifdef GG_DEBUG
  /* default to foreground mode in debug mode */
  if (!arg_force_bg) {
    DEBUG(0, "Grey Goo is compiled in debug mode and will not go to the "
             "background unless -b is specified\n\n");
    arg_force_fg = 1;
  }
#endif

  if (!arg_force_fg) {
    if (daemonize())
      return EXIT_FAILURE;
  } else {
    /* If we don't want to become a deamon we should still get rid of our
     * controlling terminal or job control will affect our workers
     *
     * (daemonize() takes care of that via setsid())
     */
    int tty;
    tty = open("/dev/tty", O_RDONLY);
    if (tty != -1) {
      /* if we do have a TTY, detach from it */
      if (ioctl(tty, TIOCNOTTY, NULL) || close(tty)) return -1;
    }
  }

  if (arg_pid_file && create_pid_file(arg_pid_file)) {
    REPORT_INFO("Could not create PID file %s\n", arg_pid_file);
    return EXIT_FAILURE;
  }

  /* Change priority, OOM score and commit all memory
   * Priority and OOM score are inherited
   */
  if (become_bullet_proof(priority)) {
    REPORT_INFO("Grey Goo could not become bullet proof. Continuing anyway.\n");
  }

  ggc = bind_keys_and_init_crypto(arg_use_test_key);
  if (!ggc)
    return EXIT_FAILURE;

  /* start and maintain a bunch of accept() workers */
  do_gg_factory(tcp_sock, arg_num_workers, ggc, server_id);

  /* if we return here, we have a serious initialization error */
  close(tcp_sock);

  return EXIT_FAILURE;
}

/* Bind the correct RSA public key and initialize the crypto
 * Returns a valid GG_crypt pointer on success, NULL on failure
 */
GG_crypt *bind_keys_and_init_crypto(int use_test_key) {
#ifdef GG_USE_OPENSSL
/* We will link the public key */
extern unsigned char _binary_public_keys_rsa_public_root_pem_start[];
extern unsigned char _binary_public_keys_rsa_public_root_pem_end[];
extern unsigned char _binary_public_keys_rsa_public_test_pem_start[];
extern unsigned char _binary_public_keys_rsa_public_test_pem_end[];
#endif

  GG_crypt *ggc;

  ggc = crypto_global_init();
  if (!ggc) {
    REPORT_ERROR("Could not initialize crypto");
    return NULL;
  }

  /* Initialize the public key we will use for verification */
#ifdef GG_USE_OPENSSL
  if (use_test_key) {
    if (crypto_verify_setkey(ggc, _binary_public_keys_rsa_public_test_pem_start,
          _binary_public_keys_rsa_public_test_pem_end -
          _binary_public_keys_rsa_public_test_pem_start)) {
      REPORT_ERROR("Could not initialize RSA (test) public key");
      return NULL;
    }
  } else {
    /* Real (root) key */
    if (crypto_verify_setkey(ggc, _binary_public_keys_rsa_public_root_pem_start,
          _binary_public_keys_rsa_public_root_pem_end -
          _binary_public_keys_rsa_public_root_pem_start)) {
      REPORT_ERROR("Could not initialize RSA (root) public key");
      return NULL;
    }
  }
#else
  if (use_test_key) {
    if (crypto_verify_setkey(ggc, NULL, KEYIDX_TEST)) {
      REPORT_ERROR("Could not initialize (test) RSA public key");
      return NULL;
    }
  } else {
    if (crypto_verify_setkey(ggc, NULL, KEYIDX_ROOT)) {
      REPORT_ERROR("Could not initialize (root) RSA public key");
      return NULL;
    }
  }
#endif
  if (use_test_key)
    REPORT_INFO("Grey goo initialized with testing key\n");
  return ggc;
}

/* sleep for at most 500ms. We could be waken up by a non blocked signal.
 * Die on error.
 */
void sleep_or_die(void) {
  int ret;

  ret = usleep(500000); /* sleep for 500ms */
  if (ret == -1 && errno != EINTR)
    FATAL("Could not sleep");
}

/*
 * Start and maintain gg_workers pre-forked and pre-initialized Grey Goo
 * workers that can accept() a connection on the given socket.
 *
 * gg_workers must be comprised between 1 and GG_MAX_WORKERS.
 *
 * Even if the main ggd process dies, workers that have already started can
 * accept commands (but won't be restarted).
 *
 * We have a main event loop (using ppoll()) that currently takes care of two
 * things:
 *  1. Restart any worker that has started a job or has died unexpectedly
 *  2. Reap any dead child
 *
 * For this we watch for two events with ppoll():
 *  1. A pipe shared with the worker becomes non blocking for reading
 *   (it got closed or something got written to it)
 *  2. Reception of a SIGCHLD signal
 *
 * (1) is a robust way of knowing if the worker accept()-ed a new connection or
 * died unexpectedly for any reason.
 */
static void do_gg_factory(int tcp_sock, unsigned int gg_workers,
                          GG_crypt *ggc, char *server_id) {
  int (*pipes)[2] = NULL; /* used as: int pipes[gg_workers][2]; */
  struct pollfd *pfds = NULL; /* used as: struct pollfd pfds[gg_workers] */
  unsigned int i, j;
  int ret, pret;
  const int ignored_fd = -1; /* Fake fd that will be ignored by poll */
  pid_t pid;
  sigset_t ppoll_mask;

  /* It's a depressing truth, but calloc() implementations *do* overflow */
  if (!ggc || gg_workers < 1 || gg_workers > GG_MAX_WORKERS ||
      SIZE_MAX / sizeof(*pipes) < gg_workers ||
      SIZE_MAX / sizeof(*pfds) < gg_workers) {
    REPORT_ERROR("Too many workers requested\n");
    goto out;
  }

  /* Allocate on heap instead of stack so space is not wasted in our workers.
   */
  pipes = calloc(gg_workers, sizeof(*pipes));
  if (!pipes)
    goto out;
  pfds = calloc(gg_workers, sizeof(*pfds));
  if (!pfds)
    goto out;

  /*
   * initialize all pipe ends to -1 so that we can know what to close and not
   * close
   */
  for (i = 0; i < gg_workers; i++) {
    pipes[i][0] = -1;
    pipes[i][1] = -1;
  }

  /* We will jump right into the loop and need a decent initial state.
   *
   * To start all of the workers in the first iteration, we "emulate" a
   * situation where poll notifies us that all of our workers have died.
   */
  for (i = 0; i < gg_workers; i++) {
    pfds[i].fd = ignored_fd;
    pfds[i].revents = POLLIN;
  }
  pret = gg_workers;

  /* Block SIGCHLD and have it unblocked in "ppoll_mask" that we can pass to
   * ppoll()
   * Setups a signal handler that sets a global "reap_child" variable when a
   * SIGCHLD is caught.
   */
  if (setup_sigchld_watcher(&ppoll_mask))
    goto out;

  /* our main event loop where we handle signals and messages from childs */
  do {
    int status;
    DEBUG(2, "ggd event loop: poll returned %d (%d)\n", pret, getpid());

    /* Did we get interrupted to handle signals ? */
    if (pret == -1) {
      /* handle signals */

      /* Reap childs if needed */
      if (reap_child) {
        /*
         * reap all childs. We can't know how many in advance because SIGCHLD
         * is not a real time signal and can't be queued.
         *
         * It's also possible that a child terminates while signals are blocked
         * (that is outside of the ppoll system call) and that we pre-emptively
         * reap this child now before the signal has been delivered.
         * So it's not an error if there are no childs to reap.
         */
        while ((ret = waitpid(-1, &status, WNOHANG)) > 0)
          DEBUG(2, "ggd event loop: reaped child %d\n", ret);

        if (ret < 0 && errno != ECHILD)
          REPORT_ERRNO("error with waitpid");

        /*
         * There is no more child to reap or there was an error and we should
         * stop reaping anyway
         */
        reap_child = 0;
      }

      /* TODO: any other signals we could wish to handle here ? */

    } else {
      /* ppoll returned a positive value */

      /* find out what workers we should start */
      for (i = 0; i < gg_workers; i++) {
        DEBUG(2, "ggd event loop: worker %d has revents: 0x%X\n", i,
              pfds[i].revents);
        /* go to the next worker if we don't have any event */
        if (!pfds[i].revents)
          continue;

        if (!(pfds[i].revents & (POLLIN | POLLHUP))) {
          /*
           * If anything we don't understand happens, we sleep
           */
          REPORT_ERRNO("Got unexpected ppoll event");
          DEBUG(1, "Unexpected event: 0x%X\n", pfds[i].revents);
          sleep_or_die();
        } else {
          /* we need to restart worker i */

          /* create a new pipe for this worker */
          ret = pipe(pipes[i]);
          if (ret) {
            REPORT_ERRNO("Could not create pipe\n");
            sleep_or_die();
            continue;
          }

          /* Sleep for 100ms to throttle the forking of new workers. If our
           * children start dying right away (maybe because of a connect DoS or
           * because the machine is hosed), we don't want to ever initialize
           * more than 10 workers per second
           */
          usleep(100000);
          pid = fork();

          if (pid == -1) {
            /* fork failed, let's sleep before resuming the loop, in the next
             * ppoll loop iteration, we'll try and fork again for this
             * worker
             * Note: if this happen during initialization (the first ever
             * iteration) the fd is -1 and won't ever return an event. This
             * worker will never get activated. This is what we want.
             */
            sleep_or_die();

            /* in any case, we have to close the pipe open above.
             * We do it after sleeping in hope it decreases chances
             * of failure */
            close(pipes[i][0]);
            close(pipes[i][1]);
            /* mark as closed */
            pipes[i][0] = -1;
            pipes[i][1] = -1;

            REPORT_ERROR("Fork failed");
          } else {
            /* Fork succeedded, we don't need that pipe end anymore,
             * close it (in both child and parent) */
            if (pfds[i].fd != ignored_fd && close(pfds[i].fd))
              REPORT_ERRNO("Could not close fd");

            if(!pid) {
              int notif_pipe;
              /* child */
              /* close all the reader ends
               * (at this point we only have one writer end open, the others had
               * already been closed in the parent)
               */
              for (j = 0; j < gg_workers; j++) {
                if (pipes[j][0] != -1)
                  close(pipes[j][0]);
              }
              notif_pipe = pipes[i][1];
              free(pipes);
              free(pfds);
              do_gg_worker(tcp_sock, notif_pipe, ggc, server_id);
              FATAL("Worker returned to dead code");
            } else {
              /* parent */
              /* make poll return when a child dies or writes to the pipe */
              pfds[i].fd = pipes[i][0];
              pfds[i].events = POLLIN;
              /* close the writer end in the parent */
              close(pipes[i][1]);
            }
          }
        }
      }
    }
    pret = old_libc_compatible_ppoll(pfds, gg_workers, NULL, &ppoll_mask);

    /* we can get interrupted by a signal, and it's not an error */
    if (pret < 0 && (errno != EINTR))
      break;
  } while (1);

  REPORT_ERRNO("ppoll failed");
out:
  if (pipes)
    free(pipes);
  if (pfds)
    free(pfds);
  return;
}

/* Filter incoming connections
 *
 * Returns:
 *  1: we should accept this address
 *  0: we should reject this address
 */
static int is_acceptable_address(struct sockaddr_in6 *addr) {
  static const struct in6_addr ip4_localhost =
                      { { { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF,127,0,0,1 } } };
  if (!addr)
    return 0;
  /* blacklist ::ffff:127.0.0.1 */
  if (!memcmp(ip4_localhost.s6_addr, addr->sin6_addr.s6_addr, 16)) {
    DEBUG(3, "Worker %d rejected connection\n", getpid());
    return 0;
  }
  return 1;
}

/* A Grey Goo worker process starting point
 *
 * It'll accept() a connection and notify the parent right away by closing its
 * notification pipe
 *
 * Will exit() and not return.
 */
__attribute__ ((noreturn))
static void do_gg_worker(int tcp_sock, int notifier, GG_crypt *ggc,
                         char *server_id) {
  static GG_cnx cnx;
  static char socket_text[INET6_ADDRSTRLEN];
  int as;
  struct sockaddr_in6 accepted_address;
  socklen_t accepted_sl;
  const char *remote_id;
  int ret;

  DEBUG(2, "New worker spawned: %d\n", getpid());

  /* Workers (and especially their descendant) should not have OOM immunity */
  if (adjust_oom_score("-1")) {
    DEBUG(2, "Could not adjust OOM score of worker %d\n", getpid());
  }

  if (!crypto_stage2_init(ggc)) {
    exit(EXIT_FAILURE);
  }

  accepted_sl = sizeof(struct sockaddr_in6);

  /* loop on accept() until we get a connection from an IP we like */
  do {
    as = accept(tcp_sock, (struct sockaddr *) &accepted_address,
                (socklen_t *) &accepted_sl);

    if (as < 0) {
      FATAL_ERRNO("Could not accept incoming connection");
    }

    if (is_acceptable_address(&accepted_address))
      break;
    if (close(as))
      FATAL_ERRNO("Could not close as");

  } while (1);

  /*
   * We are now in the critical path. We don't exit on errors anymore, we try
   * to survive at all costs.
   */

  /* closing the notifier is enough to notify the parent.
   * Note: if needed we could also write to the notifier. We'd need to handle
   * SIGPIPE or use send() with MSG_NOSIGNAL.
   */
  close(notifier);

  close(tcp_sock);

  /* initialize our connection structure */

  remote_id =
      inet_ntop(AF_INET6, &accepted_address.sin6_addr, socket_text,
                sizeof(socket_text));
  if (remote_id == NULL) {
    REPORT_ERROR("Got a new connection but can't print the address");
    remote_id = "unknown";
  }

  REPORT_INFO("Connection from %s, port %d\n", remote_id,
              (int) ntohs(accepted_address.sin6_port));

  /* initialize our GG_cnx structure with the socket, server id, id of the
   * client and crypto context
   */
  gg_cnx_init(&cnx, as, server_id, (char *) remote_id, ggc, 1);

  ret = do_handle_connection(&cnx);

  exit(ret);
}

/*
 * Bind to a certain port and listen() on it
 *
 * returns: -1 on failure
 *          socket on success
 */
static int listen_on_port(in_port_t port) {
  int tcp_sock;
  int ret;
  struct sockaddr_in6 bind_address;

  /* Get an IPV6/IPV4 compatible socket */
  tcp_sock = socket(AF_INET6, SOCK_STREAM, 0);
  if (tcp_sock == -1) {
    REPORT_ERRNO("Could not create socket");
    return -1;
  }

  memset(&bind_address, 0, sizeof(bind_address));

  bind_address = (struct sockaddr_in6) {
    .sin6_family = AF_INET6,
    .sin6_port = htons(port),
    .sin6_addr = in6addr_any,
  };

  ret = bind(tcp_sock, (const struct sockaddr *) &bind_address,
             sizeof(bind_address));
  if (ret) {
    close(tcp_sock);
    REPORT_ERRNO("Could not bind to socket");
    return -1;
  }

  ret = listen(tcp_sock, SOMAXCONN);
  if (ret) {
    close(tcp_sock);
    REPORT_ERRNO("Could not listen on socket");
    return -1;
  }

  return tcp_sock;
}

static void usage(char *name) {
  printf("usage: %s [-f|-b] [-p port] [-n priority] "
         "[-t \""ENABLE_TESTKEY_MAGIC"\"] [-i pid_file] "
         "[-w num_workers]\n\n"
         "  -f              force foreground mode\n"
         "  -b              force background mode\n\n",
         name);
}

/* return 0 on success, -1 on failure */
static int daemonize(void) {
  int ret = 0;
  pid_t pid;
  int nullfd;

  nullfd = open("/dev/null", O_RDWR);

  if (nullfd == -1) {
    REPORT_ERRNO("Could not open null");
    ret = -1;
    goto out;
  }

  pid = fork();

  if (pid < 0) {
    ret = -1;
    goto out;
  }

  /* exit the parent */
  if (pid > 0)
    _exit(EXIT_SUCCESS);

  /* we are the child */

  /* become a session leader and a process group leader */
  if (setsid() == (pid_t) -1) {
    REPORT_ERRNO("Could not create a new session");
    ret = -1;
    goto out;
  }

  REPORT_INFO("Going into background, process group: %d\n\n", getpgrp());

  /* disable stderr in error reporting */
  disable_stderr();

  /* Point standard I/O descriptors to /dev/null */
  if (dup2(nullfd, 0) == -1 || dup2(nullfd, 1) == -1 || dup2(nullfd, 2) == -1) {
    REPORT_ERRNO("Could not redirectd standard I/O");
    ret = -1;
    goto out;
  }

  if (chdir("/"))
    ret = -1;

out:
  /* always close nullfd if we failed.
   * On success close if it's not stdin/stdout/stderr */
  if (nullfd != -1 && (ret == -1 || nullfd > 2))
    if (close(nullfd))
      ret = -1;
  return ret;
}

/* Get our server id. For now we just try to get the hostname */
static int get_server_id(char *buf, size_t len) {

  const char default_id[] = "gg-unknown";

  if (!len)
    return -1;

  if (gethostname(buf, len)) {
    /* gethostname() failed, bake our own id */
    DEBUG(0, "Could not get my own hostname\n");

    if (len >= sizeof(default_id)) {
      memcpy(buf, default_id, sizeof(default_id));
      return 0;
    } else {
      return -1;
    }
  } else {
    /* gethostname() was successful, but maybe the result was truncated */

    /* make sure we are NUL terminated */
    buf[len - 1] = 0;
    return 0;
  }
}

/* Create a PID file with the current pid at "path"
 * If the file already exists, it will be truncated
 *
 * It's the responsibility of the caller to give a safe path for the pid file
 * (i.e. not a shared temp directory for instance).
 *
 * Return 0 on success, -1 on error
 */
static int create_pid_file(char *path) {
  FILE *pid_file = NULL;
  int ret = -1;
  if (!path)
    goto out;
  pid_file = fopen(path, "w");
  if (!pid_file)
    goto out;
  if (fprintf(pid_file, "%d\n", getpid()) > 0)
    ret = 0;
out:
  if (pid_file && fclose(pid_file))
    return -1;
  return ret;
}
