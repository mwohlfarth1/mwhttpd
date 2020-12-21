#include "main.h"
#include "server.h"
#include "socket.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>

#define DEFAULT_PORT (59639)

/*
 * Print the usage for the program. Takes the name of the program as an
 * argument.
 */

void print_usage(char *name) {
    printf("USAGE: %s [-f|-t|-pNUM_THREADS] [-h] PORT_NO\n", name);
} /* print_usage() */

/*
 * Runs the webserver.
 */

int main(int argc, char **argv) {
  /* default to linear */

  concurrency_mode mode = E_NO_CONCURRENCY;

  int port_no = 0;
  int num_threads = 0;

  int c = 0;
  while ((c = getopt(argc, argv, "hftp:")) != -1) {
    switch (c) {
    case 'h':
      print_usage(argv[0]);
      return 0;
    case 'f':
    case 't':
    case 'p':
      if (mode != E_NO_CONCURRENCY) {
        fputs("Multiple concurrency modes specified\n", stdout);
        print_usage(argv[0]);
        return -1;
      }
      mode = (concurrency_mode) c;
      if (mode == E_THREAD_POOL) {
        num_threads = atoi(optarg);
      }
      break;
    case '?':
      if (isprint(optopt)) {
        fprintf(stderr, "Unknown option: -%c\n", optopt);
      }
      else {
        fprintf(stderr, "Unknown option\n");
      }
      /* Fall through */
    default:
      print_usage(argv[0]);
      return 1;
    }
  }

  if (optind > argc) {
    fprintf(stderr, "Extra arguments were specified");
    print_usage(argv[0]);
    return 1;
  }
  else if (optind == argc) {
    /* use default port */

    port_no = DEFAULT_PORT;
  }
  else {
    port_no = atoi(argv[optind]);
  }

  printf("%d %d %d\n", mode, port_no, num_threads);

  acceptor *acceptor = create_socket_acceptor(port_no);

  if (acceptor == NULL) {
	  return 1;
  }

  switch (mode) {
  case E_FORK_PER_REQUEST:
    run_forking_server(acceptor);
    break;
  case E_THREAD_PER_REQUEST:
    run_threaded_server(acceptor);
    break;
  case E_THREAD_POOL:
    run_thread_pool_server(acceptor, num_threads);
    break;
  default:
    run_linear_server(acceptor);
    break;
  }

  close_socket_acceptor(acceptor);

  return 0;
} /* main() */
