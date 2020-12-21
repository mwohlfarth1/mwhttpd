#include "http_messages.h"
#include "routes.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

/* typedef a function pointer for httprun */

typedef void (*httprunfunc) (int ssock, const char *query_string);

/*
 * Handle a CGI request
 */

void handle_cgi_bin(const http_request *request, socket_t *sock_to_write_to) {

  /* check if we need to handle this as a module request */

  char *ptr_to_period = strchr(request->request_uri, '.');
  if (ptr_to_period != NULL) {
    /* there is a period, check if the characters after it are "so" */

    if (strncmp(ptr_to_period, ".so", 3) == 0) {
      handle_cgi_bin_mod(request, sock_to_write_to);
      return;
    }
  }

  /* fork a child process */

  int fork_ret = fork();
  if (fork_ret == 0) {
    /* this is the child process */

    /* set the environment variable REQUEST_METHOD=GET */

    int set_env_ret = setenv("REQUEST_METHOD", "GET", 1);
    if (set_env_ret == -1) {
      perror("setenv");
      return;
    }

    /* set the environment variable QUERY_STRING=(arguments after ?) */

    char *ptr_to_q_mark = strchr(request->request_uri, '?');

    if (ptr_to_q_mark != NULL) {
      set_env_ret = setenv("QUERY_STRING", (ptr_to_q_mark + 1), 1);
      if (set_env_ret == -1) {
        perror("setenv");
        return;
      }

      /* set this question mark to '\0' so that we can send the name of the */
      /* script to execl later                                              */

      *(ptr_to_q_mark) = '\0';
    }

    /* get the name of the script */

    char *slash = strchr(request->request_uri + 1, '/');
    char *script_name = (slash + 1);

    /* set up things for the script */

    char *path_to_cgi_bin_dir =
          "/u/riker/u93/mwohlfar/cs252/lab5/http-root-dir/cgi-bin/";
    char *path_to_exe = calloc(1, (sizeof(char) *
                               strlen(request->request_uri + 1) +
                               strlen(path_to_cgi_bin_dir) + 1));
    if (path_to_exe == NULL) {
      perror("malloc");
      return;
    }
    strcat(path_to_exe, path_to_cgi_bin_dir);
    strcat(path_to_exe, script_name);

    /* send the output of any print statements or execv to the socket */

    dup2(sock_to_write_to->socket_fd, 1);

    /* print header to the socket */

    char *header = "HTTP/1.1 200 Document follows\r\nServer: Server-Type\r\n";
    printf("%s", header);
    fflush(NULL);

    /* execute the script */

    execl(path_to_exe, script_name, NULL);
    perror("cgi_bin execl error");
    exit(-1);
  }

  /* this is the parent process */

  /* wait on the child process */

  int status = 0;
  if (waitpid(fork_ret, &status, 0) == -1) {
    perror("cgi_bin waitpid error");
    exit(-1);
  }

  return;

} /* handle_cgi_bin() */

/*
 * Handle modified cgi-bin requests (ones that end in .so)
 */

void handle_cgi_bin_mod(const http_request *request,
                        socket_t *sock_to_write_to) {

  /* set ptr_to_q_mark to the end of the .so name */

  char *duplicate_uri = strdup(request->request_uri);
  char *ptr_to_q_mark = strchr(duplicate_uri, '.');
  if (ptr_to_q_mark != NULL) {
    ptr_to_q_mark += 3;
  }

  /* set so_name_start to the beginning of the .so name */

  char *so_name_start = strchr(duplicate_uri + 1, '/');
  if (so_name_start != NULL) {
    so_name_start += 1;
  }

  /* allocate enough memory for the name of the .so exe */

  const char *root_dir = "http-root-dir/cgi-bin/";
  char *so_name = malloc(sizeof(char) * (strlen(root_dir) +
                                        (ptr_to_q_mark - so_name_start) + 1));
  if (so_name == NULL) {
    perror("malloc");
    exit(-1);
  }

  /* start the so_name string with the root directory */

  strncat(so_name, root_dir, strlen(root_dir));

  /* copy the name of the .so file into so_name */

  strncpy(so_name + strlen(root_dir), so_name_start,
          (ptr_to_q_mark - so_name_start));
  so_name[strlen(root_dir) + (ptr_to_q_mark - duplicate_uri)] = '\0';

  /* get the query string for dlopen */

  char *query_string = NULL;
  ptr_to_q_mark = strchr(duplicate_uri, '?');
  if (ptr_to_q_mark != NULL) {
    /* we need to send a query string */

    /* allocate space for the query string */

    query_string = malloc(sizeof(char) * (strlen(ptr_to_q_mark + 1) + 1));
    if (query_string == NULL) {
      perror("malloc");
      exit(1);
    }

    /* put the query string in to query_string */

    strncpy(query_string, ptr_to_q_mark + 1, (strlen(ptr_to_q_mark + 1)));
    query_string[strlen(ptr_to_q_mark + 1)] = '\0';
  }

  /* use dlopen */

  void *lib = dlopen(so_name, RTLD_LAZY);
  if (lib == NULL) {
    perror("dlopen");
    exit(1);
  }

  /* Get function to print response, defined in the .so file */

  httprunfunc so_file_httprun;

  /* use dlsym to handle opened lib */

  so_file_httprun = (httprunfunc) dlsym(lib, "httprun");
  if (so_file_httprun == NULL) {
    perror("dlsym: httprun not found:");
    exit(1);
  }
  free(so_name);
  so_name = NULL;

  /* call the httprun fuction with the socket to write to and the */
  /* query string                                                 */

  so_file_httprun(sock_to_write_to->socket_fd, query_string);

} /* handle_cgi_bin_mod() */
