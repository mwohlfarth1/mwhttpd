#include "server.h"
#include "http_messages.h"
#include "misc.h"
#include "routes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/types.h>

char g_user_pass[MAX_USR_PWD_LEN];

/*
 * Return a string in a format <user>:<password>
 * either from auth.txt or from your implememtation.
 */

char *return_user_pwd_string(void) {
  /* Read from ./auth.txt. Don't change this. We will use it for testing */

  FILE *fp = NULL;
  char *line = NULL;
  size_t len = 0;

  fp = fopen("./auth.txt", "r");
  if (fp == NULL) {
    perror("couldn't read auth.txt");
    exit(-1);
  }

  if (getline(&line, &len, fp) == -1) {
    perror("couldn't read auth.txt");
    free(line);
    line = NULL;
    exit(-1);
  }

  sprintf(g_user_pass, "%s", line);

  free(line);
  line = NULL;
  fclose(fp);

  return g_user_pass;
} /* return_user_pwd_string() */

/*
 * Accept connections one at a time and handle them.
 */

void run_linear_server(acceptor *acceptor) {
  while (1) {
    socket_t *sock = accept_connection(acceptor);
    handle(sock);
  }
} /* run_linear_server() */

/*
 * Accept connections, creating a different child process to handle each one.
 */

void run_forking_server(acceptor *acceptor) {
  while (1) {
    socket_t *sock = accept_connection(acceptor);
    if (sock != NULL) {
      int fork_ret = fork();
      if (fork_ret == 0) {
        /* this is the child process */

        /* handle the connection on this socket and then exit */

        handle(sock);
        exit(0);
      }

      /* this is the parent process */

      /* reap the child process that was created */

      int status_value = 0;
      fork_ret = waitpid(fork_ret, &status_value, 0);
      if (fork_ret == -1) {
        perror("waitpid");
        return;
      }

      /* the parent needs to close the socket as well as the child */

      close_socket(sock);
    }
  }

} /* run_forking_server() */

/*
 * Accept connections, creating a new thread to handle each one.
 */

void run_threaded_server(acceptor *acceptor) {
  while (1) {
    /* accept the connection */

    socket_t *sock = accept_connection(acceptor);

    /* create the thread and set up the thread as detached  */
    /* so that we don't have to call join on it             */

    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    /* start the thread on handling the new request */

    pthread_create(&thread, &attr, (void * (*)(void *)) handle, (void *) sock);
  }

} /* run_threaded_server() */

/*
 * Accept connections, drawing from a thread pool with num_threads to handle the
 * connections.
 */

void run_thread_pool_server(acceptor *acceptor, int num_threads) {

  /* create the threads for the pool */

  pthread_t threads[num_threads];

  /* start each of these threads on their own loop_thread function call */

  for (int i = 0; i < num_threads; i++) {
    pthread_create(&threads[i], NULL,
                   (void * (*)(void *)) loop_thread, acceptor);
  }
  loop_thread(acceptor);

} /* run_thread_pool_server() */

/*
 * This is the function that the threads in run_thread_pool_server() run.
 * Each of them run like a linear server, so that they continuously pull
 * new requests as they come in.
 */

void *loop_thread(acceptor *acceptor) {
  while (1) {
    socket_t *sock = accept_connection(acceptor);
    handle(sock);
  }
} /* loop_thread() */

/*
 * Handle an incoming connection on the passed socket.
 */

void handle(socket_t *sock) {
  http_request request;

#define SINGLE_REQUEST_SIZE 2048

  /* allocate the initial memory for the request buffer */

  int buffer_size = SINGLE_REQUEST_SIZE;
  char * buffer = malloc(sizeof(char) * buffer_size);
  if (buffer == NULL) {
    perror("malloc");
    return;
  }

  /* read in the request. if more needs to be read, read more */

  int read_ret = 0;
  while (1) {
    read_ret = socket_read(sock, buffer, (size_t) SINGLE_REQUEST_SIZE);

    /* if there is more to read, then increase the buffer size */

    if (read_ret == SINGLE_REQUEST_SIZE) {
      buffer_size += SINGLE_REQUEST_SIZE;
      buffer = realloc(buffer, buffer_size);
    }

    /* if there is not more to read, then we're done reading */

    else {
      break;
    }
  }

	printf("buffer: %s\n", buffer);
  /* sometimes, a browser will send a request that has nothing in it */
  /* or at least this is what it seems like it's doing. This causes  */
  /* read_ret to be 0, no data is written to 'buffer', and since     */
  /* 'buffer' is just meaningless data, the program will seg fault   */
  /* later on in operation. To prevent this, don't process the       */
  /* request if read_ret is 0                                        */

  if (read_ret == 0) {
    /* a blank request was sent for some reason */
    /* send a malformed request response        */

    http_response response = { 0 };
    response.http_version = "HTTP/1.1";
    response.status_code = 400;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send response */

    char *to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(buffer);
    buffer = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;

    close_socket(sock);
    return;
  }

  /* create the response in case there was a malformed request */

  http_response response = { 0 };
  request.query = "";
  request.message_body = "";

  /* check if there is a \n before a \r anywhere in the request */

  int malformed_request = 0;
  for (int i = 1; i < read_ret; i++) {
    if ((buffer[i] == '\n') && !(buffer[i - 1] == '\r')) {
      malformed_request = 1;
      break;
    }
  }

  if (malformed_request) {
    /* send the bad request header */

    response.http_version = "HTTP/1.1";
    response.status_code = 400;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send the response */

    char *to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  /* extract the method from the request */

  char *ptr_to_space = strchr(buffer, ' ');
  request.method = malloc(sizeof(char) * ((ptr_to_space - buffer) + 1));
  request.method = strncpy(request.method, buffer, (ptr_to_space - buffer));
  request.method[(ptr_to_space - buffer)] = '\0';

  /* extract the uri from the request */

  char *ptr_to_uri = ptr_to_space + 1;
  ptr_to_space = strchr(ptr_to_uri, ' ');
  request.request_uri = malloc(sizeof(char) *
                               ((ptr_to_space - ptr_to_uri) + 1));
  request.request_uri = strncpy(request.request_uri, ptr_to_uri,
                               (ptr_to_space - ptr_to_uri));
  request.request_uri[(ptr_to_space - ptr_to_uri)] = '\0';

  /* extract the http version from the request */

  char *ptr_to_version = ptr_to_space + 1;
  char * ptr_to_carriage_return = strchr(ptr_to_version, '\r');
  request.http_version = malloc(sizeof(char) *
                               ((ptr_to_carriage_return - ptr_to_version) + 1));
  request.http_version = strncpy(request.http_version, ptr_to_version,
                                (ptr_to_carriage_return - ptr_to_version));
  request.http_version[(ptr_to_carriage_return - ptr_to_version)] = '\0';

  /* count the number of headers in the request */

  request.num_headers = 0;
  for (int i = 0; i < read_ret; i++) {
    if (buffer[i] == '\r') {
      request.num_headers++;
    }
  }

  /* subtract two from the num headers to ignore the final '\r\n\r\n' */

  request.num_headers -= 2;

  /* create the array that the request.headers field will point to */

  header header_array[request.num_headers];
  request.headers = header_array;

  /* fill in the header fields for the request */

  char *prev_carriage_ret = strchr(buffer, '\r');
  for (int header_num = 1; header_num <= request.num_headers; header_num++) {

    /* make this header's key point to the beginning of the key */

    request.headers[header_num - 1].key = prev_carriage_ret + 2;

    /* null terminate this request's key string */

    char *semi_after_key = strchr(request.headers[header_num - 1].key, ':');
    *semi_after_key = '\0';

    /* make this header's value point to the beginning of the value */

    request.headers[header_num - 1].value = semi_after_key + 2;

    /* null terminate this request's value string and set up */
    /* prev_carriage_ret for the next loop iteration         */

    prev_carriage_ret = strchr(request.headers[header_num - 1].value, '\r');
    *prev_carriage_ret = '\0';
  }

  /* check to ensure an authorization was included in the request */

  int correct_password = 0;
  int auth_header_present = 0;
  for (int i = 0; i < request.num_headers; i++) {
    if (strcmp(request.headers[i].key, "Authorization") == 0) {

      /* there is an "Authorization" header */

      auth_header_present = 1;

      /* base 64 encode the real username and password */

      return_user_pwd_string();
      size_t encrypted_len = 0;
      unsigned char *base64_real_u_and_p = base64_encode(
                                           (const unsigned char *) g_user_pass,
                                           strlen(g_user_pass),
                                           &encrypted_len);

      /* compare the real username and password with the entered one */

      if (strncmp((char *) base64_real_u_and_p, (request.headers[i].value + 6),
                  encrypted_len - 2) == 0) {
        /* if the encryped user/pass matches the one we have, then */
        /* the authorization has succeeded                         */

        correct_password = 1;
      }
      else {
        /* the encryped user/pass doesn't match our records, fail */

        correct_password = 0;
      }

      /* we've found an authorization header and checked if it was valid */

      break;
    }
    else {
      continue;
    }
  }

  if (!auth_header_present) {
    response.http_version = "HTTP/1.1";
    response.status_code = 401;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 1;
    header response_header[1];
    response.headers = response_header;
    response.headers[0].key = "WWW-Authenticate:";
    response.headers[0].value = "Basic realm=\"myhttpd-cs252\"";
    response.message_body = NULL;

    /* send the response */

    char *to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  if (!correct_password) {
    response.http_version = "HTTP/1.1";
    response.status_code = 401;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send the response */

    char *to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  /* DONE PARSING THE REQUEST */

  /* the response http_version will always be HTTP/1.1 */

  response.http_version = "HTTP/1.1";

  /* if the http version is not "something/1.1" then we don't support it and */
  /* we're not even going to worry about the rest                            */
  /* the status code should be 505                                           */

  char *version_num = strchr(request.http_version, '/') + 1;
  if ((strcmp(version_num, "1.1") != 0) && (strcmp(version_num, "1.0") != 0)) {
    response.status_code = 505;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send the response */

    char *to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  /* if we do support this version of HTTP, then we SHOULD worry about */
  /* the rest of the request                                           */

  /* if the method is not "GET", we should return error code 405 */

  if (strcmp(request.method, "GET") != 0) {
    response.status_code = 405;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send the response */

    char *to_string = response_string(&response);
    printf("response: %s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  /* if the requested URI is from cgi-bin, then we need to handle */
  /* the request differently                                      */

  if (strncmp(request.request_uri, "/cgi-bin", 8) == 0) {

    handle_cgi_bin((const http_request *) &request, sock);

    free(buffer);
    buffer = NULL;

    close_socket(sock);
    return;
  }

  /* the method and version were correct, so check if the file requested */
  /* exists and can be opened                                            */

  char *actual_path = malloc(sizeof(char) * 128);
  if (actual_path == NULL) {
    perror("malloc");
    return;
  }

  actual_path = strcpy(actual_path, "http-root-dir/htdocs");
  actual_path = strcat(actual_path, request.request_uri);

  char * content_type = get_content_type(actual_path);
  if (content_type == NULL) {
    /* if the content_type is NULL, that means that there is no file or */
    /* directory with this name. issue a 404 error                      */

    response.status_code = 404;
    const char * reason = status_reason(response.status_code);
    response.reason_phrase = malloc(sizeof(char) * strlen(reason));
    strncpy(response.reason_phrase, reason, strlen(reason));
    response.reason_phrase[strlen(reason)] = '\0';
    response.num_headers = 0;
    response.headers = NULL;
    response.message_body = NULL;

    /* send the response */

    char * to_string = response_string(&response);
    printf("%s\n", to_string);
    socket_write_string(sock, to_string);

    /* free malloc'd memory */

    free(to_string);
    to_string = NULL;
    free(response.reason_phrase);
    response.reason_phrase = NULL;
    free(buffer);
    buffer = NULL;
    free(actual_path);
    actual_path = NULL;

    close_socket(sock);
    return;
  }
  else {
    /* if the content_type is not NULL, the requested thing exists as a */
    /* file or a directory                                              */

    if (strncmp(content_type, "inode/directory", 15) == 0) {
      /* if the content_type was "directory" then we need to check if */
      /* there is an "index.html" in this directory                   */

      /* set up the new actual path to test for */

      if (strcmp(request.request_uri, "/") == 0) {
        actual_path = strcat(actual_path, "index.html");
      }
      else {
        if (request.request_uri[strlen(request.request_uri) - 1] == '/') {
          strcat(actual_path, "index.html");
        }
        else {
          strcat(actual_path, "index.html");
        }
      }

      /* check to see if this index.html file exists */

      /* free the content_type first so we don't lose the memory */

      free(content_type);
      content_type = NULL;

      content_type = get_content_type(actual_path);
      if (content_type == NULL) {
        /* if content_type is NULL, there is no index.html file */
        /* so we should respond with a directory browsing       */

        /* shorten actual_path so it doesn't include "index.html" at the end */

        actual_path[strlen(actual_path) - strlen("index.html")] = '\0';

        /* get a string representing the html file we need to send */

        char *file_to_send = get_dir_browsing_html_string(actual_path);
        if (file_to_send == NULL) {
          perror("get_dir_browsing_html_string");
          return;
        }

        /* prepare the response */

        response.status_code = 200;
        const char * reason = status_reason(response.status_code);
        response.reason_phrase = malloc(sizeof(char) * strlen(reason));
        strncpy(response.reason_phrase, reason, strlen(reason));
        response.reason_phrase[strlen(reason)] = '\0';
        response.num_headers = 3;
        header response_header[response.num_headers];
        response.headers = response_header;
        response.headers[0].key = "Connection:";
        response.headers[0].value = "close";
        response.headers[1].key = "Content-Type:";
        response.headers[1].value = "text/html";
        response.headers[2].key = "Content-Length:";
        response.headers[2].value = malloc(sizeof(char) * 20);
        sprintf(response.headers[2].value, "%d", (int) strlen(file_to_send));
        response.message_body = file_to_send;

        /* send the response down the pipe */

        char *to_string = response_string(&response);
        printf("%s\n", to_string);
        socket_write(sock, to_string, strlen(file_to_send) + 100);

        /* free malloc'd memory */

        free(to_string);
        to_string = NULL;
        free(buffer);
        buffer = NULL;
        free(response.headers[2].value);
        response.headers[2].value = NULL;
        free(content_type);
        content_type = NULL;
        free(actual_path);
        actual_path = NULL;
        free(file_to_send);
        file_to_send = NULL;

        close_socket(sock);
        return;

      }
      else {
        /* if the content_type was not NULL, the file exists but we need */
        /* to check if we can read it                                    */

        if (access(actual_path, R_OK) != -1) {
          /* the file can be read, so we should send it to the user */

          size_t file_size = 0;
          char *file_string = file_to_string(actual_path, &file_size);
          if (file_string == NULL) {
            perror("file_to_string");
            return;
          }

          /* set up the response */

          response.status_code = 200;
          const char * reason = status_reason(response.status_code);
          response.reason_phrase = malloc(sizeof(char) * strlen(reason));
          strncpy(response.reason_phrase, reason, strlen(reason));
          response.reason_phrase[strlen(reason)] = '\0';
          response.num_headers = 3;
          header response_header[response.num_headers];
          response.headers = response_header;
          response.headers[0].key = "Connection:";
          response.headers[0].value = "close";
          response.headers[1].key = "Content-Type:";
          if (strncmp(&actual_path[strlen(actual_path) - 3], "css", 3) == 0) {
            response.headers[1].value = "text/css";
          }
          else {
            response.headers[1].value = get_content_type(actual_path);
            *(strchr(response.headers[1].value, ';')) = '\0';
          }
          response.headers[2].key = "Content-Length:";
          response.headers[2].value = malloc(sizeof(char) * 20);
          sprintf(response.headers[2].value, "%d", (int) file_size);
          response.message_body = file_string;

          /* send the response down the pipe */

          char *to_string = response_string(&response);
          printf("%s\n", to_string);
          socket_write(sock, to_string, file_size + 100);

          /* free malloc'd memory */

          free(to_string);
          to_string = NULL;
          free(file_string);
          file_string = NULL;
          free(buffer);
          buffer = NULL;
          free(response.headers[2].value);
          response.headers[2].value = NULL;
          free(content_type);
          content_type = NULL;
          free(actual_path);
          actual_path = NULL;

          close_socket(sock);
          return;

        }
        else {
          /* the file cannot be read, so we should issue a 403 error */

          response.status_code = 403;
          const char * reason = status_reason(response.status_code);
          response.reason_phrase = malloc(sizeof(char) * strlen(reason));
          strncpy(response.reason_phrase, reason, strlen(reason));
          response.reason_phrase[strlen(reason)] = '\0';
          response.num_headers = 0;
          response.headers = NULL;
          response.message_body = NULL;

          /* send the response */

          char * to_string = response_string(&response);
          printf("%s\n", to_string);
          socket_write_string(sock, to_string);

          /* free malloc'd memory */

          free(to_string);
          to_string = NULL;
          free(response.reason_phrase);
          response.reason_phrase = NULL;
          free(buffer);
          buffer = NULL;
          free(content_type);
          content_type = NULL;
          free(actual_path);
          actual_path = NULL;

          close_socket(sock);
          return;

        }
      }
    }
    else {
      /* the content type is not a directory and it's not null, so we know */
      /* the file exists. check if the file can be opened                  */

      if (access(actual_path, R_OK) != -1) {
        /* the file exists and can be opened, so send it to the user */

        /* get a string representing the file */

        size_t file_size = 0;
        char *file_string = file_to_string(actual_path, &file_size);
        if (file_string == NULL) {
          perror("file_to_string");
          return;
        }

        /* set up the response */

        response.status_code = 200;
        const char * reason = status_reason(response.status_code);
        response.reason_phrase = malloc(sizeof(char) * strlen(reason));
        strncpy(response.reason_phrase, reason, strlen(reason));
        response.reason_phrase[strlen(reason)] = '\0';
        response.num_headers = 3;
        header response_header[response.num_headers];
        response.headers = response_header;
        response.headers[0].key = "Connection:";
        response.headers[0].value = "close";
        response.headers[1].key = "Content-Type:";
        if (strncmp(&actual_path[strlen(actual_path) - 3], "css", 3) == 0) {
          response.headers[1].value = "text/css";
        }
        else {
          response.headers[1].value = get_content_type(actual_path);
          *(strchr(response.headers[1].value, ';')) = '\0';
        }
        response.headers[2].key = "Content-Length:";
        response.headers[2].value = malloc(sizeof(char) * 20);
        sprintf(response.headers[2].value, "%d", (int) file_size);
        response.message_body = file_string;

        /* send the response down the pipe */

        char *to_string = response_string(&response);
        printf("%s\n", to_string);
        socket_write(sock, to_string, file_size + 200);

        /* free malloc'd memory */

        free(to_string);
        to_string = NULL;
        free(file_string);
        file_string = NULL;
        free(response.reason_phrase);
        response.reason_phrase = NULL;
        free(response.headers[2].value);
        response.headers[2].value = NULL;
        free(buffer);
        buffer = NULL;
        free(content_type);
        content_type = NULL;
        free(actual_path);
        actual_path = NULL;

        close_socket(sock);
        return;
      }
      else {
        /* the file exists but cannot be opened, so issue a 403 error */

        response.status_code = 403;
        const char * reason = status_reason(response.status_code);
        response.reason_phrase = malloc(sizeof(char) * strlen(reason));
        strncpy(response.reason_phrase, reason, strlen(reason));
        response.reason_phrase[strlen(reason)] = '\0';
        response.num_headers = 0;
        response.headers = NULL;
        response.message_body = NULL;

        /* send the response */

        char * to_string = response_string(&response);
        printf("%s\n", to_string);
        socket_write_string(sock, to_string);

        /* free malloc'd memory */

        free(to_string);
        to_string = NULL;
        free(response.reason_phrase);
        response.reason_phrase = NULL;
        free(buffer);
        buffer = NULL;
        free(content_type);
        content_type = NULL;
        free(actual_path);
        actual_path = NULL;

        close_socket(sock);
        return;
      }
    }
  }
} /* handle() */

/*
 * This function takes a path to a file, turns the file into a string,
 * and returns a pointer to that string. The size_t passed in is set to the
 * size of the string returned.
 * If the file specified by the first argument cannot be opened, NULL is
 * returned.
 *
 * WARNING: This function allocates memory for the string it returns.
 * The user of this function needs to free the returned string.
 */

char *file_to_string(char *path_to_file, size_t *file_size) {

  /* open the file for reading */

  FILE *file = fopen(path_to_file, "r");
  if (file == NULL) {
    return NULL;
  }

  /* go to the end of the file, set the size to that location, and go back */
  /* to the beginning of the file                                          */

  fseek(file, 0, SEEK_END);
  *file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  /* allocate memory for the returned string */

  char *file_as_str = malloc(sizeof(char) * (*file_size + 1));
  if (file_as_str == NULL) {
    perror("malloc");
    return NULL;
  }

  /* read file_size bytes into the string */

  fread(file_as_str, 1, *file_size, file);

  fclose(file);
  file = NULL;

  return file_as_str;

} /* file_to_string() */

/*
 * This function takes a path to a directory and returns a string which is
 * an html file that can be sent to the client. The html file is a directory
 * listing for the directory that actual_path represents.
 */

char *get_dir_browsing_html_string(char *path_to_dir) {

  /* define some strings to use to build the html_doc later */

  char *beginning_of_html_file = \
      "<!DOCTYPE html>\n\n" \
      "<html lang=\"en\">\n\n" \
      "<head>\n" \
      "    <meta charset=\"utf-8\">\n" \
      "    <title>CS 252 HTTP Server</title>\n" \
      "    <link rel=\"stylesheet\" type=\"text/css\" href=\"/style.css\">\n" \
      "</head>\n\n" \
      "  <body>\n" \
      "    <h1>";
  char *middle_of_html_file = "</h1>\n\n" \
                              "    <ul>\n";
  char *end_of_html_file = "    </ul>\n\n" \
                           "    <hr>\n" \
                           "  </body>\n" \
                           "</html>\n";

  /* the size to allocate for the entire file */

  int size_to_allocate = 0;

  /* get the actual name of the directory */

  char *dir_name = NULL;
  if (path_to_dir[strlen(path_to_dir) - 1] == '/') {
    path_to_dir[strlen(path_to_dir) - 1] = '\0';
    dir_name = strrchr(path_to_dir, '/') + 1;
  }
  else {
    dir_name = strrchr(path_to_dir, '/') + 1;
  }

  /* open the directory */

  DIR *dir = opendir(path_to_dir);
  if (dir == NULL) {
    perror("opendir");
    return NULL;
  }

  /* allocate memory for an array of entries in the directory */

  int max_entries = 20;
  char **entries = (char **) malloc(sizeof(char *) * max_entries);
  if (entries == NULL) {
    perror("malloc");
    return NULL;
  }

  /* for each of the entries in this directory, get the name */

  int num_entries = 0;
  struct dirent *entry = NULL;
  while ((entry = readdir(dir)) != NULL) {
    /* as long as the entry isn't . or .., save the entry name */

    if (entry->d_name[0] != '.') {
      entries[num_entries] = malloc(sizeof(char) * strlen(entry->d_name));
      if (entries[num_entries] == NULL) {
        perror("malloc");
        return NULL;
      }
      strcpy(entries[num_entries], entry->d_name);
      num_entries++;
    }
  }

  /* figure out how much we need to allocate for the return string */

  size_to_allocate += strlen(beginning_of_html_file) +
                      strlen("Index of ") +
                      strlen(dir_name) +
                      strlen(middle_of_html_file);

  for (int i = 0; i < num_entries; i++) {
    /* add the size that we need for the html tags */

    size_to_allocate += strlen("    <li><a HREF=\"\"></A>\n");

    /* add the size that we need for the name (it's repeated once) */

    size_to_allocate += (2 * strlen(entries[i]));

    /* add space for the directory name we'll have to put in the HREF field */
    /* as well as the '/' we'll need to put after it                        */

    size_to_allocate += strlen(dir_name) + 1;
  }

  /* add the size we need to allocate for the end of the document */

  size_to_allocate += strlen(end_of_html_file);

  /* add the size we need to display the link to the parent directory */

  size_to_allocate += strlen("Parent directory") +
                      strlen("    <li><a HREF=\"\"></A>\n") +
                      strlen(dir_name) + 1 +
                      strlen("..");

  /* allocate memory for the html document */

  char *html_doc = calloc(1, (sizeof(char) * size_to_allocate));
  if (html_doc == NULL) {
    perror("malloc");
    return NULL;
  }

  /* build the html file in the string we allocated */

  /* add on the beginning of the file */

  strcat(html_doc, beginning_of_html_file);
  strcat(html_doc, "Index of ");
  strcat(html_doc, dir_name);
  strcat(html_doc, middle_of_html_file);

  /* add on the entry for the parent directory */

  strcat(html_doc, "    <li><a HREF=\"");
  strcat(html_doc, "../");
  strcat(html_doc, "\">");
  strcat(html_doc, "Parent directory");
  strcat(html_doc, "</A>\n");

  /* add on the entries for each of the files */

  for (int i = 0; i < num_entries; i++) {
    strcat(html_doc, "    <li><a HREF=\"");
    strcat(html_doc, dir_name);
    strcat(html_doc, "/");
    strcat(html_doc, entries[i]);
    strcat(html_doc, "\">");
    strcat(html_doc, entries[i]);
    strcat(html_doc, "</A>\n");
  }

  /* add on the end of the file */

  strcat(html_doc, end_of_html_file);

  /* free memory for the entries */

  for (int i = 0; i < num_entries; i++) {
    free(entries[i]);
    entries[i] = NULL;
  }
  free(entries);
  entries = NULL;

  return html_doc;

} /* get_dir_browsing_html_string() */

