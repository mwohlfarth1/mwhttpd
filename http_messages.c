#include "http_messages.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Return the reason string for a particular status code. You might find this
 * helpful when implementing response_string().
 */

const char *status_reason(int status) {
  switch (status) {
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 203:
      return "Non-Authoritative Information";
    case 204:
      return "No Content";
    case 205:
      return "Reset Content";
    case 206:
      return "Partial Content";
    case 300:
      return "Multiple Choices";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 305:
      return "Use Proxy";
    case 307:
      return "Temporary Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 402:
      return "Payment Required";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 406:
      return "Not Acceptable";
    case 407:
      return "Proxy Authentication Required";
    case 408:
      return "Request Time-out";
    case 409:
      return "Conflict";
    case 410:
      return "Gone";
    case 411:
      return "Length Required";
    case 412:
      return "Precondition Failed";
    case 413:
      return "Request Entity Too Large";
    case 414:
      return "Request-URI Too Large";
    case 415:
      return "Unsupported Media Type";
    case 416:
      return "Requested range not satisfiable";
    case 417:
      return "Expectation Failed";
    case 500:
      return "Internal Server Error";
    case 501:
      return "Not Implemented";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Time-out";
    case 505:
      return "HTTP Version not supported";
    default:
      return "Unknown status";
  }
} /* status_reason() */

/*
 * Create the actual response string to be sent over the socket, based
 * on the parameter.
 */

char *response_string(http_response *response) {

  int length_of_to_string = 0;

  /* add length for the http version */

  length_of_to_string += strlen(response->http_version);

  /* add length for a space, the return code, and a space */

  length_of_to_string += 1 + 3 + 1;

  /* add length for the response reason */

  length_of_to_string += strlen(response->reason_phrase);

  /* add length for the '\r\n' at the end of the line */

  length_of_to_string += 2;

  /* add length for the key, value, space between, and \r\n */
  /* at the end (for each header)                           */

  for (int i = 0; i < response->num_headers; i++) {
    length_of_to_string += strlen(response->headers[i].key) +
                           strlen(response->headers[i].value);

    /* add length for the '\r\n' at the end of the line */

    length_of_to_string += 2 + 2;
  }

  /* add length for the final \r\n */

  length_of_to_string += 2;

  /* add length of the message body if we need to */

  if (response->message_body != NULL) {
    /* find the header that contains the size of the message body */

    for (int i = 0; i < response->num_headers; i++) {
      if (strcmp(response->headers[i].key, "Content-Length:") == 0) {
        /* if this header has the size, add the size to length_of_to_string */

        length_of_to_string += atoi(response->headers[i].value);

        break;
      }
    }
  }

  /* allocate memory for the string to be returned */

  char *to_string = malloc(sizeof(char) * length_of_to_string);

  /* add the version, status code, and reason phrase to the to_string */

  strcpy(to_string, response->http_version);
  strcat(to_string, " ");
  char code[4];
  sprintf(code, "%d", response->status_code);
  strcat(to_string, code);
  strcat(to_string, " ");
  strcat(to_string, response->reason_phrase);
  strcat(to_string, "\r\n");

  /* add each of the response headers to the to_string */

  for (int i = 0; i < response->num_headers; i++) {
    strcat(to_string, response->headers[i].key);
    strcat(to_string, " ");
    strcat(to_string, response->headers[i].value);
    strcat(to_string, "\r\n");
  }

  /* add the final \r\n to the to_string and null terminate the string */

  strcat(to_string, "\r\n");

  /* if there is a message body to be sent, then add it to */
  /* the string as well                                    */

  if (response->message_body != NULL) {
    for (int i = 0; i < response->num_headers; i++) {
      if (strcmp(response->headers[i].key, "Content-Length:") == 0) {
        memcpy(&to_string[strlen(to_string)], response->message_body,
               atoi(response->headers[i].value));
        break;
      }
    }
  }

  return to_string;

} /* response_string() */

/*
 * Print the request to stdout, useful for debugging.
 */

void print_request(http_request *request) {
  // Magic string to help with autograder

  printf("\\\\==////REQ\\\\\\\\==////\n");

  printf("Method: {%s}\n", request->method);
  printf("Request URI: {%s}\n", request->request_uri);
  printf("Query string: {%s}\n", request->query);
  printf("HTTP Version: {%s}\n", request->http_version);

  printf("Headers: \n");
  for (int i = 0; i < request->num_headers; i++) {
    printf("field-name: %s; field-value: %s\n",
           request->headers[i].key, request->headers[i].value);
  }

  printf("Message body length: %ld\n", strlen(request->message_body));
  printf("%s\n", request->message_body);

  // Magic string to help with autograder

  printf("//==\\\\\\\\REQ////==\\\\\n");
} /* print_request() */
