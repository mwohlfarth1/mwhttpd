#ifndef ROUTES_H
#define ROUTES_H

#include "http_messages.h"
#include "socket.h"

void handle_cgi_bin(const http_request *request, socket_t *sock);
void handle_cgi_bin_mod(const http_request *request, socket_t *sock);
http_response handle_htdocs(const http_request *request);
http_response handle_default(const http_request *request);

typedef http_response (*route_handle) (const http_request *);

typedef struct{
    char *route_name;
    route_handle handle_func;
}  routes;

#endif  // ROUTES_H
