#include "tls.h"

#include <unistd.h>

#define ERROR -1
#define SUCCESS 0

/*
 * Close and free a TLS socket created by accept_tls_connection(). Return 0 on
 * success. You should use the polymorphic version of this function, which is
 * close_socket() in socket.c.
 */

int close_tls_socket(tls_socket *socket) {
  printf("Closing TLS socket fd %d", socket->socket_fd);

  /* print the IP address that the socket was closed from */

  char inet_pres[INET_ADDRSTRLEN];
  if (inet_ntop(socket->addr.sin_family, &(socket->addr.sin_addr),
                                         inet_pres, INET_ADDRSTRLEN)) {
    printf(" from %s", inet_pres);
  }
  putchar('\n');

  /* actually attempt to close the socket */

  int status = close(socket->socket_fd);

  /* free the ssl associated with the tls_socket */

  SSL_free(socket->ssl);

  /* free the memory associated with the other members of the tls_socket */

  free(socket);

  return status;

} /* close_tls_socket() */

/*
 * Read a buffer of length buf_len from the TLS socket. Return the length of
 * the message on successful completion.
 * You should use the polymorphic version of this function, which is
 * socket_read() in socket.c
 */

int tls_read(tls_socket *socket, char *buf, size_t buf_len) {

  /* argument checking */

  if (buf == NULL){
    return ERROR;
  }
  else if (socket == NULL) {
    return ERROR;
  }

  /* arguments were valid, so try to read from the socket */

  else {
    /* try to read buf_len bytes from the socket */

    int bytes_read = SSL_read(socket->ssl, buf, buf_len);
    if (bytes_read <= 0) {
      perror("SSL_read");
      return ERROR;
    }

    /* there was not an error reading from the socket, so */
    /* return how many bytes we read                      */

    return bytes_read;
  }

} /* tls_read() */

/*
 * Write a buffer of length buf_len to the TLS socket. Return 0 on success. You
 * should use the polymorphic version of this function, which is socket_write()
 * in socket.c
 */

int tls_write(tls_socket *socket, char *buf, size_t buf_len) {
  if (buf == NULL) {
    return ERROR;
  }
  else if (socket == NULL) {
    return ERROR;
  }

  /* try to write buf_len bytes to the socket */

  size_t bytes_sent = SSL_write(socket->ssl, buf, buf_len);
  if (bytes_sent <= 0) {
    perror("SSL_write");
    return ERROR;
  }

  /* there was not an error with writing, so return the */
  /* the number of bytes that were sent                 */

  return (int) bytes_sent;

} /* tls_write() */

/*
 * Create a new TLS socket acceptor, listening on the given port. Return NULL on
 * error. You should ues the polymorphic version of this function, which is
 * create_socket_acceptor() in socket.c.
 */

tls_acceptor *create_tls_acceptor(int port) {

  tls_acceptor *acceptor = malloc(sizeof(tls_acceptor));

  /* SSL initialization stuff */

  /* initialize the ssl */

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  /* get the method for the context */

  const SSL_METHOD *method;
  method = TLS_server_method();

  /* create the context with this method */

  acceptor->ssl_ctx = SSL_CTX_new(method);
  if (acceptor->ssl_ctx == NULL) {
    perror("SSL_CTX_new");
    return NULL;
  }

  /* configure the ssl context we just created */

  SSL_CTX_set_ecdh_auto(acceptor->ssl_ctx, 1);

  /* load the certificate into the context */

  if (SSL_CTX_use_certificate_file(acceptor->ssl_ctx, "cert.pem",
                                   SSL_FILETYPE_PEM) <= 0) {
    perror("SSL_CTX_use_certificate_file");
    return NULL;
  }

  /* add the private key into the context */

  if (SSL_CTX_use_PrivateKey_file(acceptor->ssl_ctx, "key.pem",
                                  SSL_FILETYPE_PEM) <= 0) {
    perror("SSL_CTX_use_PrivateKey_file");
    return NULL;
  }

  /* creating the master socket for this connection */

  /* set the IP address and port for this server */

  acceptor->addr.sin_family = AF_INET;
  acceptor->addr.sin_port = htons(port);
  acceptor->addr.sin_addr.s_addr = htonl(INADDR_ANY);

  /* create the acceptor's master_socket */

  acceptor->master_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (acceptor->master_socket < 0) {
    perror("socket");
    return NULL;
  }

  /* set the socket options for the master socket */

  int optval = 1;
  if (setsockopt(acceptor->master_socket,
                 SOL_SOCKET,
                 SO_REUSEADDR,
                 &optval,
                 sizeof(optval)) < 0) {
    perror("setsockopt");
    return NULL;
  }

  /* bind the master socket to the IP address and port */

  if (bind(acceptor->master_socket, (struct sockaddr *) &acceptor->addr,
           sizeof(acceptor->addr)) < 0) {
    perror("bind");
    return NULL;
  }

  /* put the socket into listening mode and set the size */
  /* of the queue of unprocessed connections */

  if (listen(acceptor->master_socket, 50) < 0) {
    perror("listen");
    return NULL;
  }

  return acceptor;

} /* create_tls_acceptor() */

/*
 * Accept a new connection from the TLS socket acceptor. Return NULL on error,
 * and the new TLS socket otherwise. You should use the polymorphic version of
 * this function, which is accept_connection() in socket.c.
 */

tls_socket *accept_tls_connection(tls_acceptor *acceptor) {

  /* call accept on the master socket. this gives us the fd for another */
  /* socket which is the slave socket                                   */

  struct sockaddr_in addr = { 0 };
  socklen_t addr_len = sizeof(addr);
  int socket_fd = accept(acceptor->master_socket,
                         (struct sockaddr *) &addr,
                         &addr_len);
  if (socket_fd == -1) {
    perror("accept");
    return NULL;
  }

  /* allocate memory for the tls_socket we will return */

  tls_socket *sock = malloc(sizeof(tls_socket));

  /* set the members of the tls_socket we created */
  /* (except for the ssl member)                  */

  sock->socket_fd = socket_fd;
  sock->addr = addr;

  /* print that we accepted a connection */

  char inet_pres[INET_ADDRSTRLEN];
  if (inet_ntop(addr.sin_family, &(addr.sin_addr), inet_pres,
                                                   INET_ADDRSTRLEN)) {
    printf("Recieved a connection from %s\n", inet_pres);
  }

  /* set up the ssl for this socket before we return it.           */
  /* The correct order for this is SSL_new, SSL_set_fd, SSL_accept */

  /* call SSL_new */

  sock->ssl = SSL_new(acceptor->ssl_ctx);
  if (sock->ssl == NULL) {
    perror("SSL_new");
    return NULL;
  }

  /* call SSL_set_fd */

  int ssl_set_fd_ret = SSL_set_fd(sock->ssl, sock->socket_fd);
  if (ssl_set_fd_ret == 0) {
    perror("SSL_set_fd");
    return NULL;
  }

  /* call SSL_accept */

  int ssl_accept_ret = SSL_accept(sock->ssl);
  if (ssl_accept_ret <= 0) {
    fflush(NULL);
    perror("SSL_accept");
    return NULL;
  }

  /* if the SSL_accept call did not fail, we can return the socket. */
  /* return this properly set up tls_socket                         */

  return sock;

} /* accept_tls_connection() */

/*
 * Close and free the passed TLS socket acceptor. Return 0 on success. You
 * should use the polymorphic version of this function, which is
 * close_socket_acceptor() in socket.c.
 */

int close_tls_acceptor(tls_acceptor *acceptor) {
  printf("Closing socket %d\n", acceptor->master_socket);

  /* close the master socket associated with the acceptor */

  int status = close(acceptor->master_socket);

  /* free the SSL context associated with the acceptor */

  SSL_CTX_free(acceptor->ssl_ctx);

  /* free the acceptor */

  free(acceptor);

  return status;

} /* close_tls_acceptor() */
