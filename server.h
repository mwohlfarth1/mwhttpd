#ifndef SERVER_H
#define SERVER_H

#include "socket.h"

#include <stdio.h>
#include <stdlib.h>

#define USE_SPECIFIED (1)
#define MAX_USR_PWD_LEN (60)

void run_linear_server(acceptor *acceptor);
void run_forking_server(acceptor *acceptor);
void run_threaded_server(acceptor *acceptor);
void run_thread_pool_server(acceptor *acceptor, int num_threads);

void handle(socket_t *sock);
char *file_to_string(char *path_to_file, size_t *file_size);
void handle_zombies();
void *loop_thread(acceptor *acceptor);
char *get_dir_browsing_html_string(char *path_to_dir);

/* Global variable for user and password */

extern char g_user_pass[MAX_USR_PWD_LEN];

#endif // SERVER_H
