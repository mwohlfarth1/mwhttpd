SOURCE_NAMES = main server misc http_messages

# Use GNU compiler
CC = gcc -g -Wall -Werror -pthread
INC = include

SRC_H = $(SOURCE_NAMES:=.h) socket.h tcp.h tls.h routes.h
SRC_O = $(SOURCE_NAMES:=.o)

all: myhttpd myhttpsd

tcp_socket.o: socket.c $(SRC_H)
	$(CC) -c $< -o $@

cgi_bin.o: cgi_bin.c $(SRC_H)
	$(CC) -c $< -o $@

htdocs.o: htdocs.c $(SRC_H)
	$(CC) -c $< -o $@

defaults.o: defaults.c $(SRC_H)
	$(CC) -c $< -o $@

tcp.o: tcp.c $(SRC_H)
	$(CC) -c $< -o $@

tls_socket.o: socket.c $(SRC_H)
	$(CC) -D USE_TLS -c $< -o $@

tls.o: tls.c $(SRC_H)
	$(CC) `pkg-config --cflags openssl` -c $< -o $@

$(SRC_O) : %.o : %.c $(SRC_H)
	$(CC) -c $<

myhttpd: $(SRC_O) tcp_socket.o tcp.o htdocs.o cgi_bin.o defaults.o
	$(CC) -o $@ $^ -ldl -lrt
	
myhttpsd: $(SRC_O) tls_socket.o tls.o htdocs.o cgi_bin.o defaults.o
	$(CC) -o $@ $^ -ldl -lrt `pkg-config --libs openssl`
	
clean:
	rm -f myhttpd myhttpsd tcp_socket.o tls_socket.o tcp.o tls.o cgi_bin.o htdocs.o defaults.o $(SRC_O)
