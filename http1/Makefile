CC=gcc
CFLAGS=-Werror -pedantic
LIBS=-lssl -levent -lcrypto -levent_openssl

server: server
	$(CC) $(CLFAGS) -o server server.c $(LIBS)
