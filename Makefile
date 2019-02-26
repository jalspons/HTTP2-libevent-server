CC=gcc
CFLAGS=-Wall -pedantic
LIBS=-lnghttp2 -lcrypto -lssl -levent -levent_openssl

all: server_no_push server_push client_push client_no_push

server_no_push: server_no_push
	$(CC) $(CFLAGS) -o server_no_push util.c server_no_push.c $(LIBS)

server_push: server_push
	$(CC) $(CFLAGS) -o server_push util.c server_push.c $(LIBS)

client_push: client_push
	$(CC) $(CFLAGS) -o client_push client_push.c http-parser/http_parser.c  $(LIBS)

client_no_push: client_no_push
	$(CC) $(CFLAGS) -o client_no_push client_no_push.c http-parser/http_parser.c  $(LIBS)


.PHONY: clean

clean:
	rm -f server_no_push server_push client_no_push client_push
