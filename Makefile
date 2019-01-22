CC=gcc
CFLAGS=-Wall -pedantic -levent -lnghttp2 -lssl

server: server
	$(CC) $(CFLAGS) -o http2-server server.c

.PHONY: clean

clean:
	rm -f http2-server
