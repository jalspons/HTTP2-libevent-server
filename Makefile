CC=gcc
CFLAGS=-Wall -Pedantic

server: all
	$(CC) $(CFLAGS) -o http2-server server.c

.PHONY: clean

clean:
	rm -f http2-server
