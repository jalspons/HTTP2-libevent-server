CC=gcc
CFLAGS=-Wall -pedantic 
server: server
	$(CC) $(CFLAGS) -o http2-server server.c -lcrypto -levent -lnghttp2 -lssl -levent_openssl


.PHONY: clean

clean:
	rm -f http2-server
