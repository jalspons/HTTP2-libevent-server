/* Derived from sample/http-server.c in libevent source tree.
 * That file does not have a license notice, but generally libevent
 * is under the 3-clause BSD.
 *
 * Plus, some additional inspiration from:
 * http://archives.seul.org/libevent/users/Jul-2010/binGK8dlinMqP.bin
 * (which is a .c file despite the extension and mime type) */

/*
  A trivial https webserver using Libevent's evhttp.
  This is not the best code in the world, and it does some fairly stupid stuff
  that you would never want to do in a production webserver. Caveat hackor!
 */

#include "https-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef S_ISDIR
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event.h>
#include <evhttp.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

/* Instead of casting between these types, create a union with all of them,
 * to avoid -Wstrict-aliasing warnings. */

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */

typedef union { 
    struct sockaddr_storage ss;
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 i6;
} sock_hop;


void die_most_horribly_from_openssl_error (const char *func)
{
    fprintf (stderr, "%s failed:\n", func);
    exit (EXIT_FAILURE);
}


static void create_ssl_ctx(SSL_CTX *ssl_ctx)
{
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options (ssl_ctx, 
            SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_SSLv2);

  /* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
   * We just hardcode a single curve which is reasonably decent.
   * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
    if (!ecdh) {
      die_most_horribly_from_openssl_error ("EC_KEY_new_by_curve_name");
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (1 != SSL_CTX_use_certificate_chain_file(ssl_ctx, "host.crt")) {
      die_most_horribly_from_openssl_error("SSL_CTX_use_certificate_chain_file");
    }

    if (1 != SSL_CTX_use_PrivateKey_file (ssl_ctx, "host.key", SSL_FILETYPE_PEM)) {
      die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");
    }
}


/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void
send_document_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = NULL;
	size_t len;
	int fd = -1;
    struct stat st;

	printf("Got a GET request\n");

    evb = evbuffer_new();
    if ((fd = open("index.html", O_RDONLY)) < 0) {
        perror("open");
        goto err;
    }

    if (fstat(fd, &st)<0) {
			/* Make sure the length still matches, now that we
			 * opened the file :/ */
			perror("fstat");
			goto err;
    }

    evhttp_add_header(evhttp_request_get_output_headers(req),
        "Content-Type", "text/html");

    evbuffer_add_file(evb, fd, 0, st.st_size);
	evhttp_send_reply(req, 200, "OK", evb);
	
    goto done;

 err:
	evhttp_send_error(req, 404, "Document was not found");
	if (fd>=0) {
		close(fd);
    }

done:
    if (evb) {
		evbuffer_free(evb);
	}
}

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent* bevcb (struct event_base *base, void *arg)
{ 
    struct bufferevent* r;
    SSL_CTX *ctx = (SSL_CTX *)arg;

    r = bufferevent_openssl_socket_new(base, -1, SSL_new(ctx),
                                      BUFFEREVENT_SSL_ACCEPTING,
                                      BEV_OPT_CLOSE_ON_FREE);
    return r;
}


static int serve_some_http (void)
{ 
    struct event_base *base;
    struct evhttp *http;
    struct evhttp_bound_socket *handle;
    SSL_CTX *ssl_ctx;
   
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options (ssl_ctx, 
            SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE | SSL_OP_NO_SSLv2);

  /* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
   * We just hardcode a single curve which is reasonably decent.
   * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
    if (!ecdh) {
      die_most_horribly_from_openssl_error ("EC_KEY_new_by_curve_name");
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (1 != SSL_CTX_use_certificate_chain_file(ssl_ctx, "host.crt")) {
      die_most_horribly_from_openssl_error("SSL_CTX_use_certificate_chain_file");
    }

    if (1 != SSL_CTX_use_PrivateKey_file (ssl_ctx, "host.key", SSL_FILETYPE_PEM)) {
      die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");
    }

    
    event_init();
    http = evhttp_start("127.0.0.1", 8080);

//    base = event_base_new();
//    if (!base) { 
//        fprintf (stderr, "Couldn't create an event_base: exiting\n");
//        return 1;
//    }
//
//    /* Create a new evhttp object to handle requests. */
//    http = evhttp_new(base);
//    if (!http) { 
//        fprintf (stderr, "couldn't create evhttp. Exiting.\n");
//        return 1;
//    }

    /* This is the magic that lets evhttp use SSL. */
    evhttp_set_bevcb(http, bevcb, ssl_ctx);
    /* This is the callback that gets called when a request comes in. */
    evhttp_set_gencb(http, send_document_cb, NULL);

    event_dispatch();

    evhttp_free(http);

 //   /* Now we tell the evhttp what port to listen on */
 //   handle = evhttp_bind_socket_with_handle (http, "127.0.0.1", 8080);
 //   if (!handle) { 
 //       fprintf (stderr, "couldn't bind to port 8079. Exiting.\n");
 //       return 1;
 //   }

    event_base_dispatch (base);

    return 0;
}


int main (int argc, char **argv)
{ 

    signal (SIGPIPE, SIG_IGN);

    SSL_library_init ();
    SSL_load_error_strings ();
    OpenSSL_add_all_algorithms ();


 
    return serve_some_http();
}
