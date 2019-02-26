#ifdef __sgi
#define errx(exitcode, format, args...)                                 \
{                                                                   \
    warnx(format, ##args);                                     \
    exit(exitcode);                                                 \
}
#define warn(format, ...) warnx(format ": %s", ##__VA_ARGS__, strerror(errno))
#define warnx(format, ...) fprintf(stderr, format "\n", ##__VA_ARGS__)
#endif


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifndef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifndef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifndef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifndef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifndef __sgi
#include <err.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>

#include "server.h"
#include "util.h"

#include "test.h"


/* 
 * Establish TLS and select TLS version
 *
 */ 

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

#ifndef OPENSSL_NO_NEXTPROTOENG
static int next_proto_cb(SSL *s , const unsigned char **data,
		unsigned int *len, void *arg ) 
{
	*data = next_proto_list;
	*len = (unsigned int)next_proto_list_len;
	return SSL_TLSEXT_ERR_OK;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_proto_cb(SSL *ssl , const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg )
{
	int rv;

	rv = nghttp2_select_next_protocol((unsigned char **)out, outlen, in, inlen);
	if (rv != 1) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif

static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file)
{
	SSL_CTX *ssl_ctx;
	EC_KEY *ecdh;

	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ssl_ctx) {
		errx(1, "Could not create SSL/TLS context: %s",
				ERR_error_string(ERR_get_error(), NULL));
	}
	
    SSL_CTX_set_options(ssl_ctx, 
            SSL_OP_ALL |
            SSL_OP_SINGLE_DH_USE |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_NO_COMPRESSION | 
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        errx(1, "EC_KEY_new_by_curve_name failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not read private key file %s", key_file);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        errx(1, "Could not read certificate file %s", cert_file);
    }

	next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
	memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
			NGHTTP2_PROTO_VERSION_ID_LEN);
	next_proto_list_len = NGHTTP2_PROTO_VERSION_ID_LEN + 1;

#ifndef OPENSSL_NO_NEXTPROTOENG
	SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
#endif

	return ssl_ctx;
}


/* Create a SSL Object */
static SSL *create_ssl(SSL_CTX *ssl_ctx)
{
    SSL *ssl;
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        errx(1, "Could not create SSL/TLS session object: %s",
                ERR_error_string(ERR_get_error(), NULL));
    }
    return ssl;     
}

/* Add the new stream object into the linked list */
static void add_stream(http2_session_data *session_data,
        http2_stream_data *stream_data)
{
    stream_data->next = session_data->root.next;
    session_data->root.next = stream_data;
    stream_data->prev = &session_data->root;
    if (stream_data->next) {
        stream_data->next->prev = stream_data;
    }
}

/* Remove the stream object from the linked list */
static void remove_stream(http2_session_data *session_data,
        http2_stream_data *stream_data)
{
    stream_data->prev->next = stream_data->next;
    if (stream_data->next) {
        stream_data->next->prev = stream_data->prev;
    }
}

/* Create a new stream object */
static http2_stream_data *create_http2_stream_data(
        http2_session_data *session_data, int32_t stream_id)
{
    http2_stream_data *stream_data;
    stream_data = malloc(sizeof(http2_stream_data));
    memset(stream_data, 0, sizeof(http2_stream_data));
    stream_data->stream_id = stream_id;
    stream_data->method = UNDEFINED;
    stream_data->fd = -1;

    add_stream(session_data, stream_data);
    return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data)
{
    if (stream_data->fd != -1) {
        close(stream_data->fd);
    }
    free(stream_data->request_path);
    free(stream_data);
}

static http2_session_data *create_http2_session_data(
        app_context *app_ctx, int fd, struct sockaddr *addr, int addrlen)
{
    int rv;
    http2_session_data *session_data;
    SSL *ssl;
    char host[NI_MAXHOST];
    int val = 1;

    ssl = create_ssl(app_ctx->ssl_ctx);
    
    session_data = malloc(sizeof(http2_session_data));
    memset(session_data, 0, sizeof(http2_session_data));
    session_data->app_ctx = app_ctx;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
    session_data->bev = bufferevent_openssl_socket_new(app_ctx->evbase,
            fd, ssl, BUFFEREVENT_SSL_ACCEPTING, 
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
    
    rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
            NI_NUMERICHOST);
    if (rv != 0) {
        session_data->client_addr = strdup("(unknown)");
    } else {
        session_data->client_addr = strdup(host);
    }

    return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data)
{
    http2_stream_data *stream_data;
    SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
    fprintf(stderr, "%s disconnected\n", session_data->client_addr);
    if (ssl) {
        SSL_shutdown(ssl);
    }

    bufferevent_free(session_data->bev);
    nghttp2_session_del(session_data->session);
    for (stream_data = session_data->root.next; stream_data;) {
        http2_stream_data *next = stream_data->next;
        delete_http2_stream_data(stream_data);
        stream_data = next;
    }
    free(session_data->client_addr);
    free(session_data);
}

/* 
 * Send pending queued frames. 
 */
static int session_send(http2_session_data *session_data)
{
	int rv;

	// nghttp2_session_send() function serializes the frame into wire
	// format and then calls the send_callback() function
	rv = nghttp2_session_send(session_data->session);
	if (rv != 0) {
		warnx("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}

	return 0;
}

/* 
 * To process the received data, we call session_recv() function
 */
static int session_recv(http2_session_data *session_data)
{
	ssize_t readlen;
	struct evbuffer *input = bufferevent_get_input(session_data->bev);
	size_t datalen = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, -1);

	// Feed all unprocessed but received data to the nghttp2 session object
	// Nghttp2 session object processes the data and may invoke callbacks
	// and queue outgoing frames (but not send yet!)
	readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
	if (readlen < 0) {
		warnx("Fatal eror: %s", nghttp2_strerror((int)readlen));
		return -1;
	}
	if (evbuffer_drain(input, (size_t)readlen) != 0) {
		warnx("Fatal error: evbuffer_drain failed");
		return -1;
	}
	if (session_send(session_data) != 0) {	
		return -1;		
	}

	return 0;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, 
		size_t length, int flags, void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	struct bufferevent *bev = session_data->bev;

	// If the evbuffer is full, block writing
	if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
			OUTPUT_WOULDBLOCK_THRESHOLD) {
		return NGHTTP2_ERR_WOULDBLOCK;
	}

	// Since the buffer have enough space, write the data into it 
	bufferevent_write(bev, data, length);
	return (ssize_t)length;
}


/*
 * File_read_callback() callback function reads the contents of the file
 */
static ssize_t file_read_callback(nghttp2_session *session,
		int32_t stream_id, uint8_t *buf, size_t length, 
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
	fprintf(stderr, "On file_read_callback\n");
    
    int fd = source->fd;
	ssize_t r;
	while ((r = read(fd, buf, length)) == -1 && errno == EINTR);
	if (r == -1) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}

    fprintf(stderr, "Error reply 4\n");
	if (r == 0) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}
	
	return r;
}

/*
 * Send the file content
 */
static int send_response(nghttp2_session *session, int32_t stream_id,
		nghttp2_nv *nva, size_t nvlen, int fd)
{
	int rv;

	/* nghttp2 uses the data_provider structure to send the entity
	 * body to the remote peer. The source member of this structure
	 * is a union, which can be either a void pointer or an int (intended
	 * to be used as file descriptor)
	 */ 
	nghttp2_data_provider data_prd;
	data_prd.source.fd = fd;
	data_prd.read_callback = file_read_callback;

    fprintf(stderr, "[RES]: S ----------------> C\n");

	rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
	if (rv != 0) {
		warnx("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}

	return 0;
}

static const char ERROR_HTML[] =    "<html><head><title>404</title></head>"
                                    "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session, 
        http2_stream_data *stream_data)
{
    int rv;
    ssize_t writelen;
    int pipefd[2];
    nghttp2_nv hdrs[] = {
        MAKE_NV(":status", "404"),
        MAKE_NV(":path", stream_data->request_path),
        MAKE_NV("Content-length", (char*)strlen(ERROR_HTML)),
        MAKE_NV("Content-type", "text/html")
    };

    rv = pipe(pipefd);
    if (rv != 0) {
        warn("Could not create pipe");
        
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
        if (rv != 0) {
            warnx("Fatal error: %s", nghttp2_strerror(rv));
            return -1;
        }
       
        return 0;
    }

    writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
    close(pipefd[1]);

    if (writelen != sizeof(ERROR_HTML) - 1) {
        close(pipefd[0]);
        return -1;
    }

    stream_data->fd = pipefd[0];

    if (send_response(session, stream_data->stream_id, hdrs, 
                ARRLEN(hdrs), pipefd[0]) != 0) {

        fprintf(stderr, "Error reply 5a\n");
        close(pipefd[0]);
        return -1;
    }

    fprintf(stderr, "Error reply 5\n");
    return 0;
}

/* Callback function to go through each of the header field */
static int on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame, const uint8_t *name,
		size_t namelen, const uint8_t *value,
		size_t valuelen, uint8_t flags, void *user_data)
{
	http2_stream_data *stream_data;
	const char PATH[] = ":path";
    const char METHOD[] = ":method";

    // Look the headers and find a match for name/value pair
	// Store the requested path into stream_data object if found
	switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
    case NGHTTP2_DATA:
		if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
			break;
		}

        stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    
        if (!stream_data || (stream_data->method == HTTP_GET && 
                    stream_data->request_path)) {
            break;
        }

        if (namelen == sizeof(METHOD) - 1 &&
                memcmp(METHOD, name, namelen) == 0) {
            if (isGET(value)) {
                stream_data->method = HTTP_GET;        
            } else if (isPOST(value)) {
                stream_data->method = HTTP_POST;
            } else if (isPUT(value)) {
                stream_data->method = HTTP_PUT;
            }
            fprintf(stderr, " %s", value);
        } 
  
        if (namelen == sizeof(PATH) - 1 && 
                memcmp(PATH, name, namelen) == 0) {
            size_t j;
            for (j = 0; j < valuelen && value[j] != '?'; ++j);
            stream_data->request_path = percent_decode(value, j);
            fprintf(stderr, " %s\n", value);
		}
	
		break;
	}

	return 0;
}

/*
 * On_begin_headers_callback() function is invoked when the reception of a header
 * block in HEADERS or PUSH_PROMISE frame is started
 */
static int on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame, void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

    fprintf(stderr, "[REQ] ");

	// Check that incoming frame is a request HEADERS 
	if (frame->hd.type != NGHTTP2_HEADERS ||
			frame->headers.cat != NGHTTP2_HCAT_REQUEST) {

		return 0;
	}

	stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
	nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, 
			stream_data);

	return 0;
}

static int on_request_recv(nghttp2_session *session,
        http2_session_data *session_data,
        http2_stream_data *stream_data)
{
    int fd;
    
    char *rel_path;


    // Check that the request path exists
    if (!stream_data->request_path) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    if (check_path(stream_data->request_path) && !(strlen(stream_data->request_path) < 1 ||
            memcmp(stream_data->request_path, "/index.html", strlen("/index.html")) == 0 || 
            memcmp(stream_data->request_path, "/css/styles.css", strlen("/css/styles.css")) == 0)) {
        if (error_reply(session, stream_data) != 0) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
  
        return 0;
    }

    // Go to the beginning of the path
    for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path);

    /* If the client desires the root */
    if (strlen(rel_path) < 1) {
        strncat(rel_path, "index.html", strlen("index.html") + 1);
    }

    fd = open(rel_path, O_RDONLY);
    if (fd == -1) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    stream_data->fd = fd;

    nghttp2_nv hdrs[] = {
        MAKE_NV(":status", "200"), 
        MAKE_NV("Content-Type", "text/html; charset=utf-8"),
        MAKE_NV("Server", "nghttp2-jals/1.0")
    };

    // Send the response to the client
    if (send_response(session, stream_data->stream_id, 
                hdrs, ARRLEN(hdrs), fd) != 0) {
        close(fd);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }     

    return 0;
}

static char filename[16];
static volatile int start = 1;
static volatile size_t total_len = 0;

/*
 * On_frame_recv_callback() is invoked when a frame is fully received.
 */
static int on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame, void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

    fprintf(stderr, "[CLIENT] S <------------ C  (frame #%d)\n", frame->hd.type);

	switch (frame->hd.type) {
    case NGHTTP2_RST_STREAM:
        fprintf(stderr, "Error code received: %d\n", frame->rst_stream.error_code);
        break;
	case NGHTTP2_DATA:
	case NGHTTP2_HEADERS:
		/* Check that the client request has finished */
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
			stream_data = nghttp2_session_get_stream_user_data(
					session, frame->hd.stream_id);

            start = 1;
            //fprintf(stderr, "TOTAL LEN: %ld\n", total_len);

			/* For DATA nad HEADERS frame, this callback may be
			 * called after on_stream_close_callback(). Check
			 * that stream is still alive.
			 */
			if (!stream_data) {
				return 0;
			}

			return on_request_recv(session, session_data, stream_data);
		}
		break;
	default:
		break;
	}
	
	return 0;
}


static int on_data_chunk_recv_callback(nghttp2_session *session,
        uint8_t flags, int32_t stream_id, const uint8_t *data,
        size_t len, void *user_data)
{
    int fd, i = 0;
    ssize_t writelen, total_write = 0;
    
    total_len += len;

    // This is a bit rigid solution. A better one would be using fgets or getline 
    // and parsing with sscanf, for instance.
    if (start) {
        int j = 0;
        // Go through the boundary id
        for (i = 0; data[++i] != '\n';);
        //Navigate through headers 
        // Skip Content-disposition field
        for (i += 1; data[++i] != ';';); 
        // Skip name field
        for (i += 1; data[++i] != ';';);
        // Save filename field value to "filename" string pointer
        for (i += 1; data[++i] != '"';); 
        // save the filename to the buffer
        // Calculate length of the filename
        while (data[i + 1] != '.' && j < 12) {
            filename[j++] = data[1 + (i++)];
        }
        strncat(filename, ".jpg", sizeof(".jpg") + 1);
        // Skip the end of the row
        for (i += 1; data[++i] != '\n';);
        // Skip Content-type row
        for (i += 1; data[++i] != '\n';);
        // Skip the empty row before the content
        for (i += 1; data[++i] != '\n';);
        // Move the pointer to the first char of the binary data
        i += 1;
        // Change state so that following callbacks skip this routine
        start = 0; 
    }
    
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
        fprintf(stderr, "Error opening a %s: %s\n", 
                filename, strerror(errno));
        return -1;
    }   

    while (total_write + i < len) {
        writelen = write(fd, data + i + total_write, len - i - total_write);
        if (writelen == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Fatal error while writing to a file: %s\n",
                        strerror(errno));
                return -1;
            }
        } else {
            total_write += writelen;
        }
    }
    
    return 0;
}

    
/*
 * On_stream_close_callback() function is invoked when the stream is about
 * to close.
 */
static int on_stream_close_callback(nghttp2_session *session, 
		int32_t stream_id, uint32_t error_code, void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

    fprintf(stderr, "[RM_STR] Closing stream %d\n", stream_id);

	stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
	if (!stream_data) {
		return 0;
	}

	remove_stream(session_data, stream_data);
	delete_http2_stream_data(stream_data);

    fprintf(stderr, "[INFO] Open streams: ");
    http2_stream_data *ptr;
    for (ptr = &session_data->root; ptr != NULL; ptr = ptr->next) {
        fprintf(stderr, "  %d,", ptr->stream_id);
    }
    fprintf(stderr, "\n");
    fflush(stderr);

	return 0;
}

/* Initialize nghttp2 connection */
static void initialize_nghttp2_session(http2_session_data *session_data)
{
	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
			on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
			on_stream_close_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, 
            on_header_callback);
	nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
			on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
            on_data_chunk_recv_callback);

	nghttp2_session_server_new(&session_data->session, callbacks, session_data);
	
	nghttp2_session_callbacks_del(callbacks);
}


/*
 * The server begins by sending the server connection preface, which always
 * consists of a SETTINGS frame. #send_server_connection_header() function
 * configures and submits it.
 */
static int send_server_connection_header(http2_session_data *session_data)
{
	nghttp2_settings_entry iv[1] = {
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, SAMPLE_CONNECTIONS},
	};

	int rv;

	// Queue the frame for transmission, but does not actually send it yet
	// Use nghttp2_session_send() function to send it 
	rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, 
			iv, ARRLEN(iv));
	if (rv != 0) {
		warnx("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}
	
	return 0;
}

/* Eventcb callback is invoked when an event (e.g. connection has been established, 
 * timeout, etc.) occurs on the underlying socket.
 * 
 * Validate that HTTP/2 is negotiated. If not, drop connection.
 */
static void eventcb(struct bufferevent *bev, short events, void *data)
{
	http2_session_data *session_data = (http2_session_data *)data;
	if (events & BEV_EVENT_CONNECTED) {
		const unsigned char *alpn = NULL;
		unsigned int alpnlen = 0;
		SSL *ssl;

		fprintf(stderr, "%s connected\n", session_data->client_addr);

		ssl = bufferevent_openssl_get_ssl(session_data->bev);

		SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (alpn == NULL) {
			SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
		}
#endif

		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
			fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);
			delete_http2_session_data(session_data);
			return;
		}

		initialize_nghttp2_session(session_data);

		if (send_server_connection_header(session_data) != 0 ||
				session_send(session_data) != 0) {
			delete_http2_session_data(session_data);
			return;
		}

		return;
	}

	if (events & BEV_EVENT_EOF) {
		fprintf(stderr, "%s EOF\n", session_data->client_addr);
	} else if (events & BEV_EVENT_ERROR) {
		fprintf(stderr, "%s network error\n", session_data->client_addr);
	} else if (events & BEV_EVENT_TIMEOUT) {
		fprintf(stderr, "%s timeout\n", session_data->client_addr);
	}
	delete_http2_session_data(session_data);
}

/* Readcb() callback function is invoked when the input buffer has data. */
static void readcb(struct bufferevent *bev, void *data)
{
	http2_session_data *session_data = (http2_session_data *)data;

	// Process the incoming data with session_recv() function
	if (session_recv(session_data) != 0) {
	       delete_http2_session_data(session_data);
	       return;
	}
}

/*
 * Writecb() callback function is invoked when all data in the bufferevent 
 * output buffer has been sent.
 */
static void writecb(struct bufferevent *bev, void *data)
{
	http2_session_data *session_data = (http2_session_data *)data;

	// Check whether the output buffer is empty or not
	if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
		return;
	}

	// Check the presence of GOAWAY frames or other error conditions
	if (nghttp2_session_want_read(session_data->session) == 0 &&
			nghttp2_session_want_write(session_data->session) == 0) {
		delete_http2_session_data(session_data);
		return;
	}

	if (session_send(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}


/* A callback function for accepting a new connection */
static void acceptcb(struct evconnlistener *listener, int fd,
		struct sockaddr *addr, int addrlen, void *arg)
{
	app_context *app_ctx = (app_context *)arg;
	http2_session_data *session_data;

	// Init session_data object
	session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

	// Define 3 callbacks for bufferevent
	bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

/* Listening and binding new connections */
static void start_listen(struct event_base *evbase, 
		const char *service, app_context *app_ctx)
{	
	int rv;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif

	rv = getaddrinfo(NULL, service, &hints, &res);
	if (rv != 0) {
		errx(1, NULL);
	}
	
	for (rp = res; rp; rp = rp->ai_next) {
		struct evconnlistener *listener;
		listener = evconnlistener_new_bind(evbase, acceptcb, app_ctx, 
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				16, rp->ai_addr, (int)rp->ai_addrlen);
		if (listener) {
			freeaddrinfo(res);

			return;
		}
	}
	errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
        struct event_base *evbase)
{
    memset(app_ctx, 0, sizeof(app_context));
    app_ctx->ssl_ctx = ssl_ctx;
    app_ctx->evbase = evbase;
}

static void run_server(const char *service, const char *key_file, 
        const char *cert_file)
{
    SSL_CTX *ssl_ctx;
    app_context app_ctx;
    struct event_base *evbase;

    ssl_ctx = create_ssl_ctx(key_file, cert_file);
    evbase = event_base_new();
    initialize_app_context(&app_ctx, ssl_ctx, evbase);
    start_listen(evbase, service, &app_ctx);

    event_base_loop(evbase, 0);

    event_base_free(evbase);
    SSL_CTX_free(ssl_ctx);
}


int main(int argc, char *argv[]) 
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s PORT KEY_FILE CERT_FILE\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    printf("Initializing server on port %s\n", argv[1]);
    printf("openssl version number: %d\n", OPENSSL_VERSION_NUMBER >= 0x10002000L);

    SSL_load_error_strings();
    SSL_library_init();

    run_server(argv[1], argv[2], argv[3]);
    
    return 0;
}


