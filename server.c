#include <stdlib.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event2.h>
#include <event2/bufferedevent_ssl.h>
#include <event2/listener.h>



struct app_context {
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;
};

typedef struct http2_session_data {
	struct http2_stream_data root;
	struct bufferevent *bev;
	app_context *app_ctx;
	nghttp2_session *session;
	char *client_addr;
} http2_session_data;

typedef struct http2_stream_data {
	struct http2_stream_data *prev, *next;
	char *request_path;
	int32_t stream_id;
	int fd;
} http2_stream_data;



/* 
 * Establish TLS and select TLS version
 *
 */ 

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static int next_proto_cb(SSL *s _U_, const unsigned char **data,
		unsigned int *len, void *arg _U_) 
{
	*data = next_proto_list;
	*len = (unsigned int)next_proto_list_len;
	return SSL_TLSEXT_ERR_OK;
}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_proto_cb(SSL *ssl _U_, const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg _U_)
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
	...


	next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
	memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
			NGHTTP2_PROTO_VERSION_ID_LEN);
	next_proto_list_len = NGHTTP2_PROTO_VERSION_LEN + 1;

#ifndef OPENSSL_NO_NEXTPROTOENG
	SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
#endif

	return ssl_ctx;
}


/* 
 * Listening and binding new connections 
 *
 */

static void start_listen(struct event_base *evbase, 
		const char *service,
		app_context *app_ctx)
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
		listener = evconnlistener_new_bind(
				evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSABLE,
				16, rp->ai_addr, (int)rp->ai_addrlen);
		if (listener) {
			freeaddrinfo(res);

			return;
		}
	}
	errx(1, "Could not start listener");
}

/* A callback function for accepting a new connection */
static void acceptcb(struct evconnlistener *listener _U_, int fd,
		struct sockaddr *addr, int addrlen, void *arg)
{
	app_context *app_ctx = (app_context *)arg;
	http2_session_data *session_data;

	// Init session_data object
	session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

	// Define 3 callbacks for bufferevent
	bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

/* Eventcb callback is invoked when an event (e.g. connection has been established, 
 * timeout, etc.) occurs on the underlying socket.
 * 
 * Validate that HTTP/2 is negotiated. If not, drop connection.
 */
static void eventcb(struct bufferevent *bev _U_, short events, void *data)
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

		if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
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


/*
 * Initialize nghttp2 connection
 */
static void initialize_nghttp2_session(http2_session_data *session_data)
{
	nghttp2_session_callbacks *callbacks;
	nghttp2_session_callbacks_new(&callbacks);

	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
			on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
			on_stream_close_callback);
	nghttp2_session_callbacks_set_on_header_callbacks(callbacks,
			on_header_callback);
	nghttp2_session_callbacks_set_begin_headers_callback(callbacks,
			on_begin_headers_callback);

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
		{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
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


static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t data, 
		size_t length, int flags _U_, void *user_data)
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
 * Readcb() callback function is invoked when the input buffer has data.
 */
static void readcb(struct buffervent *bev _U_, void *data)
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
			nghttp2_session_want_write(session_data) == 0) {
		delete_http2_session_data(session_data);
		return;
	}

	if (session_send(session_data) != 0) {
		delete_http2_session_data(session_data);
		return;
	}
}

/*
 * On_begin_headers_callback() function is invoked when the reception of a header
 * block in HEADERS or PUSH_PROMISE frame is started
 */
static int on_begin_headers_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

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



/******* TODO *******
 *  Currently,
 *  this method only implements GET method
 *  add also POST for posting images and tags
 */
static int on_header_callback(nghttp2_session *session,
		const nghttp2_frame *frame, const uint8_t *name,
		size_t namelen, const uint8_t *value,
		size_t valuelen, uint8_t *flags _U_,
		void *user_data)
{
	http2_stream_data *stream_data;
	const char PATH[] = ":path";

	// Look the headers and find a match for name/value pair
	// Store the requested path into stream_data object if found
	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
			break;
		}
		
		stream_data =
			nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
		if (!stream_data || stream_data->request_path) {
			break;
		}

		if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
			size_t j;
			for (j = 0; j < valuelen && value[j] != '?'; ++j)
				;
			stream_data->request_path = percent_decode(value, j);
		}
	
		break;
	}

	return 0;
}


/*
 * On_frame_recv_callback() is invoked when a frame is fully received.
 */
static int on_frame_recv_callback(nghttp2_session *session,
		cosnt nghttp2_frame *frame, void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

	switch (frame->hd.type) {
	case NGHTTP2_DATA:
	case NGHTTP2_HEADERS:
		/* Check that the client request has finished */
		if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
			stream_data = nghttp2_session_get_stream_user_data(
					session, frame->user_id);

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

	rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
	if (rv != 0) {
		warnx("Fatal error: %s", nghttp2_strerror(rv));
		return -1;
	}

	return 0;
}


/*
 * File_read_callback() callback function reads the contents of the file
 */
static ssize_t file_read_callback(nghttp2_session *session _U_,
		int32_t stream_id _U_, uint8_t *buf,
		size_t length, uint32_t *data_flags,
		nghttp2_data_source *source,
		void *user_data _U_)
{
	int fd = source->fd;
	ssize_t r;
	while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
		;
	if (r == -1) {
		return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
	}
	if (r == 0) {
		*data_flags |= NGHTTP2_DATA_FLAG_EOF;
	}
	
	return r;
}


/*
 * On_stream_close_callback() function is invoked when the stream is about
 * to close.
 */
static int on_stream_close_callback(nghttp2_session *session, 
		int32_t stream_id, uint32_t error_code _U_,
		void *user_data)
{
	http2_session_data *session_data = (http2_session_data *)user_data;
	http2_stream_data *stream_data;

	stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
	if (!stream_data) {
		return 0;
	}

	remove_stream(session_data, stream_data);
	delete_http2_stream_data(stream_data);
	
	return 0;
}

