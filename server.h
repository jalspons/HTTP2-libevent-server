#ifndef SERVER_H
#define SERVER_H

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                 \
{                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) -1, sizeof(VALUE) -1,    \
    NGHTTP2_NV_FLAG_NONE                                                     \
} 

#define MAKE_NV_CS(NAME, VALUE)                                              \
{                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),      \
    NGHTTP2_NV_FLAG_NONE                                                     \
}

#define isGET(a) (a[0] == 'G' && a[1] == 'E' && a[2] == 'T')
#define isPOST(a) (a[0] == 'P' && a[2] == 'O' && a[3] == 'S' && a[4] == 'T')
#define isPUT(a) (a[0] == 'P' && a[1] == 'U' && a[2] == 'T')

enum HTTP_method {
    UNDEFINED,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT
};

#define GET_STATUS(a) (a == HTTP_GET ? "200" : "301")

typedef struct {
	SSL_CTX *ssl_ctx;
	struct event_base *evbase;
} app_context;

typedef struct http2_stream_data {
	struct http2_stream_data *prev, *next;
	char *request_path;
    enum HTTP_method method;
    size_t content_length;
    int32_t stream_id;
	int fd;
} http2_stream_data;

typedef struct http2_session_data {
	struct http2_stream_data root;
	struct bufferevent *bev;
	app_context *app_ctx;
	nghttp2_session *session;
	char *client_addr;
} http2_session_data;



#endif
