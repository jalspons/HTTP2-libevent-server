

static const char ERROR_HTML[] =    "<html><head><title>404</title></head>"
                                    "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session, 
        http2_stream_data *stream_data);

