
#include <error.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>

#include "libevent-http2-error.h"

static const char ERROR_HTML[] =    "<html><head><title>404</title></head>"
                                    "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session, 
        http2_stream_data *stream_data)
{
    int rv;
    ssize_t writelen;
    int pipefd[2];
    nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

    rv = pipe(pipefd);
    if (rv != 0) {
        warn("Could not create pipe");
        
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                sream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
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

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                pipefd[0]) != 0) {
        close(pipefd[0]);
        return -1;
    }

    return 0;
}
