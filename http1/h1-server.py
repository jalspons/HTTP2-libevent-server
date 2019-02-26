from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import os


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.send_response(200)
        self.send_header("Host", "localhost:8080")
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", os.stat("index.html").st_size)
        self.end_headers()
        
        f = open('index.html', 'rb')
        while True:
            file_data = f.read(32768) # use an appropriate chunk size
            if file_data is None or len(file_data) == 0:
                break
            self.wfile.write(file_data) 
        f.close()


httpd = HTTPServer(('localhost', 8080), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket,
        keyfile="host.key",
        certfile="host.crt",
        server_side=True)

httpd.serve_forever()
