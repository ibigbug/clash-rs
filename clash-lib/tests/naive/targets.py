"""Container-local synthetic HTTP, EOF-delimited TCP, and UDP echo targets."""
import http.server
import socket
import socketserver
import threading

SIZES = (0, 7, 256 * 1024)
RESPONSE = bytes([0xA5]) * (256 * 1024)
calls = 0
calls_lock = threading.Lock()

class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global calls
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with calls_lock:
            calls += 1
        self.reply(body)

    def do_GET(self):
        with calls_lock:
            self.reply(str(calls).encode())

    def log_message(self, *_args):
        pass

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        expected = bytes(i % 251 for i in range(self.server.request_size))
        received = bytearray()
        while chunk := self.request.recv(65536):
            received.extend(chunk)
            if len(received) > len(expected):
                raise AssertionError("request is longer than expected")
        assert received == expected, "request contents differ"
        self.request.sendall(RESPONSE)
        self.request.shutdown(socket.SHUT_WR)

class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, sock = self.request
        sock.sendto(payload, self.client_address)

servers = [http.server.ThreadingHTTPServer(("127.0.0.1", 10080), HTTP)]
for index, size in enumerate(SIZES):
    server = TCPServer(("127.0.0.1", 10003 + index), TCP)
    server.request_size = size
    servers.append(server)
for port in (10090, 10091):
    servers.append(socketserver.ThreadingUDPServer(("127.0.0.1", port), UDP))
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
print("naive targets ready", flush=True)
threading.Event().wait()
