#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
#
"""Deterministic loopback HTTP, TLS and raw CONNECT integration tests."""
import concurrent.futures
import contextlib
import gzip
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import unittest


def exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("unexpected EOF")
        result += chunk
    return result


def read_header(sock):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        if len(result) > 65536:
            raise ValueError("oversized HTTP header")
    return result


@contextlib.contextmanager
def proxy_process(extra_args=()):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen([BINARY, f"127.0.0.1:{port}", *extra_args],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(150):
            try:
                with socket.create_connection(("127.0.0.1", port), .1):
                    break
            except OSError:
                if process.poll() is not None:
                    raise RuntimeError("proxy exited")
                time.sleep(.02)
        else:
            raise RuntimeError("proxy did not start")
        yield process, port
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise


BODY = b"http-proxy-demo-ok\n"


class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        status = 404 if self.path in ("/missing", "/rpc-error") else 200
        body = BODY
        if self.path == "/headers":
            body = json.dumps(dict(self.headers)).encode()
        if self.path == "/gzip":
            body = gzip.compress(BODY)
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/rpc-error":
            self.send_header("x-bd-error-code", "1008")
        if self.path == "/gzip":
            self.send_header("Content-Encoding", "gzip")
        if self.path == "/hop":
            self.send_header("Connection", "X-Reply, close")
            self.send_header("X-Reply", "must-not-be-forwarded")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        cls.https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        root = Path(__file__).resolve().parents[2]
        context.load_cert_chain(root / "test/cert1.crt", root / "test/cert1.key")
        cls.https.socket = context.wrap_socket(cls.https.socket, server_side=True)
        cls.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        for server in (cls.http, cls.https, cls.echo):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.proxy_context = proxy_process()
        cls.process, cls.port = cls.proxy_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_context.__exit__(None, None, None)
        for server in (cls.http, cls.https, cls.echo):
            server.shutdown()
            server.server_close()

    def client(self):
        sock = socket.create_connection(("127.0.0.1", self.port), 5)
        self.addCleanup(sock.close)
        return sock

    def curl(self, url, *args, data=None):
        result = subprocess.run(["curl", "--silent", "--show-error", "--max-time", "5",
            "--noproxy", "", "-x", f"http://127.0.0.1:{self.port}", *args, url],
            input=data, capture_output=True, timeout=7)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def url(self, path="/", tls=False):
        server = self.https if tls else self.http
        return f"{'https' if tls else 'http'}://127.0.0.1:{server.server_port}{path}"

    def connect(self, sock, port, payload=b""):
        sock.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode() + payload)
        header = read_header(sock)
        self.assertEqual(header, b"HTTP/1.1 200 Connection Established\r\n\r\n")

    def test_curl_http(self):
        self.assertEqual(self.curl(self.url()), BODY)

    def test_curl_https_connect(self):
        self.assertEqual(self.curl(self.url(tls=True), "--insecure"), BODY)

    def test_curl_http_proxytunnel(self):
        self.assertEqual(self.curl(self.url(), "--proxytunnel"), BODY)

    def test_post_large_body(self):
        body = os.urandom(300000)
        self.assertEqual(self.curl(self.url(), "--data-binary", "@-", data=body), body)

    def test_failed_http_upstream_returns_bad_gateway(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.assertEqual(self.curl(f"http://127.0.0.1:{port}/",
                                  "--write-out", "%{http_code}"), b"502")

    def test_status_and_body_are_preserved(self):
        self.assertEqual(self.curl(self.url("/missing"), "--write-out", "%{http_code}"), BODY + b"404")

    def test_origin_rpc_error_preserves_http_response(self):
        self.assertEqual(self.curl(self.url("/rpc-error"), "--write-out", "%{http_code}"), BODY + b"404")

    def test_head_preserves_representation_length(self):
        header = self.curl(self.url(), "--head")
        self.assertIn(f"Content-Length: {len(BODY)}\r\n".encode(), header)
        self.assertTrue(header.endswith(b"\r\n\r\n"))

    def test_gzip_representation(self):
        self.assertEqual(self.curl(self.url("/gzip"), "--compressed"), BODY)

    def test_request_hop_headers_and_authoritative_host(self):
        sock = self.client()
        sock.sendall(f"GET {self.url('/headers')} HTTP/1.1\r\nHost: wrong.example\r\n"
                     "Connection: X-Private, close\r\nX-Private: private\r\n"
                     "Proxy-Authorization: local-secret\r\n\r\n".encode())
        header = read_header(sock)
        size = int(next(line.split(b":", 1)[1] for line in header.split(b"\r\n")
                        if line.lower().startswith(b"content-length:")))
        headers = {k.lower(): v for k, v in json.loads(exact(sock, size)).items()}
        self.assertNotIn("x-private", headers)
        self.assertNotIn("proxy-authorization", headers)
        self.assertEqual(headers["host"], f"127.0.0.1:{self.http.server_port}")

    def test_response_hop_headers(self):
        response = self.curl(self.url("/hop"), "--include")
        header, body = response.split(b"\r\n\r\n", 1)
        self.assertNotIn(b"x-reply:", header.lower())
        self.assertEqual(body, BODY)

    def test_chunked_post_reframed(self):
        sock = self.client()
        sock.sendall(f"POST {self.url()} HTTP/1.1\r\nHost: localhost\r\n"
                     "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                     "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".encode())
        header = read_header(sock)
        self.assertIn(b"200", header.split(b"\r\n", 1)[0])
        self.assertEqual(exact(sock, 11), b"hello world")
        self.assertIn(b"connection: close", header.lower())

    def test_connect_coalesced_binary_payload(self):
        sock = self.client()
        payload = b"\x16\x03\x01\x00\x80" + bytes(range(256))
        self.connect(sock, self.echo.server_address[1], payload)
        self.assertEqual(exact(sock, len(payload)), payload)
        sock.sendall(b"second exchange")
        self.assertEqual(exact(sock, 15), b"second exchange")

    def test_fragmented_connect(self):
        sock = self.client()
        request = f"CONNECT 127.0.0.1:{self.echo.server_address[1]} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
        for part in (request[:3], request[3:17], request[17:-1], request[-1:]):
            sock.sendall(part)
            time.sleep(.01)
        self.assertEqual(read_header(sock), b"HTTP/1.1 200 Connection Established\r\n\r\n")
        sock.sendall(b"fragmented")
        self.assertEqual(exact(sock, 10), b"fragmented")

    def test_banner_and_immediate_eof(self):
        class Banner(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"banner" * 32768)
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            sock = self.client()
            self.connect(sock, server.server_address[1])
            self.assertEqual(exact(sock, 6 * 32768), b"banner" * 32768)
            self.assertEqual(sock.recv(1), b"")
        finally:
            server.shutdown()
            server.server_close()

    def test_forward_keepalive_multiple_requests(self):
        sock = self.client()
        for connection in ("keep-alive", "close"):
            sock.sendall(f"GET {self.url()} HTTP/1.1\r\nHost: localhost\r\nConnection: {connection}\r\n\r\n".encode())
            header = read_header(sock)
            self.assertIn(b"200", header.split(b"\r\n", 1)[0])
            self.assertEqual(exact(sock, len(BODY)), BODY)
        self.assertIn(b"connection: close", header.lower())

    def test_connect_failure_one_reply_then_close(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            sock = self.client()
            sock.sendall(f"CONNECT 127.0.0.1:{unused.getsockname()[1]} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            header = read_header(sock)
            self.assertRegex(header.split(b"\r\n", 1)[0], rb"HTTP/1.1 50[24] ")
            self.assertEqual(sock.recv(1), b"")

    def test_concurrent_tunnels(self):
        def exchange(index):
            with socket.create_connection(("127.0.0.1", self.port), 5) as sock:
                body = f"tunnel-{index}".encode()
                self.connect(sock, self.echo.server_address[1], body)
                self.assertEqual(exact(sock, len(body)), body)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(16)))

    def test_stop_closes_active_tunnel(self):
        with proxy_process() as (process, port):
            with socket.create_connection(("127.0.0.1", port), 5) as sock:
                self.connect(sock, self.echo.server_address[1])
                process.terminate()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(sock.recv(1), b"")

    def test_connect_ipv6_literal(self):
        class IPv6Server(socketserver.ThreadingTCPServer):
            address_family = socket.AF_INET6
        try:
            server = IPv6Server(("::1", 0), Echo)
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            sock = self.client()
            sock.sendall(f"CONNECT [::1]:{server.server_address[1]} HTTP/1.1\r\n"
                         "Host: localhost\r\n\r\n".encode())
            self.assertEqual(read_header(sock), b"HTTP/1.1 200 Connection Established\r\n\r\n")
            sock.sendall(b"ipv6")
            self.assertEqual(exact(sock, 4), b"ipv6")
        finally:
            sock.close()
            server.shutdown()
            server.server_close()

    def test_invalid_port_and_get_body_are_rejected(self):
        for target, body in (("http://127.0.0.1:65536/", b""),
                             (self.url(), b"unsupported-get-body")):
            with self.subTest(target=target):
                sock = self.client()
                sock.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\n"
                             f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                self.assertIn(b"400", read_header(sock).split(b"\r\n", 1)[0])


if __name__ == "__main__":
    BINARY = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else "build/http_proxy")
    unittest.main(verbosity=2)
