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
"""Local integration tests; starts the demo and an HTTP/echo upstream."""
import concurrent.futures
import http.server
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import unittest


def exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("unexpected EOF")
        data += chunk
    return data


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"socks5-demo-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        cls.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        for server in (cls.echo, cls.http):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        cls.process = subprocess.Popen([BINARY, f"127.0.0.1:{cls.port}"],
                                       stdout=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", cls.port), .1):
                    return
            except OSError:
                if cls.process.poll() is not None:
                    raise RuntimeError("proxy exited")
                time.sleep(.05)
        cls.process.terminate()
        cls.process.wait(timeout=5)
        raise RuntimeError("proxy did not start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        for server in (cls.echo, cls.http):
            server.shutdown()
            server.server_close()

    def client(self):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        self.addCleanup(s.close)
        return s

    def request(self, port, domain=False, command=1):
        addr = b"\x03\x09localhost" if domain else b"\x01\x7f\x00\x00\x01"
        return bytes([5, command, 0]) + addr + struct.pack("!H", port)

    def reply(self, s):
        header = exact(s, 4)
        self.assertEqual(header[:1], b"\x05")
        exact(s, (4 if header[3] == 1 else 16) + 2)
        return header[1]

    def handshake(self, s, port, domain=False):
        s.sendall(b"\x05\x01\x00")
        self.assertEqual(exact(s, 2), b"\x05\x00")
        s.sendall(self.request(port, domain))
        self.assertEqual(self.reply(s), 0)

    def test_fragmented_handshake_and_coalesced_payload(self):
        s = self.client()
        for byte in b"\x05\x02\x02\x00":
            s.sendall(bytes([byte]))
            time.sleep(.01)
        self.assertEqual(exact(s, 2), b"\x05\x00")
        req = self.request(self.echo.server_address[1])
        for byte in req[:-1]:
            s.sendall(bytes([byte]))
            time.sleep(.005)
        s.sendall(req[-1:] + b"early payload")
        self.assertEqual(self.reply(s), 0)
        self.assertEqual(exact(s, 13), b"early payload")

    def test_rdma_fallback_then_socks5(self):
        s = self.client()
        # A valid partial RDMA magic must still wait for the remaining hello.
        s.sendall(b"RD")
        s.settimeout(.1)
        with self.assertRaises(socket.timeout):
            s.recv(1)
        s.settimeout(5)
        s.sendall(b"MA" + struct.pack("!H", 40) + bytes(34))
        hello = exact(s, 40)
        self.assertEqual(hello[:6], b"RDMA" + struct.pack("!H", 40))
        # ACK completes fallback; the same read may contain a short greeting.
        s.sendall(bytes(4) + b"\x05\x01\x00")
        self.assertEqual(exact(s, 2), b"\x05\x00")
        s.sendall(self.request(self.echo.server_address[1]))
        self.assertEqual(self.reply(s), 0)
        s.sendall(b"fallback")
        self.assertEqual(exact(s, 8), b"fallback")

    def test_custom_service_without_upstream(self):
        if not CUSTOM_BINARY:
            self.skipTest("pass the custom service binary as the second argument")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen([CUSTOM_BINARY, f"127.0.0.1:{port}"],
                                   stdout=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    s = socket.create_connection(("127.0.0.1", port), .1)
                    break
                except OSError:
                    if process.poll() is not None:
                        self.fail("custom service exited")
                    time.sleep(.02)
            else:
                self.fail("custom service did not start")
            with s:
                s.settimeout(5)
                self.handshake(s, 9, domain=True)
                # Echoes arrive while the server is running. A second exchange
                # also verifies completion allows subsequent DATA processing.
                for payload in (b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                                b"handled by a user-defined service"):
                    s.sendall(payload)
                    self.assertEqual(exact(s, len(payload)), payload)
                    self.assertIsNone(process.poll())
                process.terminate()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(s.recv(1), b"")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def test_domain_and_large_bidirectional_transfer(self):
        s = self.client()
        self.handshake(s, self.echo.server_address[1], domain=True)
        data = os.urandom(512 * 1024)
        # Receive concurrently to exercise both relay directions.
        with concurrent.futures.ThreadPoolExecutor() as pool:
            received = pool.submit(exact, s, len(data))
            s.sendall(data)
            self.assertEqual(received.result(timeout=10), data)

    def test_ipv6(self):
        class IPv6Server(socketserver.ThreadingTCPServer):
            address_family = socket.AF_INET6
        try:
            server = IPv6Server(("::1", 0), Echo)
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            s = self.client()
            s.sendall(b"\x05\x01\x00")
            self.assertEqual(exact(s, 2), b"\x05\x00")
            s.sendall(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1")
                      + struct.pack("!H", server.server_address[1]))
            self.assertEqual(self.reply(s), 0)
            s.sendall(b"ipv6")
            self.assertEqual(exact(s, 4), b"ipv6")
            s.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_upstream_banner_and_immediate_eof(self):
        class Banner(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"upstream-banner" * 8192)
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            s = self.client()
            self.handshake(s, server.server_address[1])
            self.assertEqual(exact(s, 15 * 8192), b"upstream-banner" * 8192)
            self.assertEqual(s.recv(1), b"")
        finally:
            server.shutdown()
            server.server_close()

    def test_server_stop_with_active_sessions(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen([BINARY, f"127.0.0.1:{port}"],
                                   stdout=subprocess.DEVNULL)
        clients = []
        try:
            for _ in range(100):
                try:
                    first = socket.create_connection(("127.0.0.1", port), .1)
                    break
                except OSError:
                    time.sleep(.02)
            else:
                self.fail("second proxy did not start")
            first.settimeout(5)
            clients.append(first)
            first.sendall(b"\x05")  # incomplete handshake
            second = socket.create_connection(("127.0.0.1", port), 5)
            clients.append(second)
            self.handshake(second, self.echo.server_address[1])
            process.terminate()
            self.assertEqual(process.wait(timeout=5), 0)
            for s in clients:
                self.assertEqual(s.recv(1), b"")
        finally:
            for s in clients:
                s.close()
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_reject_auth(self):
        s = self.client()
        s.sendall(b"\x05\x01\x02")
        self.assertEqual(exact(s, 2), b"\x05\xff")
        self.assertEqual(s.recv(1), b"")

    def test_reject_command_and_address(self):
        for req, code in [(self.request(80, command=2), 7),
                          (b"\x05\x01\x00\x09", 8)]:
            with self.subTest(code=code):
                s = self.client()
                s.sendall(b"\x05\x01\x00")
                self.assertEqual(exact(s, 2), b"\x05\x00")
                s.sendall(req)
                self.assertEqual(self.reply(s), code)
                self.assertEqual(s.recv(1), b"")

    def test_connect_failure(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            s = self.client()
            s.sendall(b"\x05\x01\x00")
            self.assertEqual(exact(s, 2), b"\x05\x00")
            s.sendall(self.request(unused.getsockname()[1]))
            self.assertEqual(self.reply(s), 5)
            # A failed CONNECT gets one reply followed by EOF, not another reply.
            self.assertEqual(s.recv(1), b"")

    def test_http_protocol_coexists(self):
        s = self.client()
        s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = b""
        while b"\r\n" not in response:
            block = s.recv(4096)
            if not block:
                break
            response += block
        self.assertIn(b"200 OK", response.split(b"\r\n", 1)[0])

    def test_curl_http(self):
        result = subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--max-time", "5",
            "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{self.port}",
            f"http://localhost:{self.http.server_address[1]}/"],
            capture_output=True, check=True)
        self.assertEqual(result.stdout, b"socks5-demo-ok\n")

    def test_multiple_connections(self):
        def exchange(i):
            with socket.create_connection(("127.0.0.1", self.port), 5) as s:
                self.handshake(s, self.echo.server_address[1])
                payload = f"connection-{i}".encode()
                s.sendall(payload)
                self.assertEqual(exact(s, len(payload)), payload)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(exchange, range(16)))


if __name__ == "__main__":
    BINARY = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else
                             "build/socks5_proxy")
    CUSTOM_BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None
    unittest.main(verbosity=2)
