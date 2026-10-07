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
"""SOCKS5 and HTTP proxy on one Server/listener; reuses both smoke suites."""
import concurrent.futures
import contextlib
import http.client
import http.server
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest

import smoke_test as socks5_smoke

# Load the HTTP suite under a distinct name; both folders have smoke_test.py.
http_path = Path(__file__).resolve().parents[1] / "http_proxy/smoke_test.py"
spec = importlib.util.spec_from_file_location("http_proxy_smoke", http_path)
http_smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(http_smoke)

# Every temporary combined proxy gets its own tools port, including instances
# started by inherited HTTP cases. Explicit addresses still exercise the CLI.
original_proxy_process = http_smoke.proxy_process


def proxy_process(extra_args=()):
    if not any(arg.split("=", 1)[0] == "--admin_address" for arg in extra_args):
        extra_args = ("--admin_address=127.0.0.1:0", *extra_args)
    return original_proxy_process(extra_args)


http_smoke.proxy_process = proxy_process


class Tests(http_smoke.Tests):
    # The parent's fixture starts one combined proxy for HTTP and SOCKS5 tests.
    # Reuse the SOCKS5 helpers and cases compatible with that same fixture.
    handshake = socks5_smoke.Tests.handshake
    request = socks5_smoke.Tests.request
    reply = socks5_smoke.Tests.reply
    test_socks5_fragmented_handshake = (
        socks5_smoke.Tests.test_fragmented_handshake_and_coalesced_payload)
    test_socks5_domain_and_large_transfer = (
        socks5_smoke.Tests.test_domain_and_large_bidirectional_transfer)
    test_socks5_ipv6 = socks5_smoke.Tests.test_ipv6
    test_socks5_banner_and_immediate_eof = (
        socks5_smoke.Tests.test_upstream_banner_and_immediate_eof)
    test_socks5_reject_auth = socks5_smoke.Tests.test_reject_auth
    test_socks5_reject_command_and_address = (
        socks5_smoke.Tests.test_reject_command_and_address)

    @contextlib.contextmanager
    def short_connect_deadline(self):
        # These cases check failure replies/EOF, using a bound non-listening
        # target that may drop SYNs. Keep the configured deadline below the
        # test client's 5s read timeout, independent of the longer demo default.
        with http_smoke.proxy_process(("--connect_timeout_ms=100",)) as (_, port):
            original_port = self.port
            self.port = port
            try:
                yield
            finally:
                self.port = original_port

    def test_connect_failure_one_reply_then_close(self):
        with self.short_connect_deadline():
            http_smoke.Tests.test_connect_failure_one_reply_then_close(self)

    def test_socks5_connect_failure(self):
        with self.short_connect_deadline():
            socks5_smoke.Tests.test_connect_failure(self)

    def test_curl_socks5_http_and_https(self):
        for tls in (False, True):
            with self.subTest(tls=tls):
                args = ["curl", "--fail", "--silent", "--show-error", "--max-time", "5",
                        "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{self.port}"]
                if tls:
                    args.append("--insecure")  # Repository's loopback test certificate.
                result = subprocess.run(args + [self.url(tls=tls)],
                                        capture_output=True, timeout=7)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, http_smoke.BODY)

    def test_concurrent_protocols_on_the_same_port(self):
        barrier = threading.Barrier(16)
        port = self.echo.server_address[1]

        def exchange(index):
            with socket.create_connection(("127.0.0.1", self.port), 5) as client:
                if index % 2:
                    self.handshake(client, port)
                    # HTTP-looking bytes inside SOCKS5 must stay raw tunnel data.
                    prefix = b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n"
                else:
                    self.connect(client, port)
                    # A SOCKS5-looking prefix inside HTTP CONNECT stays raw too.
                    prefix = b"\x05\x01\x00"
                barrier.wait(timeout=5)  # Both protocols hold active tunnels together.
                for turn in range(3):
                    payload = prefix + bytes([index, turn]) + os.urandom(32768)
                    client.sendall(payload)
                    self.assertEqual(http_smoke.exact(client, len(payload)), payload)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(exchange, range(16)))

    def test_fixed_upstream_is_independent_of_requested_target(self):
        args = ("--upstream_host=127.0.0.1",
                f"--upstream_port={self.echo.server_address[1]}")
        with http_smoke.proxy_process(args) as (_, port):
            for protocol in ("socks5", "http"):
                with self.subTest(protocol=protocol), \
                        socket.create_connection(("127.0.0.1", port), 5) as client:
                    host = b"unresolvable.invalid"
                    if protocol == "socks5":
                        client.sendall(b"\x05\x01\x00")
                        self.assertEqual(http_smoke.exact(client, 2), b"\x05\x00")
                        client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) +
                                       host + (1234).to_bytes(2, "big"))
                        self.assertEqual(self.reply(client), 0)
                    else:
                        client.sendall(b"CONNECT " + host + b":1234 HTTP/1.1\r\n"
                                       b"Host: ignored\r\n\r\n")
                        self.assertEqual(http_smoke.read_header(client),
                                         b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    payload = b"fixed endpoint: " + protocol.encode() + os.urandom(32768)
                    client.sendall(payload)
                    self.assertEqual(http_smoke.exact(client, len(payload)), payload)

    def test_independent_builtin_tools_server(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            admin_port = probe.getsockname()[1]
        with http_smoke.proxy_process((f"--admin_address=127.0.0.1:{admin_port}",)) as (process, port):
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", admin_port), .1):
                        break
                except OSError:
                    self.assertIsNone(process.poll(), "tools server startup failed")
                    time.sleep(.02)
            else:
                self.fail("tools server did not start")
            with socket.create_connection(("127.0.0.1", port), 5) as socks5_client, \
                    socket.create_connection(("127.0.0.1", port), 5) as http_client:
                self.handshake(socks5_client, self.echo.server_address[1])
                self.connect(http_client, self.echo.server_address[1])
                # The tools respond while both kinds of proxy tunnel are open.
                for path in ("/", "/health", "/status", "/vars", "/connections",
                             "/flags", "/brpc_metrics", "/sockets", "/js/jquery_min"):
                    with self.subTest(path=path):
                        client = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=5)
                        try:
                            client.request("GET", path, headers={"Accept": "text/html"})
                            response = client.getresponse()
                            body = response.read()
                            self.assertEqual(response.status, 200, body[:500])
                            self.assertTrue(body)
                            if path == "/vars":
                                self.assertIn(b"rpc_server_proxy_connection_count", body)
                                self.assertIn(b"rpc_server_proxy_admin_connection_count", body)
                        finally:
                            client.close()
                for client in (socks5_client, http_client):
                    client.sendall(b"tools-and-proxy")
                    self.assertEqual(http_smoke.exact(client, 15), b"tools-and-proxy")
                # The public proxy port does not expose the builtin URL routes.
                with socket.create_connection(("127.0.0.1", port), 5) as client:
                    client.sendall(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    self.assertTrue(http_smoke.read_header(client).startswith(b"HTTP/1.1 400"))
                process.terminate()
                self.assertEqual(process.wait(timeout=5), 0)
                for client in (socks5_client, http_client):
                    self.assertEqual(client.recv(1), b"")
            # Both listening sockets are released after the process stops.
            for closed_port in (port, admin_port):
                with socket.socket() as client:
                    client.settimeout(1)
                    self.assertNotEqual(client.connect_ex(("127.0.0.1", closed_port)), 0)

    def test_admin_start_failure_rolls_back_proxy_listener(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                proxy_port = probe.getsockname()[1]
            result = subprocess.run(
                [http_smoke.BINARY, f"127.0.0.1:{proxy_port}",
                 f"--admin_address=127.0.0.1:{occupied.getsockname()[1]}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            with socket.socket() as client:
                client.settimeout(1)
                self.assertNotEqual(client.connect_ex(("127.0.0.1", proxy_port)), 0)

    def test_configured_socks5_handshake_timeout(self):
        with http_smoke.proxy_process(("--connect_timeout_ms=50",
                                      "--handshake_timeout_ms=100")) as (_, port):
            with socket.create_connection(("127.0.0.1", port), 2) as client:
                client.sendall(b"\x05")
                self.assertEqual(client.recv(1), b"")
            # Expiring one SOCKS5 session leaves HTTP CONNECT on the same server usable.
            with socket.create_connection(("127.0.0.1", port), 2) as client:
                self.connect(client, self.echo.server_address[1], b"still-live")
                self.assertEqual(http_smoke.exact(client, 10), b"still-live")

    def test_configured_http_request_timeout(self):
        class SlowHTTP(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(.3)
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The proxy has already timed out and closed this hop.

            def log_message(self, *args):
                pass

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHTTP)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        try:
            with http_smoke.proxy_process(("--connect_timeout_ms=50",
                                          "--request_timeout_ms=80")) as (_, port):
                with socket.create_connection(("127.0.0.1", port), 2) as client:
                    target = f"127.0.0.1:{upstream.server_port}"
                    client.sendall(f"GET http://{target}/ HTTP/1.1\r\n"
                                   f"Host: {target}\r\n\r\n".encode())
                    self.assertTrue(http_smoke.read_header(client).startswith(b"HTTP/1.1 504"))
        finally:
            upstream.shutdown()
            upstream.server_close()

    def test_stop_closes_both_protocols_and_partial_handshakes(self):
        # A separate combined proxy lets this test stop it without affecting
        # the shared fixture used by the other protocol tests.
        with http_smoke.proxy_process() as (process, port):
            clients = []
            try:
                for protocol in ("socks5", "http", "partial-socks5", "partial-http"):
                    client = socket.create_connection(("127.0.0.1", port), 5)
                    clients.append(client)
                    if protocol == "socks5":
                        self.handshake(client, self.echo.server_address[1])
                    elif protocol == "http":
                        self.connect(client, self.echo.server_address[1])
                    elif protocol == "partial-socks5":
                        client.sendall(b"\x05")
                    else:
                        client.sendall(b"C")
                    if protocol.startswith("partial-"):
                        client.settimeout(.1)
                        with self.assertRaises(socket.timeout):
                            client.recv(1)
                        client.settimeout(5)
                process.terminate()
                self.assertEqual(process.wait(timeout=5), 0)
                for client in clients:
                    self.assertEqual(client.recv(1), b"")
            finally:
                for client in clients:
                    client.close()


if __name__ == "__main__":
    http_smoke.BINARY = os.path.abspath(sys.argv.pop(1) if len(sys.argv) > 1 else
                                      "build/socks5_http_proxy")
    unittest.main(verbosity=2)
