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

"""Local VMess adapter integration; reuse existing proxy client/process helpers."""
import contextlib
import importlib.util
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time
import unittest

helper_path = Path(__file__).resolve().parents[1] / "http_proxy/smoke_test.py"
spec = importlib.util.spec_from_file_location("http_smoke", helper_path)
http_smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(http_smoke)
exact = http_smoke.exact
read_header = http_smoke.read_header
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


@contextlib.contextmanager
def peer(transport, mode, size):
    process = subprocess.Popen([PEER, transport, mode, str(size)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([process.stdout], [], [], 5)[0]:
            raise RuntimeError("peer did not start")
        port = int(process.stdout.readline())
        yield process, port
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def proxy_args(port, transport, extra=()):
    args = [f"--vmess_host=127.0.0.1", f"--vmess_port={port}",
            f"--vmess_uuid={UUID}", "--admin_address=127.0.0.1:0"]
    if transport == "ws":
        args += ["--vmess_ws_path=/images", "--vmess_ws_host=vmess.test"]
    return [*args, *extra]


class Tests(unittest.TestCase):
    def request(self, sock, protocol, payload=b"", expect_success=True):
        if protocol == "socks5":
            sock.sendall(b"\x05\x01\x00")
            self.assertEqual(exact(sock, 2), b"\x05\x00")
            host = b"target.invalid"
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", 443)
            # Coalesce the request and client data in the same TCP write.
            sock.sendall(request + payload)
            header = exact(sock, 4)
            exact(sock, (4 if header[3] == 1 else 16) + 2)
            self.assertEqual(header[1] == 0, expect_success)
        else:
            sock.sendall(b"CONNECT target.invalid:443 HTTP/1.1\r\n"
                         b"Host: target.invalid:443\r\n\r\n" + payload)
            header = read_header(sock)
            self.assertEqual(header.startswith(b"HTTP/1.1 200"), expect_success)
        return sock

    def exchange(self, transport, protocol, mode="normal", size=1234):
        payload = bytes(i % 251 for i in range(size))
        with peer(transport, mode, len(payload)) as (server, upstream):
            with http_smoke.proxy_process(proxy_args(upstream, transport)) as (_, port):
                with socket.create_connection(("127.0.0.1", port), 5) as client:
                    self.request(client, protocol, payload)
                    self.assertEqual(exact(client, len(payload)), payload)
                    self.assertEqual(client.recv(1), b"")
                self.assertEqual(server.wait(timeout=5), 0, server.stderr.read())
                self.assertIn("target=target.invalid:443", server.stdout.read())

    def test_tcp_socks5(self):
        self.exchange("raw", "socks5")

    def test_tcp_http_connect(self):
        self.exchange("raw", "http")

    def test_websocket_socks5(self):
        self.exchange("ws", "socks5")

    def test_websocket_http_connect(self):
        self.exchange("ws", "http")

    def test_large_bidirectional_tcp(self):
        self.exchange("raw", "socks5", size=256 * 1024)

    def test_large_bidirectional_websocket(self):
        self.exchange("ws", "http", size=256 * 1024)

    def test_native_eof_preserves_tail(self):
        self.exchange("raw", "http", "native_eof", 33000)

    def test_websocket_close_preserves_tail(self):
        self.exchange("ws", "socks5", "ws_close", 33000)

    def test_invalid_ciphertext_or_echo(self):
        for transport in ("raw", "ws"):
            for mode in ("bad_echo", "bad_tag"):
                with self.subTest(transport=transport, mode=mode):
                    with peer(transport, mode, 500) as (server, upstream):
                        with http_smoke.proxy_process(proxy_args(upstream, transport)) as (_, port):
                            with socket.create_connection(("127.0.0.1", port), 5) as client:
                                self.request(client, "http", b"a" * 500)
                                self.assertEqual(client.recv(1), b"")
                            self.assertEqual(server.wait(timeout=5), 0, server.stderr.read())

    def test_websocket_rejection(self):
        for mode in ("reject", "bad_accept"):
            for protocol in ("http", "socks5"):
                with self.subTest(mode=mode, protocol=protocol):
                    with peer("ws", mode, 0) as (server, upstream):
                        with http_smoke.proxy_process(proxy_args(upstream, "ws")) as (_, port):
                            with socket.create_connection(("127.0.0.1", port), 5) as client:
                                self.request(client, protocol, expect_success=False)
                                self.assertEqual(client.recv(1), b"")
                            self.assertEqual(server.wait(timeout=5), 0, server.stderr.read())

    def test_websocket_upgrade_timeout(self):
        with peer("ws", "stall", 0) as (_, upstream):
            with http_smoke.proxy_process(proxy_args(
                    upstream, "ws", ["--connect_timeout_ms=200"])) as (_, port):
                with socket.create_connection(("127.0.0.1", port), 5) as client:
                    started = time.monotonic()
                    self.request(client, "http", expect_success=False)
                    self.assertLess(time.monotonic() - started, 2)

    def test_shutdown_cancels_pending_upgrade(self):
        with peer("ws", "stall", 0) as (_, upstream):
            with http_smoke.proxy_process(proxy_args(upstream, "ws")) as (process, port):
                with socket.create_connection(("127.0.0.1", port), 5) as client:
                    client.sendall(b"CONNECT target.invalid:443 HTTP/1.1\r\n\r\n")
                    time.sleep(.1)
                    process.terminate()
                    self.assertEqual(process.wait(timeout=3), 0)

    def test_tcp_connect_failure(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))  # Bound but not listening.
            with http_smoke.proxy_process(proxy_args(
                    unused.getsockname()[1], "raw", ["--connect_timeout_ms=200"])) as (_, port):
                with socket.create_connection(("127.0.0.1", port), 5) as client:
                    self.request(client, "socks5", expect_success=False)

    def test_plain_http_cannot_bypass_vmess(self):
        with http_smoke.proxy_process(proxy_args(1, "raw")) as (_, port):
            with socket.create_connection(("127.0.0.1", port), 5) as client:
                client.sendall(b"GET http://target.invalid/ HTTP/1.1\r\n"
                               b"Host: target.invalid\r\nConnection: close\r\n\r\n")
                self.assertTrue(read_header(client).startswith(b"HTTP/1.1 405"))

    def test_invalid_configuration(self):
        for args in (["--vmess_uuid=bad"], ["--vmess_ws_path=/bad\r\npath"],
                     ["--vmess_port=70000"], ["--upstream_host=localhost", "--upstream_port=80"]):
            with self.subTest(args=args):
                process = subprocess.run([BINARY, *proxy_args(1, "raw"), *args],
                                         capture_output=True, timeout=5)
                self.assertNotEqual(process.returncode, 0)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: smoke_test.py <vmess_proxy> <vmess_fake_peer>")
    BINARY, PEER = [str(Path(p).resolve()) for p in sys.argv[1:]]
    http_smoke.BINARY = BINARY
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
