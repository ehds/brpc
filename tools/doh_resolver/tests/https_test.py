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

"""Public-interface tests against a local, certificate-verified HTTPS DoH server."""
import collections
import http.server
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def label(name):
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"


def record(owner, kind, data, ttl=60):
    return owner + struct.pack("!HHIH", kind, 1, ttl, len(data)) + data


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # Expected when a deadline or certificate check closes the peer.

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        offset, parts = 12, []
        while body[offset]:
            size = body[offset]
            parts.append(body[offset + 1:offset + 1 + size].decode())
            offset += size + 1
        name = ".".join(parts)
        kind, dns_class = struct.unpack("!HH", body[offset + 1:offset + 5])
        with self.server.lock:
            self.server.counts[name, kind] += 1
            self.server.hosts.append(self.headers["Host"])
        if self.path != "/dns-query" or dns_class != 1 or body[:12] != bytes.fromhex("000001000001000000000000"):
            self.send_error(400)
            return
        if self.headers["Content-Type"] != "application/dns-message" or self.headers["Accept"] != "application/dns-message":
            self.send_error(400)
            return
        if name == "slow.test" or (name == "deadline.test" and kind == 28):
            time.sleep(.4)
        flags, question, answers = 0x8180, body[12:], []
        address = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                  "192.0.2.1" if kind == 1 else "2001:db8::1")
        ttl = 0 if name == "zero.test" else (2 if name == "short.test" else 60)
        if name == "missing.test":
            flags = 0x8183
        elif name == "empty.test" or (name == "v4.test" and kind == 28):
            pass
        elif name == "cname.test":
            # An address precedes its CNAME to exercise order-independent resolution.
            answers = [record(label("alias.test"), kind, address, 50),
                       record(b"\xc0\x0c", 5, label("alias.test"), 20)]
        elif name == "loop.test":
            answers = [record(b"\xc0\x0c", 5, b"\xc0\x0c")]
        elif name == "badpointer.test":
            answers = [record(b"\xc0\x0c", 5, b"\xff\xff")]
        elif name == "badlength.test":
            answers = [record(b"\xc0\x0c", kind, b"x")]
        elif name == "unrelated.test":
            answers = [record(label("other.test"), kind, address)]
        else:
            answers = [record(b"\xc0\x0c", kind, address, ttl)]
        packet = struct.pack("!HHHHHH", 0, flags, 1, len(answers), 0, 0) + question + b"".join(answers)
        if name == "mismatch.test":
            packet = struct.pack("!HHHHHH", 0, flags, 1, 0, 0, 0) + label("wrong.test") + struct.pack("!HH", kind, 1)
        elif name == "truncated.test":
            packet = packet[:-1]
        elif name == "tc.test":
            packet = packet[:2] + struct.pack("!H", flags | 0x200) + packet[4:]
        elif name == "badid.test":
            packet = b"\0\1" + packet[2:]
        elif name == "oversized.test":
            packet += b"x" * 65536
        self.send_response(503 if name == "http-error.test" else 200)
        self.send_header("Content-Type", "application/json" if name == "media.test" else "application/dns-message")
        if name == "age.test":
            self.send_header("Age", "10")
        self.send_header("Content-Length", str(len(packet)))
        self.end_headers()
        try:
            self.wfile.write(packet)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # Expected when testing deadline cancellation.

    def log_message(self, *_):
        pass


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        config = root / "openssl.cnf"
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                          "[dn]\nCN=doh.test\n[ext]\nsubjectAltName=DNS:doh.test\n"
                          "basicConstraints=critical,CA:TRUE\n")
        cls.cert = root / "ca.pem"
        key = root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-config", str(config), "-keyout", str(key),
                        "-out", str(cls.cert)], check=True, capture_output=True)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        cls.server.counts = collections.Counter()
        cls.server.hosts = []
        cls.server.lock = threading.Lock()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.sni = []
        context.set_servername_callback(lambda _, name, __: cls.sni.append(name))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def run_query(self, name, family="both", timeout=1000, repeat=1, cache=256,
                  endpoint=None, ca=None, success=True):
        result = subprocess.run([BINARY, endpoint or f"https://doh.test:{self.port}/dns-query",
                                 "127.0.0.1", str(self.cert if ca is None else ca), name,
                                 family, str(timeout), str(repeat), str(cache)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return result.stdout

    def test_both_families_and_bootstrap_identity(self):
        text = self.run_query("both.test")
        self.assertIn("192.0.2.1", text)
        self.assertIn("2001:db8::1", text)
        self.assertIn(f"doh.test:{self.port}", self.server.hosts)
        self.assertIn("doh.test", self.sni)

    def test_cname_and_ttl(self):
        self.assertIn("ttl=", self.run_query("cname.test", "a"))
        # Returned TTL cannot exceed the 20-second CNAME, even with a 50s A record.
        ttl = int(self.run_query("cname.test", "a").split()[0][4:])
        self.assertLessEqual(ttl, 20)
        self.assertGreater(ttl, 0)

    def test_cache_and_normalization(self):
        before = self.server.counts["cache.test", 1]
        self.run_query("CACHE.TEST.", "a", repeat=2)
        self.assertEqual(self.server.counts["cache.test", 1] - before, 1)

    def test_zero_ttl_and_disabled_cache(self):
        for name, cache in (("zero.test", 256), ("disabled.test", 0)):
            with self.subTest(name=name):
                before = self.server.counts[name, 1]
                self.run_query(name, "a", repeat=2, cache=cache)
                self.assertEqual(self.server.counts[name, 1] - before, 2)

    def test_cache_expiry(self):
        before = self.server.counts["short.test", 1]
        self.run_query("short.test", "a", repeat="2:2100")
        self.assertEqual(self.server.counts["short.test", 1] - before, 2)

    def test_concurrent_resolve(self):
        self.assertEqual(self.run_query("concurrent.test", "a", repeat=-8).count("192.0.2.1"), 8)

    def test_age_reduces_ttl(self):
        ttl = int(self.run_query("age.test", "a").split()[0][4:])
        self.assertLessEqual(ttl, 50)

    def test_literal_and_invalid_name(self):
        before = sum(self.server.counts.values())
        self.assertIn("ttl=0 2001:db8::2", self.run_query("2001:db8::2"))
        self.assertIn("ttl=0 192.0.2.2", self.run_query("192.0.2.2"))
        self.run_query("bad..test", success=False)
        self.run_query("192.0.2.2", "aaaa", success=False)
        self.assertEqual(sum(self.server.counts.values()), before)

    def test_partial_family_success(self):
        self.assertIn("192.0.2.1", self.run_query("v4.test"))

    def test_shared_deadline_with_partial_success(self):
        started = time.monotonic()
        text = self.run_query("deadline.test", timeout=80)
        self.assertIn("192.0.2.1", text)
        self.assertNotIn("2001:db8::1", text)
        self.assertLess(time.monotonic() - started, 2)

    def test_dns_and_http_failures_preserve_output(self):
        for name in ("missing", "empty", "loop", "badpointer", "badlength", "unrelated",
                     "mismatch", "truncated", "tc", "badid", "media", "http-error", "oversized"):
            with self.subTest(name=name):
                self.run_query(name + ".test", "a", success=False)

    def test_certificate_and_hostname_verification(self):
        self.run_query("both.test", "a", ca="", success=False)
        self.run_query("both.test", "a",
                       endpoint=f"https://wrong.test:{self.port}/dns-query", success=False)
        self.run_query("both.test", "a",
                       endpoint=f"http://doh.test:{self.port}/dns-query", success=False)

    def test_timeout(self):
        started = time.monotonic()
        self.run_query("slow.test", timeout=80, success=False)
        self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    BINARY = str(Path(sys.argv.pop()).resolve())
    unittest.main(verbosity=2)
