#!/usr/bin/env python3
"""
Test cho stinger/request.py - parse Burp request, chèn payload, tính lại Content-Length.

Chạy:  python -m pytest tests/test_request.py -v
Hoặc:  python tests/test_request.py     (self-contained, không cần pytest)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stinger.request import (
    HttpRequest,
    RequestParseError,
    parse_request,
    parse_request_file,
    INJECTION_MARK,
)

# Một Burp request POST JSON có marker '*' ở vị trí id (giống target thật).
BURP_POST = (
    "POST /action.php HTTP/1.1\r\n"
    "Host: 154.57.164.72:32442\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 10\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    '{"id":"*"}'
)

BURP_GET = (
    "GET /search?q=*&page=1 HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Accept: */*\r\n"
    "\r\n"
)


def test_parse_basic():
    r = parse_request(BURP_POST)
    assert r.method == "POST"
    assert r.path == "/action.php"
    assert r.version == "1.1"
    assert r.get_header("Host") == "154.57.164.72:32442"
    assert r.get_header("Content-Type") == "application/json"
    assert r.body == '{"id":"*"}'


def test_url_scheme_and_port():
    r = parse_request(BURP_POST)
    # port 32442 != 443 -> http (cổng 32442 khác 443)
    assert r.url() == "http://154.57.164.72:32442/action.php"


def test_url_https_on_443():
    raw = BURP_POST.replace("154.57.164.72:32442", "secure.example.com:443")
    r = parse_request(raw)
    assert r.url().startswith("https://secure.example.com:443")


def test_marker_detection():
    r = parse_request(BURP_POST)
    assert r.has_marker() is True
    assert r.marker_location() == "body"

    g = parse_request(BURP_GET)
    assert g.marker_location() == "path"


def test_no_marker_raises():
    raw = BURP_POST.replace("*", "1")
    r = parse_request(raw)
    assert r.has_marker() is False
    try:
        r.with_payload("(if(1=1,sleep(3),1))")
    except RequestParseError:
        pass
    else:
        raise AssertionError("phải raise khi không có marker")


def test_payload_injection_and_content_length():
    """Điểm quan trọng nhất: Content-Length PHẢI được tính lại theo body mới."""
    r = parse_request(BURP_POST)
    payload = "(if(1=1,sleep(3),1))"
    injected = r.with_payload(payload)

    # payload đã thay vào marker
    expected_body = '{"id":"%s"}' % payload
    assert injected.body == expected_body

    # Content-Length mới = số BYTE của body mới (không phải 10 cũ)
    new_len = len(expected_body.encode("utf-8"))
    assert injected.get_header("Content-Length") == str(new_len)
    assert injected.get_header("Content-Length") != "10"


def test_immutability():
    """with_payload không được sửa đổi request gốc."""
    r = parse_request(BURP_POST)
    _ = r.with_payload("XXX")
    assert r.body == '{"id":"*"}'  # gốc không đổi
    assert r.get_header("Content-Length") == "10"


def test_content_length_bytes_not_chars():
    """Payload chứa ký tự multibyte -> Content-Length tính theo byte."""
    raw = BURP_POST.replace('{"id":"*"}', '{"id":"*"}')
    r = parse_request(raw)
    payload = "café"  # 'é' = 2 byte UTF-8
    injected = r.with_payload(payload)
    body = '{"id":"café"}'
    assert injected.get_header("Content-Length") == str(len(body.encode("utf-8")))


def test_roundtrip_preserves_crlf():
    r = parse_request(BURP_POST)
    out = r.to_text()
    assert "\r\n" in out
    assert out.startswith("POST /action.php HTTP/1.1\r\n")
    # dòng trống ngăn header với body
    assert "\r\n\r\n" in out


def test_header_order_preserved():
    r = parse_request(BURP_POST)
    keys = [k for k, _ in r.headers]
    assert keys == ["Host", "User-Agent", "Content-Type", "Content-Length", "Connection"]


def test_lf_only_request():
    """Request đã bị chuẩn hóa về LF (\\n) vẫn parse được."""
    raw = BURP_POST.replace("\r\n", "\n")
    r = parse_request(raw)
    assert r.method == "POST"
    assert r.body == '{"id":"*"}'
    assert r.newline == "\n"


def _run_all():
    """Chạy tất cả test không cần pytest."""
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
            print("[ OK ] %s" % t.__name__)
            passed += 1
        except Exception as e:
            print("[FAIL] %s -> %s: %s" % (t.__name__, type(e).__name__, e))
    print("\n%d/%d passed" % (passed, len(tests)))
    return passed == len(tests)


if __name__ == "__main__":
    ok = _run_all()
    sys.exit(0 if ok else 1)
