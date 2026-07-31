#!/usr/bin/env python3
"""
Test oracle.py + extract.py bang MOCK MySQL offline day du.

Mock hieu payload vector va danh gia dieu kien SQL (length/char_length/hex/ord/substr/
between) tren mot SECRET biet truoc -> chung minh pipeline trich xuat dung flag.

Chay:  python tests/test_extract.py
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stinger.vectors import VectorStore, DetectResult
from stinger.oracle import Oracle
from stinger.extract import extract, verify, bsearch, get_number, Dialect


# --------------------------------------------------------------------------- mock
class MockMySQLFull:
    """Gia lap MySQL: danh gia dieu kien inference tren SECRET, tra thoi gian.

    Chi can lo che do 'hex' cua MySQL:
      length((Q))                          -> so byte
      char_length((Q))                     -> so ky tu
      ((Q)) is not null                    -> True
      ord(substr((hex((Q))),i,1)) between lo and hi
      (Q) between 0x.. and 0x..            -> verify
    """

    def __init__(self, secret=b"HTB{t1m3_bl1nd}", baseline=0.02, sleeptime=3.0):
        self.secret = secret
        self.hexs = secret.hex().upper()  # hex(content) cua MySQL tra HOA
        self.baseline = baseline
        self.sleeptime = sleeptime
        self.calls = 0

    def measure(self, payload):
        self.calls += 1
        cond = self._extract_inference(payload)
        triggered = self._eval(cond)
        return self.baseline + (self.sleeptime if triggered else 0.0)

    def _extract_inference(self, payload):
        # inline: (if(<COND>,sleep,1)) ; query-sleep: sleep(N-if(<COND>,0,N))
        m = re.search(r"\bif\((.*),sleep", payload)
        if m:
            return m.group(1)
        m = re.search(r"\bif\((.*),0,", payload)
        if m:
            return m.group(1)
        return None

    def _eval(self, cond):
        if not cond:
            return False
        cond = cond.strip()
        if cond == "1=1":
            return True
        if cond == "1=2":
            return False

        # ((Q)) is not null
        if "is not null" in cond:
            return True

        # <expr> between lo and hi
        m = re.search(r"^(.*)\s+between\s+(\d+)\s+and\s+(\d+)$", cond, re.I)
        if m:
            expr, lo, hi = m.group(1).strip(), int(m.group(2)), int(m.group(3))
            val = self._eval_expr(expr)
            return lo <= val <= hi

        # verify: (Q) between 0xHEX and 0xHEX
        m = re.search(r"between\s+0x([0-9a-fA-F]+)\s+and\s+0x([0-9a-fA-F]+)", cond)
        if m:
            return bytes.fromhex(m.group(1)) == self.secret
        return False

    def _eval_expr(self, expr):
        # length((Q))
        if expr.startswith("length("):
            return len(self.secret)
        # char_length((Q))
        if expr.startswith("char_length("):
            return len(self.secret.decode("utf-8", "replace"))
        # ord(substr((hex((Q))),i,1))
        m = re.search(r"ord\(substr\(\(hex\(\((.*)\)\)\),(\d+),1\)\)", expr)
        if m:
            i = int(m.group(2))
            return ord(self.hexs[i - 1]) if i <= len(self.hexs) else 0
        raise AssertionError("mock khong danh gia duoc expr: %r" % expr)


def _make_oracle(mock, vector_name="mysql-inline-sleep"):
    store = VectorStore.load()
    v = store.get_vector(vector_name)
    threshold = mock.baseline + mock.sleeptime * 0.5
    detect = DetectResult(vector=v, baseline=mock.baseline,
                          slow=mock.baseline + mock.sleeptime, threshold=threshold)
    return Oracle(detect, mock.measure, sleeptime=mock.sleeptime), store.dialect("mysql")


# --------------------------------------------------------------------------- tests
def test_get_number_length():
    mock = MockMySQLFull(secret=b"HELLO")
    oracle, dia = _make_oracle(mock)
    n = get_number(oracle, Dialect(dia).length("select x"))
    assert n == 5


def test_extract_hex_simple():
    mock = MockMySQLFull(secret=b"HTB{demo}")
    oracle, dia = _make_oracle(mock)
    data, meta = extract(oracle, "select content from flag", dia, mode="hex")
    assert data == b"HTB{demo}"
    assert meta["byte_len"] == 9


def test_extract_hex_full_flag():
    mock = MockMySQLFull(secret=b"HTB{t1m3_bl1nd_3xtr4ct}")
    oracle, dia = _make_oracle(mock)
    data, meta = extract(oracle, "select content from flag", dia, mode="hex")
    assert data == b"HTB{t1m3_bl1nd_3xtr4ct}"


def test_extract_multibyte():
    """Ky tu multibyte (byte >127) - che do hex phai bat duoc."""
    secret = "café".encode("utf-8")  # 'é' = 2 byte
    mock = MockMySQLFull(secret=secret)
    oracle, dia = _make_oracle(mock)
    data, meta = extract(oracle, "select x", dia, mode="hex")
    assert data == secret
    assert meta["byte_len"] != meta["char_len"]  # phat hien multibyte


def test_verify_matches():
    mock = MockMySQLFull(secret=b"HTB{demo}")
    oracle, dia = _make_oracle(mock)
    assert verify(oracle, "select x", dia, b"HTB{demo}") is True
    assert verify(oracle, "select x", dia, b"WRONG___") is False


def test_extract_via_query_sleep_vector():
    """Dung vector query-sleep (boc subquery) thay vi inline - van phai dung."""
    mock = MockMySQLFull(secret=b"HTB{qs}")
    oracle, dia = _make_oracle(mock, vector_name="mysql-query-sleep")
    data, _ = extract(oracle, "select x", dia, mode="hex")
    assert data == b"HTB{qs}"


def test_request_count_reasonable():
    """So request cho flag ngan phai hop ly (~5/hex-digit)."""
    mock = MockMySQLFull(secret=b"AB")  # 2 byte -> 4 hex digit
    oracle, dia = _make_oracle(mock)
    extract(oracle, "select x", dia, mode="hex")
    # 4 hex digit * ~5 + do dai/notnull ~ duoi 60
    assert mock.calls < 60, "so request qua nhieu: %d" % mock.calls


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
