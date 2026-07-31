#!/usr/bin/env python3
"""
Test cho stinger/vectors.py - nap YAML, render template, do vector bang TRUE/FALSE.

Dung MOCK oracle offline: gia lap mot target MySQL biet cach xu ly (if(cond,sleep,1)).
Chay:  python tests/test_vectors.py
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stinger.vectors import (
    VectorStore,
    Vector,
    confirm_vector,
    detect_vector,
    VectorError,
    COND_TRUE,
    COND_FALSE,
)


# --------------------------------------------------------------------------- mock
class MockMySQL:
    """Gia lap target MySQL cho time-based blind - KHONG gui request that.

    Hieu cac vector mysql:
      - (if(<cond>,sleep(N),1))            -> inline
      - (select R from (select(sleep(N-if(<cond>,0,N))))X)  -> query-sleep
    Danh gia <cond> (chi ho tro cac dieu kien test: 1=1, 1=2, va ord(...) between a b).
    Tra ve thoi gian: baseline + (sleep neu cond dung).
    """

    def __init__(self, secret=b"HTB{demo}", baseline=0.05):
        self.secret = secret
        self.baseline = baseline
        self.calls = 0

    def measure(self, payload):
        self.calls += 1
        cond_true = self._eval_sleep_triggered(payload)
        return self.baseline + (self._sleep_amount(payload) if cond_true else 0.0)

    def _sleep_amount(self, payload):
        m = re.search(r"sleep\(([\d.]+)", payload)
        if m:
            return float(m.group(1))
        # query-sleep dang sleep(N-if(...)) -> lay N
        m = re.search(r"sleep\(([\d.]+)-", payload)
        return float(m.group(1)) if m else 0.0

    def _eval_sleep_triggered(self, payload):
        """True neu payload nay se lam server sleep (dieu kien inference dung)."""
        # inline: (if(COND,sleep,1)) -> sleep khi COND dung
        # query-sleep: sleep(N-if(COND,0,N)) -> neu COND dung: sleep(N-0)=N; sai: sleep(0)
        cond = self._extract_condition(payload)
        return self._eval_cond(cond)

    def _extract_condition(self, payload):
        # inline if(COND,...)
        m = re.search(r"\bif\(((?:[^()]|\([^()]*\))*?),", payload)
        if m:
            return m.group(1)
        return None

    def _eval_cond(self, cond):
        if cond is None:
            return False
        cond = cond.strip()
        if cond == "1=1":
            return True
        if cond == "1=2":
            return False
        # ord(substr(hex((...)),i,1)) between lo and hi
        m = re.search(r"between\s+(\d+)\s+and\s+(\d+)", cond, re.I)
        if m:
            # can gia tri that de danh gia - test extract se lo phan nay.
            # o day chi phuc vu confirm (1=1/1=2), tra False an toan.
            return False
        return False


# --------------------------------------------------------------------------- tests
def test_load_yaml():
    store = VectorStore.load()
    dbs = store.dbms_list()
    assert "mysql" in dbs
    assert "postgresql" in dbs
    assert "mssql" in dbs
    assert "oracle" in dbs


def test_mysql_has_vectors():
    store = VectorStore.load()
    vs = store.vectors_for("mysql")
    names = [v.name for v in vs]
    assert "mysql-inline-sleep" in names
    assert "mysql-query-sleep" in names


def test_dialect_present():
    store = VectorStore.load()
    d = store.dialect("mysql")
    assert "substr" in d and "ascii" in d and "hex" in d and "hexlit" in d


def test_render_placeholders():
    store = VectorStore.load()
    v = store.get_vector("mysql-inline-sleep")
    out = v.render("1=1", 3)
    assert "[INFERENCE]" not in out
    assert "[SLEEPTIME]" not in out
    assert "1=1" in out
    assert "sleep(3)" in out


def test_render_randnum_randstr():
    store = VectorStore.load()
    v = store.get_vector("mysql-query-sleep")
    out = v.render("1=2", 3)
    assert "[RANDNUM]" not in out
    assert "[RANDSTR]" not in out


def test_confirm_valid_vector():
    """Vector hop le: TRUE cham, FALSE nhanh -> confirm thanh cong."""
    mock = MockMySQL(baseline=0.05)
    store = VectorStore.load()
    v = store.get_vector("mysql-inline-sleep")
    res = confirm_vector(v, mock.measure, sleeptime=3)
    assert res is not None
    assert res.slow > res.threshold
    assert res.baseline < res.threshold


def test_confirm_rejects_fake_oracle():
    """Oracle gia: LUON delay bat ke dieu kien -> phai bi loai."""
    class AlwaysSlow:
        def measure(self, payload):
            return 3.05  # luon cham, ke ca 1=2
    store = VectorStore.load()
    v = store.get_vector("mysql-inline-sleep")
    res = confirm_vector(v, AlwaysSlow().measure, sleeptime=3)
    assert res is None, "oracle luon-cham phai bi loai (FALSE khong duoi threshold)"


def test_confirm_rejects_no_delay():
    """Vector khong tao delay nao -> loai."""
    class NeverSlow:
        def measure(self, payload):
            return 0.05
    store = VectorStore.load()
    v = store.get_vector("mysql-inline-sleep")
    res = confirm_vector(v, NeverSlow().measure, sleeptime=3)
    assert res is None


def test_detect_vector_auto():
    """Do tu dong: mock chi hieu vector mysql inline -> phai chot dung no."""
    mock = MockMySQL()
    store = VectorStore.load()
    res = detect_vector(store, mock.measure, sleeptime=3, dbms="auto")
    assert res.vector.dbms == "mysql"
    # mysql-query-sleep xep truoc inline; mock hieu ca hai -> chot cai dau tien hop le
    assert res.vector.name in ("mysql-query-sleep", "mysql-inline-sleep")


def test_detect_forced_vector():
    mock = MockMySQL()
    store = VectorStore.load()
    res = detect_vector(store, mock.measure, sleeptime=3, forced_vector="mysql-inline-sleep")
    assert res.vector.name == "mysql-inline-sleep"


def test_detect_fails_when_no_vector_works():
    class NeverSlow:
        def measure(self, payload):
            return 0.05
    store = VectorStore.load()
    try:
        detect_vector(store, NeverSlow().measure, sleeptime=3, dbms="mysql")
    except VectorError:
        pass
    else:
        raise AssertionError("phai raise khi khong vector nao dung")


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
