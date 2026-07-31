#!/usr/bin/env python3
"""
Oracle - tang suy luan true/false dua tren thoi gian, dung mot Vector da chot.

Khac script cu (draft/): oracle KHONG hardcode payload. No nhan:
  - mot Vector (da chot qua buoc detect) de render payload tu dieu kien [INFERENCE]
  - mot callable measure(payload)->giay (do transport cung cap) -> test duoc offline

Trach nhiem:
  - ask(condition) -> True/False: render vector voi inference=condition, do thoi gian,
    so voi threshold. Ho tro bo phieu (votes) va do lai khi map mo.
  - giu threshold da do tu buoc detect (rieng cho vector da chot).
"""

from __future__ import annotations

from typing import Callable, Optional

from stinger.vectors import Vector, DetectResult


class Oracle:
    """Hoi database cau hoi true/false qua do tre thoi gian."""

    def __init__(self,
                 detect: DetectResult,
                 measure: Callable[[str], float],
                 sleeptime: float,
                 votes: int = 1,
                 verbose: bool = False,
                 log: Optional[Callable[[str], None]] = None):
        self.vector = detect.vector
        self.measure = measure
        self.sleeptime = sleeptime
        self.baseline = detect.baseline
        self.threshold = detect.threshold
        self.votes = votes
        self.verbose = verbose
        self._log = log or (lambda m: None)
        self.n_req = 0

        # vung xam quanh threshold -> do lai de tang tin cay (re-measure)
        # rong = 20% cua khoang [baseline, baseline+sleeptime]
        self._gray = 0.2 * sleeptime

    # -- do mot lan --------------------------------------------------------
    def _timed(self, condition: str) -> float:
        payload = self.vector.render(condition, self.sleeptime)
        dt = self.measure(payload)
        self.n_req += 1
        return dt

    # -- hoi true/false ----------------------------------------------------
    def ask(self, condition: str) -> bool:
        """True neu <condition> dung (SQL). Bo phieu da so khi votes>1.

        Neu dt roi vao vung xam quanh threshold -> do lai them (tang tin cay) truoc
        khi quyet dinh, thay vi tin ngay mot phep do nhieu.
        """
        hits = 0
        n = 0
        for i in range(max(1, self.votes)):
            dt = self._timed(condition)
            n += 1

            # vung xam: do lai 1 lan neu ket qua khong ro rang
            if abs(dt - self.threshold) < self._gray:
                dt2 = self._timed(condition)
                n += 1
                # lay trung binh 2 lan de bot nhieu
                dt = (dt + dt2) / 2

            hits += 1 if dt >= self.threshold else 0

            # dong thuan som khi votes=3: 2 phieu giong nhau trong 2 dau -> dung
            if self.votes >= 3 and i == 1 and hits in (0, 2):
                break

        res = hits * 2 > n
        if self.verbose:
            self._log("      %-60s -> %s" % (condition[:60], res))
        return res
