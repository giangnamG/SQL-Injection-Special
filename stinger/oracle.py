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

import threading
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
        # ask() có thể được gọi từ nhiều thread (đa luồng theo vị trí ký tự).
        # measure() của transport đã thread-safe; ở đây chỉ cần khóa counter + log.
        self._lock = threading.Lock()

        # Ưu tiên ĐỘ CHÍNH XÁC: mỗi câu hỏi tự phân biệt bằng khoảng cách tới baseline
        # và baseline+sleeptime của CHÍNH phép đo đó, không tin mù threshold cố định.
        #   dt gần baseline          -> FALSE
        #   dt gần baseline+sleeptime -> TRUE
        # Khi dt rơi vào vùng KHÔNG rõ (giữa hai mốc) -> đo lại tới khi rõ / đủ phiếu.
        self._max_remeasure = 6      # số lần đo lại tối đa cho một câu hỏi mập mờ

    # -- đo một lần --------------------------------------------------------
    def _timed(self, condition: str) -> float:
        payload = self.vector.render(condition, self.sleeptime)
        dt = self.measure(payload)
        with self._lock:
            self.n_req += 1
        return dt

    # -- phân loại một phép đo ---------------------------------------------
    def _classify(self, dt: float):
        """Trả về True/False nếu dt rõ ràng, None nếu mập mờ (cần đo lại).

        Rõ ràng TRUE  : dt >= baseline + sleeptime*0.6   (đủ gần mốc có sleep)
        Rõ ràng FALSE : dt <= baseline + sleeptime*0.3   (đủ gần baseline)
        Ở giữa        : mập mờ -> None. Không dùng threshold cố định vì baseline
                        có thể trôi khi đa luồng; ta so tương đối với sleeptime.
        """
        low = self.baseline + self.sleeptime * 0.3
        high = self.baseline + self.sleeptime * 0.6
        if dt >= high:
            return True
        if dt <= low:
            return False
        return None

    # -- hỏi true/false ----------------------------------------------------
    def ask(self, condition: str) -> bool:
        """True nếu <condition> đúng (SQL).

        Chiến lược ưu tiên chính xác (bền với nhiễu đa luồng):
          1. Đo lần đầu. Nếu RÕ RÀNG (gần hẳn một mốc) -> trả ngay.
          2. Nếu MẬP MỜ -> đo lại, bỏ phiếu đa số, tới khi có đa số rõ ràng
             hoặc hết số lần đo lại (khi đó lấy đa số các phiếu rõ ràng đã có;
             nếu vẫn hòa, dựa vào phép so threshold cố định làm phương án cuối).
        """
        true_votes = 0
        false_votes = 0
        last_dt = 0.0

        # votes>1: người dùng ép bỏ phiếu nhiều lần ngay cả khi rõ ràng.
        base_rounds = max(1, self.votes)
        max_rounds = base_rounds + self._max_remeasure

        for r in range(max_rounds):
            dt = self._timed(condition)
            last_dt = dt
            verdict = self._classify(dt)
            if verdict is True:
                true_votes += 1
            elif verdict is False:
                false_votes += 1
            # nếu mập mờ (None) -> không tính phiếu, đo lại

            decided = true_votes + false_votes
            # đã đủ số vòng cơ bản VÀ có đa số rõ ràng -> quyết định
            if r + 1 >= base_rounds and decided > 0 and true_votes != false_votes:
                break
            # đủ phiếu áp đảo sớm -> dừng
            if true_votes >= 2 and false_votes == 0:
                break
            if false_votes >= 2 and true_votes == 0:
                break

        if true_votes != false_votes:
            res = true_votes > false_votes
        else:
            # hòa / toàn mập mờ -> phương án cuối: so với threshold cố định.
            res = last_dt >= self.threshold

        if self.verbose:
            with self._lock:
                self._log("      %-58s -> %s  (T%d/F%d)"
                          % (condition[:58], res, true_votes, false_votes))
        return res
