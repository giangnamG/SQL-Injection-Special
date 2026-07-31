#!/usr/bin/env python3
"""
Transport - gửi HttpRequest đã chèn payload đến target, trả về thời gian phản hồi.

Ghép:
  - request.py : parse Burp request + chèn payload + tính lại Content-Length
  - vector/oracle : cung cấp payload cần gửi

Trách nhiệm CHÍNH của transport là cung cấp một `measure(payload) -> giây` cho oracle:
  1. lấy HttpRequest gốc (có marker '*')
  2. chèn payload vào marker -> HttpRequest mới (Content-Length đã đúng)
  3. gửi, đo thời gian phản hồi
  4. retry khi lỗi mạng (không làm sai phép đo - chỉ thử lại)

Dùng `requests` (giống tinh thần sqlmap: tự tính Content-Length, giữ nguyên header gốc
từ Burp để không bị filter). Header Content-Length do request.py quản lý, KHÔNG để
requests tự thêm.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

import requests

from stinger.request import HttpRequest


class TransportError(Exception):
    pass


class Transport:
    """Gửi request và đo thời gian. Cung cấp measure() cho Oracle/detect."""

    def __init__(self,
                 base_request: HttpRequest,
                 timeout: float = 30.0,
                 retries: int = 4,
                 pause: float = 0.0,
                 verify_tls: bool = False):
        if not base_request.has_marker():
            raise TransportError(
                "request gốc không có marker '*'. Hãy chèn '*' vào vị trí inject."
            )
        self.base = base_request
        self.url = base_request.url()
        self.method = base_request.method
        self.timeout = timeout
        self.retries = retries
        self.pause = pause
        self.verify_tls = verify_tls
        self.n_req = 0
        # Thread-safe: mỗi thread một Session riêng (requests.Session không an toàn khi
        # nhiều thread cùng ghi). n_req tăng qua lock.
        self._local = threading.local()
        self._lock = threading.Lock()
        # requests không tự thêm Content-Length/Host - dùng đúng header ta đưa.

    @property
    def sess(self) -> requests.Session:
        """Session riêng cho mỗi thread (tạo lazy)."""
        s = getattr(self._local, "sess", None)
        if s is None:
            s = requests.Session()
            self._local.sess = s
        return s

    def _bump(self):
        with self._lock:
            self.n_req += 1

    def _headers_for(self, req: HttpRequest) -> dict:
        """Chuyển list header -> dict cho requests. Bỏ Host (requests tự đặt theo URL,
        nhưng ta vẫn đưa Host từ file để khớp) - thực tế giữ nguyên tất cả trừ Content-Length
        (requests sẽ tự tính theo body). Tuy nhiên ta ĐÃ tính Content-Length trong
        request.py; để nhất quán, ta để requests tính lại theo body thật sự gửi."""
        headers = {}
        for k, v in req.headers:
            # bỏ Content-Length: requests tự set theo body -> tránh lệch.
            if k.lower() == "content-length":
                continue
            headers[k] = v
        return headers

    def send(self, payload: str) -> requests.Response:
        """Chèn payload, gửi, trả về Response. Retry khi lỗi mạng."""
        req = self.base.with_payload(payload)
        headers = self._headers_for(req)
        body = req.body.encode("utf-8")

        last = None
        for attempt in range(self.retries):
            try:
                resp = self.sess.request(
                    method=req.method,
                    url=self.url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=False,
                )
                self._bump()
                if self.pause:
                    time.sleep(self.pause)
                return resp
            except requests.RequestException as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise TransportError("request thất bại sau %d lần: %s" % (self.retries, last))

    def measure(self, payload: str) -> float:
        """Đo thời gian phản hồi cho payload. Đây là callable Oracle/detect cần."""
        req = self.base.with_payload(payload)
        headers = self._headers_for(req)
        body = req.body.encode("utf-8")

        last = None
        for attempt in range(self.retries):
            try:
                t0 = time.time()
                self.sess.request(
                    method=req.method,
                    url=self.url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    verify=self.verify_tls,
                    allow_redirects=False,
                )
                dt = time.time() - t0
                self._bump()
                if self.pause:
                    time.sleep(self.pause)
                return dt
            except requests.RequestException as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise TransportError("request thất bại sau %d lần: %s" % (self.retries, last))
