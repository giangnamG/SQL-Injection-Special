#!/usr/bin/env python3
"""
Transport - gui HttpRequest da chen payload den target, tra ve thoi gian phan hoi.

Ghep:
  - request.py : parse Burp request + chen payload + tinh lai Content-Length
  - vector/oracle : cung cap payload can gui

Trach nhiem CHINH cua transport la cung cap mot `measure(payload) -> giay` cho oracle:
  1. lay HttpRequest goc (co marker '*')
  2. chen payload vao marker -> HttpRequest moi (Content-Length da dung)
  3. gui, do thoi gian phan hoi
  4. retry khi loi mang (khong lam sai phep do - chi thu lai)

Dung `requests` (giong tinh than sqlmap: tu tinh Content-Length, giu nguyen header goc
tu Burp de khong bi filter). Header Content-Length do request.py quan ly, KHONG de
requests tu them.
"""

from __future__ import annotations

import time
from typing import Optional

import requests

from stinger.request import HttpRequest


class TransportError(Exception):
    pass


class Transport:
    """Gui request va do thoi gian. Cung cap measure() cho Oracle/detect."""

    def __init__(self,
                 base_request: HttpRequest,
                 timeout: float = 30.0,
                 retries: int = 4,
                 pause: float = 0.0,
                 verify_tls: bool = False):
        if not base_request.has_marker():
            raise TransportError(
                "request goc khong co marker '*'. Hay chen '*' vao vi tri inject."
            )
        self.base = base_request
        self.url = base_request.url()
        self.method = base_request.method
        self.timeout = timeout
        self.retries = retries
        self.pause = pause
        self.verify_tls = verify_tls
        self.n_req = 0
        self.sess = requests.Session()
        # requests khong tu them Content-Length/Host - dung dung header ta dua.

    def _headers_for(self, req: HttpRequest) -> dict:
        """Chuyen list header -> dict cho requests. Bo Host (requests tu dat theo URL,
        nhung ta van dua Host tu file de khop) - thuc te giu nguyen tat ca tru Content-Length
        (requests se tu tinh theo body). Tuy nhien ta DA tinh Content-Length trong
        request.py; de nhat quan, ta de requests tinh lai theo body that su gui."""
        headers = {}
        for k, v in req.headers:
            # bo Content-Length: requests tu set theo body -> tranh lech.
            if k.lower() == "content-length":
                continue
            headers[k] = v
        return headers

    def send(self, payload: str) -> requests.Response:
        """Chen payload, gui, tra ve Response. Retry khi loi mang."""
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
                self.n_req += 1
                if self.pause:
                    time.sleep(self.pause)
                return resp
            except requests.RequestException as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise TransportError("request that bai sau %d lan: %s" % (self.retries, last))

    def measure(self, payload: str) -> float:
        """Do thoi gian phan hoi cho payload. Day la callable Oracle/detect can."""
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
                self.n_req += 1
                if self.pause:
                    time.sleep(self.pause)
                return dt
            except requests.RequestException as e:
                last = e
                time.sleep(2 * (attempt + 1))
        raise TransportError("request that bai sau %d lan: %s" % (self.retries, last))
