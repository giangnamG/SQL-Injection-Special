#!/usr/bin/env python3
"""
Parse mot raw HTTP request (chuan Burp Suite "Copy to file") va cung cap co che
chen payload vao vi tri marker.

Trach nhiem cua module nay (co tinh giu hep):
  * Tach raw request  -> method, path, HTTP version, headers, body
  * Dung URL day du tu Host header (scheme/port theo quy uoc sqlmap)
  * Xac dinh vi tri marker inject ('*' - giong sqlmap CUSTOM_INJECTION_MARK_CHAR)
  * Sinh ra mot ban request MOI voi payload da chen vao marker, va
    TU TINH LAI Content-Length  <-- cai bay kinh dien khi replay request

Module KHONG gui request (do transport.py lo) va KHONG sinh payload
(do vectors.py lo). No chi lam mot viec: bien raw request + payload -> request san sang gui.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Marker danh dau diem inject - dung '*' theo quy uoc sqlmap (CUSTOM_INJECTION_MARK_CHAR).
INJECTION_MARK = "*"

# Dong dau tien cua request:  METHOD PATH HTTP/x.y
_REQUEST_LINE_RE = re.compile(r"\A([A-Z]+)\s+(.+)\s+HTTP/([\d.]+)\Z")

# Mot dong header:  Key: Value
_HEADER_RE = re.compile(r"\A([^:\s]+):\s?(.*)\Z")


class RequestParseError(ValueError):
    """Raw request khong hop le / khong parse duoc."""


@dataclass
class HttpRequest:
    """Bieu dien mot HTTP request da parse.

    Giu headers duoi dang list cac cap (key, value) de BAO TOAN thu tu va cho phep
    header trung ten (vd nhieu Set-Cookie). Khong dung dict vi dict lam mat thu tu goc
    va gop mat header trung - dieu co the khien server phia sau xu ly khac di.
    """

    method: str
    path: str
    version: str = "1.1"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    # newline goc ("\r\n" cho Burp/HTTP chuan, "\n" cho file da bi chuan hoa)
    newline: str = "\r\n"

    # -- truy van header (khong phan biet hoa thuong) ------------------------
    def get_header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def has_header(self, name: str) -> bool:
        return self.get_header(name) is not None

    def set_header(self, name: str, value: str) -> None:
        """Cap nhat header ton tai (giu nguyen ten goc) hoac them moi neu chua co."""
        low = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == low:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    # -- URL ----------------------------------------------------------------
    def url(self) -> str:
        """Dung URL day du tu Host header + path.

        Quy uoc scheme (theo sqlmap): port 443 -> https, con lai -> http.
        Neu Host header da co scheme (vd 'https://...') thi ton trong scheme do.
        """
        host = self.get_header("Host")
        if not host:
            raise RequestParseError("thieu Host header - khong dung duoc URL")

        scheme = None
        if "://" in host:
            scheme, host = host.split("://", 1)

        port = None
        m = re.search(r":(\d+)\Z", host)
        if m:
            port = int(m.group(1))

        if scheme is None:
            scheme = "https" if port == 443 else "http"

        return "%s://%s%s" % (scheme, host, self.path)

    # -- marker -------------------------------------------------------------
    def has_marker(self) -> bool:
        return INJECTION_MARK in self.path or INJECTION_MARK in self.body

    def marker_location(self) -> str:
        """Tra ve 'path' | 'body' | 'both' | 'none' - marker nam o dau."""
        in_path = INJECTION_MARK in self.path
        in_body = INJECTION_MARK in self.body
        if in_path and in_body:
            return "both"
        if in_path:
            return "path"
        if in_body:
            return "body"
        return "none"

    # -- chen payload -------------------------------------------------------
    def with_payload(self, payload: str) -> "HttpRequest":
        """Tra ve mot HttpRequest MOI voi payload chen vao vi tri marker.

        - Thay TAT CA marker (path va/hoac body) bang payload tho (khong tu escape).
        - TU TINH LAI Content-Length neu request goc co header nay (tinh theo body moi).

        Khong sua doi self (immutable-style) - de goi lai nhieu lan voi payload khac nhau.
        """
        if not self.has_marker():
            raise RequestParseError(
                "khong tim thay marker '%s' trong request - "
                "hay chen '%s' vao dung vi tri inject." % (INJECTION_MARK, INJECTION_MARK)
            )

        new_path = self.path.replace(INJECTION_MARK, payload)
        new_body = self.body.replace(INJECTION_MARK, payload)

        new_headers = [(k, v) for k, v in self.headers]
        clone = HttpRequest(
            method=self.method,
            path=new_path,
            version=self.version,
            headers=new_headers,
            body=new_body,
            newline=self.newline,
        )

        # Content-Length PHAI khop voi body moi. Chi dung khi request goc co header nay
        # (khong tu y them vao GET khong body). Tinh theo so BYTE, khong phai so ky tu.
        if clone.has_header("Content-Length"):
            clone.set_header("Content-Length", str(len(new_body.encode("utf-8"))))

        return clone

    # -- serialize ----------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Dung lai raw request (bytes) san sang gui qua socket."""
        nl = self.newline
        start = "%s %s HTTP/%s" % (self.method, self.path, self.version)
        head = nl.join([start] + ["%s: %s" % (k, v) for k, v in self.headers])
        raw = head + nl + nl + self.body
        return raw.encode("utf-8")

    def to_text(self) -> str:
        return self.to_bytes().decode("utf-8", "replace")


def parse_request(raw: str) -> HttpRequest:
    """Parse mot raw HTTP request (text) thanh HttpRequest.

    Chap nhan ca ket thuc dong CRLF (\\r\\n - chuan Burp/HTTP) lan LF (\\n).
    Body la phan sau dong trong dau tien.
    """
    if not raw or not raw.strip():
        raise RequestParseError("request rong")

    # Chuan hoa newline truoc khi tach: file luu tren Windows (vd Burp save + text-mode
    # write) co the bi '\r\r\n'. Gop '\r\r\n' -> '\r\n' de body/header khong bi lech.
    raw = raw.replace("\r\r\n", "\r\n")

    # Phat hien newline goc: neu co '\r\n' o dong dau -> giu CRLF khi dung lai.
    detected_newline = "\r\n" if "\r\n" in raw else "\n"

    # Tach header-block va body tai dong trong dau tien (ho tro ca \r\n\r\n va \n\n).
    if "\r\n\r\n" in raw:
        head_part, _, body = raw.partition("\r\n\r\n")
    elif "\n\n" in raw:
        head_part, _, body = raw.partition("\n\n")
    else:
        head_part, body = raw, ""

    # Chuan hoa dong header ve LF de xu ly, giu detected_newline cho luc dung lai.
    head_lines = head_part.replace("\r\n", "\n").split("\n")
    head_lines = [ln for ln in head_lines if ln != ""]  # bo dong rong thua

    if not head_lines:
        raise RequestParseError("khong co dong request line")

    m = _REQUEST_LINE_RE.match(head_lines[0].strip())
    if not m:
        raise RequestParseError(
            "dong dau khong phai HTTP request line hop le: %r" % head_lines[0]
        )
    method, path, version = m.group(1), m.group(2), m.group(3)

    headers: list[tuple[str, str]] = []
    for line in head_lines[1:]:
        hm = _HEADER_RE.match(line)
        if not hm:
            # Dong khong phai header (vd folded header hiem gap) - bo qua an toan.
            continue
        headers.append((hm.group(1), hm.group(2)))

    return HttpRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
        newline=detected_newline,
    )


def parse_request_file(path: str) -> HttpRequest:
    """Doc file request.txt (Burp) va parse. Doc dang bytes roi decode de khong
    phu thuoc encoding mac dinh cua he thong."""
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", "replace")
    return parse_request(raw)
