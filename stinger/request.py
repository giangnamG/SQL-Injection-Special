#!/usr/bin/env python3
"""
Parse một raw HTTP request (chuẩn Burp Suite "Copy to file") và cung cấp cơ chế
chèn payload vào vị trí marker.

Trách nhiệm của module này (có tính giữ hẹp):
  * Tách raw request  -> method, path, HTTP version, headers, body
  * Dựng URL đầy đủ từ Host header (scheme/port theo quy ước sqlmap)
  * Xác định vị trí marker inject ('*' - giống sqlmap CUSTOM_INJECTION_MARK_CHAR)
  * Sinh ra một bản request MỚI với payload đã chèn vào marker, và
    TỰ TÍNH LẠI Content-Length  <-- cái bẫy kinh điển khi replay request

Module KHÔNG gửi request (do transport.py lo) và KHÔNG sinh payload
(do vectors.py lo). Nó chỉ làm một việc: biến raw request + payload -> request sẵn sàng gửi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Marker đánh dấu điểm inject - dùng '*' theo quy ước sqlmap (CUSTOM_INJECTION_MARK_CHAR).
INJECTION_MARK = "*"

# Dòng đầu tiên của request:  METHOD PATH HTTP/x.y
_REQUEST_LINE_RE = re.compile(r"\A([A-Z]+)\s+(.+)\s+HTTP/([\d.]+)\Z")

# Một dòng header:  Key: Value
_HEADER_RE = re.compile(r"\A([^:\s]+):\s?(.*)\Z")


class RequestParseError(ValueError):
    """Raw request không hợp lệ / không parse được."""


@dataclass
class HttpRequest:
    """Biểu diễn một HTTP request đã parse.

    Giữ headers dưới dạng list các cặp (key, value) để BẢO TOÀN thứ tự và cho phép
    header trùng tên (vd nhiều Set-Cookie). Không dùng dict vì dict làm mất thứ tự gốc
    và gộp mất header trùng - điều có thể khiến server phía sau xử lý khác đi.
    """

    method: str
    path: str
    version: str = "1.1"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    # newline gốc ("\r\n" cho Burp/HTTP chuẩn, "\n" cho file đã bị chuẩn hóa)
    newline: str = "\r\n"

    # -- truy vấn header (không phân biệt hoa thường) ------------------------
    def get_header(self, name: str) -> Optional[str]:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def has_header(self, name: str) -> bool:
        return self.get_header(name) is not None

    def set_header(self, name: str, value: str) -> None:
        """Cập nhật header tồn tại (giữ nguyên tên gốc) hoặc thêm mới nếu chưa có."""
        low = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == low:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    # -- URL ----------------------------------------------------------------
    def url(self) -> str:
        """Dựng URL đầy đủ từ Host header + path.

        Quy ước scheme (theo sqlmap): port 443 -> https, còn lại -> http.
        Nếu Host header đã có scheme (vd 'https://...') thì tôn trọng scheme đó.
        """
        host = self.get_header("Host")
        if not host:
            raise RequestParseError("thiếu Host header - không dựng được URL")

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
        """Trả về 'path' | 'body' | 'both' | 'none' - marker nằm ở đâu."""
        in_path = INJECTION_MARK in self.path
        in_body = INJECTION_MARK in self.body
        if in_path and in_body:
            return "both"
        if in_path:
            return "path"
        if in_body:
            return "body"
        return "none"

    # -- chèn payload -------------------------------------------------------
    def with_payload(self, payload: str) -> "HttpRequest":
        """Trả về một HttpRequest MỚI với payload chèn vào vị trí marker.

        - Thay TẤT CẢ marker (path và/hoặc body) bằng payload thô (không tự escape).
        - TỰ TÍNH LẠI Content-Length nếu request gốc có header này (tính theo body mới).

        Không sửa đổi self (immutable-style) - để gọi lại nhiều lần với payload khác nhau.
        """
        if not self.has_marker():
            raise RequestParseError(
                "không tìm thấy marker '%s' trong request - "
                "hãy chèn '%s' vào đúng vị trí inject." % (INJECTION_MARK, INJECTION_MARK)
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

        # Content-Length PHẢI khớp với body mới. Chỉ dùng khi request gốc có header này
        # (không tự ý thêm vào GET không body). Tính theo số BYTE, không phải số ký tự.
        if clone.has_header("Content-Length"):
            clone.set_header("Content-Length", str(len(new_body.encode("utf-8"))))

        return clone

    # -- serialize ----------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Dựng lại raw request (bytes) sẵn sàng gửi qua socket."""
        nl = self.newline
        start = "%s %s HTTP/%s" % (self.method, self.path, self.version)
        head = nl.join([start] + ["%s: %s" % (k, v) for k, v in self.headers])
        raw = head + nl + nl + self.body
        return raw.encode("utf-8")

    def to_text(self) -> str:
        return self.to_bytes().decode("utf-8", "replace")


def parse_request(raw: str) -> HttpRequest:
    """Parse một raw HTTP request (text) thành HttpRequest.

    Chấp nhận cả kết thúc dòng CRLF (\\r\\n - chuẩn Burp/HTTP) lẫn LF (\\n).
    Body là phần sau dòng trống đầu tiên.
    """
    if not raw or not raw.strip():
        raise RequestParseError("request rỗng")

    # Chuẩn hóa newline trước khi tách: file lưu trên Windows (vd Burp save + text-mode
    # write) có thể bị '\r\r\n'. Gộp '\r\r\n' -> '\r\n' để body/header không bị lệch.
    raw = raw.replace("\r\r\n", "\r\n")

    # Phát hiện newline gốc: nếu có '\r\n' ở dòng đầu -> giữ CRLF khi dựng lại.
    detected_newline = "\r\n" if "\r\n" in raw else "\n"

    # Tách header-block và body tại dòng trống đầu tiên (hỗ trợ cả \r\n\r\n và \n\n).
    if "\r\n\r\n" in raw:
        head_part, _, body = raw.partition("\r\n\r\n")
    elif "\n\n" in raw:
        head_part, _, body = raw.partition("\n\n")
    else:
        head_part, body = raw, ""

    # Chuẩn hóa dòng header về LF để xử lý, giữ detected_newline cho lúc dựng lại.
    head_lines = head_part.replace("\r\n", "\n").split("\n")
    head_lines = [ln for ln in head_lines if ln != ""]  # bỏ dòng rỗng thừa

    if not head_lines:
        raise RequestParseError("không có dòng request line")

    m = _REQUEST_LINE_RE.match(head_lines[0].strip())
    if not m:
        raise RequestParseError(
            "dòng đầu không phải HTTP request line hợp lệ: %r" % head_lines[0]
        )
    method, path, version = m.group(1), m.group(2), m.group(3)

    headers: list[tuple[str, str]] = []
    for line in head_lines[1:]:
        hm = _HEADER_RE.match(line)
        if not hm:
            # Dòng không phải header (vd folded header hiếm gặp) - bỏ qua an toàn.
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
    """Đọc file request.txt (Burp) và parse. Đọc dạng bytes rồi decode để không
    phụ thuộc encoding mặc định của hệ thống."""
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", "replace")
    return parse_request(raw)
