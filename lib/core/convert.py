#!/usr/bin/env python3
"""
Shim cho lib.core.convert - 3 hàm mà tamper cần: decodeHex, encodeBase64, getOrds.
Rút gọn từ sqlmap (bỏ phụ thuộc thirdparty.six, dùng chuẩn Python 3).
"""

import base64
import binascii
import codecs

UNICODE_ENCODING = "utf-8"


def _get_text(value, encoding=None):
    """bytes -> str (giống getText của sqlmap, bản rút gọn)."""
    if isinstance(value, bytes):
        return value.decode(encoding or UNICODE_ENCODING, "replace")
    return value


def decodeHex(value, binary=True):
    """
    Giải mã chuỗi hex -> bytes (hoặc str nếu binary=False).

    >>> decodeHex("313233") == b"123"
    True
    >>> decodeHex("313233", binary=False) == u"123"
    True
    """
    if isinstance(value, bytes):
        value = _get_text(value)

    if value.lower().startswith("0x"):
        value = value[2:]

    try:
        retVal = codecs.decode(value, "hex")
    except LookupError:
        retVal = binascii.unhexlify(value)

    if not binary:
        retVal = _get_text(retVal)

    return retVal


def encodeBase64(value, binary=True, encoding=None, padding=True, safe=False):
    """
    Base64-encode giá trị.

    >>> encodeBase64(b"123") == b"MTIz"
    True
    >>> encodeBase64(u"1234", binary=False)
    'MTIzNA=='
    """
    if value is None:
        return None

    if isinstance(value, str):
        value = value.encode(encoding or UNICODE_ENCODING)

    retVal = base64.b64encode(value)

    if not binary:
        retVal = _get_text(retVal, encoding)

    if safe:
        padding = False
        if isinstance(retVal, bytes):
            retVal = retVal.replace(b"+", b"-").replace(b"/", b"_")
        else:
            retVal = retVal.replace("+", "-").replace("/", "_")

    if not padding:
        retVal = retVal.rstrip(b"=" if isinstance(retVal, bytes) else "=")

    return retVal


def getOrds(value):
    """
    Trả về danh sách mã ord() của từng ký tự/byte.

    >>> getOrds(u'fo\\xf6bar')
    [102, 111, 246, 98, 97, 114]
    >>> getOrds(b"fo\\xc3\\xb6bar")
    [102, 111, 195, 182, 98, 97, 114]
    """
    return [_ if isinstance(_, int) else ord(_) for _ in value]
