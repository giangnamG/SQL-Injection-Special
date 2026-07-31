#!/usr/bin/env python3
"""
Shim cho lib.core.common - CHỈ 4 hàm mà tamper script sử dụng.

KHÔNG copy common.py thật (4711 dòng). Khảo sát 76 tamper cho thấy chúng chỉ cần:
randomRange, randomInt, singleTimeWarnMessage, zeroDepthSearch.

- randomRange/randomInt: sao logic từ sqlmap, bỏ nhánh seed/thread-data không cần.
- singleTimeWarnMessage: chuyển thành cảnh báo 1-lần qua warnings (không ảnh hưởng
  kết quả biến đổi payload - chỉ là thông báo).
- zeroDepthSearch: sao NGUYÊN VĂN (logic thuần, quan trọng cho vài tamper).
"""

import random
import re
import string
import warnings

from lib.core.compat import xrange

# nhớ các message đã cảnh báo để chỉ warn 1 lần (giống singleTimeLogMessage của sqlmap)
_warned_flags = set()


def randomRange(start=0, stop=1000, seed=None):
    """
    Trả về số nguyên ngẫu nhiên trong [start, stop].

    >>> random.seed(0); 0 <= randomRange(1, 500) <= 500
    True
    """
    randint = random.Random(seed).randint if seed is not None else random.randint
    return int(randint(start, stop))


def randomInt(length=4, seed=None):
    """
    Trả về số nguyên ngẫu nhiên với số chữ số cho trước (chữ số đầu khác 0).

    >>> len(str(randomInt(6))) == 6
    True
    """
    choice = random.Random(seed).choice if seed is not None else random.choice
    return int("".join(
        choice(string.digits if _ != 0 else string.digits.replace("0", ""))
        for _ in xrange(0, length)
    ))


def singleTimeWarnMessage(message):
    """Cảnh báo một lần cho mỗi message (không làm sai biến đổi payload)."""
    flag = hash(message)
    if flag not in _warned_flags:
        _warned_flags.add(flag)
        warnings.warn(message, stacklevel=2)


def zeroDepthSearch(expression, value):
    """
    Tìm vị trí xuất hiện của `value` trong `expression` ở mức 0-depth (ngoài ngoặc).
    Sao NGUYÊN VĂN từ sqlmap - nội dung trong chuỗi nháy '...' được coi là data, không match.

    >>> _ = "SELECT (SELECT id FROM users WHERE 2>1) AS result FROM DUAL"; _[zeroDepthSearch(_, "FROM")[0]:]
    'FROM DUAL'
    >>> _ = "a(b; c),d;e"; _[zeroDepthSearch(_, "[;, ]")[0]:]
    ',d;e'
    """
    retVal = []

    depth = 0
    quote = None
    index = 0
    while index < len(expression):
        char = expression[index]
        if quote:
            if char == quote:
                if index + 1 < len(expression) and expression[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in ('"', "'"):
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif depth == 0:
            if value.startswith('[') and value.endswith(']'):
                if re.search(value, expression[index:index + 1]):
                    retVal.append(index)
            elif expression[index:index + len(value)] == value:
                retVal.append(index)
        index += 1

    return retVal
