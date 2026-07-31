#!/usr/bin/env python3
"""
Shim cho lib.core.common - CHI 4 ham ma tamper script su dung.

KHONG copy common.py that (4711 dong). Khao sat 76 tamper cho thay chung chi can:
randomRange, randomInt, singleTimeWarnMessage, zeroDepthSearch.

- randomRange/randomInt: sao logic tu sqlmap, bo nhanh seed/thread-data khong can.
- singleTimeWarnMessage: chuyen thanh canh bao 1-lan qua warnings (khong anh huong
  ket qua bien doi payload - chi la thong bao).
- zeroDepthSearch: sao NGUYEN VAN (logic thuan, quan trong cho vai tamper).
"""

import random
import re
import string
import warnings

from lib.core.compat import xrange

# nho cac message da canh bao de chi warn 1 lan (giong singleTimeLogMessage cua sqlmap)
_warned_flags = set()


def randomRange(start=0, stop=1000, seed=None):
    """
    Tra ve so nguyen ngau nhien trong [start, stop].

    >>> random.seed(0); 0 <= randomRange(1, 500) <= 500
    True
    """
    randint = random.Random(seed).randint if seed is not None else random.randint
    return int(randint(start, stop))


def randomInt(length=4, seed=None):
    """
    Tra ve so nguyen ngau nhien voi so chu so cho truoc (chu so dau khac 0).

    >>> len(str(randomInt(6))) == 6
    True
    """
    choice = random.Random(seed).choice if seed is not None else random.choice
    return int("".join(
        choice(string.digits if _ != 0 else string.digits.replace("0", ""))
        for _ in xrange(0, length)
    ))


def singleTimeWarnMessage(message):
    """Canh bao mot lan cho moi message (khong lam sai bien doi payload)."""
    flag = hash(message)
    if flag not in _warned_flags:
        _warned_flags.add(flag)
        warnings.warn(message, stacklevel=2)


def zeroDepthSearch(expression, value):
    """
    Tim vi tri xuat hien cua `value` trong `expression` o muc 0-depth (ngoai ngoac).
    Sao NGUYEN VAN tu sqlmap - noi dung trong chuoi nhay '...' duoc coi la data, khong match.

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
