#!/usr/bin/env python3
"""
Shim cho lib.core.data - cung cap `kb` (knowledge base) GIA, dien san dung nhung
field ma tamper doc: kb.keywords, kb.aliasName, kb.bluecoat.

Khao sat 76 tamper: chi 3 field nay duoc doc tu kb. Dung AttribDict(keycheck=False)
nen field la khac se tra None thay vi crash.

kb.keywords doc tu data/txt/keywords.txt (danh sach tu khoa SQL cua sqlmap), dung boi
randomcase/uppercase/lowercase de nhan dien tu khoa can bien doi.
"""

import os
import random
import string

from lib.core.datatype import AttribDict

# object chia se ket qua runtime (giong kb cua sqlmap) - dung keycheck=False
kb = AttribDict(keycheck=False)


def _load_keywords():
    """Nap keywords.txt tu thu muc data/ cua repo (cung goc voi lib/)."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(repo_root, "data", "txt", "keywords.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(
                line.strip() for line in f
                if line.strip() and not line.strip().startswith("#")
            )
    except OSError:
        # neu thieu file, tra set rong -> randomcase/uppercase se khong bien doi gi
        # (an toan hon la crash)
        return set()


def _random_alias(length=4):
    """Tao alias ngau nhien (giong kb.aliasName = randomStr() cua sqlmap)."""
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


# Dien san cac field tamper can:
kb.keywords = _load_keywords()
kb.aliasName = _random_alias()
kb.bluecoat = False
