#!/usr/bin/env python3
"""
Shim cho lib.core.data - cung cấp `kb` (knowledge base) GIẢ, điền sẵn đúng những
field mà tamper đọc: kb.keywords, kb.aliasName, kb.bluecoat.

Khảo sát 76 tamper: chỉ 3 field này được đọc từ kb. Dùng AttribDict(keycheck=False)
nên field lạ khác sẽ trả None thay vì crash.

kb.keywords đọc từ data/txt/keywords.txt (danh sách từ khóa SQL của sqlmap), dùng bởi
randomcase/uppercase/lowercase để nhận diện từ khóa cần biến đổi.
"""

import os
import random
import string

from lib.core.datatype import AttribDict

# object chia sẻ kết quả runtime (giống kb của sqlmap) - dùng keycheck=False
kb = AttribDict(keycheck=False)


def _load_keywords():
    """Nạp keywords.txt từ thư mục data/ của repo (cùng gốc với lib/)."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(repo_root, "data", "txt", "keywords.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(
                line.strip() for line in f
                if line.strip() and not line.strip().startswith("#")
            )
    except OSError:
        # nếu thiếu file, trả set rỗng -> randomcase/uppercase sẽ không biến đổi gì
        # (an toàn hơn là crash)
        return set()


def _random_alias(length=4):
    """Tạo alias ngẫu nhiên (giống kb.aliasName = randomStr() của sqlmap)."""
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


# Điền sẵn các field tamper cần:
kb.keywords = _load_keywords()
kb.aliasName = _random_alias()
kb.bluecoat = False
