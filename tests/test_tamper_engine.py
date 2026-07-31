#!/usr/bin/env python3
"""
Test cho stinger/tamper_engine.py - chứng minh tamper của sqlmap chạy THẬT qua shim.

Chạy:  python tests/test_tamper_engine.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stinger.tamper_engine import (
    TamperChain,
    apply_tampers,
    available_tampers,
    load_tamper,
)


def test_available_tampers_found():
    names = available_tampers()
    assert len(names) >= 70, "phải có ~76 tamper, thấy %d" % len(names)
    assert "between" in names
    assert "space2comment" in names


def test_between_replaces_gt():
    """between.py: '>' -> 'NOT BETWEEN 0 AND', '=' -> 'BETWEEN # AND #'."""
    t = load_tamper("between")
    # doctest gốc của sqlmap:
    assert t.apply("1 AND A > B--") == "1 AND A NOT BETWEEN 0 AND B--"
    assert t.apply("1 AND A = B--") == "1 AND A BETWEEN B AND B--"


def test_space2comment_replaces_spaces():
    """space2comment.py: ' ' -> '/**/'."""
    t = load_tamper("space2comment")
    assert t.apply("SELECT id FROM users") == "SELECT/**/id/**/FROM/**/users"


def test_randomcase_uses_kb_keywords():
    """randomcase.py DÙNG kb.keywords - đây là ca khó nhất (phụ thuộc knowledge base).

    Nếu shim kb hoạt động: từ khóa SQL (SELECT, FROM) sẽ bị đổi hoa/thường ngẫu nhiên,
    còn định danh thường (id) giữ nguyên.
    """
    import random
    random.seed(0)
    t = load_tamper("randomcase")
    out = t.apply("SELECT id FROM users")
    # Kết quả ngẫu nhiên nhưng: phải khác input (đã biến đổi), và giữ độ dài.
    assert len(out) == len("SELECT id FROM users")
    # 'SELECT' và 'FROM' là từ khóa -> phải bị đổi case (không còn toàn hoa)
    assert out != "SELECT id FROM users"
    # so sánh không phân biệt hoa thường phải bằng nhau (chỉ đổi case)
    assert out.lower() == "select id from users"


def test_randomcase_kb_loaded():
    """Xác nhận kb.keywords thực sự được nạp (không rỗng)."""
    from lib.core.data import kb
    assert len(kb.keywords) > 100, "kb.keywords phải được nạp từ keywords.txt"
    assert "SELECT" in kb.keywords
    assert "UNION" in kb.keywords


def test_chain_between_then_space2comment():
    """Chain 2 tamper - chứng minh cơ chế chain hoạt động."""
    chain = TamperChain.from_names(["between", "space2comment"])
    assert len(chain) == 2
    # between chạy trước (HIGHEST) rồi space2comment (LOW)
    out = chain.apply("1 AND A > B")
    # between: '1 AND A > B' -> '1 AND A NOT BETWEEN 0 AND B'
    # space2comment: khoảng trắng -> /**/
    assert "/**/" in out
    assert "BETWEEN" in out
    assert " " not in out  # hết khoảng trắng


def test_chain_priority_order():
    """between (HIGHEST=100) phải xếp trước space2comment (LOW=-10) dù khai báo ngược."""
    # Khai báo ngược thứ tự -> chain vẫn phải xếp between trước theo priority.
    chain = TamperChain.from_names(["space2comment", "between"])
    order = chain.order()
    names_in_order = [n for n, _ in order]
    assert names_in_order[0] == "between", "between (priority cao) phải chạy trước"
    assert names_in_order[1] == "space2comment"


def test_apply_tampers_shortcut():
    # between đổi '> <số>' -> 'NOT BETWEEN 0 AND <số>' (nhánh regex thứ 2 cần số/chuỗi/hàm,
    # không đổi identifier trần như 'B' - đúng hành vi sqlmap gốc).
    out = apply_tampers("A > 1", ["between"])
    assert out == "A NOT BETWEEN 0 AND 1"


def test_empty_payload():
    """Tamper với payload rỗng không được crash."""
    t = load_tamper("between")
    assert t.apply("") == ""


def test_several_simple_tampers_load():
    """Load thử một loạt tamper phổ biến để bắt lỗi import shim sớm."""
    for name in ["equaltolike", "greatest", "charencode", "space2plus",
                 "apostrophemask", "uppercase", "lowercase", "multiplespaces"]:
        t = load_tamper(name)  # chỉ cần không raise
        assert callable(t.func), "%s không load được" % name


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
            print("[ OK ] %s" % t.__name__)
            passed += 1
        except Exception as e:
            import traceback
            print("[FAIL] %s -> %s: %s" % (t.__name__, type(e).__name__, e))
            traceback.print_exc()
    print("\n%d/%d passed" % (passed, len(tests)))
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
