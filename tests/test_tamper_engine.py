#!/usr/bin/env python3
"""
Test cho stinger/tamper_engine.py - chung minh tamper cua sqlmap chay THAT qua shim.

Chay:  python tests/test_tamper_engine.py
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
    assert len(names) >= 70, "phai co ~76 tamper, thay %d" % len(names)
    assert "between" in names
    assert "space2comment" in names


def test_between_replaces_gt():
    """between.py: '>' -> 'NOT BETWEEN 0 AND', '=' -> 'BETWEEN # AND #'."""
    t = load_tamper("between")
    # doctest goc cua sqlmap:
    assert t.apply("1 AND A > B--") == "1 AND A NOT BETWEEN 0 AND B--"
    assert t.apply("1 AND A = B--") == "1 AND A BETWEEN B AND B--"


def test_space2comment_replaces_spaces():
    """space2comment.py: ' ' -> '/**/'."""
    t = load_tamper("space2comment")
    assert t.apply("SELECT id FROM users") == "SELECT/**/id/**/FROM/**/users"


def test_randomcase_uses_kb_keywords():
    """randomcase.py DUNG kb.keywords - day la ca kho nhat (phu thuoc knowledge base).

    Neu shim kb hoat dong: tu khoa SQL (SELECT, FROM) se bi doi hoa/thuong ngau nhien,
    con dinh danh thuong (id) giu nguyen.
    """
    import random
    random.seed(0)
    t = load_tamper("randomcase")
    out = t.apply("SELECT id FROM users")
    # Ket qua ngau nhien nhung: phai khac input (da bien doi), va giu do dai.
    assert len(out) == len("SELECT id FROM users")
    # 'SELECT' va 'FROM' la tu khoa -> phai bi doi case (khong con toan hoa)
    assert out != "SELECT id FROM users"
    # so sanh khong phan biet hoa thuong phai bang nhau (chi doi case)
    assert out.lower() == "select id from users"


def test_randomcase_kb_loaded():
    """Xac nhan kb.keywords thuc su duoc nap (khong rong)."""
    from lib.core.data import kb
    assert len(kb.keywords) > 100, "kb.keywords phai duoc nap tu keywords.txt"
    assert "SELECT" in kb.keywords
    assert "UNION" in kb.keywords


def test_chain_between_then_space2comment():
    """Chain 2 tamper - chung minh co che chain hoat dong."""
    chain = TamperChain.from_names(["between", "space2comment"])
    assert len(chain) == 2
    # between chay truoc (HIGHEST) roi space2comment (LOW)
    out = chain.apply("1 AND A > B")
    # between: '1 AND A > B' -> '1 AND A NOT BETWEEN 0 AND B'
    # space2comment: khoang trang -> /**/
    assert "/**/" in out
    assert "BETWEEN" in out
    assert " " not in out  # het khoang trang


def test_chain_priority_order():
    """between (HIGHEST=100) phai xep truoc space2comment (LOW=-10) du khai bao nguoc."""
    # Khai bao nguoc thu tu -> chain van phai xep between truoc theo priority.
    chain = TamperChain.from_names(["space2comment", "between"])
    order = chain.order()
    names_in_order = [n for n, _ in order]
    assert names_in_order[0] == "between", "between (priority cao) phai chay truoc"
    assert names_in_order[1] == "space2comment"


def test_apply_tampers_shortcut():
    # between doi '> <so>' -> 'NOT BETWEEN 0 AND <so>' (nhanh regex thu 2 can so/chuoi/ham,
    # khong doi identifier tran nhu 'B' - dung hanh vi sqlmap goc).
    out = apply_tampers("A > 1", ["between"])
    assert out == "A NOT BETWEEN 0 AND 1"


def test_empty_payload():
    """Tamper voi payload rong khong duoc crash."""
    t = load_tamper("between")
    assert t.apply("") == ""


def test_several_simple_tampers_load():
    """Load thu mot loat tamper pho bien de bat loi import shim som."""
    for name in ["equaltolike", "greatest", "charencode", "space2plus",
                 "apostrophemask", "uppercase", "lowercase", "multiplespaces"]:
        t = load_tamper(name)  # chi can khong raise
        assert callable(t.func), "%s khong load duoc" % name


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
