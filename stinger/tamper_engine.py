#!/usr/bin/env python3
"""
Tamper engine - load động các tamper script của sqlmap và chain chúng lên payload.

Mục tiêu: DÙNG HOÀN TOÀN tamper của sqlmap (đã copy vào ./tamper/), không viết lại.
Các tamper import `from lib.core.* import ...` -> chạy được nhờ shim tại ./lib/core/.

Contract của mỗi tamper (chuẩn sqlmap):
    __priority__ = PRIORITY.XXX          # độ ưu tiên khi chain (cao chạy trước)
    def dependencies(): ...              # (tùy chọn)
    def tamper(payload, **kwargs): ...   # biến đổi payload rồi return

Cách chain (theo sqlmap): sort theo __priority__ GIẢM DẦN (priority cao xử lý trước).
Khi priority bằng nhau, giữ nguyên thứ tự người dùng khai báo.
"""

from __future__ import annotations

import importlib.util
import os
import sys

# Bảo đảm repo-root nằm trong sys.path để `import lib.core.*` của tamper hoạt động.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_TAMPER_DIR = os.path.join(_REPO_ROOT, "tamper")

# priority mặc định khi tamper không khai báo __priority__ (giống sqlmap: NORMAL=0)
_DEFAULT_PRIORITY = 0


class TamperError(Exception):
    """Lỗi khi load hoặc chạy tamper."""


class TamperModule:
    """Bọc một tamper đã load: giữ hàm tamper(), priority, tên."""

    __slots__ = ("name", "func", "priority", "module")

    def __init__(self, name, func, priority, module):
        self.name = name
        self.func = func
        self.priority = priority
        self.module = module

    def apply(self, payload, **kwargs):
        return self.func(payload, **kwargs)

    def __repr__(self):
        return "<Tamper %s (priority=%d)>" % (self.name, self.priority)


def available_tampers():
    """Liệt kê tên các tamper có sẵn trong ./tamper/ (bỏ __init__)."""
    if not os.path.isdir(_TAMPER_DIR):
        return []
    names = []
    for fn in os.listdir(_TAMPER_DIR):
        if fn.endswith(".py") and fn != "__init__.py":
            names.append(fn[:-3])
    return sorted(names)


def load_tamper(name):
    """Load một tamper theo tên (vd 'between'). Trả về TamperModule.

    Raise TamperError nếu không tìm thấy file, thiếu hàm tamper(), hoặc import lỗi.
    """
    path = os.path.join(_TAMPER_DIR, name + ".py")
    if not os.path.isfile(path):
        raise TamperError(
            "không tìm thấy tamper '%s' (tìm tại %s)" % (name, path)
        )

    # Load module từ file, đặt tên riêng để không đụng độ với package khác.
    mod_name = "stinger_tamper_%s" % name
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise TamperError("không tạo được spec cho tamper '%s'" % name)

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # import lib.core.* lỗi, syntax, ...
        raise TamperError(
            "lỗi khi load tamper '%s': %s: %s" % (name, type(e).__name__, e)
        ) from e

    func = getattr(module, "tamper", None)
    if not callable(func):
        raise TamperError("tamper '%s' không có hàm tamper(payload, **kwargs)" % name)

    priority = getattr(module, "__priority__", _DEFAULT_PRIORITY)
    # __priority__ có thể là thuộc tính của enum PRIORITY -> đã là int
    if not isinstance(priority, int):
        priority = _DEFAULT_PRIORITY

    return TamperModule(name, func, priority, module)


class TamperChain:
    """Chuỗi tamper đã sắp xếp, áp dụng tuần tự lên payload.

    Thứ tự áp dụng (theo sqlmap): priority GIẢM DẦN. Khi priority bằng nhau, giữ
    nguyên thứ tự người dùng khai báo (stable sort).
    """

    def __init__(self, tampers):
        self.tampers = list(tampers)

    @classmethod
    def from_names(cls, names):
        """Tạo chain từ danh sách tên tamper (theo thứ tự người dùng khai báo)."""
        loaded = [load_tamper(n) for n in names]
        # Python sort là STABLE: các tamper cùng priority giữ nguyên thứ tự gốc.
        # reverse=True -> priority cao trước (giống sqlmap).
        loaded.sort(key=lambda t: t.priority, reverse=True)
        return cls(loaded)

    def apply(self, payload, **kwargs):
        """Áp dụng lần lượt từng tamper lên payload."""
        result = payload
        for t in self.tampers:
            result = t.apply(result, **kwargs)
        return result

    def order(self):
        """Trả về danh sách (name, priority) theo thứ tự sẽ áp dụng - để debug/hiển thị."""
        return [(t.name, t.priority) for t in self.tampers]

    def __len__(self):
        return len(self.tampers)

    def __repr__(self):
        return "<TamperChain %r>" % (self.order(),)


def apply_tampers(payload, names, **kwargs):
    """Tiện ích: tạo chain từ tên và áp dụng ngay lên payload."""
    return TamperChain.from_names(names).apply(payload, **kwargs)
