#!/usr/bin/env python3
"""
Tamper engine - load dong cac tamper script cua sqlmap va chain chung len payload.

Muc tieu: DUNG HOAN TOAN tamper cua sqlmap (da copy vao ./tamper/), khong viet lai.
Cac tamper import `from lib.core.* import ...` -> chay duoc nho shim tai ./lib/core/.

Contract cua moi tamper (chuan sqlmap):
    __priority__ = PRIORITY.XXX          # do uu tien khi chain (cao chay truoc)
    def dependencies(): ...              # (tuy chon)
    def tamper(payload, **kwargs): ...   # bien doi payload roi return

Cach chain (theo sqlmap): sort theo __priority__ GIAM DAN (priority cao xu ly truoc).
Khi priority bang nhau, giu nguyen thu tu nguoi dung khai bao.
"""

from __future__ import annotations

import importlib.util
import os
import sys

# Bao dam repo-root nam trong sys.path de `import lib.core.*` cua tamper hoat dong.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_TAMPER_DIR = os.path.join(_REPO_ROOT, "tamper")

# priority mac dinh khi tamper khong khai bao __priority__ (giong sqlmap: NORMAL=0)
_DEFAULT_PRIORITY = 0


class TamperError(Exception):
    """Loi khi load hoac chay tamper."""


class TamperModule:
    """Boc mot tamper da load: giu ham tamper(), priority, ten."""

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
    """Liet ke ten cac tamper co san trong ./tamper/ (bo __init__)."""
    if not os.path.isdir(_TAMPER_DIR):
        return []
    names = []
    for fn in os.listdir(_TAMPER_DIR):
        if fn.endswith(".py") and fn != "__init__.py":
            names.append(fn[:-3])
    return sorted(names)


def load_tamper(name):
    """Load mot tamper theo ten (vd 'between'). Tra ve TamperModule.

    Raise TamperError neu khong tim thay file, thieu ham tamper(), hoac import loi.
    """
    path = os.path.join(_TAMPER_DIR, name + ".py")
    if not os.path.isfile(path):
        raise TamperError(
            "khong tim thay tamper '%s' (tim tai %s)" % (name, path)
        )

    # Load module tu file, dat ten rieng de khong dung do voi package khac.
    mod_name = "stinger_tamper_%s" % name
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise TamperError("khong tao duoc spec cho tamper '%s'" % name)

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # import lib.core.* loi, syntax, ...
        raise TamperError(
            "loi khi load tamper '%s': %s: %s" % (name, type(e).__name__, e)
        ) from e

    func = getattr(module, "tamper", None)
    if not callable(func):
        raise TamperError("tamper '%s' khong co ham tamper(payload, **kwargs)" % name)

    priority = getattr(module, "__priority__", _DEFAULT_PRIORITY)
    # __priority__ co the la thuoc tinh cua enum PRIORITY -> da la int
    if not isinstance(priority, int):
        priority = _DEFAULT_PRIORITY

    return TamperModule(name, func, priority, module)


class TamperChain:
    """Chuoi tamper da sap xep, ap dung tuan tu len payload.

    Thu tu ap dung (theo sqlmap): priority GIAM DAN. Khi priority bang nhau, giu
    nguyen thu tu nguoi dung khai bao (stable sort).
    """

    def __init__(self, tampers):
        self.tampers = list(tampers)

    @classmethod
    def from_names(cls, names):
        """Tao chain tu danh sach ten tamper (theo thu tu nguoi dung khai bao)."""
        loaded = [load_tamper(n) for n in names]
        # Python sort la STABLE: cac tamper cung priority giu nguyen thu tu goc.
        # reverse=True -> priority cao truoc (giong sqlmap).
        loaded.sort(key=lambda t: t.priority, reverse=True)
        return cls(loaded)

    def apply(self, payload, **kwargs):
        """Ap dung lan luot tung tamper len payload."""
        result = payload
        for t in self.tampers:
            result = t.apply(result, **kwargs)
        return result

    def order(self):
        """Tra ve danh sach (name, priority) theo thu tu se ap dung - de debug/hien thi."""
        return [(t.name, t.priority) for t in self.tampers]

    def __len__(self):
        return len(self.tampers)

    def __repr__(self):
        return "<TamperChain %r>" % (self.order(),)


def apply_tampers(payload, names, **kwargs):
    """Tien ich: tao chain tu ten va ap dung ngay len payload."""
    return TamperChain.from_names(names).apply(payload, **kwargs)
