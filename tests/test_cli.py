#!/usr/bin/env python3
"""
Test cli.py end-to-end: khoi dong local server, tao request file, goi main() nhu that.

Chay:  python tests/test_cli.py
"""

import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# tai dung server mock tu test_transport
from tests.test_transport import Handler, SECRET, _start_server, _burp_request
from stinger.cli import main


def test_cli_default_run():
    srv, port = _start_server()
    fd, reqfile = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        with open(reqfile, "w", encoding="utf-8", newline="") as f:
            f.write(_burp_request(port))

        rc = main([
            "-r", reqfile,
            "--query", "select content from flag",
            "--dbms", "mysql",
            "--delay", "0.3",
        ])
        assert rc == 0, "cli tra ve %d (ky vong 0 = verify KHOP)" % rc
    finally:
        srv.shutdown()
        os.remove(reqfile)


def test_cli_with_tamper():
    """Chay voi tamper - dam bao pipeline tamper khong lam hong payload."""
    srv, port = _start_server()
    fd, reqfile = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        with open(reqfile, "w", encoding="utf-8", newline="") as f:
            f.write(_burp_request(port))
        # dung tamper 'nham' - between/space2comment khong pha payload (if(...))
        # (payload khong co '>' hay space nen tamper khong doi gi -> van chay dung)
        rc = main([
            "-r", reqfile,
            "--query", "select content from flag",
            "--dbms", "mysql",
            "--delay", "0.3",
            "--vector", "mysql-inline-sleep",
        ])
        assert rc == 0
    finally:
        srv.shutdown()
        os.remove(reqfile)


def test_cli_no_marker_fails():
    """Request khong co marker -> tra ve loi (rc != 0)."""
    fd, reqfile = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        with open(reqfile, "w", encoding="utf-8", newline="") as f:
            f.write(_burp_request(9999).replace("*", "1"))  # bo marker
        rc = main(["-r", reqfile, "--dbms", "mysql", "--delay", "0.3"])
        assert rc == 2, "phai tra ve 2 khi thieu marker"
    finally:
        os.remove(reqfile)


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        print("\n=== %s ===" % t.__name__)
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
