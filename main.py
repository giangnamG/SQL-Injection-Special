#!/usr/bin/env python3
"""
Entrypoint cho stinger - chạy từ thư mục root:

    python main.py -r request.txt --query "select content from final_flag limit 1"
    python main.py -r request.txt --dbms mysql --vector mysql-inline-sleep
    python main.py -r request.txt --tamper between,space2comment

Chỉ là lớp mỏng chuyển tiếp sang stinger.cli:main(). Toàn bộ logic ở package stinger/.
"""

import os
import sys

# Bảo đảm import được package stinger/ và lib/ dù chạy từ thư mục nào.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from stinger.cli import main

if __name__ == "__main__":
    sys.exit(main())
