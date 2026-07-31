# SQL-Injection-Special

**stinger** — công cụ khai thác **inline time-based blind SQL injection** cho lab CTF.

Được xây riêng vì khai thác time-based của sqlmap thường không ổn định (ngưỡng thời gian
tĩnh, không hiệu chỉnh theo jitter thực tế). `stinger` tập trung vào một việc và làm cho chắc:
trích xuất dữ liệu qua **inline injection** (nhúng thẳng mệnh đề vào truy vấn, không cần ngắt
chuỗi) bằng kỹ thuật **time-based**, nhanh và chính xác.

Xem [DESIGN.md](DESIGN.md) để biết đầy đủ kiến trúc và các quyết định thiết kế.

## Tính năng

- **Đầu vào là file request Burp Suite** — chèn marker `*` vào vị trí inject, tool lo phần
  còn lại (parse raw HTTP, **tự tính lại Content-Length**).
- **Kho vector đa-DBMS** (`data/vectors.yaml`, cấu trúc 2 tầng dialect + vectors cho MySQL /
  PostgreSQL / MSSQL / Oracle) — tự dò và **xác nhận vector bằng test TRUE/FALSE** để loại
  oracle giả.
- **Tự dò DBMS** (`--dbms auto`).
- **Dùng hoàn toàn tamper của sqlmap** — 76 tamper chạy qua một shim `lib/core/` gọn.
- **Chế độ hex** — bắt được cả ký tự multibyte (byte >127).
- **`verify()` bằng hex literal** — chốt toàn chuỗi bằng 1 request.

## Dùng nhanh

```bash
# 1. Lưu request từ Burp ra file, chèn '*' vào vị trí inject, vd: {"id":"*"}
# 2. Chạy:
python main.py -r request.txt --query "select content from final_flag limit 1"

# Ép DBMS / vector, dùng tamper:
python main.py -r request.txt --dbms mysql --vector mysql-inline-sleep
python main.py -r request.txt --tamper between,space2comment
```

## Cấu trúc

```
stinger/        khung chính (request, transport, vectors, oracle, extract, tamper_engine, cli)
data/           vectors.yaml (kho vector) + txt/keywords.txt
lib/core/       shim để tamper của sqlmap chạy không cần sửa
tamper/         76 tamper copy từ sqlmap
tests/          bộ test (mock offline + end-to-end qua HTTP server cục bộ)
draft/          script gốc + request mẫu
```

## Test

```bash
python tests/test_request.py
python tests/test_tamper_engine.py
python tests/test_vectors.py
python tests/test_extract.py
python tests/test_transport.py
python tests/test_cli.py
```

## Ghi chú

- `sqlmap/` (nguồn tham khảo để copy tamper) **không** được commit — xem `.gitignore`.
- Các tamper trong `tamper/` thuộc bản quyền sqlmap developers (GPLv2).
- Công cụ phục vụ **học tập bảo mật** và giải **lab CTF** trong ngữ cảnh được phép.
