# VAI TRÒ & CÁCH LÀM VIỆC
Bạn là kỹ sư bảo mật nhúng senior. Hãy triển khai CHÍNH XÁC đặc tả dưới đây (LKP1 – Lock Key Protocol v1).
- KHÔNG tự đổi thuật toán, thứ tự trường, label hay độ dài. Nếu có điểm mơ hồ, liệt kê giả định trước rồi mới code.
- Không tự viết primitive mật mã; chỉ dùng thư viện đã kiểm chứng.
- Làm theo thứ tự các Phase ở mục 12, mỗi phase có code + test chạy được.

# 1. Mục tiêu
Secure channel giữa **nRF52840 (khóa cửa, GATT server)** và **điện thoại Android (GATT client)** qua BLE NUS, có: xác thực hai chiều bằng chứng chỉ, forward secrecy (ECDH ephemeral), mã hóa + toàn vẹn (AES-128-GCM), chống replay/downgrade/reflection. Mục tiêu có thể đưa vào sản phẩm thương mại cho thị trường EU. Luồng tối giản: 3 flight.
- nrf52840 hỗ trợ FOTA như trong code base đang làm
-  tích hợp connect sdk fota cho ứng dụng android


# 2. Bộ thuật toán (suite_id = 0x0001, KHÔNG thương lượng)
| Mục đích | Thuật toán |
|---|---|
| Chữ ký / chứng chỉ | ECDSA P-256 + SHA-256; chữ ký dạng thô r‖s (64 byte) |
| Trao đổi khóa | X25519 (ephemeral, mỗi phiên sinh mới) |
| KDF | HKDF-SHA256 (RFC 5869) |
| Finished | HMAC-SHA256 |
| AEAD | AES-128-GCM, nonce 12 byte, tag 16 byte |
| Hash transcript | SHA-256 |
Tất cả số nguyên: **big-endian**. Public key P-256: 64 byte `X‖Y` (không có tiền tố 0x04). Public key X25519: 32 byte.

# 3. BLE
- Service: Nordic UART Service `6E400001-B5A3-F393-E0A9-E50E24DCCA9E`; RX (phone→lock, Write/Write-No-Response) `6E400002-...`; TX (lock→phone, Notify) `6E400003-...`.
- Pairing: LE Secure Connections **Just Works**, không bắt buộc bonding. Chỉ để mã hóa link; KHÔNG dựa vào nó cho xác thực.
- Android: yêu cầu MTU 247, bật Data Length Extension, bật notification trước khi gửi hello.
- Chỉ cho 1 kết nối + 1 handshake tại một thời điểm.

# 4. Dữ liệu factory & Chain of Trust
## 4.1 Root of Trust (tạo trên PC offline/HSM)
- Root CA ECDSA P-256. Public key root được **nhúng vào firmware và app** (pinned), kèm `key_id`. Hỗ trợ tối đa 2 root để xoay khóa.
- Production: Root offline ký **Issuing CA** (Lock CA, Phone CA); Issuing CA ký chứng chỉ leaf. Độ dài chuỗi ≤ 2 chứng chỉ (leaf + issuing CA).
- Prototype: cho phép Root ký trực tiếp leaf (chuỗi 1 chứng chỉ).

## 4.2 Dữ liệu nRF52840 (nạp lúc factory)
- ECDSA P-256 private key (32B) + public key, `serial_number` (16B), certificate (loại LOCK), root public key(s).
- Khuyến nghị thương mại: sinh key trong thiết bị/secure element, xuất CSR; bật APPROTECT; không để key trong binary.

## 4.3 Dữ liệu điện thoại
- ECDSA P-256 keypair, `device_id` (16B, UUID), certificate (loại PHONE), root public key(s).
- **Mode A (prototype, theo yêu cầu):** PC tool sinh key + cert rồi nạp vào app.
- **Mode B (production, khuyến nghị):** sinh key trong Android Keystore/StrongBox (non-exportable), gửi CSR → CA ký → cert trả về app. Thiết kế code qua interface `KeyStoreProvider` để chuyển A→B không đổi giao thức.

## 4.4 Định dạng chứng chỉ compact (164 byte)
```
TBS (100 byte):
  cert_version   1  = 0x01
  cert_type      1  = 0x01 LOCK | 0x02 PHONE | 0x10 ISSUING_CA
  subject_id    16  = serial (LOCK) | device_id (PHONE) | ca_id
  issuer_key_id  8  = SHA256(issuer_pub X‖Y)[0..7]
  not_before     4  = unix time (uint32)
  not_after      4  = unix time, 0 = không hết hạn
  key_usage      2  = bit0 SIGN_HANDSHAKE, bit1 CA_SIGN
  subject_pub   64  = X‖Y
signature (64) = ECDSA-P256-SHA256(issuer_priv, TBS)
```
Quy tắc xác minh: kiểm tra chữ ký theo chuỗi đến root nhúng sẵn; kiểm tra cert_type đúng vai trò (lock chỉ chấp nhận PHONE, phone chỉ chấp nhận LOCK); key_usage; subject_pub nằm trên đường cong. Thời hạn: phone kiểm tra theo đồng hồ của nó; **lock không có đồng hồ tin cậy nên bỏ qua not_after** (dùng revocation list/ACL do app quản lý). Phone phải so `subject_id` của cert lock với serial đã ghim lúc setup (QR/pairing record).

# 5. Framing trên NUS
Mọi "record" có header 4 byte rồi body:
```
ver(1)=0x01 | rec_type(1) | body_len(2) | body
rec_type: 0x01 HANDSHAKE (rõ) | 0x02 HANDSHAKE_ENC | 0x03 APP_DATA | 0x04 ALERT
```
- Record được cắt thành nhiều gói ATT theo MTU-3; bên nhận ghép lại theo `body_len`. Không có header phân mảnh riêng.
- `MAX_BODY_LEN = 1024`; vượt quá → ALERT + ngắt. Timeout giữa 2 fragment: 5 s.
- Handshake message (nằm trong body): `hs_type(1) | hs_len(2) | hs_body`.
  - 0x01 ClientHello, 0x02 ServerHello, 0x0B Certificate, 0x0F CertificateVerify, 0x14 Finished.

# 6. Luồng handshake (3 flight)
```
Phone (client)                                  nRF52840 (lock)
F1: ClientHello  ───────────────────────────────►
        ◄─────────────────────────────────  F2: ServerHello (rõ)
                                                  + [Certificate_S, CertificateVerify_S, Finished_S] (mã hóa bằng hs key)
F3: [Certificate_C, CertificateVerify_C, Finished_C] (mã hóa) ─►
        ◄─────────────────────────────────  APP_DATA #0: CHANNEL_READY (tùy chọn)
```
## 6.1 Nội dung
- **ClientHello body** (66B): `suite_id(2)=0x0001 | c_eph_pub(32) | c_nonce(32)`. (ver nằm ở header record.)
- **ServerHello body** (66B): `suite_id(2) | s_eph_pub(32) | s_nonce(32)`. Server chỉ sinh sau khi nhận ClientHello hợp lệ.
- **Certificate body:** `cert_count(1) | { cert_len(2) | cert }×count` (leaf trước).
- **CertificateVerify body:** `sig(64)`.
- **Finished body:** `verify_data(32)`.

## 6.2 Transcript & chữ ký
Gọi `M1..M8` là các handshake message theo thứ tự (bao gồm hs header 3 byte, dạng plaintext): M1 ClientHello, M2 ServerHello, M3 Certificate_S, M4 CertVerify_S, M5 Finished_S, M6 Certificate_C, M7 CertVerify_C, M8 Finished_C.
`TH(Mi..Mj) = SHA256(Mi ‖ ... ‖ Mj)`.
- `sig_S = ECDSA-P256-SHA256( leaf_S_priv, "LKP1-SIG-SERVER" ‖ 0x00 ‖ TH(M1..M3) )`
- `sig_C = ECDSA-P256-SHA256( leaf_C_priv, "LKP1-SIG-CLIENT" ‖ 0x00 ‖ TH(M1..M6) )`
Nhờ transcript, chữ ký đã bao phủ: suite, hai khóa ECDH, hai nonce, serial của lock và device_id của phone (nằm trong cert). Đây là phiên bản gọn của các bước ký 5–8 trong thiết kế cũ.
- `Finished_S = HMAC(s_fin_key, TH(M1..M4))`
- `Finished_C = HMAC(c_fin_key, TH(M1..M7))`
So sánh bằng hàm constant-time.

# 7. Key schedule (HKDF-SHA256)
```
ss  = X25519(own_eph_priv, peer_eph_pub)        # từ chối nếu ss toàn 0 (low-order point)
PRK = HKDF-Extract(salt = c_nonce ‖ s_nonce, IKM = ss)
info(label, ctx) = "LKP1 " ‖ label ‖ 0x00 ‖ ctx

# Sau M1,M2 (ctx = TH_hello = SHA256(M1‖M2)):
c_hs_key(16)  = Expand(PRK, info("c hs key",  TH_hello), 16)
c_hs_iv(12)   = Expand(PRK, info("c hs iv",   TH_hello), 12)
s_hs_key(16), s_hs_iv(12)  tương tự với "s hs key", "s hs iv"
c_fin_key(32) = Expand(PRK, info("c finished", TH_hello), 32)
s_fin_key(32) = Expand(PRK, info("s finished", TH_hello), 32)

# Sau M8 (ctx = TH_app = SHA256(M1..M8)):
master(32)    = Expand(PRK,    info("master", TH_app), 32)
c2s_key(16)   = Expand(master, info("c2s key", ""), 16)
c2s_iv(12)    = Expand(master, info("c2s iv",  ""), 12)
s2c_key(16), s2c_iv(12) tương tự
session_id(4) = Expand(master, info("session id", ""), 4)
```
Sau khi bắt tay xong: zeroize ss, PRK, hs keys, fin keys, ephemeral private keys.

# 8. Mã hóa bản ghi
- Nonce: `nonce12 = iv12 XOR (0x00000000 ‖ u64_be(counter))`. Counter mỗi chiều bắt đầu từ 0, +1 mỗi bản ghi, **không bao giờ dùng lại**.
- **HANDSHAKE_ENC:** body = `ciphertext ‖ tag(16)`; dùng `{c|s}_hs_key/iv`; counter ngầm định (server F2 = 0, client F3 = 0); AAD = 4 byte header.
- **APP_DATA:** body = `session_id(4) | seq(4) | ciphertext | tag(16)`. Dùng `c2s_*` (phone→lock) hoặc `s2c_*` (lock→phone); counter = `seq`; AAD = `header(4) ‖ session_id(4) ‖ seq(4)`.
- Bên nhận yêu cầu `seq == expected` (BLE có thứ tự); sai → hủy phiên. `seq` = 0xFFFFFFFF hoặc phiên > 24h → đóng và bắt tay lại. Phiên KHÔNG resume; mỗi lần kết nối là handshake mới.
- Max plaintext/bản ghi: 512 byte. Overhead APP_DATA = 4+4+4+16 = 28 byte.
- Lớp ứng dụng bên trong plaintext (ví dụ): `cmd(1) | payload`. Quyền mở cửa (ACL theo device_id) là lớp riêng, ngoài phạm vi giao thức này nhưng lock phải kiểm tra trước khi thực thi lệnh.

# 9. State machine & xử lý lỗi
- Lock: `IDLE → GOT_CH → SENT_F2 → OPEN`. Phone: `IDLE → SENT_CH → GOT_F2 → OPEN`. Sai thứ tự/loại/độ dài message → lỗi.
- Handshake timeout tổng: 10 s.
- Lock: sau 3 handshake thất bại liên tiếp, backoff lũy tiến (1s, 2s, 4s… tối đa 60s); từ chối khi đang bận.
- Mọi lỗi → gửi ALERT 1 byte thô (`0x01` protocol, `0x02` auth, `0x03` busy) rồi ngắt. **Không** phân biệt chi tiết nguyên nhân với bên ngoài (log nội bộ).
- Kiểm tra mọi độ dài trước khi parse; không cấp phát động theo giá trị từ đối phương.
- RNG: TRNG của CryptoCell trên nRF; `SecureRandom` trên Android. ECDSA ký với nonce an toàn (RFC 6979 hoặc DRBG của thư viện).

# 10. Công nghệ triển khai
- **Firmware:** nRF Connect SDK (Zephyr) + PSA Crypto (CryptoCell-310/Oberon): ECDSA P-256, X25519, AES-GCM, HKDF, HMAC. Module `lkp1` tách khỏi lớp BLE để unit test trên host.
- **Android:** Kotlin; ECDSA/AES-GCM/HMAC qua JCA, X25519 + HKDF qua BouncyCastle hoặc Tink; private key long-term trong Keystore (Mode B).
- **Tooling PC:** Python 3 + `cryptography`: tạo root, issuing CA, cert lock/phone, nạp dữ liệu, sinh test vector.
- **Reference implementation Python** của toàn bộ giao thức (cả client lẫn server) là "nguồn chân lý" để kiểm tra chéo firmware và Android.

# 11. Yêu cầu bảo mật đưa vào checklist EU (RED/EN 18031, EN 303 645, CRA)
Key riêng cho từng thiết bị, không default secret; bảo vệ debug (APPROTECT); secure boot + OTA có chữ ký; chống replay và brute-force; zeroize khóa; log/nhận lỗi không rò thông tin; thu hồi/quản lý quyền truy cập; quy trình cập nhật bảo mật và xử lý lỗ hổng. (Việc "đạt chuẩn" phải được xác nhận bởi gap analysis/lab ngoài.)

# 12. Kế hoạch giao hàng theo Phase (mỗi phase: code + test + giải thích ngắn)
1. **Phase 1 – Reference Python:** thư viện `lkp1` (cert, framing, handshake client+server, key schedule, AEAD) + **test vector cố định** (khóa/nonce cố định → in ra từng byte M1..M8, master, keys) + test âm.
2. **Phase 2 – Provisioning tool:** CLI tạo root/CA/cert lock/phone, xuất file nạp cho nRF và app.
3. **Phase 3 – Firmware nRF52840:** module `lkp1` (C) + NUS GATT + state machine; chạy được test vector trên host (unit test).
4. **Phase 4 – Android app (Kotlin):** BLE client, `lkp1` client, màn hình demo gửi lệnh qua APP_DATA.
5. **Phase 5 – Kiểm tra chéo & test âm.**

# 13. Tiêu chí nghiệm thu / test bắt buộc
- Python, C và Kotlin cho **cùng kết quả** với test vector (M1..M8, master, keys, ciphertext đầu tiên).
- Test âm phải bị từ chối: cert sai chữ ký/sai root/sai cert_type/sai usage; sửa 1 bit bất kỳ của transcript; replay F1/F3 từ phiên cũ; reflection (gửi lại message của chính mình); seq trùng/nhảy cóc; tag sai; ephemeral key toàn 0/low-order; message quá dài/cắt cụt/sai thứ tự; downgrade `suite_id` khác 0x0001.
- Đo hiệu năng trên nRF52840: tổng thời gian handshake (mục tiêu < 1 giây gồm cả truyền BLE), RAM/flash của module.
- Lock không in/log bất kỳ khóa nào; kiểm tra zeroize sau handshake.

# 14. Phần ngoài phạm vi (cần quyết định riêng)
Mô hình cấp quyền/ACL theo phone, thu hồi chứng chỉ phone, cơ chế OTA, provisioning production tại nhà máy, pairing lần đầu giữa phone và lock (cách ghim serial).

## Trạng thái triển khai

Xem [docs/STATUS.md](docs/STATUS.md) để biết code đã có, các test đã chạy và
những việc còn phải xác nhận trên phần cứng trước khi dùng cho sản phẩm.
