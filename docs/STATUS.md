# Trạng thái triển khai LKP1

Đặc tả gốc là `README.md`. Bản hiện tại là **prototype tích hợp** cho nRF52840
DK và Android; chưa phải firmware khóa cửa được chứng nhận hay sẵn sàng triển
khai thương mại.

| Phase | Đã có | Kiểm chứng hiện tại |
|---|---|---|
| 1 Python reference | Chứng chỉ, framing, 3-flight client/server, AEAD, replay, vector cố định | 8 unittest pass |
| 2 Provisioning | CLI root/issuing CA/leaf, header factory và allowlist phone | Test CLI/chain pass |
| 3 nRF52840 | NUS, PSA, cert, handshake, APP_DATA, ACL, MCUmgr/MCUboot | Host C vector pass, NCS 3.4.0 build pass |
| 4 Android | BLE NUS, client LKP1, demo status command, McuMgr FOTA | Gradle unit tests pass |
| 5 Kiểm tra chéo | Python fixture dùng trong C/Kotlin; negative tests phần mềm | Chưa thử BLE/FOTA trên thiết bị thật |

## Điều kiện còn phải hoàn tất trước sản phẩm

1. Nạp key riêng cho từng lock tại nhà máy/secure element, bật APPROTECT;
   không dùng header private key của prototype trong firmware phát hành.
2. Tạo khóa ký MCUboot production và quy trình xoay khóa. SDK sysbuild đang
   dùng test key. Thiết kế quyền truy cập SMP FOTA và chống rollback; mã hóa
   Just Works chỉ bảo vệ link, không chứng minh phone được phép cập nhật.
3. Cài đặt setup QR/pairing record ghim serial, Keystore/StrongBox Mode B,
   enrollment/thu hồi chứng chỉ và ACL động.
4. Thử liên thông trên nRF52840 + điện thoại Android thật, lỗi mất gói/đứt
   kết nối, FOTA, nguồn điện, bộ nhớ và đo handshake dưới 1 giây.
5. Đánh giá độc lập theo RED/EN 18031, EN 303 645, CRA và kiểm thử xâm nhập.

Lệnh demo `0x01` chỉ trả trạng thái `0x81 || "ready"` sau ACL; project chưa nối
actuator mở cửa. Quy tắc quyền mở cửa cần thiết kế riêng theo mục 14 của đặc tả.
