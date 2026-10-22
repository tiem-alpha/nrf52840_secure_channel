# Firmware LKP1 trên nRF52840

Firmware dùng NCS 3.4.0, NUS GATT và PSA Crypto. Bản này chạy trên flash nội
bộ, không cần external flash. MCUboot có hai slot theo overlay của DK.

## Các tầng

| Tầng | File | Trách nhiệm |
|---|---|---|
| BLE | `src/main.c` | Một kết nối, yêu cầu LE security level 2, NUS RX/TX và timeout |
| Framing | `src/lkp1/framing.c` | Ghép record với buffer cố định, kiểm tra giới hạn/timeout |
| Chứng chỉ | `src/lkp1/certificate.c` | Chuỗi leaf + issuing CA tới tối đa hai pinned root |
| Crypto | `src/lkp1/crypto_psa.c` | PSA SHA/HMAC/HKDF/X25519/P-256/AES-GCM |
| Giao thức | `src/lkp1/server.c`, `keys.c` | F1/F2/F3, transcript, khóa, APP_DATA và sequence |
| Quyền | `src/lkp1/acl.c` | Allowlist `device_id` cho lệnh ứng dụng |

`server.c` không phụ thuộc BLE hoặc Zephyr. Khóa tạm, PRK và handshake key được
xóa sau F3 hoặc khi lỗi/ngắt kết nối. Ứng dụng hiện chỉ hỗ trợ lệnh demo
`01 ...`: khi phone nằm trong allowlist, lock trả APP_DATA `81 72 65 61 64 79`
(`0x81 || "ready"`). **Không có lệnh mở cửa hoặc GPIO actuator** trong project.

## Provisioning prototype

Tạo root, CA, lock và phone theo `python/README.md`. Tạo header cho firmware:

```sh
PYTHONPATH=python python3 -m lkp1.provisioning firmware-header \
  lock.json nrf52840/include/factory_credentials.h --allow-phone phone.json
```

Header chứa private key của lock. Giữ bí mật, tạo riêng cho từng thiết bị và
không commit. Nếu thiếu header, firmware build được nhưng từ chối mọi LKP1
record. Nếu không có `--allow-phone`, handshake có thể mở nhưng mọi lệnh ứng
dụng bị từ chối. Đường header này chỉ phục vụ prototype; production cần nạp
key an toàn tại nhà máy hoặc secure element, APPROTECT và quy trình thu hồi.

## Build và test

Trong môi trường NCS 3.4.0 đã cài toolchain:

```sh
west build -b nrf52840dk/nrf52840 -s nrf52840 -d build/lock \
  --sysbuild -- -DSB_CONFIG_BOOTLOADER_MCUBOOT=y
sh nrf52840/tests/run_host_tests.sh
sh nrf52840/tests/run_vector_test.sh
```

Sysbuild tạo `dfu_application.zip`. **Khóa ký mặc định của SDK chỉ dành cho
development**; phải cấu hình khóa ký MCUboot riêng trước khi phát hành.
Build NCS 3.4.0 đã hoàn tất với header factory tạm từ fixture: app dùng
206172 B flash và 54172 B RAM theo linker. Đây không phải số đo runtime.

## Giới hạn trước khi dùng sản phẩm

- Chưa thử BLE handshake và FOTA trên board/điện thoại thật; chưa đo thời gian
  handshake < 1 giây.
- SMP FOTA là dịch vụ BLE riêng, chưa có chính sách xác thực/ủy quyền theo
  phone LKP1. MCUboot kiểm chữ ký image nhưng chưa giải quyết quyền bắt đầu
  upload, chống rollback và chống gây quá tải flash.
- Chưa có enrollment, revocation/ACL động, secure factory provisioning và
  kiểm chứng APPROTECT. Không thể tuyên bố đạt RED/EN 18031/CRA từ code này.
