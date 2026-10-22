# LKP1 – Vì sao mỗi bước đều cần thiết

> Tài liệu đi kèm đặc tả LKP1 (Lock Key Protocol v1). Đặc tả trả lời câu hỏi **"làm thế nào"**. Tài liệu này trả lời câu hỏi **"tại sao"**: với mỗi thành phần, nếu bỏ nó đi thì kẻ tấn công làm được gì, bằng kỹ thuật nào, và rủi ro nằm ở đâu.
>
> Đối tượng đọc: lập trình viên firmware/Android, người review bảo mật, người chuẩn bị hồ sơ đánh giá cho thị trường EU.

---

## 0. Bắt đầu từ kẻ tấn công, không phải từ thuật toán

Khóa cửa là thiết bị mà hậu quả của một lỗi bảo mật là **người lạ bước vào nhà**. Vì vậy trước khi bàn đến AES hay ECDSA, cần liệt kê rõ ta đang phòng thủ trước ai.

| Kẻ tấn công | Khả năng | Ví dụ thực tế |
|---|---|---|
| **A1. Nghe lén thụ động** | Thu toàn bộ gói BLE trong không khí bằng sniffer giá vài chục USD (nRF Sniffer, Ubertooth) | Đứng ngoài hành lang ghi lại lúc chủ nhà mở cửa |
| **A2. MITM chủ động** | Chen vào giữa, chặn/sửa/chèn gói, giả làm khóa hoặc giả làm điện thoại | Hai board nRF làm "relay thông minh" trong tay kẻ tấn công |
| **A3. Phát lại (replay)** | Ghi bản tin hợp lệ hôm nay, phát lại ngày mai | Ghi gói "mở cửa" rồi phát lại |
| **A4. Relay** | Chuyển tiếp gói giữa điện thoại ở xa và khóa theo thời gian thực, không cần giải mã | Kẻ tấn công đứng cạnh điện thoại nạn nhân ở quán cà phê và đồng bọn đứng ở cửa nhà |
| **A5. Thiết bị giả** | Tự chế một "khóa" hoặc một "điện thoại" mới | Viết app giả, hoặc dùng board nRF giả làm khóa để lừa app |
| **A6. Người có thiết bị trong tay** | Có nguyên một khóa hoặc một điện thoại, có thời gian và dụng cụ | Mua khóa cùng loại về, đọc flash, cắm debug |
| **A7. Kẻ thấy được tương lai** | Một ngày nào đó lấy được khóa dài hạn, rồi áp dụng lên dữ liệu đã ghi từ trước | "Ghi bây giờ, giải mã sau" |
| **A8. Kẻ phá hoại dịch vụ** | Không muốn vào nhà, chỉ muốn khóa hết hoạt động hoặc cạn pin | Spam kết nối, gửi gói dị dạng |

Hầu hết quyết định trong LKP1 đều nhắm vào một hoặc nhiều dòng ở bảng này. Mục 14 là bảng tra ngược.

---

## 1. BLE Just Works: tại sao coi như không có bảo mật

### Nó làm gì
LE Secure Connections ở chế độ Just Works dùng ECDH P-256 để tạo khóa mã hóa link. Không có bước nào yêu cầu người dùng so mã hoặc nhập PIN.

### Vấn đề
Just Works **mã hóa nhưng không xác thực**. Mã hóa với một đối phương chưa biết là ai thì vô nghĩa: kẻ tấn công A2 chỉ cần tự thực hiện Just Works với điện thoại (đóng vai khóa) và tự thực hiện Just Works với khóa (đóng vai điện thoại), rồi chuyển tiếp nội dung ở giữa. Cả hai đầu đều thấy "link đã được mã hóa", nhưng mã hóa kết thúc ở kẻ tấn công.

Đây là điểm yếu của thiết kế, không phải lỗi cài đặt. Spec Bluetooth ghi nhận rõ Just Works không chống MITM.

### Nếu chỉ dựa vào BLE pairing
- Kẻ A2 đứng giữa đọc và sửa mọi lệnh, kể cả lệnh mở cửa.
- Kẻ A5 dựng khóa giả, app không có cách nào phân biệt với khóa thật.
- Lỗ hổng ở tầng link/pairing (đã có nhiều công bố như KNOB, BLURtooth, các lỗi downgrade pairing trên một số stack) ảnh hưởng thẳng vào bảo mật sản phẩm, và ta không kiểm soát được bản vá của hệ điều hành điện thoại.

### Quyết định thiết kế
Coi BLE pairing chỉ là lớp "bonus" (che mắt người nghe thụ động ở mức thấp). **Toàn bộ bảo mật nằm ở secure channel tầng ứng dụng.** Giao thức được thiết kế để vẫn an toàn nếu kẻ tấn công kiểm soát hoàn toàn kênh BLE, tức là giả định tầng dưới là một "dây điện công cộng".

Lý do chọn Just Works dù yếu: trải nghiệm không cần nhập mã, khóa không có màn hình. Cái giá phải trả là toàn bộ gánh nặng chuyển sang LKP1.

---

## 2. Root of Trust và chuỗi chứng chỉ: "ai nói ai là ai"

### Vấn đề cần giải
Khi điện thoại nhận được một public key tự xưng là "khóa cửa số serial X", làm sao biết đó đúng là khóa thật do nhà sản xuất làm ra, chứ không phải board tự chế của kẻ tấn công?

### Nếu không có Root of Trust
Kẻ A5 sinh một cặp khóa ECDSA, gửi public key cho app và ký mọi thứ bằng khóa đó. Chữ ký hoàn toàn hợp lệ về mặt toán học. Toán học chỉ chứng minh "người này giữ private key của public key này", không chứng minh "người này là khóa chính hãng". Cần một bên thứ ba tin cậy gắn **danh tính** vào public key. Đó là chứng chỉ.

### Cách thiết kế giải quyết
- **Root public key được nhúng (pin) sẵn trong firmware và app.** Kẻ tấn công không thể thay vì không có private key của root. Đây là điểm neo tin cậy duy nhất.
- **Root offline, ký Issuing CA, Issuing CA ký thiết bị.** Nếu Issuing CA bị lộ, chỉ phải thay Issuing CA (và thu hồi các cert nó ký), còn root vẫn nằm trong két. Nếu Root ký trực tiếp thiết bị mà root bị lộ, toàn bộ sản phẩm đã bán ra ngoài thị trường trở thành không đáng tin cậy và gần như không thể cứu vãn.
- **Hỗ trợ 2 root** để có đường xoay khóa. Không có cơ chế này, một ngày nào đó root cần đổi sẽ đòi hỏi cập nhật đồng loạt toàn bộ thiết bị cùng lúc.

### Rủi ro còn lại
- Root private key bị lộ là thảm họa không có biện pháp thuần giao thức nào cứu được. Phải bảo vệ bằng HSM, quy trình ký có nhiều người, kiểm toán.
- Pin root vào firmware nghĩa là firmware phải được bảo vệ khỏi bị sửa (secure boot). Nếu A6 thay được root key trong flash thì chuỗi tin cậy sụp đổ cho thiết bị đó.

---

## 3. Khóa riêng cho từng thiết bị, và chuyện giữ khóa ở đâu

### Nếu mọi khóa cửa dùng chung một khóa (hoặc khóa suy ra từ serial)
Kẻ A6 mua một khóa, đọc ra khóa chung, và từ đó giả được **mọi khóa cửa** cùng dòng sản phẩm. Đây là lỗi kinh điển của nhiều thiết bị IoT giá rẻ và là nội dung cấm trực tiếp trong các tiêu chuẩn như ETSI EN 303 645 (không dùng mật khẩu/khóa mặc định chung).

### Thiết kế
Mỗi khóa cửa có cặp ECDSA riêng và cert riêng. Lộ một khóa chỉ ảnh hưởng một khóa. Mỗi điện thoại cũng vậy.

### Nơi lưu khóa riêng: Mode A và Mode B
- **Mode A (PC sinh khóa rồi nạp vào):** chấp nhận cho prototype. Rủi ro: private key đã từng tồn tại trên máy PC, trong file, có thể bị sao chép trong quá trình sản xuất hoặc phát triển.
- **Mode B (sinh trong thiết bị, gửi CSR):** private key **chưa bao giờ rời** thiết bị. Trên Android dùng Keystore/StrongBox với cờ non-exportable. Kể cả app bị cài mã độc đọc bộ nhớ vẫn không lấy được khóa, chỉ nhờ ký được khi app đang chạy (tức là mã độc có thể lạm dụng, nhưng không thể mang khóa đi).
- **Với nRF52840:** bật APPROTECT để khóa cổng debug. Nếu để cổng debug mở, A6 chỉ cần dây SWD là đọc được khóa. Với sản phẩm thương mại giá trị cao, nên thêm secure element rời để giữ khóa dài hạn, vì nRF52840 không có vùng lưu khóa chống tấn công vật lý tầm cao (fault injection, side-channel).

### Tại sao khuyến nghị CSR
Nếu CA chỉ nhận public key và ký cert, thì không ai ngoài thiết bị từng nhìn thấy private key. Quy trình sản xuất trở thành một mục tiêu tấn công kém giá trị hơn nhiều.

---

## 4. Từng trường trong chứng chỉ có tác dụng gì

Chứng chỉ trong LKP1 rất gọn (164 byte) vì BLE băng thông thấp, nhưng mỗi trường đều ngăn một kiểu tấn công cụ thể.

| Trường | Nếu thiếu thì | Cách tấn công |
|---|---|---|
| `cert_type` (LOCK/PHONE/CA) | **Nhầm vai trò** | Kẻ tấn công lấy một cert PHONE hợp lệ (của chính mình, đăng ký hợp pháp) rồi trình ra như thể là cert LOCK. Phone nhận nó là khóa → kẻ đó giả thành khóa cửa được. Hoặc ngược lại, dùng cert khóa để đóng vai điện thoại mở cửa khóa khác |
| `key_usage` | Chữ ký handshake và chữ ký cấp cert lẫn lộn | Một cert thường (leaf) bị dùng để ký ra cert khác, tức là leaf tự biến thành CA. Đây là kiểu lỗi đã từng xảy ra thật ở trình duyệt web, nơi người ta ký được chứng chỉ giả chỉ vì cờ CA không được kiểm tra |
| `subject_id` | Không gắn được danh tính vào khóa | Phone không biết cert này của khóa nào để so với khóa mà người dùng đã thiết lập ban đầu |
| `issuer_key_id` | Phải thử tất cả root/CA để tìm cái ký | Chậm và mơ hồ khi có nhiều root hoặc đang xoay khóa |
| `not_before / not_after` | Cert sống mãi | Phone bị trộm hoặc nhân viên cũ vẫn dùng được cert cũ vô thời hạn |
| `subject_pub` nằm trong phần được ký | Ai đó tráo public key | Cert hợp lệ nhưng key bị thay → toàn bộ ý nghĩa của cert mất |

### Cảnh báo về thời hạn
Khóa cửa thường không có đồng hồ tin cậy (không có RTC có pin, không có Internet để đồng bộ). Nếu để khóa kiểm tra `not_after` dựa trên đồng hồ do chính điện thoại gửi sang, kẻ tấn công chỉ cần nói dối về giờ. Vì thế đặc tả quy định: **khóa bỏ qua kiểm tra hết hạn**, còn việc chặn một điện thoại cụ thể dựa vào ACL/danh sách thu hồi do app quản lý. Đây là điểm yếu có chủ ý và được ghi rõ: nếu khóa chưa được cập nhật danh sách thu hồi (mất kết nối), phone đã bị thu hồi vẫn mở được cửa cho đến khi nó nhận được cập nhật. Cần quyết định riêng ở mục "ngoài phạm vi".

### Quy tắc "phone ghim serial"
Phone phải so `subject_id` của cert khóa với serial đã lưu lúc setup (qua QR hoặc lần ghép đầu tiên). Nếu không so, mọi cert LOCK hợp lệ do chính hãng cấp đều được chấp nhận. Kẻ tấn công mua một khóa chính hãng khác, mang đến đặt cạnh cửa nhà nạn nhân, và app của nạn nhân vui vẻ nói chuyện với nó. Với kịch bản này, nếu app có thể bị lừa hiển thị "đã kết nối" rồi "đã mở", thì người dùng dễ nhầm lẫn và gây ra hành vi nguy hiểm khác. Ghim serial buộc app chỉ tin **đúng khóa của mình**.

---

## 5. Hello và `suite_id` không thương lượng: chống downgrade

### Kỹ thuật tấn công: downgrade
Nhiều giao thức cho phép hai bên "thương lượng" thuật toán, và kẻ A2 ép hai bên dùng phiên bản yếu nhất. Ví dụ lịch sử: POODLE, FREAK, Logjam trên TLS. Chúng thành công vì việc thương lượng không được xác thực.

### Thiết kế
- Chỉ có **một bộ thuật toán** (0x0001). Không có danh sách để chọn, không có đường lùi.
- `suite_id` và version nằm trong ClientHello/ServerHello, mà hai message này đi vào **transcript** được ký. Nếu kẻ tấn công sửa `suite_id`, chữ ký sẽ không còn khớp.
- Muốn nâng cấp thuật toán sau này (ví dụ hậu lượng tử), phát hành `suite_id` mới trong version mới, và thiết bị mới có thể từ chối suite cũ.

### Rủi ro còn lại
Một thiết bị đã bán ra mà chỉ hỗ trợ suite 0x0001 sẽ phải sống với nó đến hết vòng đời, trừ khi có OTA. Đây là lý do secure boot và OTA có ký là bắt buộc, không phải tùy chọn.

---

## 6. ECDH ephemeral: forward secrecy

### Câu hỏi
Tại sao không đơn giản dùng khóa dài hạn của hai bên để tính ra khóa phiên?

### Kịch bản A7 (ghi bây giờ, giải mã sau)
Giả sử khóa phiên suy ra từ khóa dài hạn. Kẻ tấn công ghi lại 3 năm lưu lượng. Một ngày khóa dài hạn của khóa cửa bị lộ (ví dụ bị đọc từ một thiết bị cũ bị vứt đi). Kẻ đó giải mã **toàn bộ** quá khứ: ai ra vào lúc nào, các lệnh đã gửi, mọi thứ.

### Với ephemeral
Mỗi phiên sinh cặp X25519 mới, dùng xong **hủy private key**. Sau khi phiên kết thúc, không ai, kể cả chủ thiết bị, còn khả năng dựng lại khóa phiên đó. Lộ khóa dài hạn chỉ cho phép giả mạo từ lúc đó trở đi, không giải mã được quá khứ. Đó là forward secrecy.

### Tại sao tách vai trò: ECDSA để xác thực, X25519 để trao đổi khóa
Khóa ký dài hạn thì cần "đứng yên" (để cert gắn vào). Khóa trao đổi thì cần "dùng một lần". Gộp hai việc vào một khóa là phá đi một trong hai tính chất.

### Kiểm tra điểm X25519 yếu
Một số public key X25519 đặc biệt (điểm bậc thấp) khiến kết quả ECDH luôn bằng 0 hoặc một giá trị cố định, bất kể private key của bên kia là gì. Kẻ A2 có thể gửi một điểm như vậy để **ép khóa chung thành giá trị biết trước**. Biện pháp: kiểm tra kết quả ECDH khác toàn 0 và từ chối nếu không. Bỏ bước này thì kẻ tấn công có thể biết trước khóa phiên mà không cần private key nào.

### Rủi ro còn lại
Forward secrecy chỉ bảo vệ **bí mật** của dữ liệu cũ, không chống được việc kẻ đó giả mạo từ giờ trở đi. Ngoài ra nó phụ thuộc vào việc private key ephemeral thật sự được xóa khỏi RAM (xem mục 12 về zeroize).

---

## 7. Nonce (hai bên đều đóng góp ngẫu nhiên)

### Vai trò
Mỗi bên gửi 32 byte ngẫu nhiên trong hello. Chúng được đưa vào `salt` của HKDF và vào transcript.

### Nếu không có nonce, kẻ A3 làm gì
Nếu một bên dùng lại ephemeral key (do lỗi cài đặt, do RNG kém, hoặc vì muốn tối ưu tốc độ), khóa phiên sẽ giống hệt nhau giữa các phiên. Kẻ tấn công ghi lại một phiên cũ rồi phát lại một bên của nó. Có nonce của **đối phương** làm đầu vào thì mỗi phiên đều khác nhau ngay cả khi một bên lặp lại ephemeral key.

### Lưu ý trung thực
Khi cả hai bên đều dùng ephemeral key mới thật sự, nonce là lớp bảo vệ dự phòng (defense in depth), không phải lớp duy nhất. Nhưng trên thiết bị nhúng RNG có thể lỗi, lỗi cài đặt có thể xảy ra, và chi phí của nonce chỉ 64 byte. Đây là khoản bảo hiểm rẻ.

### Tại sao nonce của khóa phải đến **sau** khi nhận ClientHello
Nếu khóa sinh ephemeral ngay khi có kết nối (trước khi có hello hợp lệ), kẻ A8 chỉ cần mở kết nối hàng loạt để buộc khóa tốn CPU, năng lượng, và dùng cạn TRNG. Đặc tả bắt khóa chỉ sinh sau khi hello hợp lệ.

---

## 8. Tại sao ký **transcript** thay vì ký từng nonce

Đây là phần thay đổi lớn nhất so với thiết kế ban đầu (11 bước), nên cần giải thích kỹ.

### Thiết kế cũ ký cái gì
- Bước 5: phone ký `(nonce phone + device id)`.
- Bước 6: khóa ký `(nonce khóa + mac + serial)`.
- Bước 7–8: mỗi bên ký `(ecdh pub + nonce phone + nonce khóa + id...)`.

Ý tưởng đúng hướng (có ràng buộc nonce và khóa trao đổi), nhưng có các điểm yếu mà một giao thức đã có tên tuổi đều từng vấp phải.

### Tấn công 1: chữ ký không bao phủ đủ → ghép nối (mix-and-match)
Ở bước 5–6, chữ ký chỉ bao phủ một phần dữ liệu. Kẻ A2 lấy chữ ký hợp lệ từ phiên này ghép với dữ liệu phiên khác. Nếu chữ ký không gắn với **mọi thứ đã trao đổi trước đó**, hai bên có thể đang có cái nhìn khác nhau về cuộc trao đổi mà vẫn kết luận "xác thực thành công". Cách đúng là ký **hash của toàn bộ những gì đã xảy ra** (transcript hash).

### Tấn công 2: Unknown Key-Share (UKS)
Kẻ tấn công làm cho Phone nghĩ nó đang nói chuyện với Khóa X, trong khi Khóa X nghĩ nó đang nói chuyện với kẻ tấn công (hoặc phone khác), dù không ai giải mã được nội dung. Với khóa cửa điều này nguy hiểm: log "ai mở cửa" bị sai, hoặc quyền bị gán sai người. Ký transcript có chứa **cả hai cert** (nghĩa là cả hai danh tính) chặn được vì mỗi bên ký một thứ bao gồm danh tính của bên kia.

### Tấn công 3: Reflection (phản xạ)
Nếu hai bên dùng cùng khóa/cùng định dạng chữ ký, kẻ A2 có thể lấy chính message mà khóa vừa gửi và ném ngược lại cho khóa như thể là từ phone. Biện pháp: **label khác nhau cho mỗi vai trò** (`"LKP1-SIG-SERVER"` vs `"LKP1-SIG-CLIENT"`) và khóa riêng cho mỗi chiều (mục 10). Chữ ký server không thể bị dùng như chữ ký client.

### Tấn công 4: Cross-protocol / chữ ký bị dùng lại ở chỗ khác
Nếu khóa ECDSA này còn ký những thứ khác (ví dụ ký firmware, ký token), kẻ tấn công lừa nó ký một dữ liệu trông giống một transcript. Tiền tố label cố định + byte `0x00` tách riêng không gian chữ ký của handshake.

### Tại sao giảm từ 11 bước còn 3 flight
Mỗi flight trong BLE là một vòng đi-về, tốn thời gian (connection interval thường 15–50 ms, và mỗi gói đều có thể phải phân mảnh). Thiết kế cũ có các bước ký lặp lại: bước 5–6 ký để chứng minh "tôi sống" (liveness) và bước 7–8 ký lại để gắn ECDH. Một chữ ký trên transcript đã chứa cả hai việc. Số vòng giảm không chỉ để nhanh mà còn **giảm bề mặt tấn công**: ít trạng thái trung gian để kẻ tấn công thao túng, ít code phải viết đúng trên MCU.

---

## 9. Mã hóa cert bằng khóa handshake: quyền riêng tư của danh tính

### Vấn đề
Cert chứa `device_id` của phone và serial của khóa. Nếu gửi rõ, kẻ A1 chỉ cần sniffer là biết **chính xác ai đang mở cửa nào, lúc nào**. Với khóa cửa nhà ở, đây là dữ liệu cá nhân nhạy cảm (liên quan GDPR ở EU: thói quen ra vào nhà là dữ liệu cá nhân). Cũng cho phép theo dõi một người qua nhiều khóa cửa khác nhau (tracking).

### Thiết kế (kiểu SIGMA-I)
Sau khi có ECDH, hai bên dùng khóa handshake để mã hóa Certificate. Server gửi cert **trước** và phone chỉ gửi cert của mình **sau khi đã xác thực được server**.

### Hệ quả thực tế (nói thẳng)
- Kẻ nghe lén thụ động **không thấy** cert của cả hai bên.
- Kẻ tấn công chủ động có thể kết nối giả làm phone và **vẫn thấy cert của khóa** (vì phone ẩn danh lúc đầu chưa được xác thực). Cert của khóa không bí mật cao, vì serial thường in sẵn trên vỏ. Còn danh tính phone chỉ lộ cho ai **đã được khóa thật xác thực**, đây mới là phần quan trọng.
- Địa chỉ MAC BLE vẫn lộ ở tầng link. Android hỗ trợ địa chỉ ngẫu nhiên nên không nên dùng MAC làm danh tính bảo mật. Đặc tả dùng serial/device_id trong cert thay cho MAC. MAC chỉ là thông tin phụ, dễ giả mạo, và nếu bị dùng để ra quyết định thì kẻ A5 chỉ cần đổi địa chỉ.

---

## 10. Finished (HMAC) và xác nhận khóa

### Tại sao chữ ký chưa đủ
Chữ ký chứng minh "người này giữ private key và đã đồng ý với transcript đến đây". Nó **không chứng minh** hai bên đã tính ra cùng một khóa phiên. Có thể hai bên đồng ý về transcript nhưng khóa suy ra khác nhau vì lỗi hoặc vì bị thao túng. Finished là HMAC của transcript, tính bằng khóa suy ra từ ECDH, nên khi nó khớp thì cả hai chứng minh được: (1) đã tính đúng ECDH, (2) cùng thấy cùng một transcript.

### Nếu bỏ Finished
- Lỗi lệch khóa chỉ lộ ra lúc gửi lệnh đầu tiên (gây trải nghiệm tệ, khó debug).
- Kẻ tấn công có thể thao túng các message sau chữ ký mà không bị phát hiện ngay. Đặc biệt các phần nằm sau M3 (do sig_S chỉ bao đến M3).
- Mất bằng chứng rằng **chính đối phương đang sống** và biết khóa phiên (key confirmation), điều cần để tránh "nửa kết nối" (một bên tin phiên đã mở, bên kia thì không).

### Constant-time compare
So sánh HMAC bằng `memcmp` thông thường dừng ở byte khác đầu tiên. Kẻ tấn công đo thời gian phản hồi và đoán từng byte một (timing attack). Với MCU nhúng, đo qua BLE khó hơn nhưng vẫn khả thi nếu lặp đủ nhiều lần. Dùng hàm so sánh thời gian cố định, không tốn gì thêm.

---

## 11. HKDF và tách khóa

### Tại sao không dùng thẳng kết quả ECDH làm khóa AES
- Kết quả X25519 **không phải** chuỗi ngẫu nhiên đồng đều, nó có cấu trúc đại số. Phải qua KDF để thành khóa đúng nghĩa.
- Một khóa ECDH phải sinh ra nhiều khóa: khóa handshake, khóa Finished, khóa hai chiều, session id. HKDF với `label` khác nhau cho các khóa độc lập về mặt mật mã, nên lộ một khóa không kéo theo các khóa khác.

### Tại sao ctx chứa transcript hash
Khóa được suy ra **từ cả transcript**. Nếu kẻ A2 thay đổi bất kỳ message nào, hai bên sẽ ra hai bộ khóa hoàn toàn khác nhau và mọi thứ hỏng ngay (fail-safe).

### Tại sao khóa riêng cho từng chiều (c2s, s2c)
- Nếu dùng chung một khóa cho cả hai chiều và mỗi bên có counter riêng bắt đầu từ 0, hai chiều sẽ **dùng cùng (key, nonce)** → thảm họa với AES-GCM (xem mục 12).
- Reflection: kẻ tấn công ném lại gói của khóa cho chính khóa. Nếu cùng khóa, gói đó giải mã hợp lệ. Với khóa riêng mỗi chiều, tag không khớp.

### Về "IV sinh bằng HKDF" trong thiết kế cũ
Tạo IV tĩnh bằng HKDF là ổn nếu dùng nó làm **mặt nạ** XOR với counter. Sai lầm hay gặp là dùng nguyên IV đó cho mọi bản tin, điều này lặp lại nonce. Thiết kế mới chỉ dùng IV tĩnh như vậy và mọi nonce thực tế là `IV ⊕ counter`.

---

## 12. AES-GCM: sức mạnh lớn, kỷ luật nghiêm

### Quy tắc sống còn: **không bao giờ lặp (key, nonce)**
AES-GCM bẻ gãy hoàn toàn nếu hai bản tin khác nhau dùng cùng một (key, nonce):
- XOR hai ciphertext ra XOR hai plaintext (lộ nội dung nếu biết một bên).
- Kẻ tấn công **khôi phục được khóa xác thực GHASH**, từ đó giả mạo tag cho bất kỳ bản tin nào (forgery), tức là tự tạo lệnh "mở cửa" hợp lệ.

Đây là cách thất bại tệ nhất có thể có, nên thiết kế dùng **counter đơn điệu** thay vì nonce ngẫu nhiên. Nonce ngẫu nhiên 96-bit có xác suất va chạm đáng kể sau lượng bản tin lớn, và trên MCU RNG có thể lỗi. Counter không bao giờ lặp trong một phiên, và khóa mới mỗi phiên nên không lặp giữa các phiên.

### Giới hạn
Counter 32-bit trong `seq`: khi đến 0xFFFFFFFF thì đóng phiên và bắt tay lại. Phiên không resume. Mỗi kết nối là handshake mới, loại bỏ cả một lớp lỗi quản lý trạng thái phiên cũ.

### AAD: gắn bản tin vào ngữ cảnh
AAD gồm header + session_id + seq. Hệ quả:
- Sửa header (đổi loại record, đổi độ dài) → tag sai.
- Kẻ A3 lấy gói từ phiên khác sang phiên này → session_id khác → tag sai.
- Sửa seq mà không sửa ciphertext → counter dùng cho nonce thay đổi → tag sai.

### Chống phát lại và sắp xếp lại
Bên nhận yêu cầu `seq == expected` chính xác. BLE có thứ tự và đáng tin cậy ở tầng link, nên bất kỳ sai lệch nào (trùng, nhảy cóc, đảo thứ tự) là dấu hiệu bị can thiệp, hủy phiên. Nếu để chấp nhận một cửa sổ (như DTLS), kẻ tấn công được thêm không gian thao túng mà BLE không cần.

### Kích thước tag
Giữ đủ **16 byte**. Cắt tag xuống 4–8 byte để tiết kiệm băng thông (rất hấp dẫn trên BLE) làm giảm hẳn độ khó giả mạo và đặc biệt nguy hiểm với GCM. Overhead 28 byte trên khung 247 byte là chấp nhận được.

### Zeroize
Sau handshake xóa: `ss`, PRK, khóa handshake, khóa Finished, private key ephemeral. Nếu để lại trong RAM, kẻ A6 dùng dump bộ nhớ (hoặc một lỗi bộ nhớ khác trong firmware) lấy được và phá cả forward secrecy lẫn bí mật phiên. Lưu ý: trình biên dịch có thể loại bỏ `memset` "vô ích", phải dùng hàm xóa an toàn (`mbedtls_platform_zeroize`, `explicit_bzero`, hoặc API PSA tương ứng).

### Hiện thực: không tự chế primitive
Mọi lỗ hổng nghiêm trọng của mật mã thực tế phần lớn đến từ **cách dùng**, không phải từ thuật toán. Vì vậy đặc tả cấm tự viết AES/ECDSA/X25519 và yêu cầu dùng PSA Crypto/CryptoCell, JCA/BouncyCastle/Tink.

---

## 13. Framing, timeout, trạng thái, DoS

### Giới hạn độ dài (`MAX_BODY_LEN`)
Nếu giao thức tin trường `body_len` do đối phương gửi rồi cấp phát bộ nhớ theo nó: kẻ A8 gửi `body_len = 65535` hàng loạt → cạn RAM của MCU (chỉ có 256 KB). Tệ hơn: sai sót kiểm tra biên dẫn đến **buffer overflow** → thực thi mã từ xa. Quy tắc: buffer tĩnh kích thước cố định, kiểm tra mọi độ dài **trước** khi parse hoặc copy, không bao giờ cấp phát động theo giá trị từ đối phương.

### Timeout giữa các fragment (5 s) và timeout handshake (10 s)
Kiểu tấn công slowloris: mở kết nối, gửi 1 byte mỗi vài giây, giữ khóa bận mãi. Vì chỉ cho **một** kết nối/handshake tại một thời điểm (để tiết kiệm RAM và đơn giản hóa), một kẻ giữ chỗ làm chủ nhà không vào được nhà. Timeout cắt kiểu tấn công này.

### State machine nghiêm ngặt
Mỗi trạng thái chỉ chấp nhận đúng một (hoặc rất ít) loại message. Nếu nhận Finished trong khi chưa có ServerHello thì hủy. Parser thoải mái ("cứ nhận gì xử lý nấy") là nguồn lỗi logic kinh điển. Tiêu biểu là các lỗi bypass xác thực trên TLS, nơi server tiếp tục khi bước xác thực bị bỏ qua.

### Backoff sau khi thất bại và sự đánh đổi
Backoff lũy tiến ngăn kẻ tấn công thử vô hạn (brute-force) và tiết kiệm pin. Nhưng cần nói thẳng: **chính backoff cũng là vũ khí DoS** nếu áp dụng toàn cục. Kẻ A8 cố tình gây 3 lỗi liên tiếp, sau đó chủ nhà bị khóa 60 s ngoài cửa. Cân nhắc:
- Backoff theo "nguồn" (địa chỉ BLE) hiệu quả thấp vì địa chỉ ngẫu nhiên đổi được.
- Không backoff thì dễ bị brute-force/cạn tài nguyên.
- Phương án an toàn hơn: handshake thất bại **ở bước xác thực** (sau khi cert đã được kiểm tra) đáng tin cậy hơn các lỗi sớm, nên chỉ tăng backoff mạnh cho nhóm lỗi sau; lỗi sớm (hello sai) thì rẻ để từ chối và không đếm vào ngưỡng khóa. Và cần có đường vào dự phòng cơ học (chìa khóa vật lý, mã PIN bàn phím) để chủ nhà không bị khóa ngoài. Thiết bị khóa cửa luôn phải có **phương án dự phòng** cho cả lỗi bảo mật lẫn lỗi điện.

---

## 14. ALERT không rò thông tin

### Tấn công: oracle
Nếu khóa trả lời khác nhau cho "chữ ký sai" và "cert hết hạn" và "cert sai root", kẻ tấn công dùng chênh lệch này để dò dần hệ thống (ví dụ: xác định xem một device_id có nằm trong danh sách cho phép không, hay thử các biến thể cert để tìm điểm yếu trong bộ kiểm tra). Padding oracle là ví dụ kinh điển trong TLS/CBC, và các "bleichenbacher" oracle trong RSA. Chỉ cần một bit thông tin rò rỉ là đủ cho các cuộc tấn công thích ứng.

### Thiết kế
ALERT chỉ có 3 giá trị thô (`protocol`, `auth`, `busy`), không chi tiết nguyên nhân. Log chi tiết giữ nội bộ, và **log không bao giờ chứa khóa**. Lưu ý cả thời gian phản hồi cũng là kênh rò rỉ: đường xử lý lỗi nên mất thời gian xấp xỉ nhau.

---

## 15. RNG và chữ ký ECDSA: điểm yếu chết người trên MCU

- **ECDSA nonce:** nếu hai chữ ký dùng cùng (hoặc nonce có thể đoán được/lệch thống kê) thì **lộ luôn private key** (vụ PS3 là ví dụ nổi tiếng; các lỗi nonce yếu trên một số ví tiền mã hóa cũng vậy). Dùng RFC 6979 (nonce tất định từ khóa và thông điệp) hoặc DRBG của thư viện đã kiểm chứng.
- **RNG khởi động:** trên MCU, ngay sau khi bật nguồn entropy có thể yếu nếu dùng nguồn không phải phần cứng. Phải dùng TRNG của CryptoCell, không dùng `rand()` hoặc seed theo thời gian.
- **Android:** `SecureRandom`, không dùng `java.util.Random`.
- Hệ quả của RNG yếu lan sang: ephemeral key đoán được → mất forward secrecy; nonce handshake đoán được → mất bảo vệ replay.

---

## 16. Điều giao thức **không** giải quyết được: relay và các hạn chế còn lại

Đây là phần quan trọng nhất cho sản phẩm khóa cửa, và phải nói thẳng.

### Relay attack (A4)
Kẻ tấn công không cần phá mật mã. Hai thiết bị relay chuyển tiếp **nguyên văn** gói BLE giữa điện thoại thật (ở xa, trong túi nạn nhân) và khóa thật. Mọi chữ ký, cert, AES-GCM đều hợp lệ vì đều do hai thiết bị thật tạo ra. Kẻ tấn công chỉ là một "dây dẫn dài". Các nghiên cứu công khai đã chứng minh tấn công relay trên khóa BLE của xe và khóa cửa thương mại, ngay cả khi mã hóa đúng chuẩn.

LKP1 **không chống được** điều này, vì xác thực chỉ chứng minh "đúng thiết bị", không chứng minh "thiết bị đang ở gần". Các lớp giảm thiểu cần đặt thêm:
1. **Ý định người dùng:** chỉ mở khi có hành động vật lý (chạm tay cầm, bấm nút, vặn núm), không mở tự động khi lại gần. Giảm mạnh nhất rủi ro vì relay không giả được hành động tại cửa.
2. **Đo khoảng cách:** UWB (ranging), hoặc ít nhất là kiểm tra RSSI/độ trễ khứ hồi bất thường (kém tin cậy hơn, vì RSSI bị giả được).
3. **Giới hạn thời gian:** thông điệp lệnh có cửa sổ hợp lệ ngắn, phản hồi thử thách-đáp ứng nhanh.
4. Chế độ "chủ động mở" từ app thay vì "tự động mở khi tới gần".

### Danh sách các rủi ro còn lại (đã biết, cần quyết định riêng)
| Rủi ro | Giải thích | Hướng xử lý |
|---|---|---|
| Điện thoại bị trộm/mã độc | Có thể dùng khóa trong Keystore để ký khi app còn chạy | Yêu cầu xác thực sinh trắc/PIN cho mỗi lần ký, ACL có thu hồi |
| Thu hồi chậm | Khóa không có Internet/đồng hồ | Danh sách thu hồi đẩy qua app, thời hạn ngắn cho quyền |
| Firmware bị sửa/hạ cấp | Mất toàn bộ bảo đảm | Secure boot, chữ ký OTA, chống rollback |
| Cổng debug mở | Đọc khóa, sửa root pin | APPROTECT, khóa debug khi sản xuất |
| Tấn công vật lý nâng cao | Fault injection, side-channel (DPA) | Secure element chuyên dụng |
| Root CA bị lộ | Toàn bộ chuỗi tin cậy sụp đổ | HSM, quy trình ký có kiểm soát, kế hoạch xoay root |
| Pairing lần đầu (ghim serial) | Nếu bước này bị MITM thì mọi thứ sau sai | QR in trên thiết bị hoặc kênh ngoài băng (out-of-band) |
| Lỗi stack Bluetooth của OS | Ngoài tầm kiểm soát | Thiết kế để vẫn an toàn khi tầng link bị phá |

---

## 17. Bảng tra ngược: bước → tấn công nếu thiếu → biện pháp

| Thành phần | Nếu thiếu, kẻ tấn công làm gì | Ghi chú |
|---|---|---|
| Xác thực ở tầng ứng dụng (không tin Just Works) | MITM (A2), thiết bị giả (A5) | BLE chỉ là đường truyền không tin cậy |
| Root of Trust pinned | Tự sinh khóa tự xưng là khóa chính hãng | Root offline, hỗ trợ xoay |
| Issuing CA | Lộ một khóa ký = mất cả sản phẩm | Phân tầng để giới hạn thiệt hại |
| Khóa riêng mỗi thiết bị | Một thiết bị bị mổ = lộ toàn dòng sản phẩm | Yêu cầu của EN 303 645 / RED |
| `cert_type` | Dùng cert phone như cert lock (nhầm vai trò) | Kiểm tra theo vai trò |
| `key_usage` | Leaf thành CA | Kiểm tra cờ |
| Ghim serial ở phone | Kết nối nhầm khóa chính hãng khác | Lúc setup |
| `suite_id` cố định + nằm trong transcript | Downgrade | Một suite duy nhất |
| ECDH ephemeral | Lộ khóa dài hạn → giải mã quá khứ (A7) | Forward secrecy |
| Kiểm tra điểm X25519 yếu | Ép khóa chung biết trước | Từ chối ss toàn 0 |
| Nonce hai bên | Replay khi ephemeral bị lặp | Lớp dự phòng |
| Ký **transcript** | Mix-and-match, UKS, thay đổi tham số | Thay cho chữ ký từng mảnh |
| Label khác nhau theo vai trò | Reflection, cross-protocol | Tách không gian chữ ký |
| Mã hóa cert | Lộ danh tính, theo dõi người dùng | Chủ yếu chống nghe lén thụ động |
| Finished (HMAC) | Không có key confirmation, lệch khóa mà không biết | So sánh constant-time |
| HKDF + transcript trong ctx | Khóa không độc lập, không gắn với phiên | Mọi khóa có label riêng |
| Khóa riêng mỗi chiều | Lặp (key, nonce), reflection | Bắt buộc với GCM |
| Counter thay vì nonce ngẫu nhiên | Va chạm nonce → mất khóa xác thực GCM | `IV ⊕ counter` |
| AAD (header, session_id, seq) | Sửa header, trộn gói giữa các phiên | Gắn ngữ cảnh |
| `seq` đúng chính xác | Replay, đảo thứ tự, mất gói không phát hiện | BLE có thứ tự nên không cần cửa sổ |
| Tag 16 byte | Giả mạo tag bằng đoán | Không cắt ngắn |
| Zeroize | Dump RAM lộ khóa, mất forward secrecy | Dùng hàm xóa không bị tối ưu bỏ |
| Giới hạn độ dài + buffer tĩnh | Cạn RAM, overflow, RCE | Kiểm tra biên trước khi parse |
| Timeout fragment/handshake | Slowloris giữ kết nối | Chỉ 1 kết nối nên rất dễ bị khóa |
| State machine chặt | Bypass xác thực do parser dễ dãi | Từ chối mọi thứ lệch thứ tự |
| ALERT thô | Oracle dò thông tin | Log chi tiết chỉ nội bộ |
| TRNG + nonce ECDSA an toàn | Lộ private key, đoán ephemeral | RFC 6979 / DRBG |
| **Ý định người dùng / đo khoảng cách** | **Relay (A4)** | **Giao thức không tự giải quyết được** |

---

## 18. Kết luận

Cách đọc đúng bảng trên: **mỗi thành phần là câu trả lời cho một cuộc tấn công đã từng xảy ra ở giao thức khác.** Không có thành phần nào là trang trí.

Nhưng một giao thức đúng không biến sản phẩm thành an toàn. Ba điều cần nhớ khi đưa vào sản phẩm thương mại:
1. **Cài đặt sai thì giao thức đúng cũng vô ích.** Đa số sự cố thực tế đến từ nonce lặp, RNG yếu, so sánh không constant-time, thiếu kiểm tra biên. Vì vậy test vector chéo ba nền tảng và test âm là bắt buộc.
2. **Giao thức chỉ là một lớp.** Secure boot, bảo vệ debug, OTA có ký, quản lý thu hồi, quy trình xử lý lỗ hổng cũng quan trọng không kém, và nằm trong yêu cầu của RED/EN 18031, EN 303 645, CRA.
3. **Relay là rủi ro thật của khóa cửa BLE** và cần giảm thiểu bằng thiết kế sản phẩm (ý định người dùng, UWB), không phải bằng thêm mật mã.

Trước khi phát hành, nên có một đợt **review độc lập** (pentest, hoặc ít nhất một chuyên gia mật mã ngoài nhóm) và gap analysis với phòng lab/notified body. Tài liệu này không thay thế các bước đó.
