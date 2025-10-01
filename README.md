# Hybrid Mail Encryption (AES + RSA)

## 1. Giới thiệu
Ứng dụng minh họa **mã hóa lai (hybrid encryption)** cho e-mail:
- **AES-256-GCM**: mã hóa nội dung nhanh và an toàn.
- **RSA-OAEP (SHA-256)**: mã hóa khóa AES để phân phối an toàn cho người nhận.
- **RSA-PSS (SHA-256)**: chữ ký số xác thực người gửi, chống giả mạo.

Mục tiêu: bảo vệ **bí mật, toàn vẹn, xác thực và chống chối bỏ** trong e-mail.

---
## 2. Yêu cầu hệ thống
- Python 3.9+
- Thư viện `cryptography`:
  ```bash
  pip install cryptography
  ```
## 3. Quy trình sử dụng

### 3.1. Tạo cặp khóa RSA
Chạy lệnh sau để sinh khóa cho người gửi và người nhận:

```bash
python gen_keys.py
```
Kết quả tạo ra:
  -Người gửi: sender_priv.pem, sender_pub.pem
  -Người nhận: rcpt_priv.pem, rcpt_pub.pem
### 3.2. Người gửi mã hóa e-mail
Người gửi dùng khóa riêng của mình và khóa công khai của người nhận để mã hóa:
```bash
python encrypt.py \
  --sender-priv sender_priv.pem \
  --recipient-pub rcpt_pub.pem \
  --subject "Demo Hybrid" \
  --body "Xin chào, đây là nội dung test hybrid." \
  --attach "file1.pdf" "file2.png" \
  --out envelope.json
```
Kết quả: file envelope.json chứa dữ liệu đã mã hóa, có thể gửi qua e-mail.
### 3.. Người nhận giải mã e-mail
Người nhận dùng khóa riêng của mình để giải mã:
```bash
python decrypt.py \
  --recipient-priv rcpt_priv.pem \
  --in envelope.json \
  --out-dir out_mail
```
Kết quả:
  -Thư mục out_mail/ chứa message.txt và các file đính kèm.
  -Chữ ký số được kiểm tra tự động: nếu nội dung bị thay đổi, giải mã sẽ thất bại.
