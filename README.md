# Hybrid Mail Encryption (AES + RSA)

## 1. Giới thiệu

Ứng dụng minh họa **mã hóa lai (Hybrid Encryption)** cho e-mail, kết hợp hai loại khóa:

- **AES-256-GCM**: là khóa **đối xứng**, được sinh ngẫu nhiên cho mỗi lần gửi e-mail.  
  Khóa này dùng để **mã hóa toàn bộ nội dung thư và tệp đính kèm** vì có tốc độ nhanh, an toàn và cơ chế xác thực dữ liệu (GCM).  
  Tuy nhiên, khóa AES chỉ được sử dụng tạm thời và **không gửi trực tiếp qua mạng**.

- **RSA-3072 (RSA-OAEP + RSA-PSS)**: là khóa **bất đối xứng**, gồm hai phần: **khóa công khai** và **khóa riêng**.  
  - Với **RSA-OAEP (SHA-256)**: người gửi dùng **khóa công khai của người nhận** để **mã hóa (wrap)** khóa AES.  
    → Chỉ người nhận (với khóa riêng) mới có thể giải mã được khóa AES thật.  
  - Với **RSA-PSS (SHA-256)**: người gửi dùng **khóa riêng của mình** để **ký số** lên dữ liệu đã mã hóa,  
    giúp người nhận kiểm chứng **tính xác thực và toàn vẹn** của e-mail.  

Mục tiêu: đảm bảo **bí mật**, **toàn vẹn**, **xác thực** và **chống chối bỏ** trong truyền e-mail.

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
python gen_keys.py <file_name>
```
Kết quả tạo ra:
- 2 file: `<file_name>_priv.pem`, `<file_name>_pub.pem`
Người gửi cần tạo key cho cả mình và người nhận

### 3.2. Người gửi mã hóa e-mail
Người gửi dùng khóa riêng của mình và khóa công khai của người nhận để mã hóa:
```bash
python encrypt.py 
```
Nhập thông tin theo yêu cầu 
Kết quả: file envelope chứa dữ liệu đã mã hóa, có thể gửi qua e-mail.
### 3.. Người nhận giải mã e-mail
Người nhận dùng khóa riêng của mình để giải mã:
```bash
python decrypt.py 
```
Nhập thông tin theo yêu cầu
Kết quả:
- Thư mục `out_mail/` chứa message.txt và các file đính kèm.
- Chữ ký số được kiểm tra tự động: nếu nội dung bị thay đổi, giải mã sẽ thất bại.
