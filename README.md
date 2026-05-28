# BÀI THỰC HÀNH SỐ 4 — Mã hóa tại CLIENT (Web Crypto API)
> Khoa CNTT · ĐH Khoa học Tự nhiên TP.HCM

---

## 🔑 Điểm khác biệt so với Lab 03

| | Lab 03 | Lab 04 |
|--|--------|--------|
| **Nơi mã hóa** | SQL Server (server-side) | Browser (client-side) |
| **Hàm mã hóa** | `EncryptByAsymKey()` | `Web Crypto API` |
| **Server thấy gì** | Plaintext rồi mã hóa | Chỉ nhận ciphertext |
| **Stored Procedure** | Thực hiện mã hóa | Chỉ lưu/trả dữ liệu |
| **Hash password** | `HASHBYTES('SHA1')` | `SHA-256` tại browser |

---

## 📁 Cấu trúc

```
lab04/
├── sql/
│   └── lab04_stored_procedures.sql
└── python_app/
    ├── app.py
    └── templates/lab04/
        ├── base.html        ← Chứa ClientCrypto (Web Crypto API)
        ├── login.html       ← SHA-256 hash password tại browser
        ├── dashboard.html   ← Hiển thị trạng thái Private Key
        ├── lop.html
        ├── sinhvien.html
        ├── bangdiem.html    ← RSA Encrypt/Decrypt tại browser
        └── nhanvien.html    ← Giải mã lương tại browser
```

---

## 🚀 Cách chạy

```bash
# Dùng lại DB từ Lab 03
# Chạy thêm: lab04_stored_procedures.sql

cd lab04/python_app
python app.py  # Chạy trên port 5001
```
Truy cập: **http://localhost:5001**

---

## 🔐 Luồng mã hóa CLIENT-SIDE

### Đăng nhập
```
Browser: SHA-256(password) → gửi hash lên server
Server: so sánh hash (KHÔNG biết password gốc)
```

### Thêm nhân viên
```
Browser:
  1. generateKeyPair() → RSA-OAEP 2048-bit
  2. encrypt(publicKey, luong) → ciphertext Base64
  3. SHA-256(password) → hash
  4. Gửi lên: {luong_enc, mk_hash, pubkey}
Server: INSERT thẳng, KHÔNG mã hóa thêm
```

### Nhập điểm
```
Browser:
  1. importPublicKey(pubkey từ session)
  2. encrypt(publicKey, diem) → ciphertext Base64
  3. Gửi: {masv, mahp, diem_enc}
Server: INSERT ciphertext vào BANGDIEM.DIEMTHI
```

### Xem điểm / lương
```
Server: trả về ciphertext Base64
Browser:
  1. loadPrivateKey() từ sessionStorage
  2. importPrivateKey(privKeyB64)
  3. decrypt(privateKey, ciphertext) → plaintext
  4. Hiển thị
```

---

## ⚠️ Nhận xét SQL Profiler (câu e)

Khi theo dõi thao tác nhập điểm trong SQL Profiler:
- Thấy: `EXEC SP_INS_BANGDIEM_CLIENT 'SV001','HP001','base64ciphertext...'`
- **Không thấy** câu lệnh `EncryptByAsymKey` vì mã hóa đã xảy ra ở browser
- Dữ liệu gửi lên server **đã là ciphertext** — server chỉ INSERT thẳng
- Đây là điểm **bảo mật cao hơn Lab 03**: ngay cả DBA theo dõi traffic cũng chỉ thấy ciphertext
