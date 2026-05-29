# SHA-1 Migration Fix Guide

## Problem
After updating project to use SHA-1 (instead of SHA-256), grade encryption fails:
```
❌ Cặp khóa SHA-1 hiện tại hoàn toàn lệch pha với dữ liệu điểm thi lưu trong database
```

## Root Cause
1. **Old Private Key** (SHA-256) stored in `localStorage` from previous sessions
2. **Old Public Key** (SHA-256) saved in database `NHANVIEN.PUBKEY_CLIENT`
3. **Old Grade Data** (BANGDIEM) encrypted with old SHA-256 public key
4. New login generates **new SHA-1 key pair** → old data incompatible

## Solution: 3-Step Fix

### Step 1: Clear Old Private Key (Automatic)
- ✅ **DONE** - Code now validates key version automatically
- When you call `loadPrivateKey()`, it checks version:
  - If old (SHA-256): automatically deletes it
  - Shows: "⚠️ Key cũ SHA-256 đã bị xóa"

### Step 2: Logout and Login Again
```
1. Click "Đăng xuất" (Logout)
   → Calls ClientCrypto.clearPrivateKey() 
   → Removes key from localStorage
   
2. Click "Đăng nhập" (Login)
   → Submits credentials (MÃ NV + password with SHA-1 hash)
   → Server validates
   → On success: generateKeyPair() creates NEW RSA-2048 key pair (SHA-1 configured)
   → savePrivateKey() stores with version '1.0_SHA1'
   → Dashboard shows: "✔ Phiên bản: SHA-1 (v1.0)"
```

### Step 3: Clean Database of Old Encrypted Data
Execute: `sql/04_cleanup_old_data.sql`

```sql
DELETE FROM BANGDIEM;              -- Removes old encrypted grades
UPDATE NHANVIEN SET PUBKEY_CLIENT = NULL;  -- Clears old public keys
```

## After Fix: Test Flow

### 1. View Dashboard
- URL: `/dashboard`
- Should show: "✔ Private Key đã có trong localStorage" + "✔ Phiên bản: SHA-1 (v1.0)"

### 2. Add New Grade (Encryption)
- URL: `/bangdiem`
- Tab: "Nhập điểm"
- Fill: MÃ SV, MÃ HP, Điểm
- Submit: "Mã hóa & Thêm"
- Internal process:
  1. Fetch Public Key from server (`/api/pubkey/{manv}`)
  2. Import Public Key with SHA-1 config
  3. Encrypt grade using RSA-OAEP (SHA-1)
  4. POST ciphertext to `/bangdiem/nhap`
  5. Server stores ciphertext in BANGDIEM.DIEMTHI

### 3. View Grades (Decryption)
- URL: `/bangdiem`
- Tab: "Xem điểm"
- Click: "Xem điểm"
- Internal process:
  1. Fetch encrypted grades from `/api/bangdiem/{masv}`
  2. Load Private Key from localStorage (`lab04_privateKey`)
  3. Import Private Key with SHA-1 config
  4. Decrypt each ciphertext using RSA-OAEP (SHA-1)
  5. Display plaintext grade

## Key Configuration (SHA-1 throughout)

All 5 templates updated to use **SHA-1**:

| File | Component | Hash Algorithm |
|------|-----------|-----------------|
| `login.html` | Password hash | SHA-1 |
| `login.html` | Key pair generation | RSA-2048 + SHA-1 |
| `base.html` | `hashPassword()` | SHA-1 |
| `base.html` | `generateKeyPair()` | RSA-2048 + SHA-1 |
| `base.html` | `importPublicKey()` | RSA-2048 + SHA-1 |
| `base.html` | `importPrivateKey()` | RSA-2048 + SHA-1 |
| All templates | Encryption/Decryption | RSA-OAEP + SHA-1 |

SQL Server stored procedures:
- Hash comparison: `MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2)` (hex binary compare)
- Base64 retrieval: `CONVERT(VARCHAR(MAX), LUONG)` (no hex conversion)

## Verification Checklist

- [ ] Logout and login
- [ ] Dashboard shows key version "SHA-1 (v1.0)"
- [ ] Run cleanup SQL: `04_cleanup_old_data.sql`
- [ ] Enter new grade (encryption works)
- [ ] View grades (decryption works)
- [ ] Try salary decryption (nhanvien.html)

## Troubleshooting

**"Private Key không có trong localStorage"**
- Reason: Auto-deleted old SHA-256 key
- Fix: Logout → Login again

**"Cặp khóa lệch pha với dữ liệu"**
- Reason: Old encrypted data from before migration
- Fix: Execute `04_cleanup_old_data.sql` to delete old grades

**"Không giải mã được"**
- If new data: Check Private Key version (Dashboard)
- If old data: Old data incompatible, must delete or re-encrypt

---

**Summary**: Code now auto-validates key versions and cleans up mismatched SHA-256 keys. After logout/login cycle and database cleanup, all SHA-1 operations should work correctly.
