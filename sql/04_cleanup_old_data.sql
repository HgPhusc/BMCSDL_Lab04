-- ============================================================
-- CLEANUP: X\u00d3a d\u1eef li\u1ec7u test c\u0169 (m\u00e3 h\u00f3a b\u1eb1ng SHA-256 c\u0169)
-- ============================================================
-- Sau khi c\u1eadp nh\u1eadt code th\u00e0nh SHA-1:
-- - Private Key c\u0169 (SHA-256) \u0111\u00e3 b\u1ecb x\u00f3a kh\u1ecfi localStorage
-- - Public Key c\u0169 (SHA-256) v\u1eabn c\u00f2n trong PUBKEY_CLIENT c\u1ee7a NHANVIEN
-- - D\u1eef li\u1ec7u m\u00e3 h\u00f3a c\u0169 \u00f4 BANGDIEM \u00f0\u01b0\u1ee3c m\u00e3 h\u00f3a b\u1eb1ng public key SHA-256
-- - Kh\u00f4ng th\u1ec3 gi\u1ea3i m\u00e3 b\u1eb1ng private key SHA-1 m\u1edbi
--
-- L\u1eddi: "C\u1eb6p kh\u00f3a SHA-1 hi\u1ec7n t\u1ea1i ho\u00e0n to\u00e0n l\u1ec7ch pha v\u1edbi d\u1eef li\u1ec7u"
--
-- SOLUTION: X\u00f3a d\u1eef li\u1ec7u test c\u0169 \u0111\u1ec3 b\u1eaft \u0111\u1ea7u t\u1ec9nh r\u1eafn

USE QLSVNhom;
GO

-- X\u00f3a t\u1ea5t c\u1ea3 grade (DIEMTHI) \u0111\u00e3 m\u00e3 h\u00f3a b\u1eb1ng public key c\u0169
DELETE FROM BANGDIEM;
PRINT N'\u2714 X\u00f3a t\u1ec7m th\u1eddi d\u1eef li\u1ec7u BANGDIEM (m\u00e3 h\u00f3a c\u0169)';

-- OPTIONAL: X\u00f3a PUBKEY_CLIENT c\u0169 (public key c\u0169) th\u00e0nh NULL
UPDATE NHANVIEN SET PUBKEY_CLIENT = NULL;
PRINT N'\u2714 X\u00f3a public key c\u0169 t\u1eeb NHANVIEN.PUBKEY_CLIENT';

-- OPTIONAL: X\u00f3a m\u00e3t kh\u1ea9u c\u0169 (\u0111\u00e3 hash b\u1eb1ng SHA-256)
-- CAUTION: N\u1ebfu x\u00f3a MATKHAU, user kh\u00f4ng \u0111\u0103ng nh\u1eadp l\u1ea1i \u0111\u01b0\u1ee3c!
-- UPDATE NHANVIEN SET MATKHAU = NULL;
-- PRINT N'\u2714 X\u00f3a m\u00e3t kh\u1ea9u c\u0169 (T\u1ef1 t\u00e0i lưu \u00fd!)';

-- Ki\u1ec3m tra k\u1ebft qu\u1ea3
SELECT COUNT(*) as DiemCount FROM BANGDIEM;
SELECT MANV, PUBKEY_CLIENT FROM NHANVIEN;
