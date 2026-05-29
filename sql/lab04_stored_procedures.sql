-- ============================================================
-- BÀI THỰC HÀNH SỐ 4
-- Mã hóa từ CLIENT trước khi lưu xuống CSDL
-- Giải mã ở CLIENT sau khi truy vấn
-- Sử dụng lại CSDL QLSVNhom từ Lab 03
-- ============================================================

USE QLSVNhom;
GO

-- ============================================================
-- Thêm cột PUBKEY vào NHANVIEN nếu chưa có (lưu Public Key từ client)
-- Lab04: PUBKEY lưu nội dung khóa công khai (Base64) thay vì tên key
-- ============================================================
IF NOT EXISTS (
    SELECT 1 FROM sys.columns 
    WHERE object_id = OBJECT_ID('NHANVIEN') AND name = 'PUBKEY_CLIENT'
)
BEGIN
    ALTER TABLE NHANVIEN ADD PUBKEY_CLIENT NVARCHAR(MAX);
    PRINT N'✔ Thêm cột PUBKEY_CLIENT vào NHANVIEN';
END
GO

-- ============================================================
-- BƯỚC 2: Thêm cột ROLE nếu chưa có
-- ============================================================
IF NOT EXISTS (
    SELECT 1 FROM sys.columns 
    WHERE object_id = OBJECT_ID('NHANVIEN') AND name = 'ROLE'
)
BEGIN
    ALTER TABLE NHANVIEN ADD ROLE VARCHAR(20) DEFAULT 'NHANVIEN';
    PRINT N'✔ Thêm cột ROLE';
END
GO

-- ============================================================
-- BƯỚC 4: Cập nhật ROLE cho NV hiện tại
-- ============================================================
UPDATE NHANVIEN SET ROLE = 'ADMIN'    WHERE MANV = 'NV01';
UPDATE NHANVIEN SET ROLE = 'NHANVIEN' WHERE MANV = 'NV02';
UPDATE NHANVIEN SET ROLE = 'NHANVIEN' WHERE MANV = 'NV03';
PRINT N'✔ Cập nhật ROLE';
GO

-- ============================================================
-- SP_INS_PUBLIC_ENCRYPT_NHANVIEN
-- Client đã mã hóa LUONG và MATKHAU trước khi gửi lên
-- SP chỉ lưu trực tiếp, KHÔNG mã hóa thêm
-- ============================================================
IF OBJECT_ID('SP_INS_PUBLIC_ENCRYPT_NHANVIEN', 'P') IS NOT NULL
    DROP PROCEDURE SP_INS_PUBLIC_ENCRYPT_NHANVIEN;
GO

CREATE PROCEDURE SP_INS_PUBLIC_ENCRYPT_NHANVIEN
    @MANV       VARCHAR(20),
    @HOTEN      NVARCHAR(100),
    @EMAIL      VARCHAR(100),
    @LUONG      NVARCHAR(MAX),   -- Đã mã hóa RSA từ client (Base64)
    @TENDN      NVARCHAR(100),
    @MK         NVARCHAR(MAX),   -- Đã hash SHA1 từ client (Hex)
    @PUB        NVARCHAR(MAX)    -- Public Key từ client (Base64/PEM)
AS
BEGIN
    SET NOCOUNT ON;

    IF EXISTS (SELECT 1 FROM NHANVIEN WHERE MANV = @MANV)
    BEGIN
        RAISERROR(N'Nhân viên %s đã tồn tại!', 16, 1, @MANV);
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM NHANVIEN WHERE TENDN = @TENDN)
    BEGIN
        RAISERROR(N'Tên đăng nhập %s đã được sử dụng!', 16, 1, @TENDN);
        RETURN;
    END

    -- Lưu trực tiếp, dữ liệu đã được mã hóa từ client
    INSERT INTO NHANVIEN (MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY, PUBKEY_CLIENT)
    VALUES (
        @MANV,
        @HOTEN,
        @EMAIL,
        CAST(@LUONG AS VARBINARY(MAX)),     -- LUONG đã mã hóa RSA (Base64 text stored as VARBINARY)
        @TENDN,
        CONVERT(VARBINARY(MAX), @MK, 2),    -- MATKHAU lưu SHA1 binary từ hex string
        @MANV,                               -- PUBKEY = MANV (tên định danh)
        @PUB                                 -- Nội dung Public Key đầy đủ
    );

    PRINT N'✔ Thêm nhân viên ' + @HOTEN + N' thành công (mã hóa từ client)!';
END
GO


-- ============================================================
-- SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
-- Trả về dữ liệu CHƯA giải mã (client tự giải mã)
-- ============================================================
IF OBJECT_ID('SP_SEL_PUBLIC_ENCRYPT_NHANVIEN', 'P') IS NOT NULL
    DROP PROCEDURE SP_SEL_PUBLIC_ENCRYPT_NHANVIEN;
GO

CREATE PROCEDURE SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
    @TENDN      NVARCHAR(100),
    @MK         NVARCHAR(MAX)    -- SHA1 hash từ client
AS
BEGIN
    SET NOCOUNT ON;

    -- Xác thực: so sánh hash SHA1 từ client với hash đã lưu
    IF NOT EXISTS (
        SELECT 1 FROM NHANVIEN
        WHERE TENDN = @TENDN
          AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2)
    )
    BEGIN
        RAISERROR(N'Tên đăng nhập hoặc mật khẩu không đúng!', 16, 1);
        RETURN;
    END

    -- Trả về LUONG chưa giải mã (client tự giải mã bằng Private Key)
    SELECT
        MANV,
        HOTEN,
        EMAIL,
        CONVERT(VARCHAR(MAX), LUONG) AS LUONG,   -- Base64 encrypted text
        TENDN,
        PUBKEY,
        PUBKEY_CLIENT
    FROM NHANVIEN
    WHERE TENDN = @TENDN
      AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2);
END
GO


-- ============================================================
-- SP_LOGIN_CLIENT
-- Đăng nhập: client gửi SHA1(password), server so sánh
-- ============================================================
IF OBJECT_ID('SP_LOGIN_CLIENT', 'P') IS NOT NULL
    DROP PROCEDURE SP_LOGIN_CLIENT;
GO

CREATE PROCEDURE SP_LOGIN_CLIENT
    @MANV   VARCHAR(20),
    @MK     NVARCHAR(MAX)   -- SHA1 hash từ client
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MANV, HOTEN, EMAIL, TENDN, PUBKEY, PUBKEY_CLIENT,
           CONVERT(VARCHAR(MAX), LUONG) AS LUONG_ENCRYPTED
    FROM NHANVIEN
    WHERE MANV = @MANV
      AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2);
END
GO


-- ============================================================
-- SP_INS_BANGDIEM_CLIENT
-- Nhập điểm đã mã hóa từ client bằng Public Key NV
-- ============================================================
IF OBJECT_ID('SP_INS_BANGDIEM_CLIENT', 'P') IS NOT NULL
    DROP PROCEDURE SP_INS_BANGDIEM_CLIENT;
GO

CREATE PROCEDURE SP_INS_BANGDIEM_CLIENT
    @MASV           VARCHAR(20),
    @MAHP           VARCHAR(20),
    @DIEMTHI_ENC    NVARCHAR(MAX)   -- Điểm đã mã hóa RSA từ client (Base64)
AS
BEGIN
    SET NOCOUNT ON;

    IF EXISTS (SELECT 1 FROM BANGDIEM WHERE MASV = @MASV AND MAHP = @MAHP)
        UPDATE BANGDIEM
        SET DIEMTHI = CAST(@DIEMTHI_ENC AS VARBINARY(MAX))
        WHERE MASV = @MASV AND MAHP = @MAHP;
    ELSE
        INSERT INTO BANGDIEM (MASV, MAHP, DIEMTHI)
        VALUES (@MASV, @MAHP, CAST(@DIEMTHI_ENC AS VARBINARY(MAX)));
END
GO


-- ============================================================
-- SP_SEL_BANGDIEM_CLIENT
-- Trả về điểm CHƯA giải mã (client tự giải mã)
-- ============================================================
IF OBJECT_ID('SP_SEL_BANGDIEM_CLIENT', 'P') IS NOT NULL
    DROP PROCEDURE SP_SEL_BANGDIEM_CLIENT;
GO

CREATE PROCEDURE SP_SEL_BANGDIEM_CLIENT
    @MASV VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        bd.MASV,
        sv.HOTEN        AS HOTEN_SV,
        bd.MAHP,
        hp.TENHP,
        CAST(bd.DIEMTHI AS NVARCHAR(MAX)) AS DIEMTHI_ENCRYPTED  -- Client giải mã
    FROM BANGDIEM bd
    JOIN SINHVIEN sv ON bd.MASV = sv.MASV
    JOIN HOCPHAN  hp ON bd.MAHP = hp.MAHP
    WHERE bd.MASV = @MASV;
END
GO

PRINT N'✔ Lab04 Stored Procedures tạo thành công!';
GO

-- Chuyển đổi đúng từ hex string sang binary
UPDATE NHANVIEN 
SET MATKHAU = CONVERT(VARBINARY(MAX), 'c35a37f0bca08afa583247cc461cad9c8082a47c', 2)
WHERE MANV = 'NV01';
GO

-- Xem dạng HEX thực sự đang lưu
SELECT MANV, CONVERT(VARCHAR(MAX), MATKHAU, 2) AS MK_HEX
FROM NHANVIEN;

--Lỗi do cột LUONG trong DB lưu binary của Lab 03 (mã hóa RSA SQL Server), khi cast sang NVARCHAR bị lỗi encoding.
--Sửa lại SP_LOGIN_CLIENT và SP_SEL_PUBLIC_ENCRYPT_NHANVIEN để trả về VARCHAR thay vì NVARCHAR:
--sqlUSE QLSVNhom;

ALTER PROCEDURE SP_LOGIN_CLIENT
    @MANV   VARCHAR(20),
    @MK     NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT MANV, HOTEN, EMAIL, TENDN, PUBKEY, PUBKEY_CLIENT,
           CONVERT(VARCHAR(MAX), LUONG) AS LUONG_ENCRYPTED
    FROM NHANVIEN
    WHERE MANV = @MANV
      AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2);
END
GO

ALTER PROCEDURE SP_SEL_PUBLIC_ENCRYPT_NHANVIEN
    @TENDN  NVARCHAR(100),
    @MK     NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (
        SELECT 1 FROM NHANVIEN
        WHERE TENDN = @TENDN
          AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2)
    )
    BEGIN
        RAISERROR(N'Tên đăng nhập hoặc mật khẩu không đúng!', 16, 1);
        RETURN;
    END

    SELECT MANV, HOTEN, EMAIL,
           CONVERT(VARCHAR(MAX), LUONG) AS LUONG,
           TENDN, PUBKEY, PUBKEY_CLIENT
    FROM NHANVIEN
    WHERE TENDN = @TENDN
      AND MATKHAU = CONVERT(VARBINARY(MAX), @MK, 2);
END
GO

ALTER PROCEDURE SP_SEL_BANGDIEM_CLIENT
    @MASV VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        bd.MASV,
        sv.HOTEN        AS HOTEN_SV,
        bd.MAHP,
        hp.TENHP,
        CONVERT(VARCHAR(MAX), bd.DIEMTHI) AS DIEMTHI_ENCRYPTED
    FROM BANGDIEM bd
    JOIN SINHVIEN sv ON bd.MASV = sv.MASV
    JOIN HOCPHAN  hp ON bd.MAHP = hp.MAHP
    WHERE bd.MASV = @MASV;
END
GO

-- Xóa điểm cũ
DELETE FROM BANGDIEM;

EXEC SP_LOGIN_CLIENT 'NV01', 'c35a37f0bca08afa583247cc461cad9c8082a47c';

PRINT N'=== Danh sách nhân viên ===';
SELECT 
    MANV, HOTEN, TENDN, ROLE,
    CONVERT(VARCHAR(MAX), MATKHAU, 2) AS MATKHAU_SHA256,
    CASE WHEN PUBKEY_CLIENT IS NOT NULL THEN N'Có' ELSE N'Chưa có' END AS PUBKEY_STATUS
FROM NHANVIEN;
GO

