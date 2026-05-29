"""
Bài Thực Hành Số 4 - Hoàn chỉnh
Mã hóa/Giải mã RSA thực hiện ở CLIENT (Web Crypto API)
Hash mật khẩu SHA-1 tại CLIENT
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import pyodbc

app = Flask(__name__)
app.secret_key = 'Lab04_QLSVNhom_2024'

DB_CONFIG = {
    'server':   'localhost',
    'database': 'QLSVNhom',
    'username': 'sa',
    'password': '123456',
    'driver':   '{ODBC Driver 17 for SQL Server}'
}

def get_connection():
    conn_str = (
        f"DRIVER={DB_CONFIG['driver']};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']};"
        "TrustServerCertificate=yes;"
    )
    return pyodbc.connect(conn_str)


def execute_sp(sp_name, params=None):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        if params:
            placeholders = ', '.join(['?' for _ in params])
            cursor.execute(f"EXEC {sp_name} {placeholders}", params)
        else:
            cursor.execute(f"EXEC {sp_name}")
        try:
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
            conn.commit()
            return [dict(zip(columns, row)) for row in rows]
        except TypeError:
            conn.commit()
            return []
    except pyodbc.Error as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()


@app.route('/')
def index():
    if 'manv' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data    = request.get_json()
        manv    = data.get('manv', '').strip().upper()
        mk_hash = data.get('mk_hash', '').strip()
        try:
            result = execute_sp('SP_LOGIN_CLIENT', [manv, mk_hash])
            if result:
                nv = result[0]
                session['manv']            = nv['MANV']
                session['hoten']           = nv['HOTEN']
                session['tendn']           = nv['TENDN']
                session['pubkey']          = nv['PUBKEY']
                session['pubkey_client']   = nv['PUBKEY_CLIENT']
                session['luong_encrypted'] = nv['LUONG_ENCRYPTED']
                session['mk_hash']         = mk_hash
                session['role']            = nv['ROLE']
                return jsonify({'success': True, 'role': nv['ROLE']})
            else:
                return jsonify({'success': False, 'error': 'Mã NV hoặc mật khẩu không đúng!'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    return render_template('lab04/login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'manv' not in session:
        return redirect(url_for('login'))
    return render_template('lab04/dashboard.html')


@app.route('/nhanvien')
def nhanvien():
    if 'manv' not in session:
        return redirect(url_for('login'))
    return render_template('lab04/nhanvien.html')


@app.route('/nhanvien/info')
def nhanvien_info():
    if 'manv' not in session:
        return jsonify({'error': 'Chua dang nhap'})
    try:
        result = execute_sp('SP_SEL_PUBLIC_ENCRYPT_NHANVIEN',
                            [session['tendn'], session['mk_hash']])
        return jsonify({'success': True, 'data': result[0] if result else None})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/nhanvien/them', methods=['POST'])
def nhanvien_them():
    if 'manv' not in session:
        return jsonify({'success': False, 'error': 'Chua dang nhap!'})
    data = request.get_json()
    try:
        execute_sp('SP_INS_PUBLIC_ENCRYPT_NHANVIEN', [
            data['manv'].upper(),
            data['hoten'],
            data['email'],
            data['luong_enc'],
            data['tendn'],
            data['mk_hash'],
            data['pubkey']
        ])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/nhanvien/sualuong', methods=['POST'])
def nhanvien_sualuong():
    if 'manv' not in session:
        return jsonify({'success': False, 'error': 'Chua dang nhap!'})
    if session.get('role') != 'ADMIN':
        return jsonify({'success': False, 'error': 'Chi ADMIN moi duoc sua luong!'})
    data = request.get_json()
    try:
        execute_sp('SP_UPD_LUONG_NHANVIEN', [
            session['manv'],
            data['manv_target'],
            data['luong_enc']
        ])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/pubkey/<manv>')
def get_pubkey(manv):
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT PUBKEY_CLIENT FROM NHANVIEN WHERE MANV = ?", manv)
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            return jsonify({'success': True, 'pubkey': row[0]})
        return jsonify({'success': False, 'error': 'Khong tim thay Public Key!'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/update_pubkey', methods=['POST'])
def update_pubkey():
    if 'manv' not in session:
        return jsonify({'success': False, 'error': 'Chua dang nhap!'})
    data = request.get_json()
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE NHANVIEN SET PUBKEY_CLIENT = ? WHERE MANV = ?",
            data['pubkey'], session['manv']
        )
        conn.commit()
        cursor.close()
        conn.close()
        session['pubkey_client'] = data['pubkey']
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/update_luong', methods=['POST'])
def update_luong():
    if 'manv' not in session:
        return jsonify({'success': False, 'error': 'Chua dang nhap!'})
    data = request.get_json()
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE NHANVIEN SET LUONG = CAST(? AS VARBINARY(MAX)) WHERE MANV = ?",
            data['luong_enc'], session['manv']
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/bangdiem/<masv>')
def api_bangdiem(masv):
    if 'manv' not in session:
        return jsonify({'error': 'Chua dang nhap'})
    try:
        result = execute_sp('SP_SEL_BANGDIEM_CLIENT', [masv])
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/lop')
def lop_list():
    if 'manv' not in session:
        return redirect(url_for('login'))
    try:
        lop_list = execute_sp('SP_SEL_ALL_LOP')
        return render_template('lab04/lop.html', lop_list=lop_list)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('lab04/lop.html', lop_list=[])


@app.route('/lop/them', methods=['POST'])
def lop_them():
    if 'manv' not in session:
        return redirect(url_for('login'))
    malop  = request.form.get('malop', '').strip().upper()
    tenlop = request.form.get('tenlop', '').strip()
    manv   = request.form.get('manv', '').strip().upper()
    try:
        execute_sp('SP_INS_LOP', [malop, tenlop, manv])
        flash('Them lop thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('lop_list'))


@app.route('/lop/sua', methods=['POST'])
def lop_sua():
    if 'manv' not in session:
        return redirect(url_for('login'))
    malop  = request.form.get('malop', '').strip().upper()
    tenlop = request.form.get('tenlop', '').strip()
    manv   = request.form.get('manv', '').strip().upper()
    try:
        execute_sp('SP_UPD_LOP', [malop, tenlop, manv])
        flash('Cap nhat lop thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('lop_list'))


@app.route('/lop/xoa', methods=['POST'])
def lop_xoa():
    if 'manv' not in session:
        return redirect(url_for('login'))
    malop = request.form.get('malop', '').strip().upper()
    try:
        execute_sp('SP_DEL_LOP', [malop])
        flash('Xoa lop thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('lop_list'))


@app.route('/sinhvien')
def sv_list():
    if 'manv' not in session:
        return redirect(url_for('login'))
    malop = request.args.get('malop', '')
    try:
        lop_quan_ly = execute_sp('SP_SEL_LOP_BY_MANV', [session['manv']])
        sv_list = []
        if malop:
            sv_list = execute_sp('SP_SEL_SV_BY_LOP', [malop])
        return render_template('lab04/sinhvien.html',
                               lop_quan_ly=lop_quan_ly,
                               sv_list=sv_list,
                               malop_selected=malop)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('lab04/sinhvien.html',
                               lop_quan_ly=[], sv_list=[], malop_selected='')


@app.route('/sinhvien/them', methods=['POST'])
def sv_them():
    if 'manv' not in session:
        return redirect(url_for('login'))
    masv     = request.form.get('masv', '').strip().upper()
    hoten    = request.form.get('hoten', '').strip()
    ngaySinh = request.form.get('ngaysinh', None)
    diachi   = request.form.get('diachi', '').strip()
    malop    = request.form.get('malop', '').strip().upper()
    tendn    = request.form.get('tendn', '').strip()
    matkhau  = request.form.get('matkhau', '').strip()
    lop_quan_ly = execute_sp('SP_SEL_LOP_BY_MANV', [session['manv']])
    if malop not in [l['MALOP'] for l in lop_quan_ly]:
        flash('Ban khong co quyen them SV vao lop nay!', 'error')
        return redirect(url_for('sv_list', malop=malop))
    try:
        execute_sp('SP_INS_SINHVIEN',
                   [masv, hoten, ngaySinh, diachi, malop, tendn, matkhau])
        flash('Them sinh vien thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('sv_list', malop=malop))


@app.route('/sinhvien/sua', methods=['POST'])
def sv_sua():
    if 'manv' not in session:
        return redirect(url_for('login'))
    masv     = request.form.get('masv', '').strip().upper()
    hoten    = request.form.get('hoten', '').strip()
    ngaySinh = request.form.get('ngaysinh', None)
    diachi   = request.form.get('diachi', '').strip()
    malop    = request.form.get('malop', '').strip().upper()
    tendn    = request.form.get('tendn', '').strip()
    try:
        execute_sp('SP_UPD_SINHVIEN',
                   [masv, hoten, ngaySinh, diachi, malop, tendn, session['manv']])
        flash('Cap nhat sinh vien thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('sv_list', malop=malop))


@app.route('/sinhvien/xoa', methods=['POST'])
def sv_xoa():
    if 'manv' not in session:
        return redirect(url_for('login'))
    masv  = request.form.get('masv', '').strip().upper()
    malop = request.form.get('malop', '').strip().upper()
    try:
        execute_sp('SP_DEL_SINHVIEN', [masv, session['manv']])
        flash('Xoa sinh vien thanh cong!', 'success')
    except Exception as e:
        flash(str(e), 'error')
    return redirect(url_for('sv_list', malop=malop))


@app.route('/bangdiem')
def bangdiem():
    if 'manv' not in session:
        return redirect(url_for('login'))
    masv = request.args.get('masv', '')
    try:
        lop_quan_ly  = execute_sp('SP_SEL_LOP_BY_MANV', [session['manv']])
        hocphan_list = execute_sp('SP_SEL_ALL_HOCPHAN')
        sv_list = []
        for lop in lop_quan_ly:
            sv_list.extend(execute_sp('SP_SEL_SV_BY_LOP', [lop['MALOP']]))
        return render_template('lab04/bangdiem.html',
                               sv_list=sv_list,
                               hocphan_list=hocphan_list,
                               masv_selected=masv)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('lab04/bangdiem.html',
                               sv_list=[], hocphan_list=[], masv_selected='')


@app.route('/bangdiem/nhap', methods=['POST'])
def bangdiem_nhap():
    data = request.get_json()
    try:
        execute_sp('SP_INS_BANGDIEM_CLIENT', [
            data['masv'], data['mahp'], data['diem_enc']
        ])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/favicon.ico')
def favicon():
    return '', 204


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)