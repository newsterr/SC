from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt
import re
from datetime import datetime, timedelta


app = Flask(__name__)
app.secret_key = 'supersecretkey'

# สร้างการเชื่อมต่อกับฐานข้อมูล
def get_db_connection():
    conn = sqlite3.connect('access_control.db')
    conn.row_factory = sqlite3.Row
    return conn

# ฟังก์ชันเข้ารหัสรหัสผ่าน
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# ฟังก์ชันตรวจสอบรหัสผ่าน
def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pin = request.form['pin']

        # ตรวจสอบว่าชื่อผู้ใช้ซ้ำหรือไม่
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('ชื่อผู้ใช้นี้มีอยู่แล้ว กรุณาเลือกชื่อผู้ใช้ใหม่.', 'error')
            conn.close()
            return render_template('register.html')

        # ตรวจสอบความซับซ้อนของรหัสผ่าน
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('register.html')

        hashed_password = hash_password(password)  # เข้ารหัสรหัสผ่าน
        hashed_pin = hash_password(pin)  # เข้ารหัส PIN ก่อนบันทึก

        conn.execute('INSERT INTO users (username, password, pin, last_password_change, role) VALUES (?, ?, ?, ?, ?)',
                     (username, hashed_password, hashed_pin, datetime.now(), 'user'))  # กำหนด role เป็น user
        conn.commit()
        conn.close()

        flash('ลงทะเบียนผู้ใช้สำเร็จ!')
        return redirect(url_for('login'))

    return render_template('register.html')





# หน้าเข้าสู่ระบบ
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            # ตรวจสอบว่าบัญชีถูกล็อกหรือไม่
            if user['account_locked']:
                flash('บัญชีของคุณถูกล็อกเนื่องจากความพยายามเข้าสู่ระบบที่ล้มเหลวหลายครั้ง กรุณาติดต่อผู้ดูแลระบบ.', 'error')
                conn.close()
                return render_template('login.html')

            # ตรวจสอบรหัสผ่าน
            if check_password(user['password'], password):
                # ตรวจสอบการหมดอายุของรหัสผ่าน
                if check_password_expiration(user['last_password_change']):
                    flash('รหัสผ่านของคุณหมดอายุแล้ว กรุณาเปลี่ยนรหัสผ่านใหม่', 'error')
                    return redirect(url_for('reset_password'))

                # เข้าสู่ระบบสำเร็จ รีเซ็ต failed_attempts และบันทึกบทบาทลงในเซสชัน
                session['username'] = username  # บันทึกชื่อผู้ใช้ในเซสชัน
                session['role'] = user['role']  # บันทึกบทบาทของผู้ใช้ในเซสชัน
                conn.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
                conn.commit()
                
                flash('เข้าสู่ระบบสำเร็จ!', 'success')
                log_login(username, True)  # บันทึก log การเข้าสู่ระบบ
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                # เข้าสู่ระบบล้มเหลว เพิ่มจำนวนครั้ง failed_attempts
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 5:
                    # ล็อกบัญชีถ้าผิดพลาดครบ 5 ครั้ง
                    conn.execute('UPDATE users SET account_locked = 1 WHERE username = ?', (username,))
                    flash('บัญชีของคุณถูกล็อกเนื่องจากความพยายามเข้าสู่ระบบที่ล้มเหลวหลายครั้ง กรุณาติดต่อผู้ดูแลระบบ.', 'error')
                else:
                    # บันทึก failed_attempts
                    conn.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))
                    flash(f'เข้าสู่ระบบไม่สำเร็จ! คุณพยายามผิด {failed_attempts} ครั้ง.', 'error')

                conn.commit()
                log_login(username, False)  # บันทึก log การเข้าสู่ระบบล้มเหลว
                conn.close()
        else:
            flash('ไม่พบผู้ใช้งานนี้!', 'error')

    return render_template('login.html')


# หน้า Admin
# หน้า Admin
@app.route('/admin')
def admin_page():
    # ตรวจสอบว่า ผู้ใช้ได้เข้าสู่ระบบหรือไม่
    if 'username' not in session:
        flash('กรุณาเข้าสู่ระบบก่อน!', 'error')  # แสดงข้อความแจ้งเตือน
        return redirect(url_for('login'))  # เปลี่ยนเส้นทางไปยังหน้า login

    # ตรวจสอบบทบาทของผู้ใช้
    if 'role' in session and session['role'] == 'admin':
        return render_template('admin.html')  # แสดงหน้า admin.html
    else:
        flash('คุณไม่มีสิทธิ์เข้าถึงหน้านี้!', 'error')
        return redirect(url_for('dashboard'))  # เปลี่ยนเส้นทางไปยัง dashboard

    

# logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # ลบข้อมูลผู้ใช้จากเซสชัน
    session.pop('role', None)       # ลบข้อมูล role ของผู้ใช้จากเซสชัน
    flash('คุณได้ออกจากระบบเรียบร้อยแล้ว!', 'success')
    return redirect(url_for('login'))


# หน้า Dashboard
@app.route('/dashboard')
def dashboard():
    # ตรวจสอบว่า ผู้ใช้ได้เข้าสู่ระบบหรือไม่
    if 'username' not in session:
        flash('กรุณาเข้าสู่ระบบก่อน!', 'error')  # แสดงข้อความแจ้งเตือน
        return redirect(url_for('login'))  # เปลี่ยนเส้นทางไปยังหน้า login
    
    return render_template('dashboard.html')  # แสดงหน้า dashboard.html





# ระบบรีเซ็ตรหัสผ่าน
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        pin = request.form['pin']  # รับค่า PIN ที่ผู้ใช้กรอก
        new_password = request.form['new_password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password(user['pin'], pin):  # ตรวจสอบ PIN
            hashed_password = hash_password(new_password)
            conn.execute('UPDATE users SET password = ?, last_password_change = ? WHERE username = ?',
                         (hashed_password, datetime.now(), username))
            conn.commit()
            flash('Password reset successfully!')
        else:
            flash('PIN ไม่ถูกต้อง!', 'error')

        conn.close()
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')



# ฟังก์ชันบันทึก log
def log_login(username, success):
    conn = get_db_connection()
    conn.execute('INSERT INTO login_log (username, login_time, success) VALUES (?, ?, ?)', 
                 (username, datetime.now(), success))
    conn.commit()
    conn.close()



# ฟังก์ชันตรวจสอบการหมดอายุของรหัสผ่าน
def check_password_expiration(last_password_change):
    last_password_change = last_password_change.split('.')[0]  # ลบมิลลิวินาทีออก
    last_change_date = datetime.strptime(last_password_change, '%Y-%m-%d %H:%M:%S')
    return datetime.now() > last_change_date + timedelta(days=90)


# ฟังก์ชันตรวจสอบความซับซ้อนของรหัสผ่าน
def validate_password(password):
    if len(password) < 7:
        return False, 'รหัสผ่านต้องมีความยาวอย่างน้อย 7 ตัวอักษร'
    if not re.search(r'[a-z]', password):
        return False, 'รหัสผ่านต้องมีตัวอักษรตัวเล็ก'
    if not re.search(r'[A-Z]', password):
        return False, 'รหัสผ่านต้องมีตัวอักษรตัวใหญ่'
    if not re.search(r'[0-9]', password):
        return False, 'รหัสผ่านต้องมีตัวเลข'
    if not re.search(r'[\W_]', password):  # \W หมายถึง non-alphanumeric characters
        return False, 'รหัสผ่านต้องมีสัญลักษณ์พิเศษ'
    return True, ''

# รันเซิร์ฟเวอร์
if __name__ == '__main__':
    app.run(debug=True)






