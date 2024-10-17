from flask import Flask, render_template, request, redirect, url_for, flash
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

# หน้าลงทะเบียนผู้ใช้ใหม่
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pin = request.form['pin']  # รับค่า PIN ที่ผู้ใช้กรอก

        # ตรวจสอบความซับซ้อนของรหัสผ่าน
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('register.html')

        hashed_password = hash_password(password)  # เข้ารหัสรหัสผ่าน
        hashed_pin = hash_password(pin)  # เข้ารหัส PIN ก่อนบันทึก

        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, pin, last_password_change) VALUES (?, ?, ?, ?)',
                     (username, hashed_password, hashed_pin, datetime.now()))
        conn.commit()
        conn.close()
        
        flash('User registered successfully!')
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
        
        success = False  # สถานะการเข้าสู่ระบบ
        if user and check_password(user['password'], password):
            # ตรวจสอบว่ารหัสผ่านหมดอายุหรือยัง
            if check_password_expiration(user['last_password_change']):
                flash('รหัสผ่านของคุณหมดอายุแล้ว กรุณาเปลี่ยนรหัสผ่านใหม่', 'error')
                return redirect(url_for('reset_password'))  # เปลี่ยนเส้นทางไปหน้าเปลี่ยนรหัสผ่าน
            
            success = True
            flash('เข้าสู่ระบบสำเร็จ!', 'success')
            log_login(username, success)  # บันทึก log เมื่อเข้าสู่ระบบสำเร็จ
            return redirect(url_for('dashboard'))
        else:
            flash('เข้าสู่ระบบไม่สำเร็จ! โปรดลองอีกครั้ง.', 'error')

        log_login(username, success)  # บันทึก log ในกรณีที่เข้าสู่ระบบไม่สำเร็จ
        conn.close()

    return render_template('login.html')



# หน้า Dashboard
@app.route('/dashboard')
def dashboard():
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






