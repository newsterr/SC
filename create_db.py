import sqlite3

# สร้างการเชื่อมต่อกับฐานข้อมูล
conn = sqlite3.connect('access_control.db')

# สร้าง cursor เพื่อรันคำสั่ง SQL
cursor = conn.cursor()

# คำสั่ง SQL สำหรับสร้างตาราง users
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    pin TEXT NOT NULL,
                    last_password_change TIMESTAMP NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    account_locked BOOLEAN DEFAULT 0,
                    pin_attempts INTEGER DEFAULT 0,
                    role TEXT NOT NULL DEFAULT 'user',
                    email TEXT UNIQUE -- เพิ่มฟิลด์อีเมล
                )''')

# คำสั่ง SQL สำหรับสร้างตาราง login_log
cursor.execute('''CREATE TABLE IF NOT EXISTS login_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    login_time TIMESTAMP NOT NULL,
                    success BOOLEAN NOT NULL
                )''')

# บันทึกการเปลี่ยนแปลงลงฐานข้อมูล
conn.commit()

# ปิดการเชื่อมต่อฐานข้อมูล
conn.close()

print("Tables created successfully.")
