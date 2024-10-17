import sqlite3

# เชื่อมต่อกับฐานข้อมูล
conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()

# JOIN ตาราง users และ login_log โดยใช้ username
query = '''
SELECT users.id, users.username, users.password, login_log.login_time, login_log.success
FROM users
JOIN login_log ON users.username = login_log.username
'''
cursor.execute(query)
logs = cursor.fetchall()

# แสดงข้อมูลที่ดึงมา
for log in logs:
    print(f"ID: {log[0]}, Username: {log[1]}, Password (hashed): {log[2]}, Login Time: {log[3]}, Success: {log[4]}")

# ปิดการเชื่อมต่อฐานข้อมูล
conn.close()
