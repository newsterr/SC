import sqlite3

# เชื่อมต่อกับฐานข้อมูล
conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()

# ดึงข้อมูลจาก login_log และ users โดยใช้ JOIN
cursor.execute('''
    SELECT login_log.username, login_log.login_time, login_log.success, users.password
    FROM login_log
    JOIN users ON login_log.username = users.username
''')
logs = cursor.fetchall()

# แสดงผล log
for log in logs:
    print(f"Username: {log[0]}, Login Time: {log[1]}, Success: {log[2]}, Password: {log[3]}")

# ปิดการเชื่อมต่อฐานข้อมูล
conn.close()
