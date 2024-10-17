import sqlite3

# เชื่อมต่อกับฐานข้อมูล
def get_db_connection():
    conn = sqlite3.connect('access_control.db')
    conn.row_factory = sqlite3.Row
    return conn

# ฟังก์ชันดึงข้อมูล log การเข้าสู่ระบบ
def get_login_logs():
    conn = get_db_connection()
    cursor = conn.cursor()

    # JOIN ตาราง users และ login_log โดยใช้ username
    query = '''
    SELECT users.username, login_log.login_time, login_log.success
    FROM login_log
    JOIN users ON login_log.username = users.username
    ORDER BY login_log.login_time DESC
    '''
    
    cursor.execute(query)
    logs = cursor.fetchall()

    conn.close()
    return logs

# ฟังก์ชันหลักสำหรับแสดง log
if __name__ == '__main__':
    logs = get_login_logs()
    for log in logs:
        status = "สำเร็จ" if log['success'] else "ไม่สำเร็จ"
        print(f"Username: {log['username']}, Login Time: {log['login_time']}, Status: {status}")
