import os
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import uuid
import time
import requests
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
from dotenv import load_dotenv

# ==========================================
# 1. AYARLAR VE GÜVENLİK
# ==========================================
load_dotenv()
app = Flask(__name__)

# --- ORTAM DEĞİŞKENLERİ ---
app.secret_key = os.getenv('SECRET_KEY', 'zbh_root_key_v1')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin') # Render'dan ayarla
ADMIN_PASS = os.getenv('ADMIN_PASS', 'admin123') # Render'dan ayarla
DISCORD_WEBHOOK = os.getenv('DISCORD_WEBHOOK', '')
DATABASE_URL = os.getenv('DATABASE_URL') # Render'dan gelen PostgreSQL Linki

# --- GÜVENLİK SABİTLERİ ---
BLOCK_TIME = 600  # 10 Dakika Ban
MAX_ATTEMPTS = 5  # 5 Hatalı Giriş Hakkı
IS_LOCKDOWN = False # Panic Modu Başlangıçta Kapalı
failed_attempts = {} # RAM üzerinde IP takibi

# ==========================================
# 2. VERİTABANI BAĞLANTISI (POSTGRESQL)
# ==========================================
def get_db_connection():
    if not DATABASE_URL:
        print("HATA: DATABASE_URL Bulunamadı!")
        return None
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    return conn

def init_db():
    """Tabloları PostgreSQL formatında oluşturur."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # KEYS Tablosu
        cur.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                key_code VARCHAR(100) PRIMARY KEY,
                hwid VARCHAR(255),
                status VARCHAR(20),
                expires_at TIMESTAMP,
                type VARCHAR(20),
                created_at TIMESTAMP,
                ip_address VARCHAR(50)
            );
        ''')
        
        # MAPPING Tablosu (SERIAL kullanılır)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS mapping (
                id SERIAL PRIMARY KEY,
                game_name VARCHAR(100),
                place_id VARCHAR(50),
                script_url TEXT
            );
        ''')
        
        # LOGS Tablosu
        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                action VARCHAR(50),
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Veritabanı Tabloları Hazır!")
    except Exception as e:
        print(f"❌ DB INIT ERROR: {e}")

# Başlangıçta tabloları kontrol et
init_db()

# ==========================================
# 3. YARDIMCI FONKSİYONLAR
# ==========================================
def log_action(action, details, notify_discord=False, color=0x00ff00):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_logs (action, details) VALUES (%s, %s)", (action, details))
        conn.commit()
        cur.close()
        conn.close()

        if notify_discord and DISCORD_WEBHOOK:
            payload = {
                "embeds": [{
                    "title": f"🛡️ ZBH SYSTEM | {action}",
                    "description": details,
                    "color": color,
                    "footer": {"text": "Security Protocol"},
                    "timestamp": datetime.datetime.now().isoformat()
                }]
            }
            requests.post(DISCORD_WEBHOOK, json=payload, timeout=2)
    except Exception as e:
        print(f"LOG ERROR: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# 4. WEB SAYFALARI (FRONTEND)
# ==========================================
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'logged_in' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            log_action("ADMIN_LOGIN", f"Login from {request.remote_addr}", True, 0x00FF00)
            return redirect(url_for('dashboard'))
        else:
            log_action("FAILED_LOGIN", f"IP: {request.remote_addr}", True, 0xFF0000)
            return render_template('login.html', error="Hatalı Şifre Aga!")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    # İstatistikler
    try:
        cur.execute("SELECT COUNT(*) FROM keys")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE status='active'")
        active = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE type='VIP'")
        vip = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE status='banned'")
        banned = cur.fetchone()[0]
    except:
        total, active, vip, banned = 0, 0, 0, 0
    
    cur.close()
    conn.close()
    return render_template('dashboard.html', total=total, active=active, vip=vip, banned=banned, active_page='dashboard')

@app.route('/users')
@login_required
def users():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor) # Veriyi sözlük gibi çek
    cur.execute("SELECT * FROM keys ORDER BY created_at DESC")
    keys = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('users.html', keys=keys, active_page='users')

@app.route('/mapping')
@login_required
def mapping():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM mapping ORDER BY id DESC")
    mappings = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('mapping.html', mappings=mappings, active_page='mapping')

@app.route('/audit-logs')
@login_required
def audit_logs():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('audit_logs.html', logs=logs, active_page='audit_logs')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', active_page='settings')

# ==========================================
# 5. API MOTORU (TEKNİK KISIM)
# ==========================================

@app.route('/api/verify', methods=['GET'])
def verify():
    global IS_LOCKDOWN
    client_ip = request.remote_addr
    
    # 1. PANIC MODE KONTROLÜ
    if IS_LOCKDOWN:
        return jsonify({"status": "error", "msg": "SYSTEM LOCKDOWN"})

    # 2. RATE LIMIT (Anti-Spam)
    current_time = time.time()
    if client_ip in failed_attempts:
        attempts, first_time = failed_attempts[client_ip]
        if attempts >= MAX_ATTEMPTS:
            if current_time - first_time < BLOCK_TIME:
                return jsonify({"status": "error", "msg": "BLOCKED: Too Many Requests"})
            else:
                del failed_attempts[client_ip]

    key = request.args.get('key')
    hwid = request.args.get('hwid')
    place_id = request.args.get('placeid')

    if not key: return jsonify({"status": "error", "msg": "MISSING_KEY"})

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Güvenli Sorgu
    cur.execute("SELECT * FROM keys WHERE key_code = %s", (key,))
    user = cur.fetchone()
    
    response = {"status": "error", "msg": "INVALID_KEY"}
    
    if user:
        if user['status'] == 'banned':
            response['msg'] = "ACCOUNT_BANNED"
        elif not user['hwid']:
            # İlk Giriş: HWID Kilitle
            cur2 = conn.cursor()
            cur2.execute("UPDATE keys SET hwid = %s, ip_address = %s WHERE key_code = %s", (hwid, client_ip, key))
            conn.commit()
            cur2.close()
            response = {"status": "success", "type": user['type']}
        elif user['hwid'] != hwid:
            response['msg'] = "HWID_MISMATCH"
            # Hata Puanı Ekle
            if client_ip not in failed_attempts: failed_attempts[client_ip] = [1, current_time]
            else: failed_attempts[client_ip][0] += 1
        else:
            response = {"status": "success", "type": user['type']}
            # IP Güncelle
            cur2 = conn.cursor()
            cur2.execute("UPDATE keys SET ip_address = %s WHERE key_code = %s", (client_ip, key))
            conn.commit()
            cur2.close()

    # Script URL Çekme
    if response['status'] == 'success':
        cur.execute("SELECT script_url FROM mapping WHERE place_id = %s", (place_id,))
        script = cur.fetchone()
        response['script_url'] = script['script_url'] if script else ""
        if client_ip in failed_attempts: del failed_attempts[client_ip] # Başarılıysa affet
        
        # Sadece VIP girişlerini logla (DB şişmesin diye)
        if user and user['type'] == 'VIP':
            log_action("VIP_ACCESS", f"User: {key} entered Game: {place_id}")

    cur.close()
    conn.close()
    return jsonify(response)

# --- KEY OLUŞTURMA ---
@app.route('/api/generate_key', methods=['POST'])
@login_required
def generate_key():
    data = request.json
    duration = data.get('duration')
    is_vip = data.get('is_vip')
    
    days = 3650 if duration == 'lifetime' else (30 if duration == '30_day' else 7)
    expires_at = datetime.datetime.now() + datetime.timedelta(days=days)
    
    prefix = "ZBH-VIP" if is_vip else "ZBH-GEN"
    key_code = f"{prefix}-{str(uuid.uuid4())[:8].upper()}"
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO keys (key_code, status, expires_at, type, created_at) VALUES (%s, %s, %s, %s, NOW())",
        (key_code, 'active', expires_at, 'VIP' if is_vip else 'Standard')
    )
    conn.commit()
    cur.close()
    conn.close()
    
    log_action("KEY_GENERATE", f"Key: {key_code}", True, 0x00FFFF)
    return jsonify({"success": True})

# --- HWID SIFIRLAMA ---
@app.route('/api/reset_hwid', methods=['POST'])
@login_required
def reset_hwid():
    data = request.json
    key = data.get('key')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE keys SET hwid = NULL WHERE key_code = %s", (key,))
    conn.commit()
    cur.close()
    conn.close()
    log_action("HWID_RESET", f"Reset for: {key}", True, 0xFFA500)
    return jsonify({"success": True})

# --- KULLANICI BANLAMA ---
@app.route('/api/ban_user', methods=['POST'])
@login_required
def ban_user():
    data = request.json
    key = data.get('key')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE keys SET status = 'banned' WHERE key_code = %s", (key,))
    conn.commit()
    cur.close()
    conn.close()
    log_action("USER_BANNED", f"Banned: {key}", True, 0xFF0000)
    return jsonify({"success": True})

# --- KULLANICI SİLME ---
@app.route('/api/delete_user', methods=['POST'])
@login_required
def delete_user():
    data = request.json
    key = data.get('key')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM keys WHERE key_code = %s", (key,))
    conn.commit()
    cur.close()
    conn.close()
    log_action("USER_DELETED", f"Deleted: {key}")
    return jsonify({"success": True})

# --- MAPPING İŞLEMLERİ ---
@app.route('/api/add_mapping', methods=['POST'])
@login_required
def add_mapping():
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO mapping (game_name, place_id, script_url) VALUES (%s, %s, %s)", 
                (data['game_name'], data['place_id'], data['script_url']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/delete_mapping', methods=['POST'])
@login_required
def delete_mapping():
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM mapping WHERE id = %s", (data['id'],))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"success": True})

# --- PANIC MODE ---
@app.route('/api/panic_toggle', methods=['POST'])
@login_required
def panic_toggle():
    global IS_LOCKDOWN
    data = request.json
    if 'state' in data: IS_LOCKDOWN = data['state']
    else: IS_LOCKDOWN = not IS_LOCKDOWN
    log_action("PANIC_MODE", f"System Lockdown: {IS_LOCKDOWN}", True, 0xFF0000)
    return jsonify({"success": True, "state": IS_LOCKDOWN})

# --- HEARTBEAT ---
@app.route('/api/heartbeat')
def heartbeat():
    return jsonify({"status": "alive", "online": True})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
