import os
import sqlite3
import datetime
import uuid
import logging
import hashlib
import time
import requests  # DISCORD İÇİN GEREKLİ
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
from dotenv import load_dotenv

# ==========================================
# 1. AYARLAR VE GÜVENLİK
# ==========================================
load_dotenv()
app = Flask(__name__)

# --- GİZLİ BİLGİLER (RENDER ENVIRONMENT'DAN ÇEKER) ---
app.secret_key = os.getenv('SECRET_KEY', 'zbh_holding_gizli_anahtar_999')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'admin123')
DISCORD_WEBHOOK = os.getenv('DISCORD_WEBHOOK', '') # Discord Webhook Linkini Render'a ekle!

DB_NAME = "zbh_system.db"
SECRET_SALT = "ZBH_GHOST_PROTOCOL_78"
IS_LOCKDOWN = False 

# --- GÜVENLİK DUVARI (RATE LIMIT) ---
# IP : [Hata Sayısı, İlk Hata Zamanı]
failed_attempts = {} 
BLOCK_TIME = 600  # 10 Dakika ceza
MAX_ATTEMPTS = 5  # 5 Yanlış hakkı

logging.basicConfig(filename='system.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# ==========================================
# 2. VERİTABANI VE YARDIMCI FONKSİYONLAR
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (key_code TEXT PRIMARY KEY, hwid TEXT, status TEXT, expires_at DATETIME, type TEXT, created_at DATETIME, ip_address TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS mapping (id INTEGER PRIMARY KEY AUTOINCREMENT, game_name TEXT, place_id TEXT, script_url TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- LOGLAMA SİSTEMİ (DB + DISCORD) ---
def log_action(action, details, notify_discord=False, color=0x00ff00):
    # 1. Veritabanına Yaz
    try:
        conn = get_db()
        conn.execute("INSERT INTO audit_logs (action, details) VALUES (?, ?)", (action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

    # 2. Discord'a At (Eğer istenirse)
    if notify_discord and DISCORD_WEBHOOK:
        try:
            data = {
                "embeds": [{
                    "title": f"🛡️ ZBH SYSTEM | {action}",
                    "description": details,
                    "color": color,
                    "footer": {"text": "ZBH Security Protocol"},
                    "timestamp": datetime.datetime.now().isoformat()
                }]
            }
            requests.post(DISCORD_WEBHOOK, json=data, timeout=2)
        except:
            pass # Discord hatası sistemi durdurmasın

def generate_free_key_logic(ip):
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    raw = f"{ip}{today}{SECRET_SALT}"
    hashed = hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
    return f"ZBH-FREE-{hashed}"

# ==========================================
# 3. VİTRİN (HTML SAYFALARI)
# ==========================================
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'logged_in' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        ip = request.remote_addr
        # Admin Giriş Kontrolü
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            log_action("ADMIN_LOGIN", f"Login successful from IP: {ip}", True, 0x00ff00)
            return redirect(url_for('dashboard'))
        else:
            log_action("FAILED_LOGIN", f"Failed admin attempt from IP: {ip}", True, 0xff0000)
            error = "ACCESS DENIED"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    try:
        total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM keys WHERE status='active'").fetchone()[0]
        vip = c.execute("SELECT COUNT(*) FROM keys WHERE type='VIP'").fetchone()[0]
        banned = c.execute("SELECT COUNT(*) FROM keys WHERE status='banned'").fetchone()[0]
    except:
        total, active, vip, banned = 0, 0, 0, 0
    conn.close()
    return render_template('dashboard.html', total=total, active=active, vip=vip, banned=banned, active_page='dashboard')

@app.route('/users')
@login_required
def users():
    conn = get_db()
    keys = conn.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('users.html', keys=keys, active_page='users')

@app.route('/mapping')
@login_required
def mapping():
    conn = get_db()
    mappings = conn.execute("SELECT * FROM mapping ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('mapping.html', mappings=mappings, active_page='mapping')

@app.route('/audit-logs')
@login_required
def audit_logs():
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs, active_page='audit_logs')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', active_page='settings')

@app.route('/free-key')
def free_key_page():
    return render_template('free_key.html')

# ==========================================
# 4. API MOTORU (GÜVENLİKLİ & DETAYLI)
# ==========================================

@app.route('/api/verify', methods=['GET'])
def verify():
    global IS_LOCKDOWN
    client_ip = request.remote_addr
    
    # 1. KİLİT KONTROLÜ
    if IS_LOCKDOWN:
        return jsonify({"status": "error", "msg": "SYSTEM LOCKDOWN ACTIVE"})

    # 2. RATE LIMIT (ANTİ-SPAM)
    current_time = time.time()
    if client_ip in failed_attempts:
        attempts, first_time = failed_attempts[client_ip]
        if attempts >= MAX_ATTEMPTS:
            if current_time - first_time < BLOCK_TIME:
                remaining = int(BLOCK_TIME - (current_time - first_time))
                return jsonify({"status": "error", "msg": f"BLOCKED FOR {remaining}s"})
            else:
                del failed_attempts[client_ip] # Süre dolmuş, affet

    key = request.args.get('key')
    hwid = request.args.get('hwid')
    place_id = request.args.get('placeid')

    if not key: return jsonify({"status": "error", "msg": "MISSING KEY"})

    # --- KEY KONTROLÜ ---
    status = "error"
    msg = "UNKNOWN"
    response_data = {}
    is_vip_log = False

    # A. FREE KEY
    if key.startswith("ZBH-FREE"):
        expected = generate_free_key_logic(client_ip)
        if key == expected:
            status = "success"
            response_data = {"type": "Free"}
        else:
            msg = "INVALID FREE KEY"

    # B. VIP / GEN KEY
    else:
        conn = get_db()
        user = conn.execute("SELECT * FROM keys WHERE key_code=?", (key,)).fetchone()
        
        if not user:
            msg = "KEY NOT FOUND"
        elif user['status'] == 'banned':
            msg = "ACCOUNT BANNED"
        else:
            # HWID KONTROLÜ
            if not user['hwid']:
                conn.execute("UPDATE keys SET hwid=?, ip_address=? WHERE key_code=?", (hwid, client_ip, key))
                conn.commit()
                status = "success"
                response_data = {"type": user['type']}
                if user['type'] == 'VIP': is_vip_log = True
            elif user['hwid'] != hwid:
                msg = "HWID MISMATCH"
            else:
                status = "success"
                response_data = {"type": user['type']}
                if user['type'] == 'VIP': is_vip_log = True
        conn.close()

    # --- SONUÇ YÖNETİMİ ---
    if status == "success":
        if client_ip in failed_attempts: del failed_attempts[client_ip] # Başarılıysa sicili temizle
        
        # Script URL çek
        conn = get_db()
        script_row = conn.execute("SELECT script_url FROM mapping WHERE place_id=?", (place_id,)).fetchone()
        conn.close()
        
        response_data["script_url"] = script_row[0] if script_row else ""
        response_data["status"] = "success"
        
        # Sadece VIP girişlerini veya önemli olayları logla (DB şişmesin)
        if is_vip_log:
            log_action("VIP_ACCESS", f"Key: {key} entered Game: {place_id}", True, 0xFFA500)
            
        return jsonify(response_data)
        
    else:
        # BAŞARISIZ GİRİŞ -> Ceza Puanı Ekle
        if client_ip not in failed_attempts:
            failed_attempts[client_ip] = [1, current_time]
        else:
            failed_attempts[client_ip][0] += 1
            
        log_action("VERIFY_FAIL", f"Key: {key} IP: {client_ip} Reason: {msg}")
        return jsonify({"status": "error", "msg": msg})

# --- DİĞER API FONKSİYONLARI ---

@app.route('/api/generate_key', methods=['POST'])
@login_required
def generate_key():
    data = request.json
    duration = data.get('duration')
    is_vip = data.get('is_vip')
    
    now = datetime.datetime.now()
    days = 1
    if duration == '7_day': days = 7
    elif duration == '30_day': days = 30
    elif duration == 'lifetime': days = 3650
    
    expires_at = now + datetime.timedelta(days=days)
    prefix = "ZBH-VIP" if is_vip else "ZBH-GEN"
    key_code = f"{prefix}-{str(uuid.uuid4())[:8].upper()}"
    
    conn = get_db()
    conn.execute("INSERT INTO keys (key_code, status, expires_at, type, created_at) VALUES (?, ?, ?, ?, ?)",
                 (key_code, 'active', expires_at, 'VIP' if is_vip else 'Standard', now))
    conn.commit()
    conn.close()
    
    log_action("KEY_GENERATE", f"Key: {key_code} ({duration})", True, 0x00FFFF)
    return jsonify({"success": True})

@app.route('/api/add_mapping', methods=['POST'])
@login_required
def add_mapping():
    data = request.json
    conn = get_db()
    conn.execute("INSERT INTO mapping (game_name, place_id, script_url) VALUES (?, ?, ?)", 
                 (data['game_name'], data['place_id'], data['script_url']))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/delete_mapping', methods=['POST'])
@login_required
def delete_mapping():
    data = request.json
    conn = get_db()
    conn.execute("DELETE FROM mapping WHERE id=?", (data['id'],))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/ban_user', methods=['POST'])
@login_required
def ban_user():
    data = request.json
    conn = get_db()
    conn.execute("UPDATE keys SET status='banned' WHERE key_code=?", (data['key'],))
    conn.commit()
    conn.close()
    log_action("USER_BANNED", f"Key: {data['key']} was banned manually.", True, 0xFF0000)
    return jsonify({"success": True})

@app.route('/api/delete_user', methods=['POST'])
@login_required
def delete_user():
    data = request.json
    conn = get_db()
    conn.execute("DELETE FROM keys WHERE key_code=?", (data['key'],))
    conn.commit()
    conn.close()
    log_action("USER_DELETED", f"Key: {data['key']} was deleted.", False)
    return jsonify({"success": True})

@app.route('/api/public_key', methods=['POST'])
def public_key():
    key = generate_free_key_logic(request.remote_addr)
    return jsonify({"key": key})

@app.route('/api/panic_toggle', methods=['POST'])
@login_required
def panic_toggle():
    global IS_LOCKDOWN
    data = request.json
    if 'state' in data: IS_LOCKDOWN = data['state']
    else: IS_LOCKDOWN = not IS_LOCKDOWN
    
    log_action("PANIC_MODE", f"Lockdown set to: {IS_LOCKDOWN}", True, 0xFF0000)
    return jsonify({"success": True, "state": IS_LOCKDOWN})

@app.route('/api/heartbeat')
def heartbeat():
    return jsonify({"status": "alive", "online": True})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
