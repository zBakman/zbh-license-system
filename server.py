import os
import sqlite3
import datetime
import uuid
import logging
import hashlib
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
from dotenv import load_dotenv

# ==========================================
# 1. AYARLAR VE GÜVENLİK
# ==========================================
load_dotenv()
app = Flask(__name__)

# GÜVENLİK ANAHTARLARI (GitHub'a atarken burayı .env dosyasından çekecek)
app.secret_key = os.getenv('SECRET_KEY', 'zbh_holding_gizli_anahtar_999')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'admin123')
DB_NAME = "zbh_system.db"
SECRET_SALT = "ZBH_GHOST_PROTOCOL_78" # Free key şifreleme tuzu

# Global Panik Değişkeni (RAM'de tutulur, server kapanınca sıfırlanır)
IS_LOCKDOWN = False 

# Loglama Ayarı
logging.basicConfig(filename='system.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# ==========================================
# 2. VERİTABANI BAĞLANTISI VE KURULUMU
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # 1. Lisanslar Tablosu (Users)
    c.execute('''CREATE TABLE IF NOT EXISTS keys 
                 (key_code TEXT PRIMARY KEY, hwid TEXT, status TEXT, expires_at DATETIME, type TEXT, created_at DATETIME, ip_address TEXT)''')
    
    # 2. Mapping Tablosu (Scriptler)
    c.execute('''CREATE TABLE IF NOT EXISTS mapping
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, game_name TEXT, place_id TEXT, script_url TEXT)''')
    
    # 3. Loglar Tablosu (Audit)
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

# Server her başladığında tabloları kontrol et
init_db()

# ==========================================
# 3. YARDIMCI FONKSİYONLAR
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_action(action, details):
    try:
        conn = get_db()
        conn.execute("INSERT INTO audit_logs (action, details) VALUES (?, ?)", (action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log Error: {e}")

# Free Key Üretme Mantığı (IP + Tarih + Tuz = Hash)
def generate_free_key_logic(ip):
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    raw = f"{ip}{today}{SECRET_SALT}"
    # SHA256 ile şifrele ve ilk 12 karakteri al
    hashed = hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
    return f"ZBH-FREE-{hashed}"

# ==========================================
# 4. VİTRİN (HTML SAYFALARI)
# ==========================================

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            log_action("LOGIN", f"Admin access granted from {request.remote_addr}")
            return redirect(url_for('dashboard'))
        else:
            log_action("FAILED_LOGIN", f"Failed attempt from {request.remote_addr}")
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
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
    conn.close()
    return render_template('audit_logs.html', logs=logs, active_page='audit_logs')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', active_page='settings')

# FREE KEY SAYFASI (Müşteri Vitrini)
@app.route('/free-key')
def free_key_page():
    return render_template('free_key.html')

# ==========================================
# 5. API MOTORU (LUA & PANEL İLETİŞİMİ)
# ==========================================

# 1. DOĞRULAMA (Start.lua Buraya Sorar)
@app.route('/api/verify', methods=['GET'])
def verify():
    global IS_LOCKDOWN
    if IS_LOCKDOWN:
        return jsonify({"status": "error", "msg": "SYSTEM LOCKDOWN ACTIVE"})

    key = request.args.get('key')
    hwid = request.args.get('hwid')
    place_id = request.args.get('placeid')
    client_ip = request.remote_addr

    if not key:
        return jsonify({"status": "error", "msg": "MISSING KEY"})

    # --- A. FREE KEY KONTROLÜ ---
    if key.startswith("ZBH-FREE"):
        expected = generate_free_key_logic(client_ip)
        
        # IP Kontrolü: Eğer VPN açıp kapattıysa IP değişir, key geçersiz olur.
        if key != expected:
             return jsonify({"status": "error", "msg": "INVALID FREE KEY (IP MISMATCH)"})
        
        # Free user için script bul (Mapping Tablosundan)
        conn = get_db()
        script_row = conn.execute("SELECT script_url FROM mapping WHERE place_id=?", (place_id,)).fetchone()
        conn.close()
        
        script_url = script_row[0] if script_row else ""
        return jsonify({"status": "success", "type": "Free", "script_url": script_url})

    # --- B. VIP/NORMAL KEY KONTROLÜ ---
    conn = get_db()
    user = conn.execute("SELECT * FROM keys WHERE key_code=?", (key,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({"status": "error", "msg": "KEY NOT FOUND"})
    
    if user['status'] == 'banned':
        conn.close()
        return jsonify({"status": "error", "msg": "ACCOUNT BANNED"})
    
    # Süre Kontrolü
    if user['expires_at']:
        try:
            expire_date = datetime.datetime.strptime(user['expires_at'], '%Y-%m-%d %H:%M:%S.%f')
            if datetime.datetime.now() > expire_date:
                conn.close()
                return jsonify({"status": "error", "msg": "KEY EXPIRED"})
        except:
            pass # Tarih formatı hatası olursa (eski veri) geç

    # HWID Kilitleme
    if not user['hwid']:
        conn.execute("UPDATE keys SET hwid=?, ip_address=? WHERE key_code=?", (hwid, client_ip, key))
        conn.commit()
    elif user['hwid'] != hwid:
        conn.close()
        return jsonify({"status": "error", "msg": "HWID MISMATCH"})

    # Scripti Bul
    script_row = conn.execute("SELECT script_url FROM mapping WHERE place_id=?", (place_id,)).fetchone()
    script_url = script_row[0] if script_row else ""
    
    conn.close()
    return jsonify({
        "status": "success", 
        "type": user['type'], 
        "script_url": script_url
    })

# 2. KEY ÜRETME (Panelden)
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
    log_action("KEY_GENERATE", f"Key: {key_code} ({duration})")
    return jsonify({"success": True})

# 3. MAPPING (Script Ekle/Sil)
@app.route('/api/add_mapping', methods=['POST'])
@login_required
def add_mapping():
    data = request.json
    conn = get_db()
    try:
        conn.execute("INSERT INTO mapping (game_name, place_id, script_url) VALUES (?, ?, ?)",
                     (data['game_name'], data['place_id'], data['script_url']))
        conn.commit()
        log_action("MAP_ADD", f"Game: {data['game_name']} ID: {data['place_id']}")
        success = True
    except Exception as e:
        success = False
        print(e)
    finally:
        conn.close()
    return jsonify({"success": success})

@app.route('/api/delete_mapping', methods=['POST'])
@login_required
def delete_mapping():
    data = request.json
    conn = get_db()
    conn.execute("DELETE FROM mapping WHERE id=?", (data['id'],))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# 4. YÖNETİM (Ban/Sil)
@app.route('/api/ban_user', methods=['POST'])
@login_required
def ban_user():
    data = request.json
    conn = get_db()
    conn.execute("UPDATE keys SET status='banned' WHERE key_code=?", (data['key'],))
    conn.commit()
    conn.close()
    log_action("BAN_USER", f"Target: {data['key']}")
    return jsonify({"success": True})

@app.route('/api/delete_user', methods=['POST'])
@login_required
def delete_user():
    data = request.json
    conn = get_db()
    conn.execute("DELETE FROM keys WHERE key_code=?", (data['key'],))
    conn.commit()
    conn.close()
    log_action("DELETE_USER", f"Target: {data['key']}")
    return jsonify({"success": True})

# 5. PUBLIC KEY API (Free Key Sayfası İçin)
@app.route('/api/public_key', methods=['POST'])
def public_key():
    # Bu API, free_key.html sayfasından çağrılır ve o anki IP'ye özel key üretir.
    key = generate_free_key_logic(request.remote_addr)
    return jsonify({"key": key})

# 6. PANIC MODE (LOCKDOWN)
@app.route('/api/panic_toggle', methods=['POST'])
@login_required
def panic_toggle():
    global IS_LOCKDOWN
    data = request.json
    # True/False gelmezse mevcut durumu tersine çevir
    if 'state' in data:
        IS_LOCKDOWN = data['state']
    else:
        IS_LOCKDOWN = not IS_LOCKDOWN
        
    log_action("PANIC_MODE", f"Lockdown set to: {IS_LOCKDOWN}")
    return jsonify({"success": True, "state": IS_LOCKDOWN})
    # --- HEARTBEAT API (CANLI NABIZ) ---
    @app.route('/api/heartbeat')
    def heartbeat():
        return jsonify({"status": "alive", "online": True})
    
if __name__ == '__main__':
    # 0.0.0.0 ile dış dünyaya açılır (Port açtıysan veya Render'da)
    # Port env'den alınır, yoksa 5000 kullanılır
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)