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

# =================================================================
# 1. AYARLAR, GÜVENLİK VE BAŞLANGIÇ
# =================================================================
load_dotenv()
app = Flask(__name__)

# --- ORTAM DEĞİŞKENLERİ (RENDER'DAN ALIR) ---
app.secret_key = os.getenv('SECRET_KEY', 'zbh_root_key_v1_gizli')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin') 
ADMIN_PASS = os.getenv('ADMIN_PASS', 'admin123') 
DISCORD_WEBHOOK = os.getenv('DISCORD_WEBHOOK', '')
# DATABASE_URL = os.getenv('DATABASE_URL')  <-- BUNU SİL VEYA YORUMA AL
DATABASE_URL = "postgres://sifreler:adresler@dpg-blabla-a/zbh_db" # <-- DİREKT BURAYA YAPIŞTIR

# --- GÜVENLİK AYARLARI ---
BLOCK_TIME = 600  # 10 Dakika (Saniye cinsinden) ban süresi
MAX_ATTEMPTS = 5  # Kaç kere yanlış girerse banlasın?
IS_LOCKDOWN = False # Panic Mode (Sistemi kilitleme) başlangıçta kapalı
failed_attempts = {} # Geçici hafıza (RAM) üzerinde IP takibi

# =================================================================
# 2. VERİTABANI BAĞLANTISI (POSTGRESQL - KALICI HAFIZA)
# =================================================================
def get_db_connection():
    """PostgreSQL veritabanına bağlanır."""
    if not DATABASE_URL:
        print("HATA: DATABASE_URL Environment Variable bulunamadı!")
        return None
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        return conn
    except Exception as e:
        print(f"DB Bağlantı Hatası: {e}")
        return None

def init_db():
    """Tablolar yoksa oluşturur (İlk kurulum için)."""
    try:
        conn = get_db_connection()
        if not conn: return
        cur = conn.cursor()
        
        # KEYS Tablosu (Kullanıcılar)
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
        
        # MAPPING Tablosu (Oyun - Script Eşleşmesi)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS mapping (
                id SERIAL PRIMARY KEY,
                game_name VARCHAR(100),
                place_id VARCHAR(50),
                script_url TEXT
            );
        ''')
        
        # LOGS Tablosu (Kayıt Defteri)
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
        print("✅ Veritabanı Tabloları Başarıyla Kontrol Edildi.")
    except Exception as e:
        print(f"❌ DB INIT ERROR: {e}")

# Server başlarken veritabanını kontrol et
init_db()

# =================================================================
# 3. YARDIMCI FONKSİYONLAR (LOGLAMA VE GİRİŞ KONTROLÜ)
# =================================================================
def log_action(action, details, notify_discord=False, color=0x00ff00):
    """Hem veritabanına hem Discord'a log basar."""
    try:
        # DB'ye Yaz
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO audit_logs (action, details) VALUES (%s, %s)", (action, details))
            conn.commit()
            cur.close()
            conn.close()

        # Discord'a Gönder
        if notify_discord and DISCORD_WEBHOOK:
            payload = {
                "embeds": [{
                    "title": f"🛡️ ZBH SYSTEM | {action}",
                    "description": details,
                    "color": color,
                    "footer": {"text": "Security Protocol v2.0"},
                    "timestamp": datetime.datetime.now().isoformat()
                }]
            }
            try:
                requests.post(DISCORD_WEBHOOK, json=payload, timeout=2)
            except:
                pass # Discord hatası sistemi durdurmasın
    except Exception as e:
        print(f"LOG ERROR: {e}")

def login_required(f):
    """Admin paneline giriş yapılmamışsa login sayfasına atar."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =================================================================
# 4. WEB SAYFALARI (HTML ARAYÜZÜ)
# =================================================================
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'logged_in' in session else redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Admin kullanıcı adı ve şifre kontrolü
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            log_action("ADMIN_LOGIN", f"Login successful from IP: {request.remote_addr}", True, 0x00FF00)
            return redirect(url_for('dashboard'))
        else:
            log_action("FAILED_LOGIN", f"Failed attempt from IP: {request.remote_addr}", True, 0xFF0000)
            return render_template('login.html', error="Hatalı Bilgi Aga! Zorlama kapıyı.")
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
    
    # İstatistikleri Çek
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
    # RealDictCursor sayesinde veriyi user['key_code'] şeklinde çekebiliriz
    cur = conn.cursor(cursor_factory=RealDictCursor) 
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

# =================================================================
# 5. API SİSTEMİ (ROBLOX SCRIPT'IN KONUŞTUĞU YER)
# =================================================================

@app.route('/api/verify', methods=['GET'])
def verify():
    global IS_LOCKDOWN
    client_ip = request.remote_addr
    
    # --- 1. PANIC MODE KONTROLÜ ---
    if IS_LOCKDOWN:
        return jsonify({"status": "error", "msg": "SYSTEM LOCKDOWN ACTIVE"})

    # --- 2. ANTI-SPAM (RATE LIMIT) ---
    current_time = time.time()
    if client_ip in failed_attempts:
        attempts, first_time = failed_attempts[client_ip]
        if attempts >= MAX_ATTEMPTS:
            # Süre dolmuş mu?
            if current_time - first_time < BLOCK_TIME:
                remaining = int(BLOCK_TIME - (current_time - first_time))
                return jsonify({"status": "error", "msg": f"BLOCKED: Too Many Requests ({remaining}s)"})
            else:
                del failed_attempts[client_ip] # Affet

    # --- 3. PARAMETRE KONTROLÜ ---
    key = request.args.get('key')
    hwid = request.args.get('hwid')
    place_id = request.args.get('placeid')

    if not key: return jsonify({"status": "error", "msg": "MISSING_KEY"})

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Key'i veritabanında ara
    cur.execute("SELECT * FROM keys WHERE key_code = %s", (key,))
    user = cur.fetchone()
    
    response = {"status": "error", "msg": "INVALID_KEY"}
    
    if user:
        if user['status'] == 'banned':
            response['msg'] = "ACCOUNT_BANNED"
        elif not user['hwid']:
            # İlk giriş: HWID'yi kilitle
            cur2 = conn.cursor()
            cur2.execute("UPDATE keys SET hwid = %s, ip_address = %s WHERE key_code = %s", (hwid, client_ip, key))
            conn.commit()
            cur2.close()
            response = {"status": "success", "type": user['type']}
            # Logla (Sadece ilk girişte)
            log_action("FIRST_LOGIN", f"Key: {key} bound to HWID", True, 0x00FFFF)
            
        elif user['hwid'] != hwid:
            # HWID Uyuşmazlığı
            response['msg'] = "HWID_MISMATCH"
            # Hata puanı ekle
            if client_ip not in failed_attempts: failed_attempts[client_ip] = [1, current_time]
            else: failed_attempts[client_ip][0] += 1
            log_action("SECURITY_ALERT", f"HWID Mismatch! Key: {key} IP: {client_ip}", True, 0xFF0000)
            
        else:
            # Başarılı Giriş
            response = {"status": "success", "type": user['type']}
            # Son IP'yi güncelle
            cur2 = conn.cursor()
            cur2.execute("UPDATE keys SET ip_address = %s WHERE key_code = %s", (client_ip, key))
            conn.commit()
            cur2.close()

    # --- 4. SCRIPT URL GÖNDERME ---
    if response['status'] == 'success':
        # Mapping tablosundan scripti bul
        cur.execute("SELECT script_url FROM mapping WHERE place_id = %s", (place_id,))
        script = cur.fetchone()
        
        response['script_url'] = script['script_url'] if script else ""
        
        # IP cezasını sil (Başarılı girdi çünkü)
        if client_ip in failed_attempts: del failed_attempts[client_ip]
        
        # VIP girişlerini logla (İsteğe bağlı)
        if user and user['type'] == 'VIP':
            pass # DB şişmesin diye her girişi loglamıyoruz, istersen burayı aç.

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
    # Rastgele benzersiz key üret
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
    
    log_action("KEY_GENERATE", f"Generated: {key_code} ({duration})", True, 0x00FF00)
    return jsonify({"success": True})

# --- HWID SIFIRLAMA (RESET) ---
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
    
    log_action("HWID_RESET", f"HWID Reset for: {key}", True, 0xFFA500)
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
    
    log_action("USER_BANNED", f"Banned User: {key}", True, 0xFF0000)
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
    
    log_action("USER_DELETED", f"Deleted User: {key}", False)
    return jsonify({"success": True})

# --- MAPPING (OYUN-SCRIPT) EKLEME ---
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

# --- PANIC MODE (SİSTEMİ KİLİTLE) ---
@app.route('/api/panic_toggle', methods=['POST'])
@login_required
def panic_toggle():
    global IS_LOCKDOWN
    data = request.json
    if 'state' in data: 
        IS_LOCKDOWN = data['state']
    else: 
        IS_LOCKDOWN = not IS_LOCKDOWN
    
    log_action("PANIC_MODE", f"System Lockdown: {IS_LOCKDOWN}", True, 0xFF0000)
    return jsonify({"success": True, "state": IS_LOCKDOWN})

# --- HEARTBEAT (CANLILIK KONTROLÜ) ---
@app.route('/api/heartbeat')
def heartbeat():
    return jsonify({"status": "alive", "online": True})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

