import sqlite3
import json
from datetime import datetime
import bcrypt
import re
import os

DB_NAME = os.path.join(os.path.dirname(__file__), 'sharanga.db')

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Assets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_number TEXT UNIQUE NOT NULL,
                device_name TEXT,
                username TEXT,
                domain TEXT,
                os_name TEXT,
                os_version TEXT,
                ip_address TEXT,
                ram_gb REAL,
                system_manufacturer TEXT,
                system_model TEXT,
                mac_address TEXT,
                connection_type TEXT,
                last_scan_time TIMESTAMP,
                risk_score INTEGER DEFAULT 0,
                total_apps INTEGER DEFAULT 0,
                total_processes INTEGER DEFAULT 0,
                suspicious_processes INTEGER DEFAULT 0,
                scan_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan History table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_score INTEGER,
                suspicious_processes INTEGER,
                total_apps INTEGER,
                total_processes INTEGER,
                full_data TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
            )
        ''')
        
        # Default Admin
        admin = cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            password_hash = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt())
            cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                          ('admin', password_hash, 'admin'))
            print("✅ Default admin created: admin / admin123")
        
        # Default User
        user = cursor.execute('SELECT * FROM users WHERE username = ?', ('user',)).fetchone()
        if not user:
            password_hash = bcrypt.hashpw('user123'.encode(), bcrypt.gensalt())
            cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                          ('user', password_hash, 'user'))
            print("✅ Default user created: user / user123")
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully!")
        return True
    except Exception as e:
        print(f"❌ Database init error: {e}")
        import traceback
        traceback.print_exc()
        return False

def generate_asset_number(device_name=None):
    if device_name:
        asset_num = device_name.upper().replace(' ', '_').replace('-', '_')
        asset_num = re.sub(r'[^A-Z0-9_]', '', asset_num)
        if not asset_num:
            asset_num = "UNKNOWN"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        existing = cursor.execute('SELECT asset_number FROM assets WHERE asset_number = ?', (asset_num,)).fetchone()
        conn.close()
        
        if existing:
            return existing['asset_number']
        return asset_num
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM assets')
        count = cursor.fetchone()['count']
        conn.close()
        return f"SHAR-{str(count + 1).zfill(4)}"

def save_scan_data(asset_number, scan_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    device = scan_data.get('device', {})
    network = scan_data.get('network', {})
    stats = scan_data.get('stats', {})
    
    existing = cursor.execute('SELECT * FROM assets WHERE asset_number = ?', (asset_number,)).fetchone()
    
    if existing:
        cursor.execute('''
            UPDATE assets SET
                device_name = ?, username = ?, domain = ?, os_name = ?, os_version = ?,
                ip_address = ?, ram_gb = ?, system_manufacturer = ?, system_model = ?,
                mac_address = ?, connection_type = ?, last_scan_time = ?,
                risk_score = ?, total_apps = ?, total_processes = ?, suspicious_processes = ?,
                scan_data = ?, updated_at = CURRENT_TIMESTAMP
            WHERE asset_number = ?
        ''', (
            device.get('device_name'), device.get('username'), device.get('domain'),
            device.get('os_name'), device.get('os_release'), device.get('ip_address'),
            device.get('ram_gb'), device.get('system_manufacturer'), device.get('system_model'),
            network.get('mac_address'), network.get('connection_type'),
            datetime.now().isoformat(), stats.get('risk_score', 0), stats.get('total_apps', 0),
            stats.get('total_processes', 0), stats.get('suspicious_processes', 0),
            json.dumps(scan_data, default=str), asset_number
        ))
    else:
        cursor.execute('''
            INSERT INTO assets (
                asset_number, device_name, username, domain, os_name, os_version,
                ip_address, ram_gb, system_manufacturer, system_model,
                mac_address, connection_type, last_scan_time, risk_score,
                total_apps, total_processes, suspicious_processes, scan_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset_number, device.get('device_name'), device.get('username'),
            device.get('domain'), device.get('os_name'), device.get('os_release'),
            device.get('ip_address'), device.get('ram_gb'), device.get('system_manufacturer'),
            device.get('system_model'), network.get('mac_address'), network.get('connection_type'),
            datetime.now().isoformat(), stats.get('risk_score', 0),
            stats.get('total_apps', 0), stats.get('total_processes', 0),
            stats.get('suspicious_processes', 0), json.dumps(scan_data, default=str)
        ))
    
    conn.commit()
    conn.close()

def get_all_assets():
    conn = get_db_connection()
    cursor = conn.cursor()
    assets = cursor.execute('SELECT * FROM assets ORDER BY updated_at DESC').fetchall()
    conn.close()
    return [dict(a) for a in assets]

def get_asset_by_number(asset_number):
    conn = get_db_connection()
    cursor = conn.cursor()
    asset = cursor.execute('SELECT * FROM assets WHERE asset_number = ?', (asset_number,)).fetchone()
    conn.close()
    return dict(asset) if asset else None

def get_scan_history(asset_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    history = cursor.execute('''
        SELECT * FROM scan_history WHERE asset_id = ? ORDER BY scan_time DESC LIMIT 20
    ''', (asset_id,)).fetchall()
    conn.close()
    return [dict(h) for h in history]

if __name__ == '__main__':
    init_db()