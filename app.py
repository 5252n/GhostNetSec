import nmap
import threading
import time
import datetime
import json
import os
import subprocess
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g
from flask_socketio import SocketIO, emit
from scapy.all import ARP, Ether, srp
import pytz
from datetime import timedelta
import socket
import netifaces
import psutil
import platform
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['DATABASE'] = 'ghostnetsec.db'
app.config['LOG_FILE'] = 'ghostnetsec.log'

# Configure logging
handler = RotatingFileHandler(app.config['LOG_FILE'], maxBytes=100000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

socketio = SocketIO(app, logger=True, engineio_logger=True)

# Database functions
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                email TEXT,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT UNIQUE NOT NULL,
                hostname TEXT,
                vendor TEXT,
                os TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_trusted INTEGER DEFAULT 0,
                threat_level INTEGER DEFAULT 0,
                ports TEXT,
                services TEXT,
                vulnerabilities TEXT,
                notes TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY(device_id) REFERENCES devices(id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                source_mac TEXT,
                destination_ip TEXT,
                destination_mac TEXT,
                port INTEGER,
                protocol TEXT,
                size INTEGER,
                timestamp TEXT NOT NULL,
                flagged INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            hashed_pw = generate_password_hash('admin123')
            cursor.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                ('admin', hashed_pw, 'admin', 'admin@ghostnetsec.local')
            )
        
        db.commit()

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Security functions
def log_event(user_id, action, details=None):
    try:
        ip_address = request.remote_addr
        db = get_db()
        db.execute(
            "INSERT INTO system_logs (user_id, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, action, details, ip_address, datetime.datetime.now(pytz.utc).isoformat())
        )
        db.commit()
    except Exception as e:
        app.logger.error(f"Failed to log event: {str(e)}")

def check_lockout(username):
    db = get_db()
    user = db.execute(
        "SELECT locked_until FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    
    if user and user['locked_until']:
        lock_time = datetime.datetime.fromisoformat(user['locked_until'])
        if datetime.datetime.now(pytz.utc) < lock_time:
            return True
    return False

# Network monitoring functions
class NetworkMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True
        self.scan_interval = 300  # 5 minutes
        self.last_scan = None
        self.nm = nmap.PortScanner()
    
    def run(self):
        while self.running:
            try:
                self.scan_network()
                time.sleep(self.scan_interval)
            except Exception as e:
                app.logger.error(f"Network monitor error: {str(e)}")
                time.sleep(60)
    
    def scan_network(self):
        app.logger.info("Starting network scan...")
        current_time = datetime.datetime.now(pytz.utc).isoformat()
        
        try:
            # Get local network interface information
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface == 'lo':
                    continue
                
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        if 'addr' in addr_info and 'netmask' in addr_info:
                            ip = addr_info['addr']
                            netmask = addr_info['netmask']
                            network = self.calculate_network(ip, netmask)
                            
                            # Perform scan on this network
                            self.perform_scan(network, current_time)
        
        except Exception as e:
            app.logger.error(f"Network scan failed: {str(e)}")
        
        self.last_scan = current_time
        socketio.emit('scan_complete', {'time': current_time})
    
    def calculate_network(self, ip, netmask):
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, netmask.split('.')))
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
    
    def perform_scan(self, network, timestamp):
        try:
            self.nm.scan(hosts=network, arguments='-sn -T4 --max-retries 1 --host-timeout 30s')
            
            for host in self.nm.all_hosts():
                if 'mac' in self.nm[host]['addresses']:
                    mac = self.nm[host]['addresses']['mac']
                    ip = host
                    hostname = self.nm[host].hostname() if 'hostname' in self.nm[host] else ''
                    vendor = self.nm[host]['vendor'].get(mac, '') if 'vendor' in self.nm[host] else ''
                    
                    # Check if device exists
                    db = get_db()
                    device = db.execute(
                        "SELECT id, ip, is_trusted FROM devices WHERE mac = ?",
                        (mac,)
                    ).fetchone()
                    
                    if device:
                        # Update existing device
                        if device['ip'] != ip:
                            # IP change detected
                            db.execute(
                                "UPDATE devices SET ip = ?, last_seen = ? WHERE id = ?",
                                (ip, timestamp, device['id'])
                            )
                            
                            # Create alert
                            alert_msg = f"IP change detected for {mac}. Old IP: {device['ip']}, New IP: {ip}"
                            db.execute(
                                "INSERT INTO alerts (device_id, alert_type, severity, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                                (device['id'], 'IP Change', 'Medium', alert_msg, timestamp)
                            )
                            
                            # Log event
                            log_event(None, 'device_ip_change', 
                                    f"Device {mac} changed IP from {device['ip']} to {ip}")
                        else:
                            # Just update last seen
                            db.execute(
                                "UPDATE devices SET last_seen = ? WHERE id = ?",
                                (timestamp, device['id'])
                            )
                    else:
                        # New device detected
                        db.execute(
                            "INSERT INTO devices (ip, mac, hostname, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                            (ip, mac, hostname, vendor, timestamp, timestamp)
                        )
                        device_id = db.lastrowid
                        
                        # Create alert
                        alert_msg = f"New device detected: {mac} ({ip})"
                        db.execute(
                            "INSERT INTO alerts (device_id, alert_type, severity, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                            (device_id, 'New Device', 'High', alert_msg, timestamp)
                        )
                        
                        # Log event
                        log_event(None, 'new_device_detected', 
                                f"New device detected: MAC {mac}, IP {ip}")
                    
                    db.commit()
                    socketio.emit('device_update', {'ip': ip, 'mac': mac, 'status': 'online'})
        
        except Exception as e:
            app.logger.error(f"Error scanning network {network}: {str(e)}")
    
    def stop(self):
        self.running = False

# Initialize network monitor
network_monitor = NetworkMonitor()
network_monitor.start()

# Threat detection functions
def detect_anomalies():
    """Analyze network traffic and device behavior for anomalies"""
    db = get_db()
    
    # Check for devices that haven't been seen recently
    threshold = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours=24)
    missing_devices = db.execute(
        "SELECT id, ip, mac FROM devices WHERE last_seen < ?",
        (threshold.isoformat(),)
    ).fetchall()
    
    for device in missing_devices:
        alert_msg = f"Device {device['mac']} ({device['ip']}) has not been seen for 24 hours"
        db.execute(
            "INSERT INTO alerts (device_id, alert_type, severity, message, timestamp) VALUES (?, ?, ?, ?, ?)",
            (device['id'], 'Device Missing', 'Medium', alert_msg, datetime.datetime.now(pytz.utc).isoformat())
        )
    
    # Check for suspicious port activity
    suspicious_ports = db.execute(
        """SELECT DISTINCT source_mac, port, COUNT(*) as count 
           FROM network_events 
           WHERE port IN (22, 23, 3389, 5900) 
           AND timestamp > datetime('now', '-1 hour')
           GROUP BY source_mac, port
           HAVING count > 10"""
    ).fetchall()
    
    for event in suspicious_ports:
        device = db.execute(
            "SELECT id, ip FROM devices WHERE mac = ?",
            (event['source_mac'],)
        ).fetchone()
        
        if device:
            alert_msg = f"Suspicious port activity detected from {event['source_mac']} on port {event['port']} ({event['count']} attempts)"
            db.execute(
                "INSERT INTO alerts (device_id, alert_type, severity, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                (device['id'], 'Suspicious Activity', 'High', alert_msg, datetime.datetime.now(pytz.utc).isoformat())
            )
    
    db.commit()

# Routes
@app.route('/')
@login_required
def dashboard():
    db = get_db()
    
    # Get system stats
    stats = {
        'total_devices': db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        'trusted_devices': db.execute("SELECT COUNT(*) FROM devices WHERE is_trusted = 1").fetchone()[0],
        'alerts_24h': db.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-1 day')").fetchone()[0],
        'high_alerts': db.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'High' AND timestamp > datetime('now', '-1 day')").fetchone()[0],
    }
    
    # Get recent alerts
    recent_alerts = db.execute(
        """SELECT a.id, a.alert_type, a.severity, a.message, a.timestamp, d.ip, d.mac 
           FROM alerts a LEFT JOIN devices d ON a.device_id = d.id 
           ORDER BY a.timestamp DESC LIMIT 10"""
    ).fetchall()
    
    # Get device distribution by vendor
    vendors = db.execute(
        "SELECT vendor, COUNT(*) as count FROM devices GROUP BY vendor ORDER BY count DESC LIMIT 10"
    ).fetchall()
    
    # Get system information
    system_info = {
        'hostname': socket.gethostname(),
        'os': platform.platform(),
        'cpu': f"{psutil.cpu_percent()}%",
        'memory': f"{psutil.virtual_memory().percent}%",
        'disk': f"{psutil.disk_usage('/').percent}%",
        'last_scan': network_monitor.last_scan
    }
    
    return render_template('dashboard.html', 
                         stats=stats,
                         recent_alerts=recent_alerts,
                         vendors=vendors,
                         system_info=system_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_page = request.args.get('next')
        
        # Check if account is locked
        if check_lockout(username):
            flash('Account temporarily locked due to too many failed attempts. Try again later.', 'danger')
            return redirect(url_for('login'))
        
        db = get_db()
        user = db.execute(
            "SELECT id, username, password, role, failed_attempts FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # Successful login
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Reset failed attempts
            db.execute(
                "UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?",
                (datetime.datetime.now(pytz.utc).isoformat(), user['id'])
            )
            db.commit()
            
            log_event(user['id'], 'login_success')
            flash('Login successful!', 'success')
            
            return redirect(next_page or url_for('dashboard'))
        else:
            # Failed login
            if user:
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 5:
                    lock_time = datetime.datetime.now(pytz.utc) + datetime.timedelta(minutes=15)
                    db.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                        (failed_attempts, lock_time.isoformat(), user['id'])
                    )
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                else:
                    db.execute(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?",
                        (failed_attempts, user['id'])
                    )
            db.commit()
            
            log_event(None, 'login_failed', f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_event(session['user_id'], 'logout')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Device management routes
@app.route('/api/acknowledge_alert', methods=['POST'])
@login_required
def api_acknowledge_alert():
    data = request.get_json()
    alert_id = data.get('alert_id')
    
    db = get_db()
    db.execute(
        "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
        (alert_id,)
    )
    db.commit()
    db.close()
    
    log_event(session['user_id'], 'alert_acknowledged', f"Acknowledged alert {alert_id}")
    return jsonify({'status': 'success'})
@app.route('/alerts')
@login_required
def alerts():
    db = get_db()
    alerts = db.execute(
        """SELECT a.id, a.alert_type, a.severity, a.message, a.timestamp, d.ip, d.mac 
           FROM alerts a LEFT JOIN devices d ON a.device_id = d.id 
           ORDER BY a.timestamp DESC"""
    ).fetchall()
    db.close()
    return render_template('alerts.html', alerts=alerts)
@app.route('/devices')
@login_required
def devices():
    db = get_db()
    devices = db.execute(
        "SELECT id, ip, mac, hostname, vendor, is_trusted, threat_level, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
    ).fetchall()
    return render_template('devices.html', devices=devices)

@app.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    db = get_db()
    
    device = db.execute(
        "SELECT id, ip, mac, hostname, vendor, os, is_trusted, threat_level, first_seen, last_seen, ports, services, vulnerabilities, notes FROM devices WHERE id = ?",
        (device_id,)
    ).fetchone()
    
    if not device:
        flash('Device not found', 'danger')
        return redirect(url_for('devices'))
    
    alerts = db.execute(
        "SELECT id, alert_type, severity, message, timestamp FROM alerts WHERE device_id = ? ORDER BY timestamp DESC LIMIT 50",
        (device_id,)
    ).fetchall()
    
    events = db.execute(
        """SELECT id, event_type, source_ip, destination_ip, port, protocol, size, timestamp 
           FROM network_events 
           WHERE source_mac = ? OR destination_mac = ?
           ORDER BY timestamp DESC LIMIT 50""",
        (device['mac'], device['mac'])
    ).fetchall()
    
    return render_template('device_detail.html', device=device, alerts=alerts, events=events)

# API endpoints
@app.route('/api/devices', methods=['GET'])
@login_required
def api_devices():
    db = get_db()
    devices = db.execute(
        "SELECT id, ip, mac, hostname, vendor, is_trusted, threat_level FROM devices"
    ).fetchall()
    return jsonify([dict(device) for device in devices])

@app.route('/api/device/<int:device_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_device(device_id):
    db = get_db()
    
    if request.method == 'GET':
        device = db.execute(
            "SELECT id, ip, mac, hostname, vendor, is_trusted, threat_level, first_seen, last_seen FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()
        
        if device:
            return jsonify(dict(device))
        return jsonify({'error': 'Device not found'}), 404
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        updates = []
        params = []
        
        for field in ['hostname', 'vendor', 'is_trusted', 'threat_level', 'notes']:
            if field in data:
                updates.append(f"{field} = ?")
                params.append(data[field])
        
        if updates:
            params.append(device_id)
            query = f"UPDATE devices SET {', '.join(updates)} WHERE id = ?"
            db.execute(query, params)
            db.commit()
            
            log_event(session['user_id'], 'device_updated', f"Updated device {device_id}")
            return jsonify({'status': 'success'})
        
        return jsonify({'error': 'No valid fields to update'}), 400
    
    elif request.method == 'DELETE':
        db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        db.commit()
        
        log_event(session['user_id'], 'device_deleted', f"Deleted device {device_id}")
        return jsonify({'status': 'success'})

# System management routes
@app.route('/api/users', methods=['POST'])
@admin_required
def api_create_user():
    data = request.get_json()
    
    db = get_db()
    try:
        hashed_pw = generate_password_hash(data['password'])
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (data['username'], data.get('email'), hashed_pw, data['role'])
        )
        db.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        db.close()

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def api_user(user_id):
    db = get_db()
    
    if request.method == 'GET':
        user = db.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        return jsonify(dict(user)) if user else jsonify({'error': 'User not found'}), 404
    
    elif request.method == 'PUT':
        data = request.get_json()
        updates = []
        params = []
        
        if 'email' in data:
            updates.append("email = ?")
            params.append(data['email'])
        
        if 'role' in data:
            updates.append("role = ?")
            params.append(data['role'])
        
        if 'password' in data and data['password']:
            updates.append("password = ?")
            params.append(generate_password_hash(data['password']))
        
        if updates:
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            db.execute(query, params)
            db.commit()
        
        return jsonify({'status': 'success'})
    
    elif request.method == 'DELETE':
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        return jsonify({'status': 'success'})
    
    db.close()
@app.route('/api/settings', methods=['POST'])
@admin_required
def api_save_settings():
    data = request.get_json()
    # Here you would typically save these settings to a configuration file or database
    # For now, we'll just log them
    app.logger.info(f"Settings updated: {data}")
    return jsonify({'status': 'success'})
@app.route('/settings')
@admin_required
def settings():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, email, last_login FROM users ORDER BY username"
    ).fetchall()
    
    system_stats = {
        'devices': db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        'alerts': db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        'events': db.execute("SELECT COUNT(*) FROM network_events").fetchone()[0],
        'logs': db.execute("SELECT COUNT(*) FROM system_logs").fetchone()[0],
    }
    
    db.close()
    return render_template('settings.html', users=users, system_stats=system_stats)

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        emit('connection_response', {'status': 'authenticated', 'username': session['username']})
    else:
        emit('connection_response', {'status': 'unauthenticated'})

@socketio.on('request_device_update')
def handle_device_update_request():
    db = get_db()
    devices = db.execute(
        "SELECT id, ip, mac, hostname, is_trusted FROM devices ORDER BY last_seen DESC LIMIT 50"
    ).fetchall()
    emit('device_update', {'devices': [dict(device) for device in devices]})

# Scheduled tasks
def schedule_daily_tasks():
    while True:
        try:
            now = datetime.datetime.now(pytz.utc)
            
            # Run threat detection every hour
            if now.minute == 0:
                detect_anomalies()
            
            # Daily maintenance at 2 AM
            if now.hour == 2 and now.minute == 0:
                perform_maintenance()
            
            time.sleep(60)  # Check every minute
        
        except Exception as e:
            app.logger.error(f"Scheduled task error: {str(e)}")
            time.sleep(300)

def perform_maintenance():
    """Perform daily database maintenance"""
    db = get_db()
    
    # Archive old alerts (older than 30 days)
    db.execute("DELETE FROM alerts WHERE timestamp < datetime('now', '-30 days')")
    
    # Archive old network events (older than 7 days)
    db.execute("DELETE FROM network_events WHERE timestamp < datetime('now', '-7 days')")
    
    # Optimize database
    db.execute("VACUUM")
    db.commit()
    
    app.logger.info("Daily maintenance completed")

# Start scheduled tasks thread
scheduler_thread = threading.Thread(target=schedule_daily_tasks)
scheduler_thread.daemon = True
scheduler_thread.start()

if __name__ == '__main__':
    # Initialize database
    with app.app_context():
        init_db()
    
    # Start the application
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)