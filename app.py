#!/usr/bin/env python3
"""
WiFi Billing System - Main Application
FreeRADIUS + Multi-Router + Admin Panel
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import subprocess
import secrets
import string
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration file path
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

def load_config():
    """Load configuration from file"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def get_database_uri():
    """Get database URI from config or environment"""
    config = load_config()
    if config.get('database'):
        db_config = config['database']
        return f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config.get('port', 3306)}/{db_config['name']}"
    return os.environ.get('DATABASE_URL', 'mysql+pymysql://radius:radius@localhost/radius')

def is_configured():
    """Check if system is configured"""
    config = load_config()
    return config.get('configured', False)

# Set database URI
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ============================================
# DATABASE MODELS
# ============================================

class AdminUser(UserMixin, db.Model):
    __tablename__ = 'admin_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100))
    role = db.Column(db.Enum('superadmin', 'admin', 'operator'), default='operator')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class NAS(db.Model):
    """Network Access Servers (Routers)"""
    __tablename__ = 'nas'
    id = db.Column(db.Integer, primary_key=True)
    nasname = db.Column(db.String(128), nullable=False)  # IP Address
    shortname = db.Column(db.String(32))
    type = db.Column(db.String(30), default='other')
    ports = db.Column(db.Integer)
    secret = db.Column(db.String(60), nullable=False)
    server = db.Column(db.String(64))
    community = db.Column(db.String(50))
    description = db.Column(db.String(200))
    coa_port = db.Column(db.Integer, default=3799)
    status = db.Column(db.Enum('active', 'inactive'), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)  # Last RADIUS request from this NAS
    # MikroTik API settings for NAT environments
    api_enabled = db.Column(db.Boolean, default=False)
    api_ip = db.Column(db.String(128))  # Public IP or different IP for API
    api_port = db.Column(db.Integer, default=8728)
    api_username = db.Column(db.String(64))
    api_password = db.Column(db.String(128))
    # WireGuard VPN settings
    wg_enabled = db.Column(db.Boolean, default=False)
    wg_public_key = db.Column(db.String(64))
    wg_preshared_key = db.Column(db.String(64))
    wg_allowed_ip = db.Column(db.String(32))  # e.g., 10.10.0.2/32
    wg_endpoint = db.Column(db.String(128))   # Public IP:Port if known
    
    def get_connection_status(self):
        """Check if router is reachable and has recent RADIUS activity"""
        import subprocess
        import platform
        
        # Check ping
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            result = subprocess.run(
                ['ping', param, '1', '-W', '2', self.nasname],
                capture_output=True, timeout=5
            )
            is_reachable = result.returncode == 0
        except:
            is_reachable = False
        
        # Check last RADIUS activity
        last_activity = RadAcct.query.filter_by(nasipaddress=self.nasname).order_by(
            RadAcct.acctstarttime.desc()
        ).first()
        
        has_recent_activity = False
        if last_activity and last_activity.acctstarttime:
            time_diff = (datetime.utcnow() - last_activity.acctstarttime).total_seconds()
            has_recent_activity = time_diff < 3600  # Activity in last hour
        
        # Active sessions count
        active_sessions = RadAcct.query.filter(
            RadAcct.nasipaddress == self.nasname,
            RadAcct.acctstoptime.is_(None)
        ).count()
        
        return {
            'reachable': is_reachable,
            'has_recent_activity': has_recent_activity,
            'last_activity': last_activity.acctstarttime if last_activity else None,
            'active_sessions': active_sessions,
            'status': 'online' if is_reachable and has_recent_activity else ('reachable' if is_reachable else 'offline')
        }


class BandwidthPlan(db.Model):
    __tablename__ = 'bandwidth_plans'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    download_speed = db.Column(db.Integer, nullable=False)  # Kbps
    upload_speed = db.Column(db.Integer, nullable=False)    # Kbps
    data_limit = db.Column(db.BigInteger, default=0)        # Bytes, 0 = unlimited
    description = db.Column(db.String(200))
    price = db.Column(db.Numeric(10, 2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class VoucherBatch(db.Model):
    __tablename__ = 'voucher_batches'
    id = db.Column(db.Integer, primary_key=True)
    batch_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('bandwidth_plans.id'))
    duration_minutes = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), default=0)
    created_by = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    plan = db.relationship('BandwidthPlan', backref='batches')
    creator = db.relationship('AdminUser', backref='batches')


class Voucher(db.Model):
    __tablename__ = 'vouchers'
    id = db.Column(db.Integer, primary_key=True)
    voucher_code = db.Column(db.String(20), unique=True, nullable=False)
    batch_id = db.Column(db.Integer, db.ForeignKey('voucher_batches.id'))
    plan_id = db.Column(db.Integer, db.ForeignKey('bandwidth_plans.id'))
    duration_minutes = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum('unused', 'active', 'expired', 'disabled'), default='unused')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activated_at = db.Column(db.DateTime)
    expiry_at = db.Column(db.DateTime)
    used_by_mac = db.Column(db.String(17))
    nas_id = db.Column(db.Integer, db.ForeignKey('nas.id'))
    
    batch = db.relationship('VoucherBatch', backref='vouchers')
    plan = db.relationship('BandwidthPlan', backref='vouchers')
    nas = db.relationship('NAS', backref='vouchers')


class RadAcct(db.Model):
    """RADIUS Accounting - Active Sessions"""
    __tablename__ = 'radacct'
    radacctid = db.Column(db.BigInteger, primary_key=True)
    acctsessionid = db.Column(db.String(64), nullable=False)
    acctuniqueid = db.Column(db.String(32))
    username = db.Column(db.String(64), nullable=False)
    nasipaddress = db.Column(db.String(15), nullable=False)
    nasportid = db.Column(db.String(32))
    acctstarttime = db.Column(db.DateTime)
    acctstoptime = db.Column(db.DateTime)
    acctsessiontime = db.Column(db.Integer)
    acctinputoctets = db.Column(db.BigInteger, default=0)
    acctoutputoctets = db.Column(db.BigInteger, default=0)
    calledstationid = db.Column(db.String(50))
    callingstationid = db.Column(db.String(50))
    acctterminatecause = db.Column(db.String(32))
    framedipaddress = db.Column(db.String(15))


class RadCheck(db.Model):
    """RADIUS Check attributes"""
    __tablename__ = 'radcheck'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, default='')
    attribute = db.Column(db.String(64), nullable=False, default='')
    op = db.Column(db.String(2), nullable=False, default='==')
    value = db.Column(db.String(253), nullable=False, default='')


class RadReply(db.Model):
    """RADIUS Reply attributes"""
    __tablename__ = 'radreply'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, default='')
    attribute = db.Column(db.String(64), nullable=False, default='')
    op = db.Column(db.String(2), nullable=False, default='=')
    value = db.Column(db.String(253), nullable=False, default='')


class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('AdminUser', backref='activities')


# ============================================
# HELPER FUNCTIONS
# ============================================

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))


def generate_voucher_code(length=8, prefix=''):
    chars = string.ascii_uppercase + string.digits
    code = ''.join(secrets.choice(chars) for _ in range(length))
    return f"{prefix}{code}" if prefix else code


def log_activity(action, details=None):
    log = ActivityLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()


def send_coa_disconnect(nas_ip, nas_secret, username, coa_port=3799):
    """Send CoA Disconnect-Request to NAS"""
    try:
        cmd = f'echo "User-Name={username}" | radclient -x {nas_ip}:{coa_port} disconnect {nas_secret}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        print(f"CoA Error: {e}")
        return False


def mikrotik_api_disconnect(api_ip, api_port, api_user, api_pass, username):
    """Disconnect user via MikroTik API - works through NAT with port forwarding"""
    import socket
    import hashlib
    import binascii
    
    try:
        # Connect to MikroTik API
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((api_ip, api_port))
        
        def encode_length(length):
            if length < 0x80:
                return bytes([length])
            elif length < 0x4000:
                return bytes([((length >> 8) | 0x80), (length & 0xFF)])
            elif length < 0x200000:
                return bytes([((length >> 16) | 0xC0), ((length >> 8) & 0xFF), (length & 0xFF)])
            elif length < 0x10000000:
                return bytes([((length >> 24) | 0xE0), ((length >> 16) & 0xFF), ((length >> 8) & 0xFF), (length & 0xFF)])
            else:
                return bytes([0xF0, ((length >> 24) & 0xFF), ((length >> 16) & 0xFF), ((length >> 8) & 0xFF), (length & 0xFF)])
        
        def send_word(word):
            sock.send(encode_length(len(word)) + word.encode('utf-8'))
        
        def send_sentence(words):
            for word in words:
                send_word(word)
            sock.send(b'\x00')
        
        def read_length():
            c = sock.recv(1)[0]
            if c < 0x80:
                return c
            elif c < 0xC0:
                return ((c & 0x3F) << 8) + sock.recv(1)[0]
            elif c < 0xE0:
                c2 = sock.recv(2)
                return ((c & 0x1F) << 16) + (c2[0] << 8) + c2[1]
            elif c < 0xF0:
                c2 = sock.recv(3)
                return ((c & 0x0F) << 24) + (c2[0] << 16) + (c2[1] << 8) + c2[2]
            else:
                c2 = sock.recv(4)
                return (c2[0] << 24) + (c2[1] << 16) + (c2[2] << 8) + c2[3]
        
        def read_sentence():
            words = []
            while True:
                length = read_length()
                if length == 0:
                    break
                words.append(sock.recv(length).decode('utf-8'))
            return words
        
        # Login
        send_sentence(['/login', f'=name={api_user}', f'=password={api_pass}'])
        response = read_sentence()
        
        if '!done' not in response:
            sock.close()
            return False
        
        # Find and remove hotspot active user
        send_sentence(['/ip/hotspot/active/print', f'?user={username}'])
        response = read_sentence()
        
        # Extract .id from response
        active_id = None
        for word in response:
            if word.startswith('=.id='):
                active_id = word.split('=')[2]
                break
        
        if active_id:
            # Remove the active session
            send_sentence(['/ip/hotspot/active/remove', f'=.id={active_id}'])
            read_sentence()
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"MikroTik API Error: {e}")
        return False


def disconnect_user(nas, username):
    """Smart disconnect - tries API first if enabled, falls back to CoA"""
    if nas.api_enabled and nas.api_ip and nas.api_username:
        # Try MikroTik API first (works through NAT)
        success = mikrotik_api_disconnect(
            nas.api_ip, 
            nas.api_port or 8728,
            nas.api_username,
            nas.api_password,
            username
        )
        if success:
            return True
    
    # Fallback to CoA
    return send_coa_disconnect(nas.nasname, nas.secret, username, nas.coa_port)


def format_bytes(bytes_val):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"


def format_duration(minutes):
    """Format minutes to human readable"""
    if minutes < 60:
        return f"{minutes} min"
    elif minutes < 1440:
        return f"{minutes // 60}h {minutes % 60}m"
    else:
        days = minutes // 1440
        hours = (minutes % 1440) // 60
        return f"{days}d {hours}h"


# ============================================
# WIREGUARD FUNCTIONS
# ============================================

def get_wireguard_status():
    """Get WireGuard interface status and connected peers"""
    try:
        result = subprocess.run(['wg', 'show', 'wg0'], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return {'running': False, 'peers': []}
        
        output = result.stdout
        peers = []
        current_peer = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                if current_peer:
                    peers.append(current_peer)
                current_peer = {'public_key': line.split(':')[1].strip()}
            elif line.startswith('endpoint:'):
                current_peer['endpoint'] = line.split(':',1)[1].strip()
            elif line.startswith('allowed ips:'):
                current_peer['allowed_ips'] = line.split(':',1)[1].strip()
            elif line.startswith('latest handshake:'):
                current_peer['last_handshake'] = line.split(':',1)[1].strip()
            elif line.startswith('transfer:'):
                current_peer['transfer'] = line.split(':',1)[1].strip()
        
        if current_peer:
            peers.append(current_peer)
        
        return {'running': True, 'peers': peers, 'raw': output}
    except Exception as e:
        return {'running': False, 'error': str(e), 'peers': []}


def get_wireguard_peer_status(public_key):
    """Check if a specific WireGuard peer is connected"""
    wg_status = get_wireguard_status()
    if not wg_status['running']:
        return {'connected': False, 'wg_running': False}
    
    for peer in wg_status['peers']:
        if peer.get('public_key') == public_key:
            # Check if handshake is recent (within 3 minutes)
            handshake = peer.get('last_handshake', '')
            connected = 'minute' in handshake or 'second' in handshake
            return {
                'connected': connected,
                'wg_running': True,
                'last_handshake': handshake,
                'transfer': peer.get('transfer', ''),
                'endpoint': peer.get('endpoint', '')
            }
    
    return {'connected': False, 'wg_running': True, 'last_handshake': 'Never'}


def generate_wireguard_keys():
    """Generate WireGuard key pair"""
    try:
        private = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
        public = subprocess.run(['wg', 'pubkey'], input=private, capture_output=True, text=True).stdout.strip()
        preshared = subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()
        return {'private': private, 'public': public, 'preshared': preshared}
    except:
        return None


def add_wireguard_peer(public_key, preshared_key, allowed_ip):
    """Add a peer to WireGuard interface"""
    try:
        cmd = ['wg', 'set', 'wg0', 'peer', public_key, 'allowed-ips', allowed_ip]
        if preshared_key:
            # Write preshared key to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(preshared_key)
                psk_file = f.name
            cmd.extend(['preshared-key', psk_file])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Save config
        subprocess.run(['wg-quick', 'save', 'wg0'], capture_output=True)
        
        return result.returncode == 0
    except Exception as e:
        print(f"WireGuard add peer error: {e}")
        return False


def remove_wireguard_peer(public_key):
    """Remove a peer from WireGuard interface"""
    try:
        result = subprocess.run(['wg', 'set', 'wg0', 'peer', public_key, 'remove'], 
                               capture_output=True, text=True)
        subprocess.run(['wg-quick', 'save', 'wg0'], capture_output=True)
        return result.returncode == 0
    except:
        return False


def get_system_status():
    """Get overall system status - RADIUS, WireGuard, Database"""
    status = {
        'radius': {'running': False, 'status': 'unknown'},
        'wireguard': {'running': False, 'status': 'unknown', 'peers': 0},
        'database': {'running': False, 'status': 'unknown', 'connected': False},
        'nginx': {'running': False, 'status': 'unknown'}
    }
    
    # Check FreeRADIUS
    try:
        result = subprocess.run(['systemctl', 'is-active', 'freeradius'], 
                               capture_output=True, text=True, timeout=5)
        status['radius']['running'] = result.stdout.strip() == 'active'
        status['radius']['status'] = result.stdout.strip()
    except:
        pass
    
    # Check WireGuard
    wg = get_wireguard_status()
    status['wireguard']['running'] = wg['running']
    status['wireguard']['status'] = 'active' if wg['running'] else 'inactive'
    status['wireguard']['peers'] = len(wg.get('peers', []))
    status['wireguard']['connected_peers'] = sum(1 for p in wg.get('peers', []) 
        if 'minute' in p.get('last_handshake', '') or 'second' in p.get('last_handshake', ''))
    
    # Check MariaDB service
    try:
        result = subprocess.run(['systemctl', 'is-active', 'mariadb'], 
                               capture_output=True, text=True, timeout=5)
        status['database']['running'] = result.stdout.strip() == 'active'
        status['database']['status'] = result.stdout.strip()
    except:
        pass
    
    # Check actual database connection
    try:
        db.session.execute(db.text('SELECT 1'))
        status['database']['connected'] = True
        status['database']['connection_status'] = 'connected'
        # Get some DB stats
        voucher_count = db.session.execute(db.text('SELECT COUNT(*) FROM vouchers')).scalar()
        nas_count = db.session.execute(db.text('SELECT COUNT(*) FROM nas')).scalar()
        status['database']['vouchers'] = voucher_count
        status['database']['routers'] = nas_count
    except Exception as e:
        status['database']['connected'] = False
        status['database']['connection_status'] = 'disconnected'
        status['database']['error'] = str(e)
    
    # Check Nginx
    try:
        result = subprocess.run(['systemctl', 'is-active', 'nginx'], 
                               capture_output=True, text=True, timeout=5)
        status['nginx']['running'] = result.stdout.strip() == 'active'
        status['nginx']['status'] = result.stdout.strip()
    except:
        pass
    
    return status


# ============================================
# ROUTES - SETUP WIZARD
# ============================================

def setup_required(f):
    """Decorator to check if setup is complete"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_configured() and request.endpoint not in ['setup', 'setup_test_db', 'static']:
            return redirect(url_for('setup'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup wizard - configure database and create admin"""
    config = load_config()
    
    # If already configured, redirect to login
    if config.get('configured') and request.args.get('force') != '1':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'test_connection':
            # Test database connection
            db_host = request.form.get('db_host', 'localhost')
            db_port = request.form.get('db_port', '3306')
            db_user = request.form.get('db_user')
            db_pass = request.form.get('db_pass')
            db_name = request.form.get('db_name')
            
            try:
                import pymysql
                conn = pymysql.connect(
                    host=db_host,
                    port=int(db_port),
                    user=db_user,
                    password=db_pass,
                    database=db_name
                )
                conn.close()
                return jsonify({'success': True, 'message': 'Connection successful!'})
            except Exception as e:
                return jsonify({'success': False, 'message': str(e)})
        
        elif action == 'save_config':
            # Save database configuration
            db_config = {
                'host': request.form.get('db_host', 'localhost'),
                'port': int(request.form.get('db_port', 3306)),
                'user': request.form.get('db_user'),
                'password': request.form.get('db_pass'),
                'name': request.form.get('db_name')
            }
            
            admin_user = request.form.get('admin_user', 'admin')
            admin_pass = request.form.get('admin_pass', 'admin123')
            admin_email = request.form.get('admin_email', '')
            
            # Save config
            config['database'] = db_config
            config['server_ip'] = request.form.get('server_ip', '44.204.164.145')
            save_config(config)
            
            # Update SQLAlchemy URI
            new_uri = f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['name']}"
            app.config['SQLALCHEMY_DATABASE_URI'] = new_uri
            
            try:
                # Recreate engine with new URI
                db.engine.dispose()
                
                # Create all tables
                with app.app_context():
                    db.create_all()
                    
                    # Create admin user if not exists
                    from sqlalchemy import text
                    result = db.session.execute(text("SELECT COUNT(*) FROM admin_users WHERE username = :user"), {'user': admin_user})
                    if result.scalar() == 0:
                        admin = AdminUser(
                            username=admin_user,
                            email=admin_email,
                            role='superadmin'
                        )
                        admin.set_password(admin_pass)
                        db.session.add(admin)
                    
                    # Create default bandwidth plans
                    result = db.session.execute(text("SELECT COUNT(*) FROM bandwidth_plans"))
                    if result.scalar() == 0:
                        plans = [
                            BandwidthPlan(name='Basic 2Mbps', download_speed=2048, upload_speed=1024, description='2 Mbps Down / 1 Mbps Up'),
                            BandwidthPlan(name='Standard 5Mbps', download_speed=5120, upload_speed=2048, description='5 Mbps Down / 2 Mbps Up'),
                            BandwidthPlan(name='Premium 10Mbps', download_speed=10240, upload_speed=5120, description='10 Mbps Down / 5 Mbps Up'),
                            BandwidthPlan(name='Unlimited', download_speed=0, upload_speed=0, description='No speed limit'),
                        ]
                        for p in plans:
                            db.session.add(p)
                    
                    db.session.commit()
                
                # Mark as configured
                config['configured'] = True
                config['setup_date'] = datetime.now().isoformat()
                save_config(config)
                
                flash('Setup complete! Please login with your admin credentials.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                flash(f'Error during setup: {str(e)}', 'error')
                return redirect(url_for('setup'))
    
    return render_template('setup.html', config=config)


@app.route('/setup/test-db', methods=['POST'])
def setup_test_db():
    """Test database connection"""
    data = request.get_json()
    try:
        import pymysql
        conn = pymysql.connect(
            host=data.get('host', 'localhost'),
            port=int(data.get('port', 3306)),
            user=data.get('user'),
            password=data.get('password'),
            database=data.get('database')
        )
        conn.close()
        return jsonify({'success': True, 'message': 'Connection successful!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# ============================================
# ROUTES - AUTHENTICATION
# ============================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if setup is needed
    if not is_configured():
        return redirect(url_for('setup'))
    
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = AdminUser.query.filter_by(username=username).first()
            
            if user and user.check_password(password):
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                log_activity('login', f'User {username} logged in')
                return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Database error: {str(e)}', 'error')
            return render_template('login.html')
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_activity('logout', f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('login'))


# ============================================
# ROUTES - DASHBOARD
# ============================================

@app.route('/')
@login_required
def dashboard():
    # Check database connection
    db_connected = True
    try:
        db.session.execute(db.text('SELECT 1'))
    except:
        db_connected = False
    
    stats = {
        'total_vouchers': Voucher.query.count() if db_connected else 0,
        'active_vouchers': Voucher.query.filter_by(status='active').count() if db_connected else 0,
        'unused_vouchers': Voucher.query.filter_by(status='unused').count() if db_connected else 0,
        'expired_vouchers': Voucher.query.filter_by(status='expired').count() if db_connected else 0,
        'total_routers': NAS.query.filter_by(status='active').count() if db_connected else 0,
        'active_sessions': RadAcct.query.filter(RadAcct.acctstoptime.is_(None)).count() if db_connected else 0,
        'total_data_today': db.session.query(
            db.func.sum(RadAcct.acctinputoctets + RadAcct.acctoutputoctets)
        ).filter(db.func.date(RadAcct.acctstarttime) == datetime.today().date()).scalar() or 0 if db_connected else 0,
        'db_connected': db_connected
    }
    
    recent_sessions = []
    if db_connected:
        recent_sessions = RadAcct.query.filter(
            RadAcct.acctstoptime.is_(None)
        ).order_by(RadAcct.acctstarttime.desc()).limit(10).all()
    
    # Get system status for health indicator
    system_status = get_system_status()
    
    return render_template('dashboard.html', stats=stats, recent_sessions=recent_sessions, 
                          format_bytes=format_bytes, system_status=system_status)


# ============================================
# ROUTES - VOUCHERS
# ============================================

@app.route('/vouchers')
@login_required
def vouchers():
    status_filter = request.args.get('status', 'all')
    query = Voucher.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    vouchers = query.order_by(Voucher.created_at.desc()).limit(500).all()
    plans = BandwidthPlan.query.all()
    
    return render_template('vouchers.html', vouchers=vouchers, plans=plans, 
                         status_filter=status_filter, format_duration=format_duration)


@app.route('/vouchers/generate', methods=['POST'])
@login_required
def generate_vouchers():
    try:
        quantity = int(request.form.get('quantity', 1))
        plan_id = int(request.form.get('plan_id'))
        duration = int(request.form.get('duration'))
        prefix = request.form.get('prefix', '').upper()
        batch_name = request.form.get('batch_name', f'Batch-{datetime.now().strftime("%Y%m%d-%H%M")}')
        
        if quantity < 1 or quantity > 1000:
            flash('Quantity must be between 1 and 1000', 'error')
            return redirect(url_for('vouchers'))
        
        # Create batch
        batch = VoucherBatch(
            batch_name=batch_name,
            quantity=quantity,
            plan_id=plan_id,
            duration_minutes=duration,
            created_by=current_user.id
        )
        db.session.add(batch)
        db.session.flush()
        
        # Generate vouchers
        generated = 0
        for _ in range(quantity):
            for attempt in range(10):  # Retry if code exists
                code = generate_voucher_code(8, prefix)
                if not Voucher.query.filter_by(voucher_code=code).first():
                    voucher = Voucher(
                        voucher_code=code,
                        batch_id=batch.id,
                        plan_id=plan_id,
                        duration_minutes=duration,
                        status='unused'
                    )
                    db.session.add(voucher)
                    
                    # Add to radcheck for FreeRADIUS
                    radcheck = RadCheck(
                        username=code,
                        attribute='Cleartext-Password',
                        op=':=',
                        value=code
                    )
                    db.session.add(radcheck)
                    
                    # Add bandwidth limits to radreply
                    plan = BandwidthPlan.query.get(plan_id)
                    if plan and plan.download_speed > 0:
                        db.session.add(RadReply(
                            username=code,
                            attribute='Mikrotik-Rate-Limit',
                            op=':=',
                            value=f'{plan.upload_speed}k/{plan.download_speed}k'
                        ))
                    
                    generated += 1
                    break
        
        db.session.commit()
        log_activity('generate_vouchers', f'Generated {generated} vouchers in batch {batch_name}')
        flash(f'Successfully generated {generated} vouchers', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error generating vouchers: {str(e)}', 'error')
    
    return redirect(url_for('vouchers'))


@app.route('/vouchers/<int:id>/disable', methods=['POST'])
@login_required
def disable_voucher(id):
    voucher = Voucher.query.get_or_404(id)
    voucher.status = 'disabled'
    
    # Remove from radcheck
    RadCheck.query.filter_by(username=voucher.voucher_code).delete()
    RadReply.query.filter_by(username=voucher.voucher_code).delete()
    
    # Disconnect if active
    if voucher.nas:
        disconnect_user(voucher.nas, voucher.voucher_code)
    
    db.session.commit()
    log_activity('disable_voucher', f'Disabled voucher {voucher.voucher_code}')
    flash('Voucher disabled', 'success')
    return redirect(url_for('vouchers'))


@app.route('/vouchers/<int:id>/delete', methods=['POST'])
@login_required
def delete_voucher(id):
    voucher = Voucher.query.get_or_404(id)
    code = voucher.voucher_code
    
    RadCheck.query.filter_by(username=code).delete()
    RadReply.query.filter_by(username=code).delete()
    db.session.delete(voucher)
    db.session.commit()
    
    log_activity('delete_voucher', f'Deleted voucher {code}')
    flash('Voucher deleted', 'success')
    return redirect(url_for('vouchers'))


@app.route('/vouchers/batch/<int:batch_id>')
@login_required
def view_batch(batch_id):
    batch = VoucherBatch.query.get_or_404(batch_id)
    vouchers = Voucher.query.filter_by(batch_id=batch_id).all()
    return render_template('batch_view.html', batch=batch, vouchers=vouchers, format_duration=format_duration)


@app.route('/vouchers/print/<int:batch_id>')
@login_required
def print_vouchers(batch_id):
    batch = VoucherBatch.query.get_or_404(batch_id)
    vouchers = Voucher.query.filter_by(batch_id=batch_id, status='unused').all()
    return render_template('print_vouchers.html', batch=batch, vouchers=vouchers, format_duration=format_duration)


# ============================================
# ROUTES - ROUTERS/NAS
# ============================================

@app.route('/routers')
@login_required
def routers():
    nas_list = NAS.query.order_by(NAS.created_at.desc()).all()
    # Get connection status for each router
    router_status = {}
    for nas in nas_list:
        router_status[nas.id] = nas.get_connection_status()
    return render_template('routers.html', routers=nas_list, router_status=router_status)


@app.route('/api/router/<int:id>/status')
@login_required
def api_router_status(id):
    """API endpoint to check router status"""
    nas = NAS.query.get_or_404(id)
    status = nas.get_connection_status()
    return jsonify(status)


@app.route('/api/routers/status')
@login_required
def api_all_routers_status():
    """API endpoint to check all routers status"""
    nas_list = NAS.query.filter_by(status='active').all()
    result = {}
    for nas in nas_list:
        result[nas.id] = nas.get_connection_status()
    return jsonify(result)


@app.route('/routers/add', methods=['GET', 'POST'])
@login_required
def add_router():
    if request.method == 'POST':
        # Handle WireGuard
        wg_enabled = request.form.get('wg_enabled') == 'on'
        wg_public_key = request.form.get('wg_public_key') or None
        wg_preshared_key = request.form.get('wg_preshared_key') or None
        wg_allowed_ip = request.form.get('wg_allowed_ip') or None
        
        nas = NAS(
            nasname=request.form.get('nasname'),
            shortname=request.form.get('shortname'),
            type=request.form.get('type', 'other'),
            secret=request.form.get('secret'),
            coa_port=int(request.form.get('coa_port', 3799)),
            description=request.form.get('description'),
            status='active',
            # MikroTik API settings
            api_enabled=request.form.get('api_enabled') == 'on',
            api_ip=request.form.get('api_ip') or None,
            api_port=int(request.form.get('api_port', 8728)),
            api_username=request.form.get('api_username') or None,
            api_password=request.form.get('api_password') or None,
            # WireGuard settings
            wg_enabled=wg_enabled,
            wg_public_key=wg_public_key,
            wg_preshared_key=wg_preshared_key,
            wg_allowed_ip=wg_allowed_ip
        )
        db.session.add(nas)
        db.session.flush()
        
        # Add WireGuard peer if enabled
        if wg_enabled and wg_public_key and wg_allowed_ip:
            add_wireguard_peer(wg_public_key, wg_preshared_key, wg_allowed_ip)
            # Update API IP to use WireGuard tunnel IP
            if nas.api_enabled:
                nas.api_ip = wg_allowed_ip.split('/')[0]
        
        db.session.commit()
        
        log_activity('add_router', f'Added router {nas.shortname} ({nas.nasname})')
        flash('Router added successfully', 'success')
        return redirect(url_for('routers'))
    
    # Generate next available WireGuard IP
    next_wg_ip = get_next_wireguard_ip()
    return render_template('router_form.html', router=None, next_wg_ip=next_wg_ip)


def get_next_wireguard_ip():
    """Get next available WireGuard IP for a new router"""
    # Base network: 10.10.0.0/24, server is 10.10.0.1
    used_ips = set()
    routers = NAS.query.filter(NAS.wg_allowed_ip.isnot(None)).all()
    for r in routers:
        if r.wg_allowed_ip:
            ip = r.wg_allowed_ip.split('/')[0]
            try:
                last_octet = int(ip.split('.')[-1])
                used_ips.add(last_octet)
            except:
                pass
    
    # Find next available (start from 2, 1 is server)
    for i in range(2, 255):
        if i not in used_ips:
            return f"10.10.0.{i}/32"
    return "10.10.0.2/32"


@app.route('/routers/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_router(id):
    nas = NAS.query.get_or_404(id)
    old_wg_key = nas.wg_public_key
    
    if request.method == 'POST':
        nas.nasname = request.form.get('nasname')
        nas.shortname = request.form.get('shortname')
        nas.type = request.form.get('type', 'other')
        nas.secret = request.form.get('secret')
        nas.coa_port = int(request.form.get('coa_port', 3799))
        nas.description = request.form.get('description')
        nas.status = request.form.get('status', 'active')
        # MikroTik API settings
        nas.api_enabled = request.form.get('api_enabled') == 'on'
        nas.api_ip = request.form.get('api_ip') or None
        nas.api_port = int(request.form.get('api_port', 8728))
        nas.api_username = request.form.get('api_username') or None
        nas.api_password = request.form.get('api_password') or None
        # WireGuard settings
        wg_enabled = request.form.get('wg_enabled') == 'on'
        new_wg_key = request.form.get('wg_public_key') or None
        wg_preshared_key = request.form.get('wg_preshared_key') or None
        wg_allowed_ip = request.form.get('wg_allowed_ip') or None
        
        # Handle WireGuard peer changes
        if old_wg_key and old_wg_key != new_wg_key:
            remove_wireguard_peer(old_wg_key)
        
        if wg_enabled and new_wg_key and wg_allowed_ip:
            add_wireguard_peer(new_wg_key, wg_preshared_key, wg_allowed_ip)
            # Auto-set API IP to WireGuard IP if API enabled
            if nas.api_enabled and not nas.api_ip:
                nas.api_ip = wg_allowed_ip.split('/')[0]
        elif not wg_enabled and old_wg_key:
            remove_wireguard_peer(old_wg_key)
        
        nas.wg_enabled = wg_enabled
        nas.wg_public_key = new_wg_key
        nas.wg_preshared_key = wg_preshared_key
        nas.wg_allowed_ip = wg_allowed_ip
        
        db.session.commit()
        
        log_activity('edit_router', f'Updated router {nas.shortname}')
        flash('Router updated successfully', 'success')
        return redirect(url_for('routers'))
    
    next_wg_ip = nas.wg_allowed_ip or get_next_wireguard_ip()
    return render_template('router_form.html', router=nas, next_wg_ip=next_wg_ip)


@app.route('/routers/<int:id>/delete', methods=['POST'])
@login_required
def delete_router(id):
    nas = NAS.query.get_or_404(id)
    name = nas.shortname
    db.session.delete(nas)
    db.session.commit()
    
    log_activity('delete_router', f'Deleted router {name}')
    flash('Router deleted', 'success')
    return redirect(url_for('routers'))


@app.route('/routers/<int:id>/script')
@login_required
def router_script(id):
    nas = NAS.query.get_or_404(id)
    server_ip = request.host.split(':')[0]
    if server_ip in ['localhost', '127.0.0.1']:
        server_ip = '44.204.164.145'  # Your VPS IP
    wg_info = get_server_wireguard_info()
    wg_info['endpoint'] = f"{server_ip}:{wg_info['listen_port']}"
    return render_template('router_script.html', router=nas, server_ip=server_ip, wg_info=wg_info)


# ============================================
# ROUTES - BANDWIDTH PLANS
# ============================================

@app.route('/plans')
@login_required
def plans():
    plans = BandwidthPlan.query.all()
    return render_template('plans.html', plans=plans)


@app.route('/plans/add', methods=['GET', 'POST'])
@login_required
def add_plan():
    if request.method == 'POST':
        plan = BandwidthPlan(
            name=request.form.get('name'),
            download_speed=int(request.form.get('download_speed', 0)),
            upload_speed=int(request.form.get('upload_speed', 0)),
            data_limit=int(request.form.get('data_limit', 0)) * 1024 * 1024,  # MB to bytes
            description=request.form.get('description'),
            price=float(request.form.get('price', 0))
        )
        db.session.add(plan)
        db.session.commit()
        
        log_activity('add_plan', f'Added bandwidth plan {plan.name}')
        flash('Plan added successfully', 'success')
        return redirect(url_for('plans'))
    
    return render_template('plan_form.html', plan=None)


@app.route('/plans/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_plan(id):
    plan = BandwidthPlan.query.get_or_404(id)
    
    if request.method == 'POST':
        plan.name = request.form.get('name')
        plan.download_speed = int(request.form.get('download_speed', 0))
        plan.upload_speed = int(request.form.get('upload_speed', 0))
        plan.data_limit = int(request.form.get('data_limit', 0)) * 1024 * 1024
        plan.description = request.form.get('description')
        plan.price = float(request.form.get('price', 0))
        db.session.commit()
        
        log_activity('edit_plan', f'Updated plan {plan.name}')
        flash('Plan updated successfully', 'success')
        return redirect(url_for('plans'))
    
    return render_template('plan_form.html', plan=plan)


@app.route('/plans/<int:id>/delete', methods=['POST'])
@login_required
def delete_plan(id):
    plan = BandwidthPlan.query.get_or_404(id)
    name = plan.name
    db.session.delete(plan)
    db.session.commit()
    
    log_activity('delete_plan', f'Deleted plan {name}')
    flash('Plan deleted', 'success')
    return redirect(url_for('plans'))


# ============================================
# ROUTES - SESSIONS (Active Users)
# ============================================

@app.route('/sessions')
@login_required
def sessions():
    active = RadAcct.query.filter(RadAcct.acctstoptime.is_(None)).order_by(RadAcct.acctstarttime.desc()).all()
    return render_template('sessions.html', sessions=active, format_bytes=format_bytes)


@app.route('/sessions/disconnect/<int:id>', methods=['POST'])
@login_required
def disconnect_session(id):
    session = RadAcct.query.get_or_404(id)
    nas = NAS.query.filter_by(nasname=session.nasipaddress).first()
    
    if nas:
        success = disconnect_user(nas, session.username)
        if success:
            flash(f'Disconnect request sent for {session.username}', 'success')
        else:
            flash('Failed to send disconnect request', 'error')
    else:
        flash('NAS not found for this session', 'error')
    
    log_activity('disconnect_session', f'Disconnected {session.username} from {session.nasipaddress}')
    return redirect(url_for('sessions'))


@app.route('/sessions/disconnect-all/<nas_ip>', methods=['POST'])
@login_required
def disconnect_all_sessions(nas_ip):
    nas = NAS.query.filter_by(nasname=nas_ip).first()
    if not nas:
        flash('Router not found', 'error')
        return redirect(url_for('sessions'))
    
    sessions = RadAcct.query.filter(
        RadAcct.nasipaddress == nas_ip,
        RadAcct.acctstoptime.is_(None)
    ).all()
    
    count = 0
    for s in sessions:
        if disconnect_user(nas, s.username):
            count += 1
    
    log_activity('disconnect_all', f'Disconnected {count} users from {nas_ip}')
    flash(f'Sent disconnect to {count} users', 'success')
    return redirect(url_for('sessions'))


# ============================================
# ROUTES - REPORTS
# ============================================

@app.route('/reports')
@login_required
def reports():
    # Date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    # Daily usage stats
    daily_stats = db.session.query(
        db.func.date(RadAcct.acctstarttime).label('date'),
        db.func.count(RadAcct.radacctid).label('sessions'),
        db.func.sum(RadAcct.acctinputoctets + RadAcct.acctoutputoctets).label('total_bytes')
    ).filter(
        RadAcct.acctstarttime >= start_date
    ).group_by(
        db.func.date(RadAcct.acctstarttime)
    ).all()
    
    # Top users by data
    top_users = db.session.query(
        RadAcct.username,
        db.func.sum(RadAcct.acctinputoctets + RadAcct.acctoutputoctets).label('total_bytes'),
        db.func.count(RadAcct.radacctid).label('sessions')
    ).group_by(RadAcct.username).order_by(
        db.desc('total_bytes')
    ).limit(20).all()
    
    # Router stats
    router_stats = db.session.query(
        RadAcct.nasipaddress,
        db.func.count(RadAcct.radacctid).label('sessions'),
        db.func.sum(RadAcct.acctinputoctets + RadAcct.acctoutputoctets).label('total_bytes')
    ).group_by(RadAcct.nasipaddress).all()
    
    # Voucher stats
    voucher_stats = {
        'total': Voucher.query.count(),
        'unused': Voucher.query.filter_by(status='unused').count(),
        'active': Voucher.query.filter_by(status='active').count(),
        'expired': Voucher.query.filter_by(status='expired').count(),
        'disabled': Voucher.query.filter_by(status='disabled').count()
    }
    
    return render_template('reports.html', 
                         daily_stats=daily_stats,
                         top_users=top_users,
                         router_stats=router_stats,
                         voucher_stats=voucher_stats,
                         format_bytes=format_bytes)


# ============================================
# ROUTES - SETTINGS & ADMIN
# ============================================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if current_user.role not in ['superadmin', 'admin']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    config = load_config()
    
    # Check database connection
    db_connected = False
    try:
        db.session.execute(db.text('SELECT 1'))
        db_connected = True
    except:
        pass
    
    return render_template('settings.html', config=config, db_connected=db_connected)


@app.route('/settings/save', methods=['POST'])
@login_required
def save_settings():
    if current_user.role not in ['superadmin', 'admin']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    config = load_config()
    section = request.form.get('section')
    
    if section == 'database':
        db_config = {
            'host': request.form.get('db_host', 'localhost'),
            'port': int(request.form.get('db_port', 3306)),
            'user': request.form.get('db_user'),
            'name': request.form.get('db_name')
        }
        # Only update password if provided
        new_pass = request.form.get('db_pass')
        if new_pass:
            db_config['password'] = new_pass
        elif config.get('database', {}).get('password'):
            db_config['password'] = config['database']['password']
        
        config['database'] = db_config
        save_config(config)
        
        # Update SQLAlchemy URI
        new_uri = f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['name']}"
        app.config['SQLALCHEMY_DATABASE_URI'] = new_uri
        db.engine.dispose()
        
        flash('Database settings saved. Restart the application for changes to take effect.', 'success')
    
    elif section == 'server':
        config['server_ip'] = request.form.get('server_ip', '44.204.164.145')
        save_config(config)
        flash('Server settings saved.', 'success')
    
    elif section == 'general':
        config['site_name'] = request.form.get('site_name', 'RADIUS Server')
        config['voucher_prefix'] = request.form.get('voucher_prefix', 'WIFI')
        config['voucher_length'] = int(request.form.get('voucher_length', 8))
        config['cleanup_interval'] = int(request.form.get('cleanup_interval', 5))
        save_config(config)
        flash('General settings saved.', 'success')
    
    return redirect(url_for('settings'))


@app.route('/settings/recreate-tables')
@login_required
def recreate_tables():
    if current_user.role != 'superadmin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        with app.app_context():
            db.create_all()
        flash('Database tables recreated successfully.', 'success')
    except Exception as e:
        flash(f'Error recreating tables: {str(e)}', 'error')
    
    return redirect(url_for('settings'))


@app.route('/users')
@login_required
def admin_users():
    if current_user.role != 'superadmin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    users = AdminUser.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_admin_user():
    if current_user.role != 'superadmin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user = AdminUser(
            username=request.form.get('username'),
            email=request.form.get('email'),
            role=request.form.get('role', 'operator')
        )
        user.set_password(request.form.get('password'))
        db.session.add(user)
        db.session.commit()
        
        log_activity('add_admin', f'Added admin user {user.username}')
        flash('User added successfully', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_user_form.html', user=None)


@app.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def delete_admin_user(id):
    if current_user.role != 'superadmin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if id == current_user.id:
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('admin_users'))
    
    user = AdminUser.query.get_or_404(id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_activity('delete_admin', f'Deleted admin user {username}')
    flash('User deleted', 'success')
    return redirect(url_for('admin_users'))


@app.route('/activity-log')
@login_required
def activity_log():
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(500).all()
    return render_template('activity_log.html', logs=logs)


# ============================================
# API ENDPOINTS
# ============================================

@app.route('/api/voucher/validate', methods=['POST'])
def api_validate_voucher():
    """API endpoint for external voucher validation"""
    data = request.get_json()
    code = data.get('voucher_code')
    
    voucher = Voucher.query.filter_by(voucher_code=code).first()
    if not voucher:
        return jsonify({'valid': False, 'error': 'Voucher not found'})
    
    if voucher.status == 'unused':
        return jsonify({'valid': True, 'status': 'unused', 'duration': voucher.duration_minutes})
    elif voucher.status == 'active':
        remaining = (voucher.expiry_at - datetime.now()).total_seconds() / 60
        return jsonify({'valid': True, 'status': 'active', 'remaining_minutes': max(0, remaining)})
    else:
        return jsonify({'valid': False, 'error': f'Voucher is {voucher.status}'})


@app.route('/api/voucher/activate', methods=['POST'])
def api_activate_voucher():
    """API endpoint to activate a voucher"""
    data = request.get_json()
    code = data.get('voucher_code')
    mac = data.get('mac_address')
    nas_ip = data.get('nas_ip')
    
    voucher = Voucher.query.filter_by(voucher_code=code, status='unused').first()
    if not voucher:
        return jsonify({'success': False, 'error': 'Invalid or already used voucher'})
    
    nas = NAS.query.filter_by(nasname=nas_ip).first()
    
    voucher.status = 'active'
    voucher.activated_at = datetime.now()
    voucher.expiry_at = datetime.now() + timedelta(minutes=voucher.duration_minutes)
    voucher.used_by_mac = mac
    voucher.nas_id = nas.id if nas else None
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'expiry_at': voucher.expiry_at.isoformat(),
        'duration_minutes': voucher.duration_minutes
    })


@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard stats"""
    return jsonify({
        'active_sessions': RadAcct.query.filter(RadAcct.acctstoptime.is_(None)).count(),
        'active_vouchers': Voucher.query.filter_by(status='active').count(),
        'total_routers': NAS.query.filter_by(status='active').count()
    })


@app.route('/api/system/status')
@login_required
def api_system_status():
    """API endpoint for system status"""
    return jsonify(get_system_status())


@app.route('/api/database/health')
@login_required
def api_database_health():
    """API endpoint for database health check"""
    try:
        # Test connection
        start = datetime.now()
        db.session.execute(db.text('SELECT 1'))
        latency = (datetime.now() - start).total_seconds() * 1000
        
        # Get stats
        stats = {
            'connected': True,
            'latency_ms': round(latency, 2),
            'vouchers': db.session.execute(db.text('SELECT COUNT(*) FROM vouchers')).scalar(),
            'active_vouchers': db.session.execute(db.text("SELECT COUNT(*) FROM vouchers WHERE status='active'")).scalar(),
            'routers': db.session.execute(db.text('SELECT COUNT(*) FROM nas')).scalar(),
            'sessions': db.session.execute(db.text('SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL')).scalar(),
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'connected': False, 'error': str(e)})


@app.route('/api/wireguard/status')
@login_required
def api_wireguard_status():
    """API endpoint for WireGuard status"""
    return jsonify(get_wireguard_status())


@app.route('/api/router/<int:id>/wg-status')
@login_required
def api_router_wg_status(id):
    """Check WireGuard connection status for a router"""
    nas = NAS.query.get_or_404(id)
    if not nas.wg_enabled or not nas.wg_public_key:
        return jsonify({'enabled': False})
    
    status = get_wireguard_peer_status(nas.wg_public_key)
    status['enabled'] = True
    return jsonify(status)


# ============================================
# ROUTES - SYSTEM STATUS
# ============================================

@app.route('/system-status')
@login_required
def system_status():
    """System status dashboard"""
    status = get_system_status()
    wg_status = get_wireguard_status()
    
    # Get router WireGuard status
    routers = NAS.query.filter_by(status='active').all()
    router_wg_status = {}
    for r in routers:
        if r.wg_enabled and r.wg_public_key:
            router_wg_status[r.id] = get_wireguard_peer_status(r.wg_public_key)
    
    # Get server IP
    server_ip = request.host.split(':')[0]
    if server_ip in ['localhost', '127.0.0.1']:
        server_ip = '44.204.164.145'  # Your VPS IP
    
    return render_template('system_status.html', 
                          status=status, 
                          wg_status=wg_status,
                          routers=routers,
                          router_wg_status=router_wg_status,
                          server_ip=server_ip)


@app.route('/wireguard/generate-config/<int:router_id>')
@login_required
def generate_wg_config(router_id):
    """Generate WireGuard config for a router"""
    nas = NAS.query.get_or_404(router_id)
    
    # Get server public key
    try:
        result = subprocess.run(['wg', 'show', 'wg0', 'public-key'], 
                               capture_output=True, text=True)
        server_public_key = result.stdout.strip()
    except:
        server_public_key = 'SERVER_PUBLIC_KEY_HERE'
    
    # Get server endpoint (VPS public IP)
    server_ip = request.host.split(':')[0]
    if server_ip in ['localhost', '127.0.0.1']:
        server_ip = '44.204.164.145'  # Your VPS IP
    
    return render_template('wireguard_config.html', 
                          router=nas, 
                          server_public_key=server_public_key,
                          server_ip=server_ip)


def get_server_wireguard_info():
    """Get WireGuard server info for MikroTik config generation"""
    info = {
        'public_key': '',
        'endpoint': '',
        'listen_port': 51820,
        'server_ip': '10.10.0.1'
    }
    
    try:
        # Get public key
        result = subprocess.run(['wg', 'show', 'wg0', 'public-key'], 
                               capture_output=True, text=True)
        info['public_key'] = result.stdout.strip()
        
        # Get listen port
        result = subprocess.run(['wg', 'show', 'wg0', 'listen-port'], 
                               capture_output=True, text=True)
        info['listen_port'] = int(result.stdout.strip()) if result.stdout.strip() else 51820
    except:
        pass
    
    return info


# ============================================
# INITIALIZATION
# ============================================

def init_db():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create default admin if not exists
        if not AdminUser.query.filter_by(username='admin').first():
            admin = AdminUser(
                username='admin',
                email='admin@localhost',
                role='superadmin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
        
        # Create default bandwidth plans
        if not BandwidthPlan.query.first():
            plans = [
                BandwidthPlan(name='Basic 2Mbps', download_speed=2048, upload_speed=1024, description='2 Mbps Down / 1 Mbps Up'),
                BandwidthPlan(name='Standard 5Mbps', download_speed=5120, upload_speed=2048, description='5 Mbps Down / 2 Mbps Up'),
                BandwidthPlan(name='Premium 10Mbps', download_speed=10240, upload_speed=5120, description='10 Mbps Down / 5 Mbps Up'),
                BandwidthPlan(name='Unlimited', download_speed=0, upload_speed=0, description='No speed limit'),
            ]
            for p in plans:
                db.session.add(p)
        
        db.session.commit()


@app.context_processor
def utility_processor():
    """Make utility functions available in templates"""
    return {
        'now': datetime.now
    }


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
