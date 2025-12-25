#!/bin/bash
# ============================================
# WiFi Billing System - VPS Installation
# FreeRADIUS + Multi-Router + Web Admin Panel
# ============================================
# Usage: sudo bash setup.sh
# Tested on: Ubuntu 20.04/22.04, Debian 11/12
# ============================================

set -e

# ------------------------
# CONFIGURATION
# ------------------------
DB_USER="radius"
DB_PASS="radius_$(openssl rand -hex 12)"
DB_NAME="radius"
ADMIN_USER="admin"
ADMIN_PASS="admin123"  # CHANGE THIS AFTER INSTALL!
INSTALL_DIR="/opt/wifi-billing"
WEB_PORT=5000
DOMAIN=""  # Set your domain for SSL (optional)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║     WiFi Billing System - FreeRADIUS Installation      ║"
    echo "║         Multi-Router Support + Web Admin Panel         ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_banner

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo bash setup.sh${NC}"
    exit 1
fi

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "${GREEN}Detected Server IP: ${SERVER_IP}${NC}"

# ------------------------
# STEP 1: Install Dependencies
# ------------------------
echo -e "${YELLOW}[1/10] Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    freeradius freeradius-mysql freeradius-utils \
    mariadb-server mariadb-client \
    python3 python3-pip python3-venv python3-dev \
    nginx certbot python3-certbot-nginx \
    wireguard wireguard-tools \
    git curl wget ufw

# ------------------------
# STEP 2: Configure Firewall
# ------------------------
echo -e "${YELLOW}[2/10] Configuring firewall...${NC}"
ufw allow 22/tcp      # SSH
ufw allow 80/tcp      # HTTP
ufw allow 443/tcp     # HTTPS
ufw allow 1812/udp    # RADIUS Auth
ufw allow 1813/udp    # RADIUS Accounting
ufw allow 51820/udp   # WireGuard VPN
ufw --force enable
echo -e "${GREEN}Firewall configured.${NC}"

# ------------------------
# STEP 2.5: Setup WireGuard VPN
# ------------------------
echo -e "${YELLOW}[2.5/10] Setting up WireGuard VPN...${NC}"

# Generate WireGuard keys
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

# Create WireGuard config
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = $WG_PRIVATE_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true

# Peers will be added dynamically via admin panel
WGCONF

chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo -e "${GREEN}WireGuard configured. Server IP: 10.10.0.1${NC}"
echo -e "${GREEN}WireGuard Public Key: ${WG_PUBLIC_KEY}${NC}"
echo -e "${YELLOW}[2.5/10] Setting up WireGuard VPN...${NC}"

# Generate WireGuard keys
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

# Detect main network interface
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
[ -z "$MAIN_IFACE" ] && MAIN_IFACE="eth0"

# Create WireGuard config
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = $WG_PRIVATE_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE
SaveConfig = true

# Peers (MikroTik routers) will be added dynamically via admin panel
# Each router gets a unique IP: 10.10.0.2, 10.10.0.3, etc.
WGCONF

chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0 || true

echo -e "${GREEN}WireGuard configured.${NC}"
echo -e "${GREEN}  Server Tunnel IP: 10.10.0.1${NC}"
echo -e "${GREEN}  Server Public Key: ${WG_PUBLIC_KEY}${NC}"
echo -e "${GREEN}  Listen Port: 51820/UDP${NC}"

# ------------------------
# STEP 3: Setup Python Environment
# ------------------------
echo -e "${YELLOW}[3/9] Setting up Python environment...${NC}"
mkdir -p "$INSTALL_DIR"

# Copy application files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || true

cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install flask flask-sqlalchemy flask-login flask-wtf pymysql gunicorn python-dateutil werkzeug

# ------------------------
# STEP 4: Setup MariaDB
# ------------------------
echo -e "${YELLOW}[4/9] Configuring MariaDB...${NC}"
systemctl start mariadb
systemctl enable mariadb

mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '$DB_USER'@'localhost';
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

# ------------------------
# STEP 5: Create Database Schema
# ------------------------
echo -e "${YELLOW}[5/9] Creating database schema...${NC}"
mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" <<'SCHEMA'
-- Admin Users Table
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('superadmin', 'admin', 'operator') DEFAULT 'operator',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

-- NAS/Routers Table
CREATE TABLE IF NOT EXISTS nas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nasname VARCHAR(128) NOT NULL,
    shortname VARCHAR(32),
    type VARCHAR(30) DEFAULT 'other',
    ports INT,
    secret VARCHAR(60) NOT NULL,
    server VARCHAR(64),
    community VARCHAR(50),
    description VARCHAR(200),
    coa_port INT DEFAULT 3799,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NULL,
    api_enabled BOOLEAN DEFAULT FALSE,
    api_ip VARCHAR(128),
    api_port INT DEFAULT 8728,
    api_username VARCHAR(64),
    api_password VARCHAR(128),
    wg_enabled BOOLEAN DEFAULT FALSE,
    wg_public_key VARCHAR(64),
    wg_preshared_key VARCHAR(64),
    wg_allowed_ip VARCHAR(32),
    wg_endpoint VARCHAR(128)
);

-- Bandwidth Plans Table
CREATE TABLE IF NOT EXISTS bandwidth_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    download_speed INT NOT NULL COMMENT 'in Kbps',
    upload_speed INT NOT NULL COMMENT 'in Kbps',
    description VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Voucher Batches Table
CREATE TABLE IF NOT EXISTS voucher_batches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    batch_name VARCHAR(100) NOT NULL,
    quantity INT NOT NULL,
    plan_id INT,
    duration_minutes INT NOT NULL,
    price DECIMAL(10,2) DEFAULT 0,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plan_id) REFERENCES bandwidth_plans(id),
    FOREIGN KEY (created_by) REFERENCES admin_users(id)
);

-- Vouchers Table
CREATE TABLE IF NOT EXISTS vouchers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    voucher_code VARCHAR(20) UNIQUE NOT NULL,
    batch_id INT,
    plan_id INT,
    duration_minutes INT NOT NULL,
    status ENUM('unused', 'active', 'expired', 'disabled') DEFAULT 'unused',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP NULL,
    expiry_at TIMESTAMP NULL,
    used_by_mac VARCHAR(17),
    nas_id INT,
    FOREIGN KEY (batch_id) REFERENCES voucher_batches(id),
    FOREIGN KEY (plan_id) REFERENCES bandwidth_plans(id),
    FOREIGN KEY (nas_id) REFERENCES nas(id)
);

-- Accounting Table (RADIUS accounting)
CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGINT AUTO_INCREMENT PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL,
    acctuniqueid VARCHAR(32) NOT NULL,
    username VARCHAR(64) NOT NULL,
    realm VARCHAR(64),
    nasipaddress VARCHAR(15) NOT NULL,
    nasportid VARCHAR(32),
    nasporttype VARCHAR(32),
    acctstarttime DATETIME,
    acctupdatetime DATETIME,
    acctstoptime DATETIME,
    acctinterval INT,
    acctsessiontime INT UNSIGNED,
    acctauthentic VARCHAR(32),
    connectinfo_start VARCHAR(128),
    connectinfo_stop VARCHAR(128),
    acctinputoctets BIGINT,
    acctoutputoctets BIGINT,
    calledstationid VARCHAR(50),
    callingstationid VARCHAR(50),
    acctterminatecause VARCHAR(32),
    servicetype VARCHAR(32),
    framedprotocol VARCHAR(32),
    framedipaddress VARCHAR(15),
    framedipv6address VARCHAR(45),
    framedipv6prefix VARCHAR(45),
    framedinterfaceid VARCHAR(44),
    delegatedipv6prefix VARCHAR(45),
    class VARCHAR(64),
    INDEX idx_username (username),
    INDEX idx_acctsessionid (acctsessionid),
    INDEX idx_nasipaddress (nasipaddress),
    INDEX idx_acctstarttime (acctstarttime)
);

-- System Settings Table
CREATE TABLE IF NOT EXISTS settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value TEXT,
    description VARCHAR(200),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Activity Log Table
CREATE TABLE IF NOT EXISTS activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES admin_users(id)
);

-- FreeRADIUS radcheck table
CREATE TABLE IF NOT EXISTS radcheck (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT '',
    INDEX idx_username (username(32))
);

-- FreeRADIUS radreply table
CREATE TABLE IF NOT EXISTS radreply (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT '',
    INDEX idx_username (username(32))
);

-- FreeRADIUS radgroupcheck table
CREATE TABLE IF NOT EXISTS radgroupcheck (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT '',
    INDEX idx_groupname (groupname(32))
);

-- FreeRADIUS radgroupreply table
CREATE TABLE IF NOT EXISTS radgroupreply (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT '',
    INDEX idx_groupname (groupname(32))
);

-- FreeRADIUS radusergroup table
CREATE TABLE IF NOT EXISTS radusergroup (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority INT NOT NULL DEFAULT 1,
    INDEX idx_username (username(32))
);

-- FreeRADIUS radpostauth table
CREATE TABLE IF NOT EXISTS radpostauth (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    pass VARCHAR(64) NOT NULL DEFAULT '',
    reply VARCHAR(32) NOT NULL DEFAULT '',
    authdate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    class VARCHAR(64) DEFAULT NULL,
    INDEX idx_username (username(32)),
    INDEX idx_class (class(32))
);

-- Insert default bandwidth plans
INSERT IGNORE INTO bandwidth_plans (id, name, download_speed, upload_speed, description) VALUES
(1, 'Basic', 2048, 1024, '2 Mbps Download / 1 Mbps Upload'),
(2, 'Standard', 5120, 2048, '5 Mbps Download / 2 Mbps Upload'),
(3, 'Premium', 10240, 5120, '10 Mbps Download / 5 Mbps Upload'),
(4, 'Unlimited', 0, 0, 'No speed limit');

-- Insert default settings
INSERT IGNORE INTO settings (setting_key, setting_value, description) VALUES
('site_name', 'WiFi Billing System', 'Website name'),
('voucher_prefix', 'WIFI', 'Prefix for voucher codes'),
('voucher_length', '8', 'Length of voucher code'),
('session_timeout', '3600', 'Default session timeout in seconds'),
('cleanup_interval', '5', 'Cleanup interval in minutes');
SCHEMA

echo -e "${GREEN}Database schema created.${NC}"

# Create default admin user
ADMIN_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('$ADMIN_PASS'))")
mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" <<ADMIN_SQL
INSERT INTO admin_users (username, password_hash, email, role) 
VALUES ('$ADMIN_USER', '$ADMIN_HASH', 'admin@localhost', 'superadmin')
ON DUPLICATE KEY UPDATE password_hash='$ADMIN_HASH';
ADMIN_SQL

# ------------------------
# STEP 6: Configure FreeRADIUS
# ------------------------
echo -e "${YELLOW}[6/9] Configuring FreeRADIUS...${NC}"

# Stop FreeRADIUS during configuration
systemctl stop freeradius 2>/dev/null || true

# Backup original configs
cp /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-available/sql.bak.$(date +%s) 2>/dev/null || true

# Configure SQL module for FreeRADIUS
cat > /etc/freeradius/3.0/mods-available/sql <<SQLCONF
sql {
    driver = "rlm_sql_mysql"
    dialect = "mysql"
    
    server = "localhost"
    port = 3306
    login = "$DB_USER"
    password = "$DB_PASS"
    radius_db = "$DB_NAME"
    
    read_clients = yes
    client_table = "nas"
    
    acct_table1 = "radacct"
    acct_table2 = "radacct"
    postauth_table = "radpostauth"
    authcheck_table = "radcheck"
    authreply_table = "radreply"
    groupcheck_table = "radgroupcheck"
    groupreply_table = "radgroupreply"
    usergroup_table = "radusergroup"
    
    delete_stale_sessions = yes
    
    pool {
        start = \${thread[pool].start_servers}
        min = \${thread[pool].min_spare_servers}
        max = \${thread[pool].max_servers}
        spare = \${thread[pool].max_spare_servers}
        uses = 0
        lifetime = 0
        idle_timeout = 60
    }
    
    read_groups = yes
    
    group_attribute = "SQL-Group"
    
    \$INCLUDE \${modconfdir}/\${.:name}/main/\${dialect}/queries.conf
}
SQLCONF

# Enable SQL module
ln -sf /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-enabled/sql

# Configure default site to use SQL
SITE_DEFAULT="/etc/freeradius/3.0/sites-available/default"
sed -i 's/^#[[:space:]]*sql$/\tsql/' "$SITE_DEFAULT" 2>/dev/null || true
sed -i 's/^#[[:space:]]*-sql$/\t-sql/' "$SITE_DEFAULT" 2>/dev/null || true

# Configure inner-tunnel
SITE_INNER="/etc/freeradius/3.0/sites-available/inner-tunnel"
sed -i 's/^#[[:space:]]*sql$/\tsql/' "$SITE_INNER" 2>/dev/null || true

# Set correct permissions
chgrp -R freerad /etc/freeradius/3.0/mods-available/sql
chmod 640 /etc/freeradius/3.0/mods-available/sql

echo -e "${GREEN}FreeRADIUS configured.${NC}"

# ------------------------
# STEP 7: Create Web Application Config
# ------------------------
echo -e "${YELLOW}[7/9] Setting up web application...${NC}"

# Create environment file
cat > "$INSTALL_DIR/.env" <<ENVFILE
SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=mysql+pymysql://$DB_USER:$DB_PASS@localhost/$DB_NAME
FLASK_ENV=production
ENVFILE

chmod 600 "$INSTALL_DIR/.env"

# Update app.py to use environment variables
sed -i "s|os.environ.get('DATABASE_URL', 'mysql+pymysql://radius:radius@localhost/radius')|'mysql+pymysql://$DB_USER:$DB_PASS@localhost/$DB_NAME'|g" "$INSTALL_DIR/app.py"

echo -e "${GREEN}Web application configured.${NC}"

# ------------------------
# STEP 8: Create Systemd Services
# ------------------------
echo -e "${YELLOW}[8/9] Creating systemd services...${NC}"

# Web application service
cat > /etc/systemd/system/wifi-billing.service <<SVCFILE
[Unit]
Description=WiFi Billing System Web Interface
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:$WEB_PORT --timeout 120 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCFILE

# Cleanup service (expires vouchers and disconnects users)
cat > /usr/local/bin/wifi-billing-cleanup.sh <<'CLEANUP'
#!/bin/bash
cd /opt/wifi-billing
source venv/bin/activate
python3 <<PYSCRIPT
from app import app, db, Voucher, NAS, RadAcct, send_coa_disconnect
from datetime import datetime

with app.app_context():
    # Find expired vouchers
    expired = Voucher.query.filter(
        Voucher.status == 'active',
        Voucher.expiry_at < datetime.now()
    ).all()
    
    for v in expired:
        v.status = 'expired'
        
        # Send CoA disconnect if NAS is configured
        if v.nas_id:
            nas = NAS.query.get(v.nas_id)
            if nas:
                send_coa_disconnect(nas.nasname, nas.secret, v.voucher_code, nas.coa_port)
    
    db.session.commit()
    
    if expired:
        print(f'{datetime.now()}: Expired {len(expired)} vouchers')
PYSCRIPT
CLEANUP
chmod +x /usr/local/bin/wifi-billing-cleanup.sh

# Add cron job
(crontab -l 2>/dev/null | grep -v wifi-billing-cleanup; echo "*/5 * * * * /usr/local/bin/wifi-billing-cleanup.sh >> /var/log/wifi-billing.log 2>&1") | crontab -

# ------------------------
# STEP 9: Configure Nginx
# ------------------------
echo -e "${YELLOW}[9/9] Configuring Nginx...${NC}"

cat > /etc/nginx/sites-available/wifi-billing <<NGINXCONF
server {
    listen 80;
    server_name _;
    
    client_max_body_size 10M;
    
    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /static {
        alias $INSTALL_DIR/static;
        expires 30d;
    }
}
NGINXCONF

ln -sf /etc/nginx/sites-available/wifi-billing /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Test nginx config
nginx -t

# ------------------------
# Set permissions
# ------------------------
chown -R www-data:www-data "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
mkdir -p /var/log/freeradius
chown freerad:freerad /var/log/freeradius

# ------------------------
# Start all services
# ------------------------
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable mariadb nginx freeradius wifi-billing
systemctl restart mariadb
systemctl restart nginx
systemctl restart freeradius
systemctl restart wifi-billing

# Wait for services to start
sleep 3

# ------------------------
# ------------------------
# Save credentials
# ------------------------
cat > "$INSTALL_DIR/CREDENTIALS.txt" <<CREDS
╔════════════════════════════════════════════════════════════╗
║        RADIUS Server - Installation Info                   ║
║        FreeRADIUS + WireGuard + Multi-Router               ║
╚════════════════════════════════════════════════════════════╝

SERVER INFORMATION
──────────────────
Server IP: $SERVER_IP
Installation: $INSTALL_DIR

WEB ADMIN PANEL
───────────────
URL: http://$SERVER_IP/
Username: $ADMIN_USER
Password: $ADMIN_PASS
⚠️  CHANGE PASSWORD AFTER FIRST LOGIN!

DATABASE
────────
Host: localhost
Database: $DB_NAME
Username: $DB_USER
Password: $DB_PASS

FREERADIUS
──────────
Auth Port: 1812/udp
Acct Port: 1813/udp
Status: $(systemctl is-active freeradius)

WIREGUARD VPN
─────────────
Server Tunnel IP: 10.10.0.1
Listen Port: 51820/udp
Public Key: $WG_PUBLIC_KEY
Status: $(systemctl is-active wg-quick@wg0)

Router IPs: 10.10.0.2, 10.10.0.3, ... (assigned per router)

FIREWALL PORTS OPENED
─────────────────────
22/tcp    - SSH
80/tcp    - HTTP
443/tcp   - HTTPS
1812/udp  - RADIUS Auth
1813/udp  - RADIUS Accounting
51820/udp - WireGuard VPN

USEFUL COMMANDS
───────────────
Test RADIUS:      radtest testuser testpass localhost 0 testing123
Debug RADIUS:     freeradius -X
View RADIUS logs: tail -f /var/log/freeradius/radius.log
WireGuard status: wg show
Restart services: systemctl restart freeradius wifi-billing wg-quick@wg0

SSL CERTIFICATE (Optional)
──────────────────────────
To enable HTTPS with Let's Encrypt:
  certbot --nginx -d yourdomain.com

════════════════════════════════════════════════════════════
CREDS

chmod 600 "$INSTALL_DIR/CREDENTIALS.txt"

# Save WireGuard public key for easy access
echo "$WG_PUBLIC_KEY" > "$INSTALL_DIR/wireguard_public_key.txt"

# ------------------------
# Final status check
# ------------------------
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete!                        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Service Status:"
echo -e "  MariaDB:     $(systemctl is-active mariadb)"
echo -e "  FreeRADIUS:  $(systemctl is-active freeradius)"
echo -e "  WireGuard:   $(systemctl is-active wg-quick@wg0)"
echo -e "  Nginx:       $(systemctl is-active nginx)"
echo -e "  Web App:     $(systemctl is-active wifi-billing)"
echo ""
echo -e "${YELLOW}Admin Panel:${NC}  http://$SERVER_IP/"
echo -e "${YELLOW}Username:${NC}     $ADMIN_USER"
echo -e "${YELLOW}Password:${NC}     $ADMIN_PASS"
echo ""
echo -e "${BLUE}WireGuard VPN:${NC}"
echo -e "  Server IP:   10.10.0.1"
echo -e "  Public Key:  $WG_PUBLIC_KEY"
echo -e "  Port:        51820/udp"
echo ""
echo -e "Credentials saved to: ${BLUE}$INSTALL_DIR/CREDENTIALS.txt${NC}"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Change the admin password after first login!${NC}"
echo ""
