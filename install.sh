#!/bin/bash
# ============================================
# RADIUS Server - One-Click Installer
# ============================================
# Run with: curl -sSL https://raw.githubusercontent.com/Canol001/radius/main/install.sh | sudo bash
# Or: wget -qO- https://raw.githubusercontent.com/Canol001/radius/main/install.sh | sudo bash
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_URL="https://github.com/Canol001/radius.git"
INSTALL_DIR="/opt/radius-server"
WEB_PORT=5000

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║     ██████╗  █████╗ ██████╗ ██╗██╗   ██╗███████╗             ║"
    echo "║     ██╔══██╗██╔══██╗██╔══██╗██║██║   ██║██╔════╝             ║"
    echo "║     ██████╔╝███████║██║  ██║██║██║   ██║███████╗             ║"
    echo "║     ██╔══██╗██╔══██║██║  ██║██║██║   ██║╚════██║             ║"
    echo "║     ██║  ██║██║  ██║██████╔╝██║╚██████╔╝███████║             ║"
    echo "║     ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝ ╚══════╝             ║"
    echo "║                                                               ║"
    echo "║        FreeRADIUS + WireGuard + Multi-Router System          ║"
    echo "║                    One-Click Installer                        ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_banner

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    echo "Usage: sudo bash install.sh"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. This script supports Ubuntu/Debian only.${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VERSION${NC}"

if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
    echo -e "${RED}This script only supports Ubuntu and Debian.${NC}"
    exit 1
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
echo -e "${GREEN}Server IP: $SERVER_IP${NC}"

echo ""
echo -e "${YELLOW}This script will install:${NC}"
echo "  • FreeRADIUS 3.0 with MySQL support"
echo "  • MariaDB Database Server"
echo "  • WireGuard VPN Server"
echo "  • Nginx Web Server"
echo "  • Python Flask Application"
echo "  • UFW Firewall Rules"
echo ""
read -p "Continue with installation? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}[1/10] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

echo -e "${BLUE}[2/10] Installing dependencies...${NC}"
apt-get install -y \
    git curl wget \
    freeradius freeradius-mysql freeradius-utils \
    mariadb-server mariadb-client \
    python3 python3-pip python3-venv python3-dev \
    nginx certbot python3-certbot-nginx \
    wireguard wireguard-tools \
    ufw

echo -e "${BLUE}[3/10] Configuring firewall...${NC}"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 1812/udp
ufw allow 1813/udp
ufw allow 51820/udp
ufw --force enable

echo -e "${BLUE}[4/10] Setting up WireGuard VPN...${NC}"
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo "$WG_PRIVATE_KEY" | wg pubkey)

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = $WG_PRIVATE_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true
WGCONF

chmod 600 /etc/wireguard/wg0.conf

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo -e "${BLUE}[5/10] Setting up MariaDB...${NC}"
systemctl start mariadb
systemctl enable mariadb

# Generate random password
DB_PASS=$(openssl rand -hex 16)

mysql -u root <<MYSQL
CREATE DATABASE IF NOT EXISTS radius CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS 'radius'@'localhost';
CREATE USER 'radius'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON radius.* TO 'radius'@'localhost';
FLUSH PRIVILEGES;
MYSQL

echo -e "${BLUE}[6/10] Cloning repository...${NC}"
rm -rf $INSTALL_DIR
git clone $REPO_URL /tmp/radius-repo
# Move files from radius-server subfolder if it exists, otherwise from root
if [ -d "/tmp/radius-repo/radius-server" ]; then
    mv /tmp/radius-repo/radius-server $INSTALL_DIR
else
    mv /tmp/radius-repo $INSTALL_DIR
fi
rm -rf /tmp/radius-repo
cd $INSTALL_DIR

echo -e "${BLUE}[7/10] Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || pip install flask flask-sqlalchemy flask-login flask-wtf pymysql gunicorn werkzeug python-dateutil

echo -e "${BLUE}[8/10] Configuring FreeRADIUS...${NC}"
# Backup and configure SQL module
cp /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-available/sql.bak

cat > /etc/freeradius/3.0/mods-available/sql <<SQLCONF
sql {
    driver = "rlm_sql_mysql"
    dialect = "mysql"
    server = "localhost"
    port = 3306
    login = "radius"
    password = "$DB_PASS"
    radius_db = "radius"
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

ln -sf /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-enabled/sql
chgrp -R freerad /etc/freeradius/3.0/mods-available/sql
chmod 640 /etc/freeradius/3.0/mods-available/sql

# Enable SQL in default site
sed -i 's/^#[[:space:]]*sql$/\tsql/' /etc/freeradius/3.0/sites-available/default
sed -i 's/^#[[:space:]]*-sql$/\t-sql/' /etc/freeradius/3.0/sites-available/default

echo -e "${BLUE}[9/10] Creating systemd service...${NC}"
cat > /etc/systemd/system/radius-server.service <<SERVICE
[Unit]
Description=RADIUS Server Web Interface
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:$WEB_PORT --timeout 120 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

echo -e "${BLUE}[10/10] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/radius-server <<NGINX
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
NGINX

ln -sf /etc/nginx/sites-available/radius-server /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Set permissions
chown -R www-data:www-data $INSTALL_DIR
chmod -R 755 $INSTALL_DIR

# Create initial config with database credentials
cat > $INSTALL_DIR/config.json <<CONFIG
{
  "database": {
    "host": "localhost",
    "port": 3306,
    "user": "radius",
    "password": "$DB_PASS",
    "name": "radius"
  },
  "server_ip": "$SERVER_IP",
  "configured": false
}
CONFIG
chown www-data:www-data $INSTALL_DIR/config.json
chmod 600 $INSTALL_DIR/config.json

# Save WireGuard public key
echo "$WG_PUBLIC_KEY" > $INSTALL_DIR/wireguard_public_key.txt

# Reload and start services
systemctl daemon-reload
systemctl enable mariadb nginx freeradius radius-server wg-quick@wg0
systemctl restart mariadb
systemctl restart nginx
systemctl restart freeradius
systemctl restart radius-server

# Wait for services
sleep 3

# Save credentials
cat > $INSTALL_DIR/INSTALL_INFO.txt <<INFO
╔═══════════════════════════════════════════════════════════════╗
║              RADIUS Server - Installation Complete            ║
╚═══════════════════════════════════════════════════════════════╝

SERVER INFORMATION
──────────────────
Public IP: $SERVER_IP
Install Directory: $INSTALL_DIR

WEB ADMIN PANEL
───────────────
URL: http://$SERVER_IP/
(Complete setup wizard on first visit)

DATABASE (Pre-configured)
─────────────────────────
Host: localhost
Database: radius
Username: radius
Password: $DB_PASS

WIREGUARD VPN
─────────────
Server IP: 10.10.0.1
Public Key: $WG_PUBLIC_KEY
Port: 51820/udp

FREERADIUS
──────────
Auth Port: 1812/udp
Acct Port: 1813/udp

SERVICE STATUS
──────────────
MariaDB:     $(systemctl is-active mariadb)
FreeRADIUS:  $(systemctl is-active freeradius)
WireGuard:   $(systemctl is-active wg-quick@wg0)
Nginx:       $(systemctl is-active nginx)
Web App:     $(systemctl is-active radius-server)

USEFUL COMMANDS
───────────────
Restart all:  systemctl restart radius-server freeradius nginx
View logs:    journalctl -u radius-server -f
Test RADIUS:  radtest testuser testpass localhost 0 testing123

═══════════════════════════════════════════════════════════════
INFO

chmod 600 $INSTALL_DIR/INSTALL_INFO.txt

# Print completion message
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete!                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Service Status:"
echo -e "  MariaDB:     $(systemctl is-active mariadb)"
echo -e "  FreeRADIUS:  $(systemctl is-active freeradius)"
echo -e "  WireGuard:   $(systemctl is-active wg-quick@wg0)"
echo -e "  Nginx:       $(systemctl is-active nginx)"
echo -e "  Web App:     $(systemctl is-active radius-server)"
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Access your admin panel:${NC}"
echo -e "  ${GREEN}http://$SERVER_IP/${NC}"
echo ""
echo -e "${YELLOW}Complete the setup wizard to create your admin account.${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Database credentials saved to: ${BLUE}$INSTALL_DIR/INSTALL_INFO.txt${NC}"
echo ""
echo -e "${YELLOW}WireGuard Public Key:${NC}"
echo -e "  $WG_PUBLIC_KEY"
echo ""
