# RADIUS Server - FreeRADIUS + WireGuard + Multi-Router

A complete FreeRADIUS-based WiFi billing system with WireGuard VPN support for multi-router management behind NAT.

## One-Click Installation

```bash
curl -sSL https://raw.githubusercontent.com/Canol001/radius/main/install.sh | sudo bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/Canol001/radius/main/install.sh | sudo bash
```

## Features

- **Multi-Router Support**: Manage unlimited MikroTik routers from a single panel
- **WireGuard VPN**: Secure tunnel for routers behind NAT - no port forwarding needed
- **Real-time Status**: Monitor RADIUS, WireGuard, and router connection status
- **Instant Disconnect**: Kick users immediately via MikroTik API through VPN tunnel
- **Voucher Management**: Generate, print, disable, and track vouchers
- **Bandwidth Plans**: Create speed-limited plans for vouchers
- **Active Sessions**: Monitor connected users in real-time
- **CoA Support**: Change of Authorization works through VPN tunnel
- **Reports**: Usage statistics, top users, daily charts
- **Activity Logging**: Track all admin actions
- **Setup Wizard**: Easy database and admin configuration on first run

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        VPS SERVER                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ FreeRADIUS  │  │  WireGuard  │  │   Web Admin Panel   │ │
│  │  1812/1813  │  │    51820    │  │    (Flask/Nginx)    │ │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────┘ │
│         │                │                                  │
│         └────────┬───────┘                                  │
│                  │ 10.10.0.1                                │
└──────────────────┼──────────────────────────────────────────┘
                   │
          WireGuard Tunnel (Encrypted)
                   │
     ┌─────────────┼─────────────┐
     │             │             │
┌────┴────┐  ┌────┴────┐  ┌────┴────┐
│ Router1 │  │ Router2 │  │ Router3 │
│10.10.0.2│  │10.10.0.3│  │10.10.0.4│
│(NAT OK) │  │(NAT OK) │  │(NAT OK) │
└─────────┘  └─────────┘  └─────────┘
```

## Requirements

- Ubuntu 20.04/22.04 or Debian 11/12
- Root access to VPS
- MikroTik router(s) with RouterOS 7+ (for WireGuard)

## Manual Installation

If you prefer manual installation:

```bash
git clone https://github.com/Canol001/radius.git
cd radius
sudo bash install.sh
```

## What Gets Installed

- FreeRADIUS 3.0 with MySQL support
- MariaDB database
- WireGuard VPN server
- Nginx web server
- Python Flask application
- UFW firewall rules

## After Installation

1. Access admin panel: `http://YOUR_VPS_IP/`
2. Complete the **Setup Wizard** (database config, admin account)
3. Go to **System Status** to verify all services are running
4. Add your MikroTik router(s) with WireGuard enabled
5. Follow the generated WireGuard config on each router
6. Create bandwidth plans and generate vouchers

## Adding a Router with WireGuard

### 1. In Admin Panel
- Go to **Routers** → **Add Router**
- Enable **WireGuard VPN Tunnel**
- Note the assigned tunnel IP (e.g., 10.10.0.2/32)
- Enable **MikroTik API** for instant disconnect
- Save the router

### 2. On MikroTik Router (RouterOS 7+)
```routeros
# Create WireGuard interface
/interface wireguard add name=wg-radius listen-port=13231

# Get your public key (copy this to admin panel)
:put [/interface wireguard get wg-radius public-key]

# Add VPS as peer
/interface wireguard peers add \
    interface=wg-radius \
    public-key="YOUR_VPS_PUBLIC_KEY" \
    endpoint-address=YOUR_VPS_IP \
    endpoint-port=51820 \
    allowed-address=10.10.0.0/24 \
    persistent-keepalive=25

# Assign tunnel IP
/ip address add address=10.10.0.2/24 interface=wg-radius

# Configure RADIUS to use tunnel
/radius add service=hotspot,login address=10.10.0.1 secret="your_secret"
/radius incoming set accept=yes port=3799

# Enable API (secured via tunnel)
/ip service set api disabled=no address=10.10.0.0/24
```

## Firewall Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP |
| 443 | TCP | HTTPS |
| 1812 | UDP | RADIUS Auth |
| 1813 | UDP | RADIUS Accounting |
| 51820 | UDP | WireGuard VPN |

## System Status Dashboard

The **System Status** page shows:
- FreeRADIUS service status
- WireGuard VPN status with connected peers
- Database status
- Web server status
- Per-router WireGuard connection status

## Troubleshooting

### Check Service Status
```bash
systemctl status radius-server freeradius wg-quick@wg0 nginx
```

### WireGuard
```bash
# Show WireGuard status and peers
wg show

# Check if peer is connected (look for recent handshake)
wg show wg0
```

### FreeRADIUS
```bash
# Test authentication
radtest VOUCHER_CODE VOUCHER_CODE localhost 0 testing123

# Debug mode
systemctl stop freeradius
freeradius -X
```

### Logs
```bash
journalctl -u radius-server -f
tail -f /var/log/freeradius/radius.log
```

## File Structure

```
/opt/radius-server/
├── app.py                 # Main Flask application
├── templates/             # HTML templates
├── venv/                  # Python virtual environment
├── config.json            # Database & server config
├── INSTALL_INFO.txt       # Installation credentials
└── wireguard_public_key.txt

/etc/wireguard/
└── wg0.conf              # WireGuard server config

/etc/freeradius/3.0/
├── mods-enabled/sql      # SQL module config
└── clients.conf          # NAS clients (managed via DB)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/system/status` | GET | System services status |
| `/api/wireguard/status` | GET | WireGuard peers status |
| `/api/router/<id>/status` | GET | Router connection status |
| `/api/router/<id>/wg-status` | GET | Router WireGuard status |
| `/api/database/health` | GET | Database connection status |

## Useful Commands

```bash
# Check service status
systemctl status radius-server freeradius wg-quick@wg0 nginx

# View logs
journalctl -u radius-server -f
tail -f /var/log/freeradius/radius.log

# Test RADIUS
radtest VOUCHER_CODE VOUCHER_CODE localhost 0 testing123

# WireGuard status
wg show

# Restart services
systemctl restart radius-server freeradius
```

## Security Notes

- Change default admin password immediately
- WireGuard traffic is encrypted end-to-end
- MikroTik API is only accessible via VPN tunnel
- Use strong RADIUS secrets
- Consider enabling HTTPS with Let's Encrypt:
  ```bash
  certbot --nginx -d yourdomain.com
  ```

## License

MIT License
