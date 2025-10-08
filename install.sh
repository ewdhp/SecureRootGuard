#!/bin/bash

# SecureRootGuard Installation Script
# This script installs SecureRootGuard system components

set -e

echo "🛡️  SecureRootGuard Installation"
echo "================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

echo "✅ Running with root privileges"

# Create system directories
echo "📁 Creating system directories..."
mkdir -p /etc/securerootguard
mkdir -p /var/log/securerootguard
mkdir -p /var/lib/securerootguard

# Set permissions
chmod 755 /etc/securerootguard
chmod 750 /var/log/securerootguard  
chmod 700 /var/lib/securerootguard

# Create default configuration
echo "⚙️  Creating default configuration..."
cat > /etc/securerootguard/config.json << 'EOF'
{
  "sessionTimeout": "00:15:00",
  "totpWindow": 30,
  "requireTotpForSudo": true,
  "logLevel": "Information",
  "auditPath": "/var/log/securerootguard/",
  "encryptionKey": "auto-generated",
  "allowedUsers": [],
  "restrictedCommands": ["rm -rf /", "dd if="],
  "security": {
    "keyRotationInterval": "01:00:00",
    "maxConcurrentSessions": 3,
    "requireReauthentication": true,
    "memoryEncryption": "AES-256-GCM",
    "sessionIsolation": true
  }
}
EOF

# Install binary
echo "📦 Installing SecureRootGuard binary..."
if [ -f "./bin/Release/net8.0/SecureRootGuard" ]; then
    cp ./bin/Release/net8.0/SecureRootGuard /usr/local/bin/securerootguard
    chmod 755 /usr/local/bin/securerootguard
    echo "✅ Binary installed to /usr/local/bin/securerootguard"
else
    echo "❌ Binary not found. Please build the project first:"
    echo "   dotnet build --configuration Release"
    exit 1
fi

# Create systemd service
echo "🔧 Installing systemd service..."
cat > /etc/systemd/system/securerootguard.service << 'EOF'
[Unit]
Description=SecureRootGuard - Root Privilege Protection Service  
After=network.target
Wants=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/securerootguard daemon
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory=/var/lib/securerootguard
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securerootguard

# Security settings
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/securerootguard /var/log/securerootguard /etc/securerootguard
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Create sudoers integration (optional)
echo "🔐 Setting up sudo integration..."
if [ -d "/etc/sudoers.d" ]; then
    cat > /etc/sudoers.d/securerootguard << 'EOF'
# SecureRootGuard sudo integration
# Uncomment the following line to require SecureRootGuard for all sudo operations
# Defaults env_reset,timestamp_timeout=0,requiretty,!authenticate
# %sudo ALL=(ALL:ALL) !/usr/local/bin/securerootguard exec *
EOF
    chmod 440 /etc/sudoers.d/securerootguard
    echo "✅ Sudoers integration file created (disabled by default)"
fi

# Create log rotation
echo "📝 Setting up log rotation..."
cat > /etc/logrotate.d/securerootguard << 'EOF'
/var/log/securerootguard/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl reload securerootguard 2>/dev/null || true
    endscript
}
EOF

echo ""
echo "🎉 Installation Complete!"
echo "========================"
echo ""
echo "Next steps:"
echo "1. Start the service: systemctl start securerootguard"
echo "2. Enable auto-start: systemctl enable securerootguard"  
echo "3. Setup TOTP: securerootguard setup --user \$USER"
echo "4. Test setup: securerootguard test"
echo ""
echo "Configuration file: /etc/securerootguard/config.json"
echo "Logs directory: /var/log/securerootguard/"
echo ""
echo "⚠️  Review the configuration before enabling sudo integration!"