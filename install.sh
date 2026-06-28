#!/bin/bash
# ALPHVDR Installer
# Configures the EDR service with an unassuming name to avoid detection.

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Building ALPHVDR EDR..."
cd "$(dirname "$0")" || exit
cargo build --release

echo "Installing binary..."
mkdir -p /usr/local/bin
cp target/release/alphvdr-agent /usr/local/bin/sys-thermald
chmod +x /usr/local/bin/sys-thermald

echo "Creating systemd service..."
cat > /etc/systemd/system/sys-thermald.service << 'EOF'
[Unit]
Description=System Thermal and Power Management Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sys-thermald
Restart=always
RestartSec=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable sys-thermald
systemctl start sys-thermald

echo "Installation complete. Service 'sys-thermald' is running."
