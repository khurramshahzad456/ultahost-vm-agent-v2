#!/bin/bash
set -e

AGENT_NAME="ultaai-agent"
INSTALL_DIR="/usr/bin"
UUID_FILE="/etc/ultaai-agent-id"
BASE_DIR="/var/vm-agent"
JAIL_DIR="/tmp/testjail"
TEST_SERVICE="test-agent"

# --- Cleanup mode first ---
if [[ "$1" == "cleanup" ]]; then
    echo "🛑 Stopping test service..."
    sudo systemctl stop $TEST_SERVICE || true
    sudo systemctl disable $TEST_SERVICE || true
    sudo rm -f /etc/systemd/system/$TEST_SERVICE.service
    sudo systemctl daemon-reload
    echo "🧹 Removing chroot jail..."
    sudo rm -rf "$JAIL_DIR"
    echo "✅ Cleanup complete."
    exit 0
fi

# --- Setup mode ---
echo "🔧 Setting up temporary chroot jail for testing..."

# Create jail directories
sudo mkdir -p "$JAIL_DIR$INSTALL_DIR"
sudo mkdir -p "$JAIL_DIR$BASE_DIR/logs/ultaai"
sudo mkdir -p "$JAIL_DIR$BASE_DIR/scripts"
sudo mkdir -p "$JAIL_DIR$BASE_DIR/config"
sudo mkdir -p "$JAIL_DIR/etc"

# Copy binary
sudo cp "$INSTALL_DIR/$AGENT_NAME" "$JAIL_DIR$INSTALL_DIR/"
sudo chmod +x "$JAIL_DIR$INSTALL_DIR/$AGENT_NAME"

# Copy UUID file if exists
if [ -f "$UUID_FILE" ]; then
    sudo cp "$UUID_FILE" "$JAIL_DIR/etc/"
fi

# Create test systemd service
echo "⚙️ Creating temporary systemd service..."
sudo tee /etc/systemd/system/$TEST_SERVICE.service >/dev/null <<EOF
[Unit]
Description=UltaAI Agent (Chroot Test)
After=network.target

[Service]
Type=simple
User=nobody
RootDirectory=$JAIL_DIR
ExecStart=$INSTALL_DIR/$AGENT_NAME
WorkingDirectory=$BASE_DIR
Restart=always
RestartSec=5
StandardOutput=append:$BASE_DIR/logs/ultaai/agent.log
StandardError=append:$BASE_DIR/logs/ultaai/agent-error.log

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl start $TEST_SERVICE
sudo systemctl status $TEST_SERVICE --no-pager

echo ""
echo "✅ Chroot test service started: $TEST_SERVICE"
echo "📜 Logs: journalctl -u $TEST_SERVICE -f"
echo "🛑 To stop & clean up: sudo ./test-chroot.sh cleanup"
