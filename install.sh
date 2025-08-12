#!/bin/bash

set -e

if [[ "$EUID" -ne 0 ]]; then
  echo "❌ Please run as root."
  exit 1
fi

# echo $OSTYPE 
# if [[ "$OSTYPE" != "linux-gnu"* ]]; then
#   echo "❌ Unsupported OS: $OSTYPE"
#   exit 1
# fi

OSTYPE=$(uname | tr '[:upper:]' '[:lower:]')-$(uname -m)

AGENT_NAME="ultaai-agent"
INSTALL_DIR="/usr/bin"
SERVICE_NAME="ultahost-agent"
SCRIPT_URL="http://193.109.193.72:8088/ultahost-agent-binary-${OSTYPE}"
# SCRIPT_URL="http://193.109.193.72:8088/ultahost-agent-binary"

UUID_FILE="/etc/ultaai-agent-id"
BASE_DIR="/var/vm-agent"

echo $SCRIPT_URL

echo "📦 Installing UltaAI Agent..."

# --- Create directory structure ---
echo "📁 Creating directories..."
mkdir -p "$BASE_DIR/logs/ultaai"
mkdir -p "$BASE_DIR/scripts"
touch "$BASE_DIR/scripts/test_file.sh"

mkdir -p "$BASE_DIR/config"

# --- Remove old binary if exists ---
if [ -f "$INSTALL_DIR/$AGENT_NAME" ]; then
  echo "🧹 Removing old agent binary..."
  rm -f "$INSTALL_DIR/$AGENT_NAME"
fi

# --- Download the binary ---
echo "⬇️ Downloading agent binary..."
curl -o "$INSTALL_DIR/$AGENT_NAME" -L "$SCRIPT_URL"
chmod +x "$INSTALL_DIR/$AGENT_NAME"

# --- Generate Agent ID ---
if [ ! -f "$UUID_FILE" ]; then
  echo "🔑 Generating unique agent ID..."
  uuidgen > "$UUID_FILE"
fi

# --- Create systemd Service ---
echo "⚙️ Setting up systemd service..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=UltaAI Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$AGENT_NAME
WorkingDirectory=$BASE_DIR
#tandardOutput=append:$BASE_DIR/logs/ultaai/agent.log
#tandardError=append:$BASE_DIR/logs/ultaai/agent-error.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and start service ---
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME.service


echo "✅ UltaAI Agent installed and running!"
echo "✅ To get $SERVICE_NAME.service logs: journalctl -u $SERVICE_NAME.service"