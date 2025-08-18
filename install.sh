#!/bin/bash
set -e

if [[ "$EUID" -ne 0 ]]; then
  echo "❌ Please run as root."
  exit 1
fi

# Detect OS/Arch
OSTYPE=$(uname | tr '[:upper:]' '[:lower:]')-$(uname -m)

AGENT_NAME="ultaai-agent"
INSTALL_DIR="/usr/bin"
SERVICE_NAME="ultahost-agent"
SCRIPT_URL="http://193.109.193.72:8089/ultahost-agent-binary-${OSTYPE}"
UUID_FILE="/etc/ultaai-agent-id"
# BASE_DIR="/var/lib/ultaai"  
BASE_DIR="/ultaai-dev"

ULUSER="ultaai"

# --- Parse token arg ---
for i in "$@"; do
  case $i in
    --token=*)
      INSTALL_TOKEN="${i#*=}"
      shift
      ;;
    *)
      ;;
  esac
done

if [ -z "$INSTALL_TOKEN" ]; then
  echo "❌ Missing required --token parameter"
  exit 1
fi

echo "🔑 Using install token: $INSTALL_TOKEN"

# --- Store token in environment file for systemd ---
ENV_FILE="/etc/default/$SERVICE_NAME"
echo "INSTALL_TOKEN=$INSTALL_TOKEN" > "$ENV_FILE"
chown "$ULUSER":"$ULUSER" "$ENV_FILE" || true
chmod 600 "$ENV_FILE"

echo "📦 Installing UltaAI Agent for $OSTYPE..."
echo "Download URL: $SCRIPT_URL"

# --- Stop and remove old service if exists ---
if systemctl list-units --type=service --all | grep -q "$SERVICE_NAME.service"; then
  echo "🛑 Stopping old service..."
  systemctl stop "$SERVICE_NAME" || true
  systemctl disable "$SERVICE_NAME" || true
  rm -f "/etc/systemd/system/$SERVICE_NAME.service"
  systemctl daemon-reload
  echo "🧹 Old service removed."aca
fi

# --- Create dedicated ultaai user if missing ---
if ! id -u "$ULUSER" >/dev/null 2>&1; then
  echo "👤 Creating system user: $ULUSER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$ULUSER"
fi

# --- Create directory structure ---
echo "📁 Creating directories..."
mkdir -p "$BASE_DIR/logs"
mkdir -p "$BASE_DIR/scripts"
mkdir -p "$BASE_DIR/config"
touch "$BASE_DIR/scripts/test_file.sh"

# Assign ownership to ultaai
chown -R "$ULUSER":"$ULUSER" "$BASE_DIR"
chmod -R 750 "$BASE_DIR"

# --- Remove old binary if exists ---
if [ -f "$INSTALL_DIR/$AGENT_NAME" ]; then
  echo "🧹 Removing old agent binary..."
  rm -f "$INSTALL_DIR/$AGENT_NAME"
fi

# --- Download the binary ---
echo "⬇️ Downloading agent binary..."
curl -sS -o "$INSTALL_DIR/$AGENT_NAME" -L "$SCRIPT_URL"
chmod +x "$INSTALL_DIR/$AGENT_NAME"
chown "$ULUSER":"$ULUSER" "$INSTALL_DIR/$AGENT_NAME"

# --- Generate Agent ID ---
if [ ! -f "$UUID_FILE" ]; then
  echo "🔑 Generating unique agent ID..."
  uuidgen > "$UUID_FILE"
  chown "$ULUSER":"$ULUSER" "$UUID_FILE"
fi

# --- Create systemd Service ---
echo "⚙️ Setting up systemd service..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=UltaAI Agent
After=network.target

[Service]
Type=simple
User=$ULUSER
EnvironmentFile=/etc/default/$SERVICE_NAME
ExecStart=$INSTALL_DIR/$AGENT_NAME
WorkingDirectory=$BASE_DIR
Restart=always
RestartSec=5
StandardOutput=append:$BASE_DIR/logs/agent.log
StandardError=append:$BASE_DIR/logs/agent-error.log

[Install]
WantedBy=multi-user.target
EOF

# --- Reload systemd and start service ---
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "✅ UltaAI Agent installed and running as user '$ULUSER'!"
echo "✅ To get $SERVICE_NAME.service logs: journalctl -u $SERVICE_NAME.service -f"
