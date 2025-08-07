#!/bin/bash

set -e

AGENT_BINARY=run-agent
SERVICE_FILE=run-agent.service
ENV_FILE=run-agent.env

echo "📦 Installing Ultahost VM Agent..."

# 1. Copy binary
if [ ! -f "$AGENT_BINARY" ]; then
  echo "❌ Error: $AGENT_BINARY not found in current directory."
  exit 1
fi
sudo cp $AGENT_BINARY /usr/local/bin/run-agent
sudo chmod +x /usr/local/bin/run-agent

# 2. Copy environment file
if [ ! -f "$ENV_FILE" ]; then
  echo "❌ Error: $ENV_FILE not found in current directory."
  exit 1
fi
sudo cp $ENV_FILE /etc/run-agent.env
sudo chmod 600 /etc/run-agent.env

# 3. Copy service file
if [ ! -f "$SERVICE_FILE" ]; then
  echo "❌ Error: $SERVICE_FILE not found in current directory."
  exit 1
fi
sudo cp $SERVICE_FILE /etc/systemd/system/run-agent.service

# 4. Reload systemd and enable service
sudo systemctl daemon-reexec
sudo systemctl enable run-agent
sudo systemctl restart run-agent

# 5. Check status
echo "🔍 Checking service status:"
sudo systemctl status run-agent --no-pager

echo "✅ VM Agent is now installed and running."
