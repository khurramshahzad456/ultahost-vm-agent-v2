# Ultahost VM Agent

This is a secure HTTP-based agent designed to be installed on Ultahost-provisioned VMs to receive and execute Linux commands remotely via `/run-command`.

## Features
- 🔐 Token-based authentication (hash)
- 🔒 IP whitelisting (backend-only)
- ✅ Lightweight, single binary Go app
- 🛡️ No SSH required, safe for cloud environments

## Environment Variables
- `RUN_AGENT_HASH`: Shared secret to authenticate the backend
- `WHITELISTED_IP`: Public IP of Ultahost backend allowed to send requests

## Endpoints

### POST `/run-command`
Request:
```json
{
  "command": "df -h",
  "hash": "3432748974983jc93..."
}
```

Response:
```json
{
  "output": "Filesystem info...",
  "error": ""
}
```

## Deploy via systemd
1. Copy binary to `/usr/local/bin/run-agent`
2. Copy `run-agent.service` to `/etc/systemd/system/`
3. Copy `run-agent.env` to `/etc/`
4. Run:
```bash
sudo systemctl daemon-reexec
sudo systemctl enable run-agent
sudo systemctl start run-agent
```

## Docker
```bash
docker build -t ultahost-agent .
docker run -p 8080:8080 -e RUN_AGENT_HASH=... -e WHITELISTED_IP=... ultahost-agent
```
