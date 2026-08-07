# Connecting a VM to the ESCA Dashboard on the same network

The dashboard (`app.py`) runs on this host and binds to `0.0.0.0`, so any
device on the same network can reach it. The agent (`main.py`) running in a
VM connects to the dashboard to sync the allowlist and report events.

## How the dashboard URL is chosen

On startup, `config.py` auto-detects this host's LAN IP and sets:

    DASHBOARD_URL = http://<LAN_IP>:5000

This works for **bridged** VMs (the VM has its own LAN IP and reaches the
host at the host's LAN IP).

### Override via environment variables

For **VirtualBox NAT** mode (the old `10.0.2.2` host alias) or a fixed IP,
set the full URL before starting the agent:

```bash
export ESCA_DASHBOARD_URL="http://10.0.2.2:5000"   # NAT mode
# or a fixed IP
export ESCA_DASHBOARD_URL="http://192.168.1.50:5000"
```

You can also force the LAN IP used in the banner:

```bash
export ESCA_LAN_IP="192.168.1.50"
```

## Dashboard (server) configuration

All optional, via environment variables on the host:

| Variable          | Default            | Purpose                          |
|-------------------|--------------------|----------------------------------|
| `ESCA_HOST`       | `0.0.0.0`          | Bind address for Flask           |
| `ESCA_PORT`       | `5000`             | Port for Flask                   |
| `ESCA_DEBUG`      | off                | `1` to enable Flask debugger     |
| `ESCA_WEB_USER`   | empty (disabled)   | Enable basic auth for web UI     |
| `ESCA_WEB_PASS`   | empty              | Password for web UI auth         |
| `ESCA_API_KEY`    | `esca-demo-key-001`| Shared key for agent API calls   |
| `ESCA_DATABASE_URI`| `sqlite:///esca.db`| SQLAlchemy database URI          |
| `ESCA_SECRET_KEY` | dev-secret-change-me | Flask secret key                |

> **Security:** set `ESCA_WEB_USER`/`ESCA_WEB_PASS` and change `ESCA_API_KEY`
> (and pass the same key to the agent) before exposing the dashboard beyond a
> trusted lab network. Consider placing it behind HTTPS/reverse proxy for real
> deployments.

## Agent configuration

On the VM, edit `config.py` (or set `ESCA_DASHBOARD_URL`) so the agent points
at the dashboard. The agent rejects/ignores mismatched API keys.

## Getting the LAN IP

Run the dashboard and read the banner, or use:

```bash
# Windows
ipconfig

# Linux
hostname -I
```

## Firewall note

Make sure port `5000` is open/allowed on the host's firewall so a bridged VM
(or any LAN device) can reach the dashboard:

```bash
# Windows (admin PowerShell)
New-NetFirewallRule -DisplayName "ESCA Dashboard" -Direction Inbound \
  -Protocol TCP -LocalPort 5000 -Action Allow
```

```bash
# Linux (ufw)
sudo ufw allow 5000/tcp
