# ESCA - Endpoint Software Control Agent

A semester project implementing endpoint monitoring for unauthorized
software installation "shadow IT", with a central dashboard.

## Architecture

```
Ubuntu VM (endpoint)                Windows Host (dashboard)
+-------------------+   HTTPS/JSON  +----------------------+
|  agent/main.py     | ------------> |  dashboard/app.py     |
|  - process poll    |  reports      |  - Flask + SQLite     |
|  - allowlist check | <------------ |  - API + Web UI        |
|  - kill+quarantine |  allowlist    |                        |
+-------------------+   sync        +----------------------+
```

## Setup: Dashboard (Windows host)

```
cd dashboard
pip install -r requirements.txt
python app.py
```

Runs at `http://0.0.0.0:5000`. Reachable from the VM at `http://10.0.2.2:5000`
(VirtualBox's NAT alias for the host) as long as the VM's Adapter 1 is set to
plain "NAT" mode.

Open `http://localhost:5000` in a browser on the host to use the dashboard UI.

**Before testing blocking behavior**, add at least a few known-safe binaries
to the Allowlist (via the web UI + Hash Tool) — e.g. `/bin/bash`, `/usr/bin/gedit`
— otherwise ALL processes will be flagged as violations, including normal
system processes, which will make the VM hard to use.

## Setup: Agent (Ubuntu VM)

```
cd agent
pip3 install -r requirements.txt
sudo python3 main.py
```

`sudo` is required because the agent needs permission to kill processes it
doesn't own and to modify file permissions during quarantine.

Edit `config.py` first if your dashboard isn't at `10.0.2.2:5000`.

## Testing the flow

1. Start the dashboard, add a couple of safe binaries to the allowlist
   (use the Hash Tool to get their SHA-256 first)
2. Start the agent on the VM
3. Launch an allowlisted app -> should log as "allowed" in the dashboard's event log
4. Launch something NOT on the allowlist (e.g. `sudo apt install -y sl && sl`)
   -> should be killed, quarantined to `/var/lib/esca/quarantine/`, and logged
   as a "violation" on the dashboard

## Known limitations (documented for the report)

- Detection uses `psutil` polling (2s interval) rather than kernel-level hooks
  (e.g. `auditd` or a filter driver) - a very short-lived process could be
  missed. Documented as a deliberate scope tradeoff for a semester project.
- Single shared API key for all agents, rather than per-device credentials.
- No TLS between agent and dashboard (plain HTTP) - acceptable for an isolated
  lab network, would need HTTPS for any real deployment.
- Only covers process execution + manual/apt installs; does not cover
  cloud/SaaS shadow IT (a separate CASB-style problem).
