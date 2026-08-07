import os
import socket
import platform

# ---------------------------------------------------------------------------
# Dashboard connection
# ---------------------------------------------------------------------------
# The dashboard (server) runs on this host. The agent running in a VM on the
# same network needs to reach it. We auto-detect the host's LAN IP so the
# dashboard URL is usable by a bridged VM. This can be overridden with the
# ESCA_DASHBOARD_URL env var (e.g. for VirtualBox NAT mode where the host is
# reachable at its gateway/bridge IP, or a fixed IP).
def _detect_lan_ip():
    """Return the primary LAN IPv4 address of this host, or loopback."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't actually send packets; just picks the outbound interface.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


LAN_IP = os.environ.get("ESCA_LAN_IP", _detect_lan_ip())

# Default dashboard URL. Override fully with ESCA_DASHBOARD_URL.
if os.environ.get("ESCA_DASHBOARD_URL"):
    DASHBOARD_URL = os.environ["ESCA_DASHBOARD_URL"].rstrip("/")
else:
    DASHBOARD_URL = f"http://{LAN_IP}:5000"

API_KEY = os.environ.get("ESCA_API_KEY", "esca-demo-key-001")

# Device identity (used so dashboard can tell agents apart)
DEVICE_ID = socket.gethostname()

# ---------------------------------------------------------------------------
# Dashboard (server) binding
# ---------------------------------------------------------------------------
SERVER_HOST = os.environ.get("ESCA_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("ESCA_PORT", "5000"))
# Enable Flask debugger only when explicitly requested (RCE risk otherwise).
SERVER_DEBUG = os.environ.get("ESCA_DEBUG", "").lower() in ("1", "true", "yes")

# Optional simple auth for the dashboard web UI (set ESCA_WEB_USER / ESCA_WEB_PASS).
WEB_USER = os.environ.get("ESCA_WEB_USER", "")
WEB_PASS = os.environ.get("ESCA_WEB_PASS", "")

# ---------------------------------------------------------------------------
# Polling / sync intervals (seconds)
# ---------------------------------------------------------------------------
PROCESS_POLL_INTERVAL = 2
ALLOWLIST_SYNC_INTERVAL = 60
HEARTBEAT_INTERVAL = 30
# How often to re-validate currently-running processes against the allowlist
# (in addition to checking brand-new PIDs). 0 disables periodic re-check.
PROCESS_RECHECK_INTERVAL = 60

# ---------------------------------------------------------------------------
# Local storage
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_ALLOWLIST_CACHE = os.path.join(BASE_DIR, "allowlist_cache.json")
LOCAL_EVENT_QUEUE = os.path.join(BASE_DIR, "event_queue.json")
LOG_FILE = os.path.join(BASE_DIR, "esca_agent.log")

# ---------------------------------------------------------------------------
# Quarantine + watch dirs (platform-aware so it runs on Windows OR Linux)
# ---------------------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    QUARANTINE_DIR = os.path.join(os.environ.get(
        "LOCALAPPDATA", os.path.expanduser("~")), "ESCA", "quarantine")
    WATCH_DIRS = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop"),
        os.environ.get("TEMP", os.path.expanduser("~")),
    ]
else:
    QUARANTINE_DIR = os.environ.get("ESCA_QUARANTINE_DIR", "/var/lib/esca/quarantine")
    WATCH_DIRS = [
        "/home",
        "/tmp",
        "/opt",
    ]
