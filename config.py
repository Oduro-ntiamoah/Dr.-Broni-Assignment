import socket

# Dashboard connection
DASHBOARD_URL = "http://10.0.2.2:5000"   # Windows host, reachable via VirtualBox NAT alias
API_KEY = "esca-demo-key-001"             # simple shared key for this project (per-device keys = future improvement)

# Device identity (used so dashboard can tell agents apart)
DEVICE_ID = socket.gethostname()

# Polling / sync intervals (seconds)
PROCESS_POLL_INTERVAL = 2
ALLOWLIST_SYNC_INTERVAL = 60
HEARTBEAT_INTERVAL = 30

# Local storage
LOCAL_ALLOWLIST_CACHE = "allowlist_cache.json"
LOCAL_EVENT_QUEUE = "event_queue.json"
LOG_FILE = "esca_agent.log"
QUARANTINE_DIR = "/var/lib/esca/quarantine"

# Directories to watch for manually-downloaded/executed binaries
WATCH_DIRS = [
    "/home",
    "/tmp",
    "/opt",
]
