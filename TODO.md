# ESCA Fix Plan - Task List

## Step 1: config.py
- [x] Auto-detect host LAN IP with env override (ESCA_DASHBOARD_URL)
- [x] Platform-aware QUARANTINE_DIR and WATCH_DIRS
- [x] Add ESCA_HOST / ESCA_PORT for dashboard binding

## Step 2: blocker.py
- [x] Cross-platform quarantine (Windows vs Linux chmod)
- [x] Retry on transient file lock/permission errors
- [x] Clear AccessDenied handling

## Step 3: main.py
- [x] Validate baseline processes at startup against allowlist
- [x] Periodically re-check running processes (not just new PIDs)
- [x] Handle PID/process races gracefully

## Step 4: allowlist.py
- [x] No change needed (already exposes entries for re-check)

## Step 5: app.py (dashboard server)
- [x] Bind 0.0.0.0 with ESCA_HOST/ESCA_PORT env config
- [x] Optional web UI management auth (env-configurable)
- [x] Disable debug=True by default (env override)
- [x] Print LAN IP & config at startup banner for agent config

## Step 6: Documentation
- [x] Add NETWORK.md explaining bridged + NAT setup

## Step 7: Verify
- [x] Syntax-check all edited files
- [x] Confirm config auto-detects LAN IP + Windows paths
