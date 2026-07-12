import logging
import time

import psutil

import config
from allowlist import Allowlist
from blocker import handle_violation
from reporter import Reporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)


def get_current_processes():
    current = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
        try:
            info = proc.info
            current[info["pid"]] = {
                "name": info["name"],
                "exe": info["exe"] or "",
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return current


def main():
    logging.info("ESCA Agent starting on device: %s", config.DEVICE_ID)

    allowlist = Allowlist()
    reporter = Reporter()

    # Initial sync attempt (falls back to local cache if dashboard unreachable)
    allowlist.sync_from_dashboard()

    known_pids = set(get_current_processes().keys())
    logging.info("Baseline established: %d processes running", len(known_pids))

    last_allowlist_sync = time.time()
    last_heartbeat = time.time()

    try:
        while True:
            time.sleep(config.PROCESS_POLL_INTERVAL)
            now = time.time()

            # --- Periodic allowlist sync ---
            if now - last_allowlist_sync >= config.ALLOWLIST_SYNC_INTERVAL:
                allowlist.sync_from_dashboard()
                last_allowlist_sync = now

            # --- Periodic heartbeat ---
            if now - last_heartbeat >= config.HEARTBEAT_INTERVAL:
                reporter.heartbeat()
                last_heartbeat = now

            # --- Detect new processes ---
            current = get_current_processes()
            current_pids = set(current.keys())
            new_pids = current_pids - known_pids

            for pid in new_pids:
                proc = current[pid]
                name = proc["name"]
                exe_path = proc["exe"]

                if not exe_path:
                    # Can't verify hash without a path - treat conservatively
                    logging.warning("New process with no readable exe path: PID=%s Name=%s", pid, name)
                    reporter.report_event("violation", name, pid=pid, action_taken="flagged_no_path",
                                          detail="Executable path unreadable - could not verify")
                    continue

                allowed, file_hash = allowlist.is_allowed(exe_path)

                if allowed:
                    logging.info("ALLOWED | PID=%s Name=%s Path=%s", pid, name, exe_path)
                    reporter.report_event("allowed", name, pid=pid, file_path=exe_path,
                                          file_hash=file_hash, action_taken="none")
                else:
                    logging.warning("VIOLATION | PID=%s Name=%s Path=%s", pid, name, exe_path)
                    result = handle_violation(pid, name, exe_path)
                    reporter.report_event(
                        "violation", name, pid=pid, file_path=exe_path,
                        file_hash=file_hash, action_taken=result["action"],
                        detail=f"Quarantined to: {result['quarantined_path']}" if result["quarantined_path"] else ""
                    )

            known_pids = current_pids

    except KeyboardInterrupt:
        logging.info("ESCA Agent stopped by user.")


if __name__ == "__main__":
    main()
