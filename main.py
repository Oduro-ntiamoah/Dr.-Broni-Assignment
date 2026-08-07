import logging
import time

import psutil

import config
from allowlist import Allowlist
from blocker import handle_violation
from reporter import Reporter


def setup_logging():
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


def check_process(pid, proc, allowlist, reporter, force_block=False):
    """
    Evaluate a single process against the allowlist. If force_block is True
    (e.g. baseline or re-check), a violation is handled even if we already
    flagged this process before.
    Returns True if the process is allowed or was handled, False on failure.
    """
    name = proc["name"]
    exe_path = proc["exe"]

    if not exe_path:
        logging.warning("Process with no readable exe path: PID=%s Name=%s", pid, name)
        reporter.report_event("violation", name, pid=pid, action_taken="flagged_no_path",
                              detail="Executable path unreadable - could not verify")
        return True

    allowed, file_hash = allowlist.is_allowed(exe_path)

    if allowed and not force_block:
        logging.info("ALLOWED | PID=%s Name=%s Path=%s", pid, name, exe_path)
        reporter.report_event("allowed", name, pid=pid, file_path=exe_path,
                              file_hash=file_hash, action_taken="none")
        return True

    if allowed:
        # force_block means it was previously allowed but removed from allowlist,
        # or baseline re-check. Treat as violation now.
        logging.warning("VIOLATION (re-check) | PID=%s Name=%s Path=%s", pid, name, exe_path)
        result = handle_violation(pid, name, exe_path)
        reporter.report_event(
            "violation", name, pid=pid, file_path=exe_path,
            file_hash=file_hash, action_taken=result["action"],
            detail=f"Pre-existing process flagged on re-check. Quarantined to: {result['quarantined_path']}"
            if result["quarantined_path"] else "Pre-existing process flagged on re-check"
        )
        return True

    logging.warning("VIOLATION | PID=%s Name=%s Path=%s", pid, name, exe_path)
    result = handle_violation(pid, name, exe_path)
    reporter.report_event(
        "violation", name, pid=pid, file_path=exe_path,
        file_hash=file_hash, action_taken=result["action"],
        detail=f"Quarantined to: {result['quarantined_path']}" if result["quarantined_path"] else ""
    )
    return True


def main():
    setup_logging()
    logging.info("ESCA Agent starting on device: %s (dashboard: %s)",
                 config.DEVICE_ID, config.DASHBOARD_URL)

    allowlist = Allowlist()
    reporter = Reporter()

    # Initial sync attempt (falls back to local cache if dashboard unreachable)
    allowlist.sync_from_dashboard()

    current = get_current_processes()
    known_pids = set(current.keys())
    logging.info("Baseline established: %d processes running", len(known_pids))

    # Validate the baseline processes now (they were already running before
    # the agent started, so they'd otherwise be trusted forever).
    for pid, proc in current.items():
        check_process(pid, proc, allowlist, reporter, force_block=True)

    last_allowlist_sync = time.time()
    last_heartbeat = time.time()
    last_recheck = time.time()

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
                check_process(pid, current[pid], allowlist, reporter)

            # --- Periodically re-check all running processes ---
            # Catches processes that were allowed at start / first-seen but whose
            # hash has since been removed from the allowlist, or that re-execed.
            if config.PROCESS_RECHECK_INTERVAL > 0 and \
               now - last_recheck >= config.PROCESS_RECHECK_INTERVAL:
                logging.info("Periodic re-check of %d running processes", len(current_pids))
                for pid in current_pids:
                    proc = current[pid]
                    allowed, _ = allowlist.is_allowed(proc["exe"]) if proc["exe"] else (False, None)
                    # Only re-kill if it's now a violation (deny-by-default).
                    if not allowed:
                        check_process(pid, proc, allowlist, reporter, force_block=True)
                last_recheck = now

            known_pids = current_pids

    except KeyboardInterrupt:
        logging.info("ESCA Agent stopped by user.")


if __name__ == "__main__":
    main()
