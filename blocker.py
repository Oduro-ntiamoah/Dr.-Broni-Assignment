"""
ESCA Agent - Blocking & Quarantine
Kills unauthorized processes and moves their executable to a
locked-down quarantine directory.
"""

import logging
import os
import shutil
import stat
import time

import psutil

import config


def ensure_quarantine_dir():
    os.makedirs(config.QUARANTINE_DIR, exist_ok=True)


def kill_process(pid, name="unknown"):
    """Attempt graceful terminate, then force kill if it won't die."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
            logging.info("Process terminated gracefully: PID=%s Name=%s", pid, name)
        except psutil.TimeoutExpired:
            proc.kill()
            logging.info("Process force-killed after timeout: PID=%s Name=%s", pid, name)
        return True
    except psutil.NoSuchProcess:
        logging.info("Process already gone by the time we tried to kill it: PID=%s", pid)
        return True
    except psutil.AccessDenied:
        logging.error("Access denied killing PID=%s Name=%s (needs root?)", pid, name)
        return False


def quarantine_file(file_path):
    """
    Moves the offending executable into the quarantine directory and
    strips its execute permission. Returns the new quarantined path,
    or None if quarantine failed.
    """
    ensure_quarantine_dir()

    if not os.path.isfile(file_path):
        logging.warning("Cannot quarantine - file not found: %s", file_path)
        return None

    timestamp = int(time.time())
    base_name = os.path.basename(file_path)
    dest_name = f"{base_name}.quarantined_{timestamp}"
    dest_path = os.path.join(config.QUARANTINE_DIR, dest_name)

    try:
        shutil.move(file_path, dest_path)
        # Strip all execute permissions
        os.chmod(dest_path, stat.S_IREAD)
        logging.info("File quarantined: %s -> %s", file_path, dest_path)
        return dest_path
    except (PermissionError, OSError) as e:
        logging.error("Failed to quarantine %s: %s (needs root?)", file_path, e)
        return None


def handle_violation(pid, name, file_path):
    """
    Full response to a detected violation: kill the process, then
    quarantine the file it ran from. Returns a dict summarizing the
    action taken, for reporting to the dashboard.
    """
    killed = kill_process(pid, name)
    quarantined_path = quarantine_file(file_path) if file_path else None

    action = "blocked_and_quarantined" if (killed and quarantined_path) else (
        "blocked_only" if killed else "quarantine_only" if quarantined_path else "failed"
    )

    return {
        "action": action,
        "quarantined_path": quarantined_path,
    }
