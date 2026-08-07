"""
ESCA Agent - Blocking & Quarantine
Kills unauthorized processes and moves their executable to a
locked-down quarantine directory.
"""

import logging
import os
import platform
import shutil
import stat
import time

import psutil

import config


def ensure_quarantine_dir():
    if not os.path.exists(config.QUARANTINE_DIR):
        try:
            os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
            logging.info("Created quarantine dir: %s", config.QUARANTINE_DIR)
        except OSError as e:
            logging.error("Could not create quarantine dir %s: %s", config.QUARANTINE_DIR, e)


def kill_process(pid, name="unknown"):
    """Attempt graceful terminate, then force kill if it won't die."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
            logging.info("Process terminated gracefully: PID=%s Name=%s", pid, name)
        except psutil.TimeoutExpired:
            try:
                proc.kill()
                logging.info("Process force-killed after timeout: PID=%s Name=%s", pid, name)
            except psutil.AccessDenied:
                logging.error("Access denied force-killing PID=%s Name=%s (needs root?)", pid, name)
                return False
        return True
    except psutil.NoSuchProcess:
        logging.info("Process already gone by the time we tried to kill it: PID=%s", pid)
        return True
    except psutil.AccessDenied:
        logging.error("Access denied killing PID=%s Name=%s (needs root?)", pid, name)
        return False


def _is_windows():
    return platform.system() == "Windows"


def _set_read_only(path):
    """Strip write/execute permissions so the file is read-only.
    On Windows, os.chmod is limited, so also set the read-only attribute."""
    try:
        if _is_windows():
            os.chmod(path, stat.S_IREAD)
            import ctypes
            # Set FILE_ATTRIBUTE_READONLY (0x1) via Windows API for reliability.
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x1)
        else:
            os.chmod(path, stat.S_IREAD)
    except OSError as e:
        logging.warning("Could not set read-only on %s: %s", path, e)


def quarantine_file(file_path):
    """
    Moves the offending executable into the quarantine directory and
    strips its write/execute permission. Returns the new quarantined path,
    or None if quarantine failed.
    """
    ensure_quarantine_dir()

    if not file_path:
        return None

    if not os.path.isfile(file_path):
        logging.warning("Cannot quarantine - file not found: %s", file_path)
        return None

    timestamp = int(time.time())
    base_name = os.path.basename(file_path)
    dest_name = f"{base_name}.quarantined_{timestamp}"
    dest_path = os.path.join(config.QUARANTINE_DIR, dest_name)

    # Retry a few times on transient errors (file being read, AV scan, etc.)
    for attempt in range(3):
        try:
            shutil.move(file_path, dest_path)
            break
        except (PermissionError, OSError) as e:
            if attempt < 2:
                logging.warning("Quarantine attempt %d failed for %s (%s); retrying...",
                                attempt + 1, file_path, e)
                time.sleep(1)
            else:
                logging.error("Failed to quarantine %s after %d attempts: %s (needs privileged?)",
                              file_path, attempt + 1, e)
                return None

    _set_read_only(dest_path)
    logging.info("File quarantined: %s -> %s", file_path, dest_path)
    return dest_path


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
