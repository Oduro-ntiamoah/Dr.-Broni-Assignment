"""
ESCA Agent - Allowlist Management
Handles hashing executables, caching the allowlist locally, and
syncing it from the dashboard so the agent still works if the
dashboard is briefly unreachable.
"""

import hashlib
import json
import logging
import os
import time
import requests

import config


def hash_file(path, block_size=65536):
    """Return SHA-256 hash of a file, or None if unreadable."""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None


class Allowlist:
    def __init__(self):
        self.entries = {}  # hash -> {"name": ..., "publisher": ...}
        self.last_sync = 0
        self._load_local_cache()

    def _load_local_cache(self):
        if os.path.exists(config.LOCAL_ALLOWLIST_CACHE):
            try:
                with open(config.LOCAL_ALLOWLIST_CACHE, "r") as f:
                    self.entries = json.load(f)
                logging.info("Loaded %d allowlist entries from local cache", len(self.entries))
            except (json.JSONDecodeError, IOError) as e:
                logging.warning("Could not read local allowlist cache: %s", e)
                self.entries = {}
        else:
            logging.info("No local allowlist cache found - starting empty (deny-by-default)")

    def _save_local_cache(self):
        try:
            with open(config.LOCAL_ALLOWLIST_CACHE, "w") as f:
                json.dump(self.entries, f, indent=2)
        except IOError as e:
            logging.error("Could not write local allowlist cache: %s", e)

    def sync_from_dashboard(self):
        """Pull the latest allowlist from the dashboard. Falls back to
        cached copy silently on failure (agent keeps working offline)."""
        try:
            resp = requests.get(
                f"{config.DASHBOARD_URL}/api/allowlist",
                headers={"X-API-Key": config.API_KEY},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Expected format: {hash: {"name": ..., "publisher": ...}, ...}
                self.entries = data.get("entries", {})
                self._save_local_cache()
                self.last_sync = time.time()
                logging.info("Allowlist synced from dashboard: %d entries", len(self.entries))
                return True
            else:
                logging.warning("Allowlist sync failed - status %s. Using cached copy.", resp.status_code)
                return False
        except requests.exceptions.RequestException as e:
            logging.warning("Allowlist sync failed - dashboard unreachable (%s). Using cached copy.", e)
            return False

    def is_allowed(self, file_path):
        """
        Returns True if the executable's hash is in the allowlist.
        Deny-by-default: unknown/unreadable files are treated as violations.
        """
        file_hash = hash_file(file_path)
        if file_hash is None:
            return False, None
        return (file_hash in self.entries), file_hash
