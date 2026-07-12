import json
import logging
import os
import time
import requests

import config


class Reporter:
    def __init__(self):
        self.queue = []
        self._load_queue()

    def _load_queue(self):
        if os.path.exists(config.LOCAL_EVENT_QUEUE):
            try:
                with open(config.LOCAL_EVENT_QUEUE, "r") as f:
                    self.queue = json.load(f)
                if self.queue:
                    logging.info("Loaded %d queued events from previous session", len(self.queue))
            except (json.JSONDecodeError, IOError):
                self.queue = []

    def _save_queue(self):
        try:
            with open(config.LOCAL_EVENT_QUEUE, "w") as f:
                json.dump(self.queue, f, indent=2)
        except IOError as e:
            logging.error("Could not persist event queue: %s", e)

    def _send(self, event):
        try:
            resp = requests.post(
                f"{config.DASHBOARD_URL}/api/report",
                json=event,
                headers={"X-API-Key": config.API_KEY},
                timeout=5,
            )
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def report_event(self, event_type, name, pid=None, file_path=None,
                      file_hash=None, action_taken="none", detail=""):
        """
        event_type: 'allowed' | 'violation' | 'heartbeat'
        """
        event = {
            "device_id": config.DEVICE_ID,
            "timestamp": time.time(),
            "event_type": event_type,
            "process_name": name,
            "pid": pid,
            "file_path": file_path,
            "file_hash": file_hash,
            "action_taken": action_taken,
            "detail": detail,
        }

        # Try queued events first, then this new one, so ordering is preserved
        self.queue.append(event)
        self._flush_queue()

    def _flush_queue(self):
        if not self.queue:
            return
        remaining = []
        for event in self.queue:
            if not self._send(event):
                remaining.append(event)
        sent_count = len(self.queue) - len(remaining)
        if sent_count:
            logging.info("Flushed %d queued event(s) to dashboard", sent_count)
        self.queue = remaining
        self._save_queue()

    def heartbeat(self):
        try:
            resp = requests.post(
                f"{config.DASHBOARD_URL}/api/heartbeat",
                json={"device_id": config.DEVICE_ID, "timestamp": time.time()},
                headers={"X-API-Key": config.API_KEY},
                timeout=5,
            )
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            logging.warning("Heartbeat failed - dashboard unreachable")
            return False
