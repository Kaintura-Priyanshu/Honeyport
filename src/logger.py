"""
Logging utilities for the honeypot.
Writes both human-readable and JSON-lines logs, and can optionally
fire a webhook alert when an IP exceeds an attempt threshold.
"""

import json
import logging
import os
import time
import threading
from collections import defaultdict, deque

try:
    import requests
except ImportError:  # requests is optional, only needed if alerting is enabled
    requests = None


class HoneypotLogger:
    def __init__(self, cfg):
        log_cfg = cfg.get("logging", {})
        self.log_dir = log_cfg.get("log_dir", "logs")
        os.makedirs(self.log_dir, exist_ok=True)

        self.text_log_path = os.path.join(self.log_dir, log_cfg.get("log_file", "honeypot.log"))
        self.json_log_path = os.path.join(self.log_dir, log_cfg.get("json_log_file", "honeypot_events.jsonl"))
        self.console_output = log_cfg.get("console_output", True)

        self._lock = threading.Lock()

        self._logger = logging.getLogger("honeypot")
        self._logger.setLevel(logging.INFO)
        if not self._logger.handlers:
            fh = logging.FileHandler(self.text_log_path)
            fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            self._logger.addHandler(fh)

            if self.console_output:
                ch = logging.StreamHandler()
                ch.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                self._logger.addHandler(ch)

        # Alerting setup
        alert_cfg = cfg.get("alerting", {})
        self.alerting_enabled = alert_cfg.get("enabled", False)
        self.webhook_url = alert_cfg.get("webhook_url", "")
        self.attempt_threshold = alert_cfg.get("attempt_threshold", 5)
        self.alert_window = alert_cfg.get("alert_window_seconds", 60)
        self._attempts_by_ip = defaultdict(deque)

    def log_event(self, service, event_type, src_ip, src_port, details=None):
        """Log a single honeypot event as text + JSON, and check alert thresholds."""
        details = details or {}
        record = {
            "timestamp": time.time(),
            "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "service": service,
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "details": details,
        }

        with self._lock:
            self._logger.info(
                "[%s] %s from %s:%s -> %s",
                service, event_type, src_ip, src_port, details
            )
            with open(self.json_log_path, "a") as f:
                f.write(json.dumps(record) + "\n")

        self._maybe_alert(service, src_ip, record)

    def _maybe_alert(self, service, src_ip, record):
        if not self.alerting_enabled:
            return

        now = time.time()
        dq = self._attempts_by_ip[src_ip]
        dq.append(now)

        # drop attempts outside the window
        while dq and now - dq[0] > self.alert_window:
            dq.popleft()

        if len(dq) == self.attempt_threshold:
            self._send_webhook_alert(service, src_ip, len(dq))

    def _send_webhook_alert(self, service, src_ip, count):
        if not self.webhook_url or requests is None:
            return
        payload = {
            "text": (
                f":rotating_light: Honeypot alert: {src_ip} made {count} attempts "
                f"against service '{service}' within {self.alert_window}s"
            )
        }
        try:
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception as exc:  # pragma: no cover - best effort alerting
            self._logger.info("Failed to send webhook alert: %s", exc)
