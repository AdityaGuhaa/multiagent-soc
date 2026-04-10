"""
utils/alert_logger.py — Structured Alert Persistence

Writes all SOC alerts to a JSON-Lines file (one JSON object per line).
Provides query/filtering capabilities for post-incident analysis.
Thread-safe via a reentrant lock.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("SOC.AlertLogger")


class AlertLogger:
    """
    Persists SOC alerts to a JSON-Lines (.jsonl) file.

    Each line is a self-contained JSON object:
    {
      "timestamp": "2024-04-10T12:00:00.000000",
      "ip": "192.168.1.100",
      "detection_type": "BRUTE_FORCE",
      "action": "BLOCK",
      "confidence": 0.92,
      "reason": "...",
      "raw": { <original detection dict> }
    }
    """

    def __init__(self, log_path: str):
        self._path = Path(log_path)
        self._lock = threading.RLock()
        self._count = 0

        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Count existing entries on startup
        self._count = self._count_existing()
        logger.info(
            f"AlertLogger ready: {self._path} ({self._count} existing alerts)"
        )

    # ── Write ──────────────────────────────────────────────────────────────────

    def log(
        self,
        ip: str,
        detection_type: str,
        action: str,
        reason: str,
        confidence: float,
        raw: Optional[dict] = None,
        extra: Optional[dict] = None,
    ) -> dict:
        """
        Write a structured alert to the log file.

        Args:
            ip             : Source IP address
            detection_type : Type from DetectionEngine (e.g. "BRUTE_FORCE")
            action         : AI decision ("ALLOW" or "BLOCK")
            reason         : Human-readable reason from AI
            confidence     : AI confidence score 0.0–1.0
            raw            : Original detection dict from DetectionEngine
            extra          : Any additional key-value pairs to include

        Returns:
            The full alert dict that was written.
        """
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip": ip,
            "detection_type": detection_type,
            "action": action,
            "confidence": round(confidence, 4),
            "reason": reason,
            "raw": raw or {},
        }
        if extra:
            alert.update(extra)

        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(alert) + "\n")
                self._count += 1
                logger.debug(f"Alert written: {ip} → {action}")
            except OSError as exc:
                logger.error(f"Failed to write alert: {exc}")

        return alert

    # ── Read / Query ───────────────────────────────────────────────────────────

    def all_alerts(self) -> list[dict]:
        """Return all alerts from the log file."""
        return self._read_all()

    def filter(
        self,
        ip: Optional[str] = None,
        action: Optional[str] = None,
        detection_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        min_confidence: float = 0.0,
    ) -> list[dict]:
        """
        Filter alerts by one or more criteria.

        Args:
            ip             : Exact IP match
            action         : "ALLOW" or "BLOCK"
            detection_type : e.g. "BRUTE_FORCE", "INVALID_USER_SCAN"
            since          : Include alerts at or after this UTC datetime
            until          : Include alerts at or before this UTC datetime
            min_confidence : Minimum confidence threshold

        Returns:
            Filtered list of alert dicts, newest-first.
        """
        results = []
        for alert in self._read_all():
            if ip and alert.get("ip") != ip:
                continue
            if action and alert.get("action") != action.upper():
                continue
            if detection_type and alert.get("detection_type") != detection_type:
                continue
            if min_confidence and alert.get("confidence", 0) < min_confidence:
                continue
            if since or until:
                ts = self._parse_ts(alert.get("timestamp", ""))
                if ts:
                    if since and ts < since:
                        continue
                    if until and ts > until:
                        continue
            results.append(alert)

        return list(reversed(results))  # newest first

    def stats(self) -> dict:
        """Return summary statistics over all logged alerts."""
        alerts = self._read_all()
        if not alerts:
            return {"total": 0}

        actions = {}
        types = {}
        ips: dict[str, int] = {}

        for a in alerts:
            actions[a.get("action", "?")] = actions.get(a.get("action", "?"), 0) + 1
            types[a.get("detection_type", "?")] = types.get(a.get("detection_type", "?"), 0) + 1
            ip = a.get("ip", "?")
            ips[ip] = ips.get(ip, 0) + 1

        top_ips = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total": len(alerts),
            "by_action": actions,
            "by_type": types,
            "top_ips": top_ips,
            "avg_confidence": round(
                sum(a.get("confidence", 0) for a in alerts) / len(alerts), 3
            ),
        }

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last n alerts."""
        return self._read_all()[-n:]

    # ── Internal ───────────────────────────────────────────────────────────────

    def _read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        with self._lock:
            alerts = []
            with open(self._path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping malformed alert line: {line[:80]}")
            return alerts

    def _count_existing(self) -> int:
        try:
            return sum(1 for _ in open(self._path, "r", encoding="utf-8") if _.strip())
        except OSError:
            return 0

    @staticmethod
    def _parse_ts(ts_str: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return None
