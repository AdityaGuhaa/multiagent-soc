"""
detection/engine.py — Rule-Based Detection Engine

Implements stateful, sliding-window detection for:
  • SSH brute-force attacks   (multiple failed passwords from one IP)
  • Invalid user attempts     (auth with non-existent accounts)
  • Root login attempts       (direct root auth attempts)
  • Repeated sudo failures    (privilege escalation probing)

Each detector is a standalone class; the DetectionEngine composes them.
"""

import re
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("SOC.Detection")


# ── Shared Data Structures ────────────────────────────────────────────────────

@dataclass
class AttemptRecord:
    """Tracks repeated attempt state for a single IP."""
    count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    usernames: list = field(default_factory=list)

    def reset(self):
        self.count = 0
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.usernames.clear()


# ── Regex Patterns ────────────────────────────────────────────────────────────

PATTERNS = {
    # Failed password for valid user
    "failed_password": re.compile(
        r"Failed password for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port \d+"
    ),
    # Failed password for invalid user
    "invalid_user": re.compile(
        r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # Invalid user (without "Failed password" prefix, older sshd)
    "invalid_user_alt": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # Direct root login attempt
    "root_attempt": re.compile(
        r"Failed password for root from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # Sudo authentication failure
    "sudo_failure": re.compile(
        r"sudo:.*authentication failure.*rhost=(?P<ip>[\d.a-fA-F:]+)"
    ),
    # Connection closed / reset (rapid reconnects)
    "connection_closed": re.compile(
        r"Connection closed by (?:authenticating user \S+ )?(?P<ip>[\d.a-fA-F:]+)"
    ),
    # Disconnected (too many auth failures)
    "too_many_failures": re.compile(
        r"Disconnecting.*: Too many authentication failures.*\[(?P<ip>[\d.a-fA-F:]+)"
    ),
    # Repeated POSSIBLE BREAK-IN attempt message
    "reverse_map_fail": re.compile(
        r"POSSIBLE BREAK-IN ATTEMPT.*\[(?P<ip>[\d.a-fA-F:]+)\]"
    ),
}


# ── Individual Detectors ───────────────────────────────────────────────────────

class BruteForceDetector:
    """
    Sliding-window brute-force detector.
    Counts failed auth attempts per IP; fires when threshold is crossed.
    Resets the counter after `time_window_seconds` of inactivity.
    """

    def __init__(self, threshold: int = 5, time_window: int = 60):
        self.threshold = threshold
        self.time_window = time_window
        self._state: dict[str, AttemptRecord] = defaultdict(AttemptRecord)

    def process(self, line: str) -> Optional[dict]:
        for pattern_name in ("failed_password", "root_attempt"):
            m = PATTERNS[pattern_name].search(line)
            if m:
                ip = m.group("ip")
                user = m.groupdict().get("user", "root")
                return self._record(ip, user, pattern_name)
        return None

    def _record(self, ip: str, user: str, ptype: str) -> Optional[dict]:
        rec = self._state[ip]
        now = time.time()

        # Reset if outside window
        if now - rec.first_seen > self.time_window:
            rec.reset()

        rec.count += 1
        rec.last_seen = now
        if user not in rec.usernames:
            rec.usernames.append(user)

        if rec.count >= self.threshold:
            detection = {
                "type": "BRUTE_FORCE",
                "ip": ip,
                "count": rec.count,
                "usernames": list(rec.usernames),
                "window_seconds": self.time_window,
                "pattern": ptype,
            }
            # Reset after firing to avoid repeated alerts for same burst
            rec.reset()
            return detection
        return None

    def get_state(self, ip: str) -> dict:
        """Return current attempt record for an IP (for diagnostics)."""
        r = self._state.get(ip)
        if not r:
            return {}
        return {
            "count": r.count,
            "first_seen": r.first_seen,
            "last_seen": r.last_seen,
            "usernames": r.usernames,
        }


class InvalidUserDetector:
    """
    Detects attempts to authenticate with usernames that don't exist on the system.
    These are almost always scanning/dictionary attacks.
    """

    def __init__(self, threshold: int = 3, time_window: int = 60):
        self.threshold = threshold
        self.time_window = time_window
        self._state: dict[str, AttemptRecord] = defaultdict(AttemptRecord)

    def process(self, line: str) -> Optional[dict]:
        for key in ("invalid_user", "invalid_user_alt"):
            m = PATTERNS[key].search(line)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                return self._record(ip, user)
        return None

    def _record(self, ip: str, user: str) -> Optional[dict]:
        rec = self._state[ip]
        now = time.time()

        if now - rec.first_seen > self.time_window:
            rec.reset()

        rec.count += 1
        rec.last_seen = now
        if user not in rec.usernames:
            rec.usernames.append(user)

        if rec.count >= self.threshold:
            detection = {
                "type": "INVALID_USER_SCAN",
                "ip": ip,
                "count": rec.count,
                "usernames": list(rec.usernames),
                "window_seconds": self.time_window,
            }
            rec.reset()
            return detection
        return None


class RootLoginDetector:
    """
    Fires immediately on ANY root login attempt — no threshold, single-shot.
    Root access attempts are always high-priority regardless of frequency.
    """

    def process(self, line: str) -> Optional[dict]:
        m = PATTERNS["root_attempt"].search(line)
        if m:
            return {
                "type": "ROOT_LOGIN_ATTEMPT",
                "ip": m.group("ip"),
                "count": 1,
                "severity": "HIGH",
            }
        return None


class SudoFailureDetector:
    """
    Tracks repeated sudo authentication failures — possible privilege escalation probe.
    """

    def __init__(self, threshold: int = 3, time_window: int = 120):
        self.threshold = threshold
        self.time_window = time_window
        self._state: dict[str, AttemptRecord] = defaultdict(AttemptRecord)

    def process(self, line: str) -> Optional[dict]:
        m = PATTERNS["sudo_failure"].search(line)
        if m:
            ip = m.group("ip")
            return self._record(ip)
        return None

    def _record(self, ip: str) -> Optional[dict]:
        rec = self._state[ip]
        now = time.time()

        if now - rec.first_seen > self.time_window:
            rec.reset()

        rec.count += 1
        rec.last_seen = now

        if rec.count >= self.threshold:
            detection = {
                "type": "SUDO_FAILURE",
                "ip": ip,
                "count": rec.count,
                "window_seconds": self.time_window,
            }
            rec.reset()
            return detection
        return None


class RapidReconnectDetector:
    """
    Detects rapid connection cycling — indicator of automated scanners
    even when they don't produce 'failed password' lines.
    """

    def __init__(self, threshold: int = 10, time_window: int = 30):
        self.threshold = threshold
        self.time_window = time_window
        self._state: dict[str, AttemptRecord] = defaultdict(AttemptRecord)

    def process(self, line: str) -> Optional[dict]:
        m = PATTERNS["connection_closed"].search(line)
        if not m:
            m = PATTERNS["too_many_failures"].search(line)
        if m:
            ip = m.group("ip")
            return self._record(ip)
        return None

    def _record(self, ip: str) -> Optional[dict]:
        rec = self._state[ip]
        now = time.time()

        if now - rec.first_seen > self.time_window:
            rec.reset()

        rec.count += 1
        rec.last_seen = now

        if rec.count >= self.threshold:
            detection = {
                "type": "RAPID_RECONNECT",
                "ip": ip,
                "count": rec.count,
                "window_seconds": self.time_window,
            }
            rec.reset()
            return detection
        return None


# ── Detection Engine (Composer) ───────────────────────────────────────────────

class DetectionEngine:
    """
    Composes all individual detectors.
    A single call to `process_line()` runs every detector and returns
    a (possibly empty) list of detection events.
    """

    def __init__(
        self,
        brute_force_threshold: int = 5,
        time_window_seconds: int = 60,
    ):
        self._detectors = [
            BruteForceDetector(
                threshold=brute_force_threshold,
                time_window=time_window_seconds,
            ),
            InvalidUserDetector(
                threshold=max(2, brute_force_threshold // 2),
                time_window=time_window_seconds,
            ),
            RootLoginDetector(),
            SudoFailureDetector(),
            RapidReconnectDetector(),
        ]
        self._total_lines = 0
        self._total_detections = 0

    def process_line(self, line: str) -> list[dict]:
        """
        Run all detectors against a single log line.
        Returns list of detection dicts (may be empty).
        """
        self._total_lines += 1
        detections = []

        for detector in self._detectors:
            result = detector.process(line)
            if result:
                detections.append(result)
                self._total_detections += 1
                logger.debug(f"Detection: {result}")

        return detections

    def stats(self) -> dict:
        """Return runtime statistics."""
        return {
            "lines_processed": self._total_lines,
            "total_detections": self._total_detections,
            "detectors_active": len(self._detectors),
        }
