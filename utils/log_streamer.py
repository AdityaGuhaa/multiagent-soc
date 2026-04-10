"""
utils/log_streamer.py — Real-Time Log Streaming with Rotation Handling

Implements `tail -F` semantics in Python:
  • Opens the target file and reads from the end
  • Yields new lines as they appear (blocking generator)
  • Detects log rotation (file replaced/truncated) and re-opens automatically
  • Handles missing files gracefully (waits for file to appear)
  • Thread-safe via a stop event for clean shutdown
"""

import logging
import os
import time
import threading
from pathlib import Path
from typing import Generator

logger = logging.getLogger("SOC.LogStreamer")


class LogStreamer:
    """
    Streams lines from a log file in real time, handling rotation.

    Usage:
        streamer = LogStreamer("/var/log/auth.log")
        for line in streamer.stream():
            process(line)

    To stop from another thread:
        streamer.stop()
    """

    def __init__(
        self,
        log_path: str,
        poll_interval: float = 0.05,
        rotation_check_interval: float = 1.0,
        encoding: str = "utf-8",
        errors: str = "replace",
    ):
        self.log_path = Path(log_path)
        self._poll_interval = poll_interval
        self._rotation_check_interval = rotation_check_interval
        self._encoding = encoding
        self._errors = errors
        self._stop_event = threading.Event()
        self._lines_yielded = 0
        self._rotations_detected = 0

    # ── Public ────────────────────────────────────────────────────────────────

    def stream(self) -> Generator[str, None, None]:
        """
        Blocking generator. Yields log lines as they are written.
        Handles file rotation and missing files automatically.
        """
        logger.info(f"Streaming log: {self.log_path}")

        while not self._stop_event.is_set():
            # Wait for the file to exist
            if not self.log_path.exists():
                logger.warning(f"Log file not found: {self.log_path} — waiting…")
                self._sleep(2.0)
                continue

            try:
                yield from self._tail_file()
            except Exception as exc:
                logger.error(f"Streamer error: {exc}", exc_info=True)
                self._sleep(1.0)

    def stop(self):
        """Signal the streaming generator to exit cleanly."""
        self._stop_event.set()
        logger.info("LogStreamer stop signal sent.")

    def stats(self) -> dict:
        return {
            "log_path": str(self.log_path),
            "lines_yielded": self._lines_yielded,
            "rotations_detected": self._rotations_detected,
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _tail_file(self) -> Generator[str, None, None]:
        """
        Open the file, seek to the end, then yield new lines.
        Detects rotation by comparing inode / file size.
        """
        with open(
            self.log_path,
            "r",
            encoding=self._encoding,
            errors=self._errors,
        ) as fh:
            # Start from the end (tail -n 0 behaviour)
            fh.seek(0, os.SEEK_END)
            current_inode = self._inode()
            last_rotation_check = time.monotonic()

            partial = ""  # Buffer for incomplete lines

            while not self._stop_event.is_set():
                chunk = fh.read(8192)

                if chunk:
                    text = partial + chunk
                    lines = text.split("\n")
                    # Last element may be an incomplete line
                    partial = lines.pop()
                    for line in lines:
                        if line:
                            self._lines_yielded += 1
                            yield line + "\n"
                else:
                    self._sleep(self._poll_interval)

                # Periodic rotation check
                now = time.monotonic()
                if now - last_rotation_check >= self._rotation_check_interval:
                    last_rotation_check = now
                    if self._detect_rotation(current_inode, fh.tell()):
                        logger.info("Log rotation detected — reopening file.")
                        self._rotations_detected += 1
                        return  # Causes outer loop to re-open

    def _detect_rotation(self, original_inode: int, current_pos: int) -> bool:
        """
        Rotation detected if:
          1. The file's inode has changed (file replaced), OR
          2. The file's size is smaller than our current position (file truncated).
        """
        if not self.log_path.exists():
            return True

        try:
            stat = self.log_path.stat()
        except OSError:
            return True

        if stat.st_ino != original_inode:
            return True

        if stat.st_size < current_pos:
            return True

        return False

    def _inode(self) -> int:
        try:
            return self.log_path.stat().st_ino
        except OSError:
            return -1

    def _sleep(self, duration: float):
        """Interruptible sleep: wakes on stop event."""
        self._stop_event.wait(timeout=duration)


# ── Simulated Log Generator (for testing without /var/log/auth.log) ───────────

class MockLogStreamer:
    """
    Replays a list of pre-canned auth log lines at a configurable rate.
    Drop-in replacement for LogStreamer in unit tests and demos.
    """

    SAMPLE_LINES = [
        "Apr 10 12:00:01 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2\n",
        "Apr 10 12:00:02 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2\n",
        "Apr 10 12:00:03 server sshd[1235]: Invalid user oracle from 10.0.0.55 port 43210\n",
        "Apr 10 12:00:04 server sshd[1236]: Failed password for invalid user postgres from 10.0.0.55 port 43211 ssh2\n",
        "Apr 10 12:00:05 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2\n",
        "Apr 10 12:00:06 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2\n",
        "Apr 10 12:00:07 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2\n",
        "Apr 10 12:00:08 server sshd[1237]: Accepted password for ubuntu from 172.16.0.10 port 51234 ssh2\n",
        "Apr 10 12:00:09 server sudo: pam_unix(sudo:auth): authentication failure; logname=www rhost=10.0.0.99\n",
        "Apr 10 12:00:10 server sshd[1238]: Connection closed by authenticating user root 203.0.113.42 port 12345\n",
        "Apr 10 12:00:11 server sshd[1238]: Connection closed by authenticating user root 203.0.113.42 port 12346\n",
        "Apr 10 12:00:12 server sshd[1238]: Disconnecting: Too many authentication failures [203.0.113.42]\n",
    ]

    def __init__(self, lines: list[str] | None = None, rate: float = 0.3):
        self._lines = lines or self.SAMPLE_LINES
        self._rate = rate

    def stream(self) -> Generator[str, None, None]:
        for line in self._lines:
            time.sleep(self._rate)
            yield line
