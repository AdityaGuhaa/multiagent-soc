"""
tools/firewall.py — Automated Firewall Response (iptables)

Manages IP blocking via iptables.
Features:
  • Whitelist enforcement (never block trusted IPs)
  • Duplicate-block protection (idempotent)
  • Dry-run mode (logs commands without executing)
  • Automatic cleanup / unblock capability
  • Full audit trail of all actions
"""

import logging
import subprocess
import shlex
import time
from datetime import datetime
from ipaddress import ip_address, AddressValueError

from config import CONFIG

logger = logging.getLogger("SOC.Firewall")


class FirewallAction:
    """Immutable record of a firewall action."""
    __slots__ = ("ip", "action", "timestamp", "reason", "success", "command")

    def __init__(self, ip, action, timestamp, reason, success, command):
        self.ip = ip
        self.action = action
        self.timestamp = timestamp
        self.reason = reason
        self.success = success
        self.command = command

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "action": self.action,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "success": self.success,
            "command": self.command,
        }


class FirewallManager:
    """
    Manages iptables rules for IP blocking and unblocking.

    iptables chain used: INPUT
    Rule appended: -A INPUT -s <ip> -j DROP

    Requires root / CAP_NET_ADMIN. Use dry_run=True in development.
    """

    def __init__(
        self,
        whitelist: set[str] | None = None,
        dry_run: bool | None = None,
        chain: str = "INPUT",
    ):
        self._whitelist: set[str] = whitelist or set()
        self._blocked: dict[str, float] = {}         # ip → block timestamp
        self._audit_log: list[FirewallAction] = []
        self._dry_run: bool = (
            dry_run if dry_run is not None else CONFIG.get("firewall_dry_run", False)
        )
        self._chain = chain

        if self._dry_run:
            logger.warning("FirewallManager running in DRY-RUN mode — no iptables changes.")

    # ── Public API ─────────────────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "SOC automated response") -> bool:
        """
        Block an IP address via iptables DROP rule.

        Returns:
            True  — rule added (or would be in dry-run)
            False — skipped (whitelist / duplicate / invalid)
        """
        ip = ip.strip()

        if not self._validate_ip(ip):
            logger.warning(f"block_ip: invalid IP address '{ip}' — skipping.")
            return False

        if self._is_whitelisted(ip):
            logger.info(f"block_ip: {ip} is whitelisted — skipping.")
            self._record(ip, "BLOCK_SKIPPED_WHITELIST", reason, False, "")
            return False

        if self._is_blocked(ip):
            logger.debug(f"block_ip: {ip} already blocked — skipping duplicate.")
            self._record(ip, "BLOCK_SKIPPED_DUPLICATE", reason, False, "")
            return False

        cmd = f"iptables -A {self._chain} -s {ip} -j DROP"
        success = self._exec(cmd)

        if success:
            self._blocked[ip] = time.time()
            logger.info(f"Blocked {ip} via iptables.")

        self._record(ip, "BLOCK", reason, success, cmd)
        return success

    def unblock_ip(self, ip: str, reason: str = "Manual unblock") -> bool:
        """
        Remove an existing DROP rule for an IP.

        Returns True if the rule was removed (or would be in dry-run).
        """
        ip = ip.strip()

        if not self._validate_ip(ip):
            logger.warning(f"unblock_ip: invalid IP '{ip}'")
            return False

        if not self._is_blocked(ip):
            logger.info(f"unblock_ip: {ip} not in blocked set — nothing to do.")
            return False

        cmd = f"iptables -D {self._chain} -s {ip} -j DROP"
        success = self._exec(cmd)

        if success:
            del self._blocked[ip]
            logger.info(f"Unblocked {ip}.")

        self._record(ip, "UNBLOCK", reason, success, cmd)
        return success

    def is_blocked(self, ip: str) -> bool:
        """Public query: is this IP currently blocked?"""
        return self._is_blocked(ip.strip())

    def blocked_ips(self) -> list[dict]:
        """Return all currently blocked IPs with block timestamps."""
        return [
            {
                "ip": ip,
                "blocked_at": datetime.utcfromtimestamp(ts).isoformat(),
                "duration_seconds": int(time.time() - ts),
            }
            for ip, ts in sorted(self._blocked.items(), key=lambda x: x[1], reverse=True)
        ]

    def flush_all(self, confirm: bool = False) -> bool:
        """
        Remove ALL iptables DROP rules in the managed chain.
        Requires explicit confirm=True to prevent accidental execution.
        """
        if not confirm:
            logger.warning("flush_all called without confirm=True — aborted.")
            return False

        cmd = f"iptables -F {self._chain}"
        success = self._exec(cmd)
        if success:
            self._blocked.clear()
            logger.warning(f"Flushed all rules from chain {self._chain}.")
        return success

    def audit_log(self) -> list[dict]:
        """Return full audit log of all firewall actions."""
        return [a.to_dict() for a in self._audit_log]

    def stats(self) -> dict:
        return {
            "currently_blocked": len(self._blocked),
            "whitelist_size": len(self._whitelist),
            "audit_entries": len(self._audit_log),
            "dry_run": self._dry_run,
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _exec(self, cmd: str) -> bool:
        """Execute an iptables command. Returns True on success."""
        if self._dry_run:
            logger.info(f"[DRY-RUN] Would execute: {cmd}")
            return True  # Simulate success in dry-run mode

        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error(
                    f"iptables error (rc={result.returncode}): {result.stderr.strip()}"
                )
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"iptables command timed out: {cmd}")
            return False
        except FileNotFoundError:
            logger.error("iptables not found — is it installed and in PATH?")
            return False
        except Exception as exc:
            logger.error(f"Unexpected error running iptables: {exc}")
            return False

    def _is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist

    def _is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ip_address(ip)
            return True
        except (AddressValueError, ValueError):
            return False

    def _record(self, ip: str, action: str, reason: str, success: bool, cmd: str):
        entry = FirewallAction(
            ip=ip,
            action=action,
            timestamp=datetime.utcnow().isoformat(),
            reason=reason,
            success=success,
            command=cmd,
        )
        self._audit_log.append(entry)
        logger.debug(f"Firewall audit: {entry.to_dict()}")
