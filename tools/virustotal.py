"""
tools/virustotal.py — VirusTotal IP Reputation Tool for CrewAI

Wraps the VirusTotal v3 API as a CrewAI-compatible tool.
Includes in-memory caching to avoid burning quota on repeated IPs.
Gracefully degrades when no API key is configured.
"""

import json
import logging
import time
from typing import Optional

import requests
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

logger = logging.getLogger("SOC.VirusTotal")


# ── Input Schema ──────────────────────────────────────────────────────────────

class VTInput(BaseModel):
    ip_address: str = Field(
        ...,
        description="The IPv4 or IPv6 address to look up on VirusTotal.",
    )


# ── Cache Entry ────────────────────────────────────────────────────────────────

class _CacheEntry:
    __slots__ = ("data", "expires_at")

    def __init__(self, data: dict, ttl: int):
        self.data = data
        self.expires_at = time.monotonic() + ttl


# ── VirusTotal Tool ────────────────────────────────────────────────────────────

class VirusTotalTool(BaseTool):
    """
    CrewAI tool: query VirusTotal for IP reputation data.

    Returns a structured JSON string with:
      - malicious_votes  : count of AV engines that flagged the IP
      - total_votes      : total engines that evaluated the IP
      - reputation_score : VirusTotal community reputation (-100 … 100)
      - country          : registered country of the IP
      - asn              : autonomous system number
      - as_owner         : AS owner name
      - tags             : list of VirusTotal tags (e.g. ["scanner", "tor"])
      - last_analysis_date : ISO timestamp of most recent analysis
    """

    name: str = "virustotal_ip_lookup"
    description: str = (
        "Look up an IP address on VirusTotal to retrieve its reputation, "
        "malicious vote count, country, ASN, and known tags. "
        "Input: a single IP address string."
    )
    args_schema: type[BaseModel] = VTInput

    # Non-pydantic private fields
    _api_key: str
    _cache: dict
    _cache_ttl: int
    _base_url: str

    def __init__(self, api_key: str, cache_ttl_seconds: int = 3600):
        super().__init__()
        # Bypass Pydantic by setting on __dict__ directly
        object.__setattr__(self, "_api_key", api_key)
        object.__setattr__(self, "_cache", {})
        object.__setattr__(self, "_cache_ttl", cache_ttl_seconds)
        object.__setattr__(self, "_base_url", "https://www.virustotal.com/api/v3")

    # ── Public Interface ───────────────────────────────────────────────────────

    def _run(self, ip_address: str) -> str:
        """Called by CrewAI agents."""
        if not self._api_key:
            return json.dumps({
                "error": "VirusTotal API key not configured.",
                "malicious_votes": 0,
                "total_votes": 0,
                "reputation_score": 0,
                "notes": "No VT key — skipping enrichment.",
            })

        ip = ip_address.strip()

        # Cache hit?
        cached = self._cache.get(ip)
        if cached and time.monotonic() < cached.expires_at:
            logger.debug(f"VT cache hit: {ip}")
            return json.dumps(cached.data)

        # Fetch from API
        result = self._fetch(ip)
        self._cache[ip] = _CacheEntry(result, self._cache_ttl)
        return json.dumps(result)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _fetch(self, ip: str) -> dict:
        url = f"{self._base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}

        try:
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 404:
                return self._not_found(ip)

            if resp.status_code == 401:
                logger.error("VirusTotal: Invalid API key.")
                return {"error": "Invalid VirusTotal API key.", "ip": ip}

            if resp.status_code == 429:
                logger.warning("VirusTotal: Rate limit hit.")
                return {"error": "VT rate limit exceeded.", "ip": ip}

            resp.raise_for_status()
            return self._parse(resp.json(), ip)

        except requests.exceptions.Timeout:
            logger.warning(f"VT request timed out for {ip}")
            return {"error": "VT request timed out.", "ip": ip}

        except requests.exceptions.RequestException as exc:
            logger.error(f"VT request error for {ip}: {exc}")
            return {"error": str(exc), "ip": ip}

    def _parse(self, data: dict, ip: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})

        # VirusTotal last_analysis_date is a Unix timestamp
        ts_raw = attrs.get("last_analysis_date", 0)
        ts_iso = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_raw))
            if ts_raw
            else "unknown"
        )

        return {
            "ip": ip,
            "malicious_votes": last_analysis.get("malicious", 0),
            "suspicious_votes": last_analysis.get("suspicious", 0),
            "harmless_votes": last_analysis.get("harmless", 0),
            "undetected_votes": last_analysis.get("undetected", 0),
            "total_votes": sum(last_analysis.values()),
            "reputation_score": attrs.get("reputation", 0),
            "country": attrs.get("country", "unknown"),
            "asn": attrs.get("asn", "unknown"),
            "as_owner": attrs.get("as_owner", "unknown"),
            "tags": attrs.get("tags", []),
            "network": attrs.get("network", "unknown"),
            "last_analysis_date": ts_iso,
        }

    @staticmethod
    def _not_found(ip: str) -> dict:
        return {
            "ip": ip,
            "malicious_votes": 0,
            "total_votes": 0,
            "reputation_score": 0,
            "notes": "IP not found in VirusTotal database.",
        }

    def cache_stats(self) -> dict:
        """Return cache statistics for diagnostics."""
        now = time.monotonic()
        active = sum(1 for e in self._cache.values() if now < e.expires_at)
        return {"total_cached": len(self._cache), "active_entries": active}
