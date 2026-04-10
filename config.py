"""
config.py — Central configuration for the SOC Automation System.
All tuneable parameters live here. Override via environment variables.
"""

import os

CONFIG = {
    # ── Log Sources ────────────────────────────────────────────────────────────
    "auth_log_path": os.getenv("AUTH_LOG_PATH", "/var/log/auth.log"),
    "alert_log_path": os.getenv("ALERT_LOG_PATH", "./alerts.log"),

    # ── Detection Thresholds ───────────────────────────────────────────────────
    # Number of failed login attempts from one IP within the time window
    # before it is flagged as a brute-force candidate.
    "brute_force_threshold": int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),

    # Sliding window (seconds) for attempt counting. Resets per IP after this.
    "time_window_seconds": int(os.getenv("TIME_WINDOW_SECONDS", "60")),

    # ── AI / LLM ──────────────────────────────────────────────────────────────
    # Ollama model tag. Must be pulled locally: `ollama pull phi3`
    "ollama_model": os.getenv("OLLAMA_MODEL", "mistral:latest"),

    # Ollama API base URL (default local)
    "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),

    # CrewAI agent LLM temperature (lower = more deterministic decisions)
    "llm_temperature": float(os.getenv("LLM_TEMPERATURE", "0.1")),

    # Max tokens for each agent response
    "llm_max_tokens": int(os.getenv("LLM_MAX_TOKENS", "512")),

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),

	#slack webhook
	"slack_webhook_url": "",

    # Cache VT results to avoid burning quota on repeated IPs
    "virustotal_cache_ttl_seconds": int(os.getenv("VT_CACHE_TTL", "3600")),

    # ── Firewall ───────────────────────────────────────────────────────────────
    # IPs that must never be blocked (admin hosts, monitoring, localhost)
    "ip_whitelist": set(
        os.getenv(
            "IP_WHITELIST",
            "127.0.0.1,::1,10.0.0.1",
        ).split(",")
    ),

    # Dry-run mode: log would-be blocks but don't execute iptables commands
    "firewall_dry_run": os.getenv("FIREWALL_DRY_RUN", "false").lower() == "true",

    # ── System ────────────────────────────────────────────────────────────────
    # How long (seconds) to sleep between log re-open attempts on rotation
    "log_rotation_sleep": float(os.getenv("LOG_ROTATION_SLEEP", "0.2")),
}
