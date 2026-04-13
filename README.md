# Multi‑Agent SOC (Security Operations Center)

**An AI‑augmented, rule‑based SOC prototype** that continuously streams Linux authentication logs, detects malicious activity with lightweight detectors, enriches events with VirusTotal intelligence, and makes automated response decisions via a three‑agent CrewAI workflow.

---

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Getting Started](#getting-started)
4. [Configuration](#configuration)
5. [Running the System](#running-the-system)
6. [Testing](#testing)
7. [Extending the SOC](#extending-the-soc)
8. [Troubleshooting & FAQ](#troubleshooting--faq)
9. [License](#license)

---

## Overview

The repository implements a **real‑time security monitoring pipeline** for SSH and sudo activity on Linux servers. It combines:

- **Rule‑based detection** (failed passwords, root login attempts, rapid reconnects, etc.)
- **AI triage** using **CrewAI** with three specialized agents (log analysis, threat intelligence, response decision)
- **Automated mitigation** (iptables block, Slack alert, persisted JSON‑Lines alert log)

All components are written in Python and can be run on any modern Linux host. The design is intentionally modular so that new detectors, intelligence sources, or response actions can be added with minimal friction.

---

## Architecture

```
+-------------------+      +-------------------+      +-------------------+
|  LogStreamer      | ---> | DetectionEngine   | ---> |  Detection Event |
|  (tail‑F semantics)|      |  (composes       )|      |  dict            |
+-------------------+      +-------------------+      +-------------------+
                                 |                               |
                                 v                               v
                     +-------------------+          +-------------------+
                     |  SOCSystem       |          |  AlertLogger      |
                     | (orchestrates)   |          | (JSON‑Lines)      |
                     +-------------------+          +-------------------+
                                 |
                                 v
                     +-------------------+      +-------------------+
                     |  SOCCrew (CrewAI) | ---> |  Slack / Firewall |
                     +-------------------+      +-------------------+
                                 |
                                 v
                     +-------------------+
                     |  Persisted Alerts |
                     +-------------------+
```

- **`main.py`** – entry point; instantiates `SOCSystem` and starts the background AI analysis worker.
- **`utils/log_streamer.py`** – provides `LogStreamer` (real log tail) and `MockLogStreamer` for deterministic unit tests.
- **`detection/engine.py`** – defines five detectors (`BruteForceDetector`, `InvalidUserDetector`, `RootLoginDetector`, `SudoFailureDetector`, `RapidReconnectDetector`). `DetectionEngine` runs each detector on every incoming line and aggregates results.
- **`agents/crew.py`** – builds three CrewAI agents:
  1. **Log Analyzer** – extracts attack type, IP, usernames, count, severity.
  2. **Threat Intel** – receives pre‑fetched VirusTotal data (via `tools/vt_client.py`).
  3. **SOC Response** – decides `BLOCK` or `ALLOW`, outputs strict JSON.
- **`tools/firewall.py`** – thin wrapper around `iptables` (or no‑op when `FIREWALL_DRY_RUN` is true). Honors a whitelist from `config.py`.
- **`integrations/slack_alert.py`** – posts a markdown‑formatted alert to a Slack webhook.
- **`utils/alert_logger.py`** – writes every decision to `alerts.log` (JSON‑Lines) and offers query helpers (`filter`, `stats`).
- **`config.py`** – centralised configuration; values are overridable via environment variables (log paths, thresholds, LLM model, VirusTotal key, whitelist, etc.).

---

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/<owner>/multiagent-soc.git
   cd multiagent-soc
   ```
2. **Create a virtual environment** (optional but recommended)
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Pull an LLM model for CrewAI** (the default is `mistral:latest`). If you use Ollama locally:
   ```bash
   ollama pull mistral:latest
   ```
   Adjust `OLLAMA_MODEL` in the environment or `config.py` if you prefer another model.

---

## Configuration

All tunables live in `config.py`. Override any value with an environment variable of the same name:

| Variable | Purpose | Default |
|----------|---------|---------|
| `AUTH_LOG_PATH` | Path to the auth log to monitor | `/var/log/auth.log` |
| `ALERT_LOG_PATH` | File where alerts are persisted | `./alerts.log` |
| `BRUTE_FORCE_THRESHOLD` | Failed‑login count to trigger brute‑force detection | `5` |
| `TIME_WINDOW_SECONDS` | Sliding‑window duration for counting attempts | `60` |
| `OLLAMA_MODEL` | Ollama model tag used by CrewAI | `mistral:latest` |
| `OLLAMA_BASE_URL` | Base URL of the Ollama API | `http://localhost:11434` |
| `VIRUSTOTAL_API_KEY` | API key for VirusTotal lookups (optional) | `''` |
| `IP_WHITELIST` | Comma‑separated list of IPs that must never be blocked | `127.0.0.1,::1,10.0.0.1` |
| `FIREWALL_DRY_RUN` | `true` disables actual iptables changes (useful for dev) | `false` |
| `LLM_TEMPERATURE` | Controls randomness of LLM output | `0.1` |
| `LLM_MAX_TOKENS` | Maximum tokens per agent response | `512` |

---

## Running the System

### Production mode (real log)
```bash
export FIREWALL_DRY_RUN=false   # optional – set to true for safe testing
python main.py
```
The system will:
1. Tail the file at `AUTH_LOG_PATH`.
2. Emit colored console output for raw logs, detections, AI decisions, and firewall actions.
3. Write a structured alert entry to `ALERT_LOG_PATH`.
4. Send a Slack notification (if `SLACK_WEBHOOK_URL` is configured).

### Development / dry‑run mode
```bash
export FIREWALL_DRY_RUN=true
python main.py
```
Blocks are logged but no `iptables` changes are made.

### Using the mock log streamer for quick demos
Replace the real `LogStreamer` with `MockLogStreamer` in `SOCSystem` (or run the supplied test harness). The mock replays a handful of representative auth log lines, demonstrating detection and AI response without needing root privileges.

---

## Testing

The repository includes a single unit‑test suite focused on `AlertLogger`. Tests can be expanded to cover detectors and the crew workflow.

```bash
pytest
```

*Running a single test file*
```bash
pytest tests/test_soc_system.py
```

When running tests that require the mock log stream, the `MockLogStreamer` class in `utils/log_streamer.py` provides deterministic input.

---

## Extending the SOC

### Adding a new detector
1. Create a class in `detection/engine.py` that implements a `process(self, line: str) -> Optional[dict]` method.
2. Register the detector in `DetectionEngine.__init__` by appending to the `_detectors` list.
3. Define any new detection‑type constants you need; the rest of the pipeline (alert logger, AI crew) will handle it automatically.

### Adding a new AI step
1. Define a new CrewAI `Agent` in `agents/crew.py` (similar to the existing three).
2. Create a corresponding `Task` builder function.
3. Insert the new task into the `tasks` list before the crew kickoff.
4. Extend `_parse_decision` if you need to interpret additional JSON fields.

### New response actions
- Implement a wrapper (e.g., `tools/email_alert.py`) and invoke it from `_run_ai_analysis` after the crew decision.
- Ensure the action respects the whitelist and dry‑run settings.

---

## Troubleshooting & FAQ

- **No detections appear** – Verify that the path in `AUTH_LOG_PATH` points to a file with SSH auth logs. Use `tail -f /var/log/auth.log` to confirm new lines are being written.
- **AI decisions always `ALLOW`** – Check that the LLM model is reachable (`ollama` running) and that `OLLAMA_BASE_URL` is correct. Review the CrewAI logs for any errors.
- **Firewall blocks are not applied** – Ensure the process runs with sufficient privileges (root) or set `FIREWALL_DRY_RUN` to `false` and verify `iptables` is present.
- **VirusTotal enrichment fails** – Confirm that `VIRUSTOTAL_API_KEY` is set and has sufficient quota. The system will fallback to a placeholder message if the key is missing.
- **Slack notifications are missing** – Set `SLACK_WEBHOOK_URL` in the environment or `config.py`. The webhook must accept POST JSON payloads.

---

## License

This project is licensed under the **MIT License** – see the `LICENSE` file for details.