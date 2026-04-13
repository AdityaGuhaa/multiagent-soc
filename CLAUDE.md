# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common development commands

- **Install dependencies**
  ```bash
  pip install -r requirements.txt
  ```
- **Run the full test suite**
  ```bash
  pytest
  ```
- **Run a single test file (if tests are added later)**
  ```bash
  pytest tests/<test_file>.py
  ```
- **Lint / format** (project uses standard Python style; run your preferred linter, e.g. `ruff` or `black`).
- **Start the SOC system** (requires an auth log or the mock streamer in tests)
  ```bash
  python main.py
  ```
- **Dry‑run mode** (no real firewall changes)
  ```bash
  export FIREWALL_DRY_RUN=true
  python main.py
  ```

## High‑level architecture

- **`main.py`** – entry point. Instantiates `SOCSystem`, starts the log‑streaming thread, and coordinates detection, AI analysis, alert logging, Slack notification, and firewall actions.
- **`utils/log_streamer.py`** – real‑time tail‑like generator with log‑rotation handling (`LogStreamer`). A `MockLogStreamer` is provided for unit‑tests.
- **`detection/engine.py`** – rule‑based detectors (`BruteForceDetector`, `InvalidUserDetector`, `RootLoginDetector`, `SudoFailureDetector`, `RapidReconnectDetector`). `DetectionEngine` composes them and returns a list of detection dicts per log line.
- **`agents/crew.py`** – builds three CrewAI agents (log analysis, threat‑intel, response). It pre‑fetches VirusTotal reputation (`tools/vt_client.py`) and runs the agents sequentially, parsing the JSON decision.
- **`tools/firewall.py`** – thin wrapper around `iptables` (or no‑op when `firewall_dry_run` is true) and respects the whitelist from `config.py`.
- **`integrations/slack_alert.py`** – posts a formatted message to a Slack webhook defined in `config.py`.
- **`utils/alert_logger.py`** – persists every AI decision to a JSON‑Lines file (`alerts.log` by default) and offers querying utilities.
- **`config.py`** – central configuration; all values can be overridden via environment variables (log paths, thresholds, LLM model, VirusTotal key, etc.).
- **`tools/vt_client.py`** – simple VirusTotal IP reputation lookup with local caching (`tools/cache.py`).
- **`tests/`** – contains unit‑tests (currently only exercising `AlertLogger`). Tests can be run with `pytest` and can use `MockLogStreamer` for deterministic log input.

The system is deliberately modular: adding a new detector only requires a new class in `detection/engine.py` and inclusion in `DetectionEngine._detectors`. Adding a new AI‑agent step can be done by extending `agents/crew.py` with another CrewAI `Agent` and updating the task list.