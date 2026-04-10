"""
AI-Powered SOC Automation System — Main Entry Point
Orchestrates log ingestion, detection, AI analysis, and automated response.
"""
import threading
import time
import signal
import sys
import logging
from datetime import datetime, timezone
from utils.log_streamer import LogStreamer
from utils.alert_logger import AlertLogger
from detection.engine import DetectionEngine
from agents.crew import SOCCrew
from tools.firewall import FirewallManager
from integrations.slack_alert import send_alert as slack_alert
from config import CONFIG

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SOC.Main")


class SOCSystem:
    """
    Top-level orchestrator.
    Wires together log streaming -> detection -> AI crew -> firewall + slack response.
    """

    def __init__(self):
        self.running = False
        self.alert_logger = AlertLogger(CONFIG["alert_log_path"])
        self.firewall = FirewallManager(whitelist=CONFIG["ip_whitelist"])
        self.detection_engine = DetectionEngine(
            brute_force_threshold=CONFIG["brute_force_threshold"],
            time_window_seconds=CONFIG["time_window_seconds"],
        )
        self.crew = SOCCrew(model=CONFIG["ollama_model"])
        self.streamer = LogStreamer(log_path=CONFIG["auth_log_path"])
        self._analysis_queue: list[dict] = []
        self._queue_lock = threading.Lock()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self):
        self.running = True
        logger.info("SOC System starting up...")
        self._print_banner()
        analysis_thread = threading.Thread(
            target=self._analysis_worker, daemon=True, name="AI-Analysis"
        )
        analysis_thread.start()
        logger.info("AI Analysis worker started.")
        try:
            self._ingest_loop()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("SOC System shutting down.")
        sys.exit(0)

    # ── Core Ingest Loop ───────────────────────────────────────────────────────

    def _ingest_loop(self):
        """Stream log lines, run detection, queue AI analysis on hits."""
        logger.info(f"Streaming: {CONFIG['auth_log_path']}")
        for line in self.streamer.stream():
            if not self.running:
                break
            print(f"\033[90m[LOG] {line.strip()}\033[0m")
            detections = self.detection_engine.process_line(line)
            for detection in detections:
                self._handle_detection(detection)

    def _handle_detection(self, detection: dict):
        """Log the raw detection and queue it for AI triage."""
        ts = datetime.now(timezone.utc).isoformat()
        detection["timestamp"] = ts
        logger.warning(
            f"[DETECTION] type={detection['type']} ip={detection['ip']} "
            f"count={detection.get('count', '?')}"
        )
        print(
            f"\033[93m[ALERT] {detection['type']} — IP: {detection['ip']} "
            f"(attempts: {detection.get('count', '?')})\033[0m"
        )
        with self._queue_lock:
            self._analysis_queue.append(detection)

    # ── AI Analysis Worker ─────────────────────────────────────────────────────

    def _analysis_worker(self):
        """
        Background thread: drain the detection queue, run CrewAI analysis,
        then execute the recommended firewall action and send Slack alert.
        """
        while self.running:
            job = None
            with self._queue_lock:
                if self._analysis_queue:
                    job = self._analysis_queue.pop(0)
            if job:
                self._run_ai_analysis(job)
            else:
                time.sleep(0.5)

    def _run_ai_analysis(self, detection: dict):
        """Run multi-agent analysis on a detection event."""
        logger.info(f"Running AI analysis for IP {detection['ip']}...")
        try:
            result = self.crew.analyze(detection)
            action = result.get("action", "ALLOW").upper()
            reason = result.get("reason", "No reason provided.")
            confidence = result.get("confidence", 0.0)

            logger.info(
                f"[AI DECISION] {action} — {detection['ip']} "
                f"(confidence={confidence:.0%}) — {reason}"
            )
            print(
                f"\033[{'91' if action == 'BLOCK' else '92'}m"
                f"[AI] {action} — {detection['ip']} | {reason}\033[0m"
            )

            # Persist alert to log file
            self.alert_logger.log(
                ip=detection["ip"],
                detection_type=detection["type"],
                action=action,
                reason=reason,
                confidence=confidence,
                raw=detection,
            )

            # Send Slack alert
            slack_alert(
                ip=detection["ip"],
                detection_type=detection["type"],
                action=action,
                reason=reason,
                confidence=confidence,
            )

            # Execute firewall action
            if action == "BLOCK":
                success = self.firewall.block_ip(detection["ip"])
                if success:
                    print(f"\033[91m[FIREWALL] Blocked {detection['ip']}\033[0m")
                else:
                    logger.warning(
                        f"Firewall block skipped for {detection['ip']} "
                        f"(whitelisted or duplicate)"
                    )

        except Exception as exc:
            logger.error(
                f"AI analysis error for {detection['ip']}: {exc}", exc_info=True
            )

    # ── Banner ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _print_banner():
        banner = r"""
  ____  ___   ____      _         _                        _   _
 / ___|/ _ \ / ___|    / \  _   _| |_ ___  _ __ ___   __ _| |_(_) ___  _ __
 \___ \ | | | |       / _ \| | | | __/ _ \| '_ ` _ \ / _` | __| |/ _ \| '_ \
  ___) | |_| | |___  / ___ \ |_| | || (_) | | | | | | (_| | |_| | (_) | | | |
 |____/ \___/ \____|/_/   \_\__,_|\__\___/|_| |_| |_|\__,_|\__|_|\___/|_| |_|

  AI-Powered SOC — Real-Time Threat Detection & Automated Response
        """
        print(f"\033[96m{banner}\033[0m")


# ── Signal Handling ────────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    logger.info("Received shutdown signal.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    soc = SOCSystem()
    soc.start()
