"""
agents/crew.py — CrewAI Multi-Agent SOC Orchestration

Three-agent pipeline:
  1. LogAnalyzerAgent   — interprets raw detection data
  2. ThreatIntelAgent   — evaluates threat using pre-fetched VT context (no tool calling)
  3. SOCResponseAgent   — makes final BLOCK / ALLOW decision

VT lookup is done in plain Python BEFORE the crew runs and injected
as text into the task prompt — no native tool-calling required.
This makes it compatible with any Ollama model including phi3 and mistral.
"""

import json
import logging
import re

from crewai import Agent, Crew, Process, Task
from crewai.llm import LLM

from tools.vt_client import check_ip
from config import CONFIG

logger = logging.getLogger("SOC.Crew")


# ── LLM Factory ───────────────────────────────────────────────────────────────

def _build_llm() -> LLM:
    return LLM(
        model=f"ollama/{CONFIG['ollama_model']}",
        base_url=CONFIG["ollama_base_url"],
        temperature=CONFIG["llm_temperature"],
        max_tokens=CONFIG["llm_max_tokens"],
    )


# ── Agent Definitions ─────────────────────────────────────────────────────────

def build_log_analyzer(llm: LLM) -> Agent:
    return Agent(
        role="SOC Log Analyzer",
        goal=(
            "Analyse raw security detection data from Linux auth logs. "
            "Extract key indicators: IP address, attack type, affected usernames, "
            "attempt frequency, and time patterns."
        ),
        backstory=(
            "You are a senior SOC analyst specialising in Linux intrusion detection. "
            "You have deep knowledge of SSH brute-force patterns, invalid user scans, "
            "and privilege-escalation probes. You are precise and concise."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )


def build_threat_intel(llm: LLM) -> Agent:
    # No tools — VT data is injected directly into the task description as text
    return Agent(
        role="Threat Intelligence Analyst",
        goal=(
            "Evaluate the malicious intent of a detected IP using the threat "
            "intelligence context provided. "
            "Produce a structured threat assessment with a confidence score."
        ),
        backstory=(
            "You are a threat intelligence specialist. You correlate reputation "
            "data and behavioural patterns to assess whether an IP is conducting "
            "targeted attacks, opportunistic scanning, or is a false positive. "
            "You always return a JSON threat assessment."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )


def build_soc_response(llm: LLM) -> Agent:
    return Agent(
        role="SOC Response Decision Maker",
        goal=(
            "Synthesise the log analysis and threat intelligence reports. "
            "Decide whether to ALLOW or BLOCK the source IP. "
            "Output ONLY a JSON object: "
            '{"action": "BLOCK"|"ALLOW", "reason": "<str>", "confidence": <float>}'
        ),
        backstory=(
            "You are the incident response lead. You receive analysis from your team "
            "and make the final call. You balance security against availability. "
            "Your output must always be valid JSON and nothing else."
        ),
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )


# ── Task Definitions ──────────────────────────────────────────────────────────

def build_analysis_task(agent: Agent, detection_data: str) -> Task:
    return Task(
        description=(
            f"Analyse this security detection event from Linux auth logs:\n\n"
            f"{detection_data}\n\n"
            "Summarise: attack type, source IP, targeted usernames, "
            "attempt count, severity (LOW/MEDIUM/HIGH/CRITICAL), and notable patterns."
        ),
        expected_output=(
            "A concise threat summary: IP, detection type, usernames targeted, "
            "attempt count, severity, and notable patterns."
        ),
        agent=agent,
    )


def build_intel_task(agent: Agent, detection_data: str, vt_context: str) -> Task:
    return Task(
        description=(
            f"Perform threat intelligence assessment for this detection:\n\n"
            f"{detection_data}\n\n"
            f"VirusTotal reputation data (pre-fetched):\n{vt_context}\n\n"
            "Using the above data, assess: is this opportunistic scanning, "
            "a targeted attack, APT behaviour, or a likely false positive?\n"
            "Return JSON: "
            "{vt_malicious: int, vt_total: int, threat_category: str, confidence: float, notes: str}"
        ),
        expected_output=(
            "JSON: {vt_malicious, vt_total, threat_category, confidence, notes}"
        ),
        agent=agent,
    )


def build_response_task(agent: Agent) -> Task:
    return Task(
        description=(
            "Based on the log analysis and threat intelligence from your colleagues, "
            "make the final response decision.\n"
            "Rules:\n"
            "  - BLOCK if threat is MEDIUM+ confidence and attempt count >= 3\n"
            "  - BLOCK immediately for ROOT_LOGIN_ATTEMPT or RAPID_RECONNECT\n"
            "  - ALLOW if evidence is weak or this looks like a false positive\n\n"
            'Output ONLY valid JSON: {"action": "BLOCK"|"ALLOW", "reason": "<str>", "confidence": <float>}'
        ),
        expected_output=(
            'Valid JSON: {"action": "BLOCK" or "ALLOW", "reason": "string", "confidence": 0.0-1.0}'
        ),
        agent=agent,
    )


# ── SOC Crew ──────────────────────────────────────────────────────────────────

class SOCCrew:
    def __init__(self, model: str):
        self._llm = _build_llm()
        self._log_analyzer = build_log_analyzer(self._llm)
        self._threat_intel = build_threat_intel(self._llm)
        self._soc_response = build_soc_response(self._llm)
        logger.info(f"SOCCrew initialised with model={model}")

    def analyze(self, detection: dict) -> dict:
        detection_data = json.dumps(detection, indent=2)

        # ── Pre-fetch VT in plain Python — no tool calling needed ─────────────
        ip = detection.get("ip", "")
        vt_context = self._fetch_vt_context(ip)

        tasks = [
            build_analysis_task(self._log_analyzer, detection_data),
            build_intel_task(self._threat_intel, detection_data, vt_context),
            build_response_task(self._soc_response),
        ]

        crew = Crew(
            agents=[self._log_analyzer, self._threat_intel, self._soc_response],
            tasks=tasks,
            process=Process.sequential,
            verbose=False,
        )

        try:
            raw_result = crew.kickoff()
            return self._parse_decision(str(raw_result))
        except Exception as exc:
            logger.error(f"CrewAI kickoff failed: {exc}", exc_info=True)
            severity_types = {"ROOT_LOGIN_ATTEMPT", "RAPID_RECONNECT", "BRUTE_FORCE"}
            action = "BLOCK" if detection.get("type") in severity_types else "ALLOW"
            return {
                "action": action,
                "reason": f"AI analysis failed ({exc}); applied fail-safe rule.",
                "confidence": 0.5,
            }

    def _fetch_vt_context(self, ip: str) -> str:
        """Call VT directly in Python and return a plain-text summary."""
        try:
            if not CONFIG.get("virustotal_api_key"):
                return "VirusTotal: no API key configured — skipping enrichment."
            result = check_ip(ip)
            malicious = result.get("malicious_votes", 0)
            total = result.get("total_votes", 0)
            reputation = result.get("reputation_score", 0)
            country = result.get("country", "unknown")
            asn = result.get("as_owner", "unknown")
            tags = ", ".join(result.get("tags", [])) or "none"
            return (
                f"VT malicious votes: {malicious}/{total} | "
                f"Reputation: {reputation} | Country: {country} | "
                f"ASN: {asn} | Tags: {tags}"
            )
        except Exception as exc:
            logger.warning(f"VT pre-fetch failed for {ip}: {exc}")
            return f"VirusTotal lookup failed: {exc}"

    def _parse_decision(self, raw: str) -> dict:
        clean = re.sub(r"```(?:json)?|```", "", raw).strip()
        match = re.search(r"\{.*?\}", clean, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                action = data.get("action", "ALLOW").upper()
                if action not in ("ALLOW", "BLOCK"):
                    action = "ALLOW"
                return {
                    "action": action,
                    "reason": data.get("reason", "No reason provided."),
                    "confidence": float(data.get("confidence", 0.5)),
                }
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error: {e} | raw={raw[:200]}")

        upper = raw.upper()
        action = "BLOCK" if "BLOCK" in upper else "ALLOW"
        return {
            "action": action,
            "reason": "Parsed from unstructured response.",
            "confidence": 0.4,
        }
