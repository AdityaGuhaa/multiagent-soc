from crewai import Agent, Task, Crew

from tools.log_parser import analyze_logs
from tools.vt_client import check_ip
from tools.firewall import block_ip


def run_soc_crew(log_lines):

    llm = "ollama/phi3"  # 🔥 FIX HERE

    log_agent = Agent(
        role="Log Analysis Expert",
        goal="Detect suspicious IPs",
        backstory="Linux log expert",
        llm=llm,
        verbose=True
    )

    threat_agent = Agent(
        role="Threat Intelligence Analyst",
        goal="Analyze IP reputation",
        backstory="Cybersecurity expert",
        llm=llm,
        verbose=True
    )

    alert_agent = Agent(
        role="SOC Manager",
        goal="Generate alerts",
        backstory="Security operations expert",
        llm=llm,
        verbose=True
    )

    # Rule-based parsing
    suspicious_ips = analyze_logs(log_lines)

    threat_results = []
    for ip_data in suspicious_ips:
        vt = check_ip(ip_data["ip"])
        threat_results.append({**ip_data, "vt": vt})

    if not threat_results:
        return "No threats detected"

    alert_task = Task(
   	 description=f"""
    	 Analyze threats:

   	 {threat_results}

    Assign severity:
    - Malicious → Critical
    - Suspicious → High
    - Safe → Low

    Suggest actions.
    """,
   	 expected_output="Structured alert with IP, severity, and action",
   	 agent=alert_agent
		)

    crew = Crew(
        agents=[log_agent, threat_agent, alert_agent],
        tasks=[alert_task],
        verbose=True
    )

    result = crew.kickoff()

    # Auto block
    for t in threat_results:
        if t["vt"]["verdict"] in ["Malicious", "Suspicious"]:
            block_ip(t["ip"])

    return result
