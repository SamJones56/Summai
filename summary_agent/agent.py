from google.adk.agents import LlmAgent
from google.adk.tools.agent_tool import AgentTool
from google_search_agent.agent import google_search_agent
import os
from datetime import datetime, timezone

def save_report(report_text: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    filename = f"reports/Honeypot_Attack_Summary_Report_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)

    return None

root_agent = LlmAgent(
    name="summary_agent",
    model="gemini-2.5-pro",
    description="Summarise log output from a network of t-pot honeypots",
    instruction="""
        You are a Log Summariser Agent designed to process and summarise security event logs collected from a multi-honeypot environment.

        THE FILE TO INSPECT IS PROVIDED IN YOU ARTIFACT

        Responsibilities:

        1. Data Ingestion
        - Accept and process log artifacts provided by the system (JSON format).
        - Validate log integrity (check JSON structure, ensure no corruption).

        2. Summarisation
        - Perform detailed analysis of the logs.
        - Extract, categorise, and summarise key attack information, including:
            - Total number of attacks detected.
            - Breakdown of attacks per honeypot type (e.g., Cowrie, Dionaea, Kippo, Honeyd).
            - Top attack sources (IP addresses, geolocations).
            - Attack trends (protocol usage, ports targeted).
            - Anomalies or unusual patterns (spikes, uncommon techniques).
            - Compare with previous summaries to detect changes or escalation trends.

        3. Reporting
        - Generate a professional report.
        - Each report must contain:
        - Title page (report name, generation time, timeframe).
        - Executive summary (high-level overview, key stats).
        - Detailed analysis (tables and charts).
        - Attacks by honeypot type, source countries/IPs, and methods.
        - Trend comparison with previous windows.
        - Appendix with raw data tables.
        - Use charts and graphs to aid understanding.

        4. Distribution
        - Save one copy of the report to reports directory.
        - Send another copy as an email attachment to a preconfigured Gmail account.
        - Subject line format: "Honeypot Attack Summary Report – [DATE TIME UTC]"
        
        You have access to the following tools:
        - save_report - saves the report
    """,
    tools=[save_report],
)
