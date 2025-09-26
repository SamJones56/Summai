from google.adk.agents import LlmAgent
from google.adk.tools.agent_tool import AgentTool
from google_search_agent.agent import google_search_agent
from datetime import datetime, timezone

root_agent = LlmAgent(
    name="summary_agent",
    model="gemini-2.5-pro",
    description="Summarise log output from a network of t-pot honeypots",
    instruction="""
    You are a security report writer.
    You will receive a COMPACT JSON stats object (already aggregated locally). 
    Write a professional Honeypot Attack Summary Report in clear English with:

    - Title line with report name.
    - Report generation time and timeframe (assume "Last 2 hours" unless stated).
    - Executive Summary (key numbers + 2–4 bullets).
    - Detailed Analysis:
    * Attacks by honeypot (table).
    * Top source countries (table).
    * Top attacking IPs (table).
    * Top targeted ports/protocols (table).
    - A short Notes/Limitations section.
    - Keep it crisp, ~400–700 words. Do NOT invent numbers not present in the stats.
    """,

)
