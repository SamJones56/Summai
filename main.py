# main.py
import asyncio
from dotenv import load_dotenv
from utils import call_agent_async, compute_stats_tool, load_json, compute_stats
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.artifacts import InMemoryArtifactService
import json

from summary_agent.agent import root_agent, save_report

load_dotenv()
session_service = InMemorySessionService()
artifact_service = InMemoryArtifactService()

LOG_PATH = "/home/kali_user/Documents/Summai/logs_last2h.json"

async def main_async():
    APP_NAME = "Summary Agent"
    USER_ID = "summari"
    SESSION_ID = "001"

    # Pre-aggregate LOCALLY to keep the LLM prompt tiny
    raw = load_json(LOG_PATH)
    stats = compute_stats(raw)
    stats_json = json.dumps(stats, indent=2)

    query = f"Here is the stats JSON:\n{stats_json}\n\nGenerate the Honeypot Attack Summary Report."

    # Create a session
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=SESSION_ID,
        state={"timeframe": "Last 2 hours"},
    )

    runner = Runner(
        agent=root_agent,
        app_name=APP_NAME,
        session_service=session_service,
    )

    print("\n--- Generating report with compact stats ---\n")
    report_text = await call_agent_async(runner, USER_ID, SESSION_ID, query)
    if report_text:
        path = save_report(report_text)
        print(f"Report saved to {path}")
    else:
        print("Agent call failed or returned no text.")

    # Persist the report
    path = save_report(report_text)
    print(f"\nSaved report to: {path}\n")
    print("\n--- Finished ---\n")

if __name__ == "__main__":
    asyncio.run(main_async())
