# main.py
import asyncio
from dotenv import load_dotenv
from utils import call_agent_async, save_report
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
import os

from summary_agent.agent import root_agent

load_dotenv()
session_service = InMemorySessionService()

APP_NAME = "Summary Agent"
USER_ID = "summari"
SESSION_ID = "001"
PROJECT_DIR = os.path.expanduser("~/Summai")
LOG_PATH = os.path.join(PROJECT_DIR, "logs_last1h.json")
os.makedirs(PROJECT_DIR, exist_ok=True)


async def main_async():
    # Create a session
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=SESSION_ID,
        state={"timeframe": "Last 1 hours"},
    )
    # Create runner
    runner = Runner(
        agent=root_agent,
        app_name=APP_NAME,
        session_service=session_service,
    )
    
    query = "Generate a report based off of the last three 20 minute report snippets."
    report_text = await call_agent_async(runner, USER_ID, SESSION_ID, query)
    if report_text:
        path = save_report(report_text)
        print(f"Report saved to {path}")
    else:
        print("Agent call failed or returned no text.")

    print(f"\nSaved report to: {path}\n")
    print("\n--- Finished ---\n")

if __name__ == "__main__":
    asyncio.run(main_async())
