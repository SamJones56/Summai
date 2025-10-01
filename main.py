import asyncio
import random
from dotenv import load_dotenv
from utils import call_agent_async  
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
os.makedirs(PROJECT_DIR, exist_ok=True)


async def safe_call_agent(runner, user_id, session_id, query, retries=10, total_time=600):
    interval = total_time // retries
    for attempt in range(1, retries + 1):
        try:
            return await call_agent_async(runner, user_id, session_id, query)
        except Exception as e:
            err_str = str(e)
            if "503" in err_str or "500" in err_str:
                print(f"[Attempt {attempt}/{retries}] Error: {err_str}")
                if attempt < retries:
                    print(f"Retrying in {interval}s...")
                    await asyncio.sleep(interval)
                else:
                    print("Retries exhausted.")
                    return None
            else:
                raise

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

    query = "Generate a report based off of the last three 2 minute snippets of tpot data"
    report_text = await safe_call_agent(runner, USER_ID, SESSION_ID, query)

    if report_text:
        print(report_text.strip())
    else:
        print("Agent call failed or returned no text after retries.")



if __name__ == "__main__":
    asyncio.run(main_async())
