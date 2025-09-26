import asyncio
from dotenv import load_dotenv
from utils import call_agent_async

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.artifacts import InMemoryArtifactService
import google.genai.types as types

from summary_agent.agent import root_agent

load_dotenv()

session_service = InMemorySessionService()
artifact_service = InMemoryArtifactService()

with open("/home/kali_user/Documents/logs_last2h.json", "rb") as f:
    log_bytes = f.read()

log_artifact = types.Part.from_bytes(
    data=log_bytes,
    mime_type="application/json",
)


async def main_async():
    
    APP_NAME = "Summary Agent"
    USER_ID = "summari"
    SESSION_ID = "001"
    initial_state = {"user_name": "summariser"}
    
    # Create a new session
    session = await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=SESSION_ID,
        state=initial_state,
    )

    # Save the artifact into the session
    await artifact_service.save_artifact(
        app_name=session.app_name,
        user_id=session.user_id,
        session_id=session.id,
        filename="logs_last2h.json",
        artifact=log_artifact,
    )

    # Create runner
    runner = Runner(
        agent=root_agent,
        app_name=APP_NAME,
        session_service=session_service,
        artifact_service=artifact_service,
    )
    
    # Run the agent with a query
    query = (
        "Use the provided honeypot log artifact to generate a full professional PDF report. "
        "The report must include:\n"
        "- Title page with report name, generation time, and timeframe.\n"
        "- Executive Summary with key findings.\n"
        "- Detailed Analysis: attacks by honeypot type, source IPs/countries, methods/techniques, trends.\n"
        "- Charts and tables for clarity.\n"
        "- Trend comparison vs. previous window if available.\n"
        "- Appendix with raw counts.\n\n"
        "Save a copy"
    )
 
    print(f"\n--- Running Query: {query} ---\n")

    await call_agent_async(runner, USER_ID, SESSION_ID, query)

    print("\n\n--- Finished ---")


if __name__ == "__main__":
    asyncio.run(main_async())
