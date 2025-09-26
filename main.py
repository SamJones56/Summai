from dotenv import load_dotenv
import uuid

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from summary_agent.agent import summary_agent

load_dotenv()

initial_state = {"user_name": "summariser"}
session_service_stateful = InMemorySessionService()


def main():
    APP_NAME = "Summary Agent"
    USER_ID = "summari"
    SESSION_ID = str(uuid.uuid4())

    stateful_session = session_service_stateful.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=SESSION_ID,
        state=initial_state,
    )

    runner = Runner(
        agent=summary_agent,
        app_name=APP_NAME,
    )


if __name__ == "__main__":
    main()
