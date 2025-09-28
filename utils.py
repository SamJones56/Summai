from google.genai import types
from datetime import datetime, timezone

def save_report(report_text: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    filename = f"reports/Honeypot_Attack_Summary_Report_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)

async def process_agent_response(event):
    """Return the final text response if available."""
    if event.is_final_response():
        if (
            event.content
            and event.content.parts
            and hasattr(event.content.parts[0], "text")
            and event.content.parts[0].text
        ):
            return event.content.parts[0].text.strip()
    return None

async def call_agent_async(runner, user_id, session_id, query):
    """Call the agent asynchronously with the user's query. 
    Return the final text or None if failed.
    """
    content = types.Content(role="user", parts=[types.Part(text=query)])
    final_response_text = None

    try:
        async for event in runner.run_async(
            user_id=user_id, session_id=session_id, new_message=content
        ):
            response = await process_agent_response(event)
            if response:
                final_response_text = response
    except Exception as e:
        # If anything fails, return None
        return None

    return final_response_text
