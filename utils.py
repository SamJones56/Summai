from google.genai import types

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
            # Debug: print the raw event
            print("DEBUG EVENT:", event)

            response = await process_agent_response(event)
            if response:
                print("DEBUG RESPONSE TEXT:", response)  
                final_response_text = response
    except Exception as e:
        print("ERROR in call_agent_async:", e)  
        return None

    return final_response_text
