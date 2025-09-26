from google.adk.tools import google_search
from google.adk.agents import LlmAgent

google_search_agent = LlmAgent(
    name="google_search_agent",
    model="gemini-2.5-pro",
    description="Google Search Agent to answer search request to assist in the completion of summarisation of T-Pot HoneyPot Logs.",
    instruction="""
    You are a google search agent that is used as a tool to search the internet.

    Your response is fed upstream another agents that need google searches.

    Once you believe you are finished return the results to the root agent so it can continue the summarisation.
    """,
    tools=[google_search],
)
