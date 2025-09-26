from google.genai import types
from collections import Counter
import os
from datetime import datetime, timezone
import json

def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# Json compute tool
def compute_stats_tool(path: str) -> dict:
    data = load_json(path)
    return compute_stats(data)

def compute_stats(es_json: dict, top_n: int = 10):
    hits = es_json.get("hits", {}).get("hits", [])
    entries = [h.get("_source", {}) for h in hits]

    total = len(entries)
    honeypots = Counter(e.get("type", "Unknown") for e in entries)
    countries = Counter(e.get("geoip", {}).get("country_name", "Unknown") for e in entries)
    ips = Counter(e.get("src_ip", "Unknown") for e in entries)

    def get_port(e):
        return (e.get("dest_port")
                or e.get("destination", {}).get("port")
                or e.get("network", {}).get("transport")
                or "Unknown")
    ports = Counter(get_port(e) for e in entries)

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_events": total,
        "honeypots": honeypots.most_common(top_n),
        "countries": countries.most_common(top_n),
        "ips": ips.most_common(top_n),
        "ports": ports.most_common(top_n),
    }

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
