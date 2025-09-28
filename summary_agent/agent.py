from google.adk.agents import LlmAgent
import os 
import subprocess
from datetime import datetime,timezone

FINAL_PATH = "reports/"
FILTERED_PATH = "filtered/"

def get_current_time():
    """Returns the current date time UTC

    Returns:
        _type_: Returns the current date time
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

def ls_files():
    """List the 3 most recent JSONL honeypot logs in the filtered logs directory."""
    try:
        files = [
            f for f in os.listdir(FILTERED_PATH) 
            if f.endswith(".jsonl")
        ]
        files.sort(key=lambda f: os.path.getmtime(os.path.join(FILTERED_PATH, f)))
        return files[-3:]  
    except Exception as e:
        return [f"Error: {e}"]


def read_contents(path: str):
    """This returns the contents of a file

    Args:
        path (str): the path which to read the contesnts of

    Returns:
        _type_: retruns the contents
    """
    full_path = os.path.join(FILTERED_PATH, path)
    with open(full_path, "r") as f:
        return f.read()
    
def save_final_report(report_text: str):
    """This method saves the final generated report to final_reports directory

    Args:
        report_text (str): the final report to save

    Returns:
        _type_: If it has done writing
    """
    timestamp = get_current_time()
    filename = os.path.join(FINAL_PATH, f"Honeypot_Attack_Summary_Report_{timestamp}.md")
    if report_text:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_text)
        return f"Done writing: {filename}\n{report_text}"
    else:
        return "Error: report text was empty"

import json

def chunk_logs(path: str, chunk_size: int = 500):
    """Read a JSONL log file and return chunks of N lines (default 500)."""
    full_path = os.path.join(FILTERED_PATH, path)
    chunks = []
    current = []

    try:
        with open(full_path, "r") as f:
            for i, line in enumerate(f, 1):
                current.append(line.strip())
                if i % chunk_size == 0:
                    chunks.append("\n".join(current))
                    current = []
            if current:
                chunks.append("\n".join(current))
    except Exception as e:
        return {"error": str(e)}

    return {"chunks": chunks}


root_agent = LlmAgent(
    name="summary_agent",
    model="gemini-2.5-pro",
    description="Summarise raw T-Pot honeypot logs into a professional hourly report",
    instruction="""
    You are a cybersecurity analyst writing Honeypot Attack Summary Reports.

    Input: A JSONL file (or multiple files) containing raw T-Pot honeypot logs.
    Each line is a JSON object representing one honeypot event (Suricata, Cowrie,
    Dionaea, Ciscoasa, Honeytrap, etc.).

    Task: Parse and analyze the raw logs directly, then produce a structured report:

    1. **Title**: "Honeypot Attack Summary Report"
    2. **Report Info**:
       - Report generation timestamp (use the system time now).
       - Timeframe covered (from earliest to latest @timestamp in the logs).
    3. **Executive Summary**:
       - Total number of attacks in this timeframe.
       - 5–10 concise bullet points of the most notable findings (e.g., a major CVE exploit, 
         large credential spray, common protocol targeted).
    4. **Detailed Analysis**:
       - **Attacks by Honeypot Type**: counts grouped by type.
       - **Top Source IPs**: list with counts.
       - **Top Targeted Ports/Protocols**: list with counts.
       - **CVEs Seen**: list *all* unique CVEs present in the logs, grouped and counted.
       - **Credentials Attempted**: list unique username/password pairs (if present).
       - **Interesting Activity**:
         * List unusual or repeated commands (from Cowrie or payload_printable).
         * Highlight anything that looks like exploitation, privilege escalation, 
           or malware download attempts (e.g. wget, curl, chmod, ./binary).
         * These will be flagged for the 8-hour report agent to investigate further.
    5. **Notes & Limitations**:
       - Mention if logs are truncated, incomplete, or missing fields.
       - State this report only covers the provided logs.

    Constraints:
        - Perform your own aggregation directly from the JSONL logs.
        - Use only values present in the input (do not invent data).
        - Explicitly list *all CVEs* found.
        - Be professional, structured, and keep report length 1000-2000 words.
        
    You have access to the following tools:
    - ls_files : Returns the three files we want to summarise
    - chunk_logs : This returns the file contents in smaller chunks (default 500 lines each)
    
    - get_current_time : Returns the current date time UTC
    - save_final_report : Use this to save the final report once you have gathered and summarised all available data
    """,
    tools=[ls_files, chunk_logs, get_current_time, save_final_report]
)


# - read_contents : This returns the content of a specified file