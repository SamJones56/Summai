from google.adk.agents import LlmAgent
import os 
import subprocess
from datetime import datetime,timezone

FINAL_PATH = os.path.expanduser("~/Summai/reports")
FILTERED_PATH = os.path.expanduser("~/Summai/filtered/agg")


def get_current_time():
    """Returns the current date time UTC

    Returns:
        _type_: Returns the current date time
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def ls_files():
    """List the 3 most recent JSON honeypot logs in the filtered logs directory."""
    try:
        files = [
            f for f in os.listdir(FILTERED_PATH) 
            if f.endswith(".json")
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

root_agent = LlmAgent(
    name="summary_agent",
    model="gemini-2.5-pro",
    description="Summarise raw T-Pot honeypot logs into a professional hourly report",
    instruction="""
        You are a cybersecurity analyst writing Honeypot Attack Summary Reports.
        This report will be read by another AI Agent every 8-12 hours so include as much relevant data as possible.
        Input comes as JSON.
        Use the `read_contents` tool to read them.
        before writing the final report with `save_final_report`.

        Steps:
        1. Call `ls_files` to get the log files to summarize.
        2. For each file, call `read_contents` repeatedly until you’ve read all lines.
        3. Aggregate: total count, attacks by type, CVEs, commands, IPs, etc.
        4. After finishing all files, generate one consolidated report.

        Create Honeypot Attack Summary:
            - Title line with report name.
            - Report generation time and timeframe.
            - List of all files used to generate the report.
            
        Below are the expected lists:
            - Executive Summary
            - Detailed Analysis:
            * Attacks by honeypot (simple list).
            * Top attacking IPs (simple list).
            * Top targeted ports/protocols (simple list).
            * Most common CVEs (simple list).
            * Commands attempted by attackers (simple list).
            * Signatures triggered (simple list).
            * Users / login attempts (simple list).
            * Files uploaded/downloaded (simple list).
            * HTTP User-Agents (simple list).
            * SSH clients and servers (two simple lists).
            * Top attacker AS organizations (simple list).
            - Key Observations and Anomalies

        Constraints:
            - Use only values in the logs (don’t invent).
            - List all CVEs.
            - Professional tone, <1000 words.

        Tools:
        - ls_files
        - read_contents : This returns the content of a specified file
        - get_current_time
        - save_final_report
    """,
    tools=[ls_files, get_current_time, read_contents, save_final_report]
)


# - read_contents : This returns the content of a specified file