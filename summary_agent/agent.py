from google.adk.agents import LLMAgnet
from google.adk.tools.agent_tool import AgentTool

from io import TextIOBase
import re


# https://fanchenbao.medium.com/chunk-read-a-large-file-in-python-4b887058215
def chunk_read(f_obj: TextIOBase, sentinel: str, max_sentinel: int):
    """Read a file object in chunks
    Read the file object line by line. Each time a sentinel is detected, we increment
    a count. Once the count reaches max_sentinel, we have gatherered the required
    chunk and yield it.
    NOTE: during chunking, we remove all the white spaces and tabs to reduce the
    memory load.
    params:
    :param f_obj: A file object from opening a text file.
    :type f_obj: TextIOBase
    :param sentinel: A string pattern (regex supported) to recognize a specific
        line.
    :type sentinel: str
    :param max_sentinel: Max number of appearance of sentinels allowed in a chunk.
        This is equivalent to a chunk size, but more meaningful than based on only
        line counts.
    :type max_sentinel: int
    :yield: A chunk of the file
    :rtype: Iterator[str]
    """
    cnt, chunk = 0, ""
    for line in f_obj:
        match = re.search(sentinel, line)
        if match:
            cnt += 1
        if cnt <= max_sentinel:
            chunk += line.strip()
        else:
            yield chunk
            cnt = 0
            chunk = line.strip()
    yield chunk


# TODO: Migrate from adk_run to scripting session, runner, and launching of the application
# TODO: Change chunk to long running tool: https://google.github.io/adk-docs/tools/function-tools/#long-run-tool
# TODO: send_email tool
# TODO: pdf_tool

summary_agent = LLMAgnet(
    name="summary_agent",
    model="gemeni-2.5.pro",
    description="Summarise log output from a network of t-pot honeypots",
    Instruction="""
    You are an log summariser agent,

    You are responsible from summarisng the log files from a multi-honeypot setup,

   You will be conducting the summarisation every 4 hours,

    This summarisation will be in the PDF format,

    A copy will be saved locally and a copy will be sent to a gmail account,

    On completion of

    You make use of the following tools:
    - Chunk reader - reads data and splits it into chunks
    -
    -

    You make use of the following Agents as tools:
    -

    """,
    tools=[AgentTool(google_search_agent), chunk_read],
)
