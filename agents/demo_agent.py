import os
import subprocess
import requests
from langchain.agents import AgentExecutor, create_react_agent
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def run_shell(cmd: str) -> str:
    """Tool: run any shell command the model asks for."""
    return subprocess.check_output(cmd, shell=True).decode()

def fetch(url: str) -> str:
    """Tool: fetch any URL."""
    return requests.get(url).text

tools = [run_shell, fetch]
# agent wired up with AgentExecutor / create_react_agent ...
