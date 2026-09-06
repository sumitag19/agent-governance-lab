"""
signals.py — the Rules seed for the governance scanner.

This is deliberately just data + tiny helpers, no scanning logic. It is the part
a governance team (your lane) owns and evolves: what counts as "agentic", and what
capabilities make an agent risky. Keeping it separate from scan.py means the rules
can be reviewed, versioned, and eventually externalised (OPA/Rego, a YAML DSL, etc.)
without touching the API/plumbing code.

Bump POLICY_VERSION whenever you change these rules — every certificate records the
version it was issued under, so you can later re-certify ONLY what a rule change
actually affects instead of rescanning the world.
"""

POLICY_VERSION = "rules-2026.09.3"

# ---------------------------------------------------------------------------
# STAGE A — cheap triage: "is this even agentic?"  (no deep reasoning)
# ---------------------------------------------------------------------------

# Filenames that, on their own, strongly imply an agent/skill/tool definition.
MARKER_FILENAMES = {
    "skill.md", "agents.md", "agent.md",
    ".mcp.json", "mcp.json", "llms.txt",
    "copilot-instructions.md",
}

# Filename suffixes that imply an agent/skill manifest.
MARKER_SUFFIXES = (".agent.yaml", ".agent.yml", ".skill.yaml", ".skill.yml")

# Path segments that suggest a file lives in an agent/skill area.
PATH_SEGMENTS = {"agents", "agent", "skills", "skill", "mcp", "copilot", "prompts"}

# Dependency-manifest filenames we will actually fetch + grep for framework names.
MANIFEST_FILENAMES = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile",
    "package.json", "go.mod", "pom.xml", "build.gradle", "gemfile", "cargo.toml",
}

# Framework / SDK tokens that mark code as part of an agentic flow.
FRAMEWORK_TOKENS = (
    "langchain", "langgraph", "llama-index", "llama_index", "llamaindex",
    "crewai", "autogen", "pyautogen", "semantic-kernel", "semantic_kernel",
    "haystack", "litellm", "dspy", "guidance", "autogpt", "babyagi",
    "openai", "anthropic", "cohere", "mistralai", "google-generativeai",
    "google.generativeai", "ollama", "transformers",
    "modelcontextprotocol", "mcp-go", "mark3labs/mcp-go", "\"mcp\"", "'mcp'",
    "azure-ai-inference", "azure-ai-projects", "azure.ai.inference",
)

# ---------------------------------------------------------------------------
# STAGE B — deep scan: capability / blast-radius signals (only for candidates)
# Each entry: capability -> substrings that indicate it in source text.
# ---------------------------------------------------------------------------
CAPABILITY_SIGNALS = {
    "shell_exec": ("subprocess", "os.system", "os/exec", "child_process",
                   "runtime.getruntime", ".popen(", "exec(", "eval("),
    "network_egress": ("requests.", "httpx", "urllib.request", "http.client",
                       "fetch(", "axios", "net/http", "socket.", "webclient"),
    "filesystem_write": ("open(", "os.remove", "shutil.", "ioutil.writefile",
                         "fs.writefile", "pathlib"),
    "secret_access": ("os.environ", "os.getenv", "process.env", "getenv(",
                      "api_key", "apikey", "secret", "token", "password"),
    "tool_calls": ("@tool", "tool(", "tool_calls", "tools=[", "function_call",
                   "functiondeclaration", "toolset", "registertool"),
    "high_autonomy": ("agentexecutor", "create_react_agent", "while true",
                      "run_until", "autonomous", "self.plan("),
}

# ---------------------------------------------------------------------------
# RISK RULES — capability profile -> verdict. This is the heart of "Rules".
# Returns one of: "certified", "certified-with-warnings", "blocked".
# ---------------------------------------------------------------------------
def verdict_for(caps: set) -> tuple:
    """Map a capability set to a verdict + human reason. Intentionally simple &
    readable so a governance reviewer can reason about it; swap for a real policy
    engine later."""
    egress = "network_egress" in caps
    shell = "shell_exec" in caps
    secrets = "secret_access" in caps

    if shell and egress and secrets:
        return "blocked", "shell execution + network egress + secret access (exfiltration risk)"
    if shell and egress:
        return "blocked", "shell execution combined with network egress"
    if egress or shell or secrets:
        risky = ", ".join(sorted(c for c in ("shell_exec", "network_egress", "secret_access") if c in caps))
        return "certified-with-warnings", f"review recommended: {risky}"
    return "certified", "no high-risk capabilities detected"
