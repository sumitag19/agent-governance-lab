#!/usr/bin/env python3
"""
scan.py — a runnable miniature of the GitHub Copilot governance loop.

It mirrors the production flow on a small scale so you can *watch* each control point:

    fetch delta  ->  blob-SHA cache (inherit)  ->  Stage-A agentic triage
                 ->  Stage-B deep scan (only if agentic)  ->  mock certificate

No third-party dependencies (urllib only), so it runs anywhere Python does.

USAGE
    # First-push mode: walk the whole default-branch tree and certify everything
    python scan.py github/github-mcp-server

    # Delta mode: only what changed between two commits (your steady-state path)
    python scan.py github/github-mcp-server --base <SHA> --head <SHA>

    # Against your GitHub Enterprise Cloud instance:
    #   set a token, and point --host at your API host
    #   (bash)  export GITHUB_TOKEN=ghp_xxx
    #   (pwsh)  $env:GITHUB_TOKEN = "ghp_xxx"
    python scan.py your-org/some-repo --host api.SUBDOMAIN.ghe.com

The certificate store persists to certs.json in the working dir, so re-running
demonstrates "already certified -> inherit, no rescan".
"""
import argparse
import ast
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

import signals

CERT_STORE = "certs.json"
MAX_CONTENT_FETCHES = 25          # keep well under the 60/hr unauth rate limit
MAX_CONTENT_BYTES = 400_000       # don't deep-scan huge blobs in a demo


# --------------------------------------------------------------------------- #
# GitHub REST helpers                                                         #
# --------------------------------------------------------------------------- #
class GitHub:
    def __init__(self, host, token):
        self.base = f"https://{host}"
        self.token = token
        self.fetches = 0
        self.rate_remaining = "?"

    def get(self, path):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gov-scan",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, headers=headers)
        resp = urllib.request.urlopen(req, timeout=30)
        self.rate_remaining = resp.headers.get("X-RateLimit-Remaining", self.rate_remaining)
        return json.load(resp)

    def changed_files(self, repo, base, head):
        """Delta mode: the Compare API -> authoritative list of changed files."""
        cmp = self.get(f"/repos/{repo}/compare/{base}...{head}")
        return [
            {"path": f["filename"], "status": f["status"], "blob_sha": f["sha"]}
            for f in cmp.get("files", [])
        ]

    def full_tree(self, repo, ref):
        """First-push mode: every file + blob SHA at a ref."""
        commit = self.get(f"/repos/{repo}/commits/{ref}")
        tree_sha = commit["commit"]["tree"]["sha"]
        tree = self.get(f"/repos/{repo}/git/trees/{tree_sha}?recursive=1")
        if tree.get("truncated"):
            print("  ! tree truncated (repo too large for one call) — demo scans the first page")
        return [
            {"path": t["path"], "status": "existing", "blob_sha": t["sha"]}
            for t in tree["tree"] if t["type"] == "blob"
        ]

    def text(self, repo, path, ref):
        """Fetch + decode one file's content (Contents API). Returns '' on failure."""
        if self.fetches >= MAX_CONTENT_FETCHES:
            return None  # signal: deferred, over budget
        self.fetches += 1
        try:
            data = self.get(f"/repos/{repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
            if data.get("encoding") != "base64" or data.get("size", 0) > MAX_CONTENT_BYTES:
                return ""
            return base64.b64decode(data["content"]).decode("utf-8", "replace")
        except Exception:
            return ""


# --------------------------------------------------------------------------- #
# Stage A — cheap agentic triage                                              #
# --------------------------------------------------------------------------- #
def is_manifest(path):
    return os.path.basename(path).lower() in signals.MANIFEST_FILENAMES


def triage(path, gh, repo, ref):
    """Return (is_agentic, reasons). Only fetches content for manifests, so it
    stays cheap — most files are decided on name/path alone."""
    name = os.path.basename(path).lower()
    reasons = []

    if name in signals.MARKER_FILENAMES or name.endswith(signals.MARKER_SUFFIXES):
        reasons.append(f"marker file '{name}'")
    segs = {s.lower() for s in path.split("/")[:-1]}
    hit = segs & signals.PATH_SEGMENTS
    if hit:
        reasons.append(f"path segment {sorted(hit)}")

    if is_manifest(path):
        content = (gh.text(repo, path, ref) or "").lower()
        found = sorted({t.strip("\"'") for t in signals.FRAMEWORK_TOKENS if t in content})
        if found:
            reasons.append(f"manifest deps {found[:6]}")

    return (bool(reasons), reasons)


# --------------------------------------------------------------------------- #
# Stage B — deep scan (only for agentic candidates)                           #
# --------------------------------------------------------------------------- #
def _fingerprint(text):
    """Short, stable content id -- sha256 of the input, first 12 hex chars."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _attr_chain(node):
    """Best-effort dotted name for a Name/Attribute node: the AST for `os.environ`
    -> 'os.environ', `subprocess.check_output` -> 'subprocess.check_output'.
    Formatting is already gone by the time we're looking at the tree."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _ast_caps(source):
    """Structural capability detection for Python. Because it reads the parsed
    syntax tree, spacing/formatting is irrelevant -- `tools=[`, `tools = [` and
    `tools   =   [` are identical here. Returns a set of capabilities, or None if
    the text isn't parseable Python (caller then falls back to substrings)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    caps, modules, names = set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                modules.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module.split(".")[0])
            for a in node.names:
                names.add(a.name)
        elif isinstance(node, ast.Attribute):
            if _attr_chain(node) in ("os.environ", "os.getenv"):
                caps.add("secret_access")
        elif isinstance(node, ast.Call):
            fn = _attr_chain(node.func)
            root, leaf = fn.split(".")[0], fn.split(".")[-1]
            if root == "subprocess" or fn in ("os.system", "eval", "exec"):
                caps.add("shell_exec")
            if root in ("requests", "httpx", "urllib", "aiohttp"):
                caps.add("network_egress")
            if leaf == "create_react_agent" or "AgentExecutor" in fn:
                caps.add("high_autonomy")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.lower() in ("tools", "toolset", "tool_registry"):
                    caps.add("tool_calls")  # `tools = [...]` at ANY spacing -- the gremlin dies here
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                dec = d.func if isinstance(d, ast.Call) else d
                if _attr_chain(dec).split(".")[-1] == "tool":
                    caps.add("tool_calls")

    # imports imply capability even when the call sites are elsewhere in the file
    if "subprocess" in modules:
        caps.add("shell_exec")
    if modules & {"requests", "httpx", "urllib", "aiohttp"}:
        caps.add("network_egress")
    if names & {"AgentExecutor", "create_react_agent"}:
        caps.add("high_autonomy")
    return caps


def deep_scan(text, path=""):
    """Stage B capability profile. Python is parsed structurally (format-independent);
    everything else -- and any Python that won't parse -- falls back to substrings."""
    if path.endswith(".py"):
        caps = _ast_caps(text)
        if caps is not None:
            return caps
    low = text.lower()
    return {cap for cap, needles in signals.CAPABILITY_SIGNALS.items()
            if any(n in low for n in needles)}


# --------------------------------------------------------------------------- #
# Certification                                                               #
# --------------------------------------------------------------------------- #
def load_certs():
    try:
        with open(CERT_STORE) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_certs(store):
    with open(CERT_STORE, "w") as fh:
        json.dump(store, fh, indent=2)


def certify(store, blob_sha, path, classification, verdict, reason, caps=None):
    store[blob_sha] = {
        "blob_sha": blob_sha,
        "path": path,
        "classification": classification,          # agentic | non-agentic
        "verdict": verdict,                          # certified | ...-with-warnings | blocked
        "reason": reason,
        "capabilities": sorted(caps) if caps else [],
        "policy_version": signals.POLICY_VERSION,
        "issued_by": "gov-scan-demo",
    }


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Miniature GitHub agent-governance scanner")
    ap.add_argument("repo", help="owner/name, e.g. github/github-mcp-server")
    ap.add_argument("--base", help="base SHA (delta mode)")
    ap.add_argument("--head", help="head SHA (delta mode)")
    ap.add_argument("--host", default="api.github.com", help="API host (GHEC: api.SUBDOMAIN.ghe.com)")
    ap.add_argument("--limit", type=int, default=40, help="max rows to print")
    args = ap.parse_args()

    gh = GitHub(args.host, os.environ.get("GITHUB_TOKEN"))
    store = load_certs()

    # 1) Get the file set: delta (Compare API) or first-push (tree)
    try:
        if args.base and args.head:
            mode = f"DELTA {args.base[:7]}..{args.head[:7]}"
            files = gh.changed_files(args.repo, args.base, args.head)
            ref = args.head
        else:
            meta = gh.get(f"/repos/{args.repo}")
            ref = meta["default_branch"]
            mode = f"FIRST-PUSH (full tree @ {ref})"
            files = gh.full_tree(args.repo, ref)
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code}: {e.read()[:200].decode('utf-8','replace')}")

    print(f"\nrepo={args.repo}  mode={mode}  files={len(files)}  auth={'yes' if gh.token else 'no'}")
    print(f"{'CLASS':13}{'VERDICT':24}{'FILE'}")
    print("-" * 90)

    counts = {"inherited": 0, "non-agentic": 0, "agentic": 0}
    members = []          # agentic files, collected for agent-level fingerprinting
    printed = 0
    for f in files:
        blob, path, status = f["blob_sha"], f["path"], f["status"]
        if status == "removed":
            continue

        # 2) blob-SHA cache: identical content is never rescanned
        if blob in store and store[blob].get("policy_version") == signals.POLICY_VERSION:
            counts["inherited"] += 1
            cached = store[blob]
            row = ("INHERIT", cached["verdict"], path)
            if cached.get("classification") == "agentic":
                members.append({"path": path, "blob_sha": blob,
                                "caps": cached.get("capabilities", []),
                                "verdict": cached["verdict"]})
        else:
            # 3) Stage A triage
            agentic, reasons = triage(path, gh, args.repo, ref)
            if not agentic:
                certify(store, blob, path, "non-agentic", "certified", "no agentic signals")
                counts["non-agentic"] += 1
                row = ("non-agentic", "certified", path)
            else:
                # 4) Stage B deep scan (fetch content, profile capabilities)
                text = gh.text(args.repo, path, ref)
                if text is None:
                    certify(store, blob, path, "agentic", "certified-with-warnings",
                            "deep scan deferred (fetch budget)", set())
                    caps, verdict, why = set(), "certified-with-warnings", "deferred"
                else:
                    caps = deep_scan(text, path)
                    verdict, why = signals.verdict_for(caps)
                    certify(store, blob, path, "agentic", verdict, why, caps)
                counts["agentic"] += 1
                cap_str = ",".join(sorted(caps)) or "-"
                row = ("AGENTIC", verdict, f"{path}  [{cap_str}]")
                members.append({"path": path, "blob_sha": blob,
                                "caps": sorted(caps), "verdict": verdict})

        if printed < args.limit:
            print(f"{row[0]:13}{row[1]:24}{row[2]}")
            printed += 1

    if len(files) > printed:
        print(f"... ({len(files) - printed} more rows hidden; --limit {len(files)} to see all)")

    # ---- Agent-level fingerprint: group agentic files into agents ----
    # An agent is usually several files. We group agentic files by their parent
    # directory and give the whole unit a stable identity:
    #   content_fp    -> hash of the exact (path:blob_sha) set  (changes on ANY byte)
    #   capability_fp -> hash of the union of capabilities      (stable across cosmetic edits)
    if members:
        rank = {"blocked": 3, "certified-with-warnings": 2, "certified": 1}
        by_agent = {}
        for m in members:
            by_agent.setdefault(os.path.dirname(m["path"]) or "(root)", []).append(m)
        print("\nAGENTS (fingerprinted identity)")
        print(f"{'AGENT':16}{'VERDICT':24}{'CAP_FP':14}{'CONTENT_FP':14}CAPABILITIES")
        print("-" * 90)
        for agent_id, fs in sorted(by_agent.items()):
            union = sorted({c for f in fs for c in f["caps"]})
            worst = max(fs, key=lambda f: rank.get(f["verdict"], 0))["verdict"]
            content_fp = _fingerprint("\n".join(sorted(f"{f['path']}:{f['blob_sha']}" for f in fs)))
            cap_fp = _fingerprint(",".join(union))
            print(f"{agent_id:16}{worst:24}{cap_fp:14}{content_fp:14}{','.join(union) or '-'}")
        print("-" * 90)

    save_certs(store)
    print("-" * 90)
    print(f"summary: agentic={counts['agentic']}  non-agentic={counts['non-agentic']}  "
          f"inherited={counts['inherited']}  |  content fetches={gh.fetches}  "
          f"rate-limit remaining={gh.rate_remaining}")
    print(f"certificates written to {os.path.abspath(CERT_STORE)} "
          f"(policy {signals.POLICY_VERSION})")


if __name__ == "__main__":
    main()
