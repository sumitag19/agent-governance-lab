# gov-scan — miniature agent-governance scanner

A dependency-free Python CLI that demonstrates the GitHub Copilot governance loop
end to end against **real** GitHub repositories, using only the REST API.

    fetch delta  ->  blob-SHA cache (inherit)  ->  Stage-A agentic triage
                 ->  Stage-B deep scan (only if agentic)  ->  mock certificate

It exists to make the moving parts tangible, not to be production. The two files map
to the two halves of the real system:

| File | Role | Who owns it |
|------|------|-------------|
| `signals.py` | The **Rules** seed: what is "agentic", what capabilities are risky, verdict logic, `POLICY_VERSION` | Governance team (your lane) |
| `scan.py`    | The **plumbing**: GitHub API calls, delta vs full-tree, the blob-SHA certificate cache, the two-tier scan | Platform |

## Run it

Requires only Python 3.8+ (no `pip install`).

```bash
# First-push mode: walk the whole default-branch tree and certify every file
python scan.py github/github-mcp-server

# Delta mode: only what changed between two commits (steady-state path)
python scan.py github/github-mcp-server --base <BASE_SHA> --head <HEAD_SHA>
```

Re-run the same command and everything shows `INHERIT` with `fetches=0` — that's the
blob-SHA certificate cache. Delete `certs.json` to start fresh.

## Point it at your GitHub Enterprise Cloud

The API surface is identical; you only change the host and add a token.

```bash
# bash
export GITHUB_TOKEN=ghp_your_token
python scan.py your-org/some-repo --host api.SUBDOMAIN.ghe.com
```

```powershell
# PowerShell
$env:GITHUB_TOKEN = "ghp_your_token"
python scan.py your-org/some-repo --host api.SUBDOMAIN.ghe.com
```

Unauthenticated calls are limited to 60/hour; a token (or GitHub App installation
token) raises that to 5,000+/hour. In production the token should be a **GitHub App
installation token**, not a PAT.

## What it deliberately does NOT do (yet)

- No real deep scan — `deep_scan()` is a substring stand-in for CodeQL / an LLM reviewer.
- No agent-level fingerprint — it certifies per file (blob SHA), not per agent.
- No webhook/queue — it's pull-only. Production adds the APIM webhook + reconciliation sweep.
- No signing — certificates are plain JSON, not cryptographically signed attestations.

See `../docs/github-governance-reference.md` for how these map to the full design.
