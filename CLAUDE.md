# CLAUDE.md — Agent Governance POC (handoff context)

You are Claude, picking up an in-progress proof-of-concept. This file is your
onboarding. Read it first, then read `src/docs/agent-governance-design.md` for the
full design. The working code is under `src/`.

## 1. What this project is

A system to **govern AI-agent code committed to repositories** in **GitHub
Enterprise Cloud (GHEC)**: detect when a change introduces or modifies agent code,
assess the agent's capabilities and risk, **certify** each piece of content against a
versioned policy, and **gate** merges when an agent is unsafe.

Keep two problems separate:
- **(A) Agents that run *on* the platform** (cloud coding agents, code-review agents) — governed by the platform's **native enterprise AI controls + agent audit log**. *Not this project.*
- **(B) Agent *code committed* to repos** (framework code, MCP servers, tool/skill/prompt defs) — **this project.**

## 2. Current state (what exists)

A dependency-free reference scanner that mirrors the full loop end-to-end:

| File | Role |
|---|---|
| `src/scan.py` | Engine: fetch delta/tree → blob-SHA cache → Stage-A triage → Stage-B deep scan (AST) → certify → agent fingerprints |
| `src/signals.py` | **The Rules**: agentic signals, capability signals, `verdict_for()`, `POLICY_VERSION` |
| `src/sweep.py` | Multi-repo sweep → findings-focused `sweep_report.json` |
| `src/explain_fp.py` | Shows how the agent fingerprints are computed |
| `src/README.md` | How to run |
| `src/docs/agent-governance-design.md` (+ `.docx`) | Full design, assumptions, flow, appendices |

Runtime outputs (`certs.json`, `sweep_report.json`) are gitignored — they regenerate.

## 3. How to run (verify it works)

Python 3.8+, no third-party packages.

```bash
# scan a repo (unauthenticated works on public repos; 60 req/hr)
python src/scan.py <owner>/<repo>

# delta mode (steady state): only what changed between two commits
python src/scan.py <owner>/<repo> --base <SHA> --head <SHA>

# multi-repo sweep -> sweep_report.json
python src/sweep.py <owner>/<repo-a> <owner>/<repo-b>

# against GHEC: set a token and point --host at the GHEC API host
#   $env:GITHUB_TOKEN = "..."   (use a GitHub App installation token in production)
python src/scan.py <org>/<repo> --host api.<SUBDOMAIN>.ghe.com
```

## 4. Core concepts & invariants — do NOT break these

1. **Certify by git blob SHA (content hash).** The cert store is keyed by blob SHA. This is what gives free caching, delta-only scanning, and global cross-repo dedup. Never key certificates by path.
2. **Policy-version guard.** A certificate is valid only when `blob in store AND store[blob].policy_version == signals.POLICY_VERSION`. Bump `POLICY_VERSION` in `signals.py` whenever the rules change → stale certs re-scan once, then settle. This is "controlled re-certification."
3. **Two-tier scanning.** Stage A (cheap: name/path/manifest) decides agentic vs non-agentic; Stage B (AST for Python) runs **only** on agentic candidates. Most files must cost **zero** content fetches — keep it that way.
4. **`signals.py` is the Rules layer** (the governance team's lane). A risk-policy change goes there **plus a `POLICY_VERSION` bump**; the engine (`scan.py`) should not need edits for a policy change.
5. **Two agent fingerprints, both kept.** `CONTENT_FP` = hash of the sorted `path:blob_sha` set (changes on any byte). `CAP_FP` = hash of the capability union (stable across cosmetic edits). They answer "did it change at all?" vs "did its powers change?".
6. **No hardcoded secrets.** The API token comes only from the `GITHUB_TOKEN` env var.

## 5. What's stubbed (the real next work)

- `deep_scan` is heuristic (AST + a substring fallback) — a production system would use CodeQL / taint analysis / an LLM reviewer.
- **No enforcement yet:** the verdict is not published as a GitHub **Check**, and no ruleset requires it.
- No webhook/queue infrastructure; scanning is pull-based.
- Certificates are plain JSON (not signed attestations).
- The agent-boundary for fingerprints is a folder heuristic.

## 6. Roadmap (suggested order)

1. **Publish a real Check** (`POST /repos/{o}/{r}/check-runs`) so a repository ruleset can require it and gate the merge. (GHEC has no pre-receive hooks, so ruleset + Check *is* the gate.)
2. **Agent dedup store** keyed by `CONTENT_FP` ("no duplicate certification").
3. **Smarter Stage B** — more capabilities (e.g. `filesystem_write`, which the AST does not yet detect), more languages.
4. **Webhook → queue → engine** ingestion + a reconciliation sweep (webhook delivery is best-effort, so completeness needs a poll/audit-stream backstop).
5. Externalize the **Rules** to a policy engine (OPA/Rego or a YAML DSL) with per-rule re-certification instead of a global version bump.
6. **Sign** certificates as tamper-evident attestations.

## 7. Organization-specific context to confirm with the user

None of this is in this (public) repo — ask the user:
- The **GHEC API host** (`api.<subdomain>.ghe.com`) and how the governance app authenticates (a **GitHub App** — with which permissions and installation?).
- Which **orgs/repos** are in scope.
- **Enforcement**: is a repository ruleset requiring the Check acceptable? Is the build pipeline separate (so governance must not depend on it)?
- **Eventing & networking**: inbound webhook to a hardened gateway vs. outbound polling vs. audit-log streaming to the enterprise cloud, given egress constraints.
- **The concrete "harmful agent" policy** — the specific capabilities and combinations that must **block** vs **warn**. This is the real product; encode it in `signals.py` and version it.

## 8. How to work with this user

- They **learn by doing**: give **one concrete step at a time**, let them run it, explain the result, then proceed. Do **not** build-and-run several steps ahead of them.
- Explain the **why**, not just the what; tie changes back to the design.
- They own **Rules + Certification** — keep those legible and reviewable.

## 9. Flow (control points) — summary

Developer change → (optional local self-check) → **push webhook** → hardened gateway
→ **durable queue** → **compliance engine** (resolve delta → blob-SHA cache → Stage-A
triage → Stage-B deep scan → certify) → **publish Check** → **ruleset** ALLOW/BLOCK →
**final-state monitor** (bypass/drift detection). Certificates & attestations are
persisted; an audit stream carries agent-runtime and bypass events. Full detail and a
diagram: `src/docs/agent-governance-design.md`.
