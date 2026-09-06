"""
explain_fp.py — shows, step by step, how the AGENT-level fingerprints
(CONTENT_FP and CAP_FP) are built out of the per-file certificates in certs.json.

It's a teaching aid: it prints the exact strings that get hashed, then hashes
them — so the numbers you see here should match what `scan.py` printed.

Run:  python explain_fp.py
"""
import json
import hashlib
import os


def sha12(text):
    """The same helper scan.py uses: sha256, first 12 hex chars."""
    return hashlib.sha256(text.encode()).hexdigest()[:12]


certs = json.load(open("certs.json"))

# 1) An agent is made only of AGENTIC files. Non-agentic files (like README)
#    are certified but belong to no agent, so we drop them here.
agentic = [c for c in certs.values() if c.get("classification") == "agentic"]

# 2) GROUP the agentic files into agents by their parent directory.
agents = {}
for c in agentic:
    agent_id = os.path.dirname(c["path"]) or "(root)"
    agents.setdefault(agent_id, []).append(c)

# 3) ROLL each group up into the two fingerprints, printing the inputs.
for agent_id, files in sorted(agents.items()):
    print(f"\n=== AGENT: {agent_id!r}  ({len(files)} file(s)) ===")

    # --- CONTENT_FP: identity of the exact bytes of every file, together ---
    content_lines = sorted(f"{f['path']}:{f['blob_sha']}" for f in files)
    print("CONTENT_FP  <- sha256 of these sorted 'path:blob_sha' lines:")
    for line in content_lines:
        print("     ", line)
    content_fp = sha12("\n".join(content_lines))
    print("   => CONTENT_FP =", content_fp)

    # --- CAP_FP: identity of what the agent can DO, pooled across files ---
    print("CAP_FP      <- sha256 of the UNION of capabilities:")
    for f in files:
        print("     ", f["path"], "->", sorted(f.get("capabilities", [])))
    union = sorted({cap for f in files for cap in f.get("capabilities", [])})
    print("      UNION =", union)
    cap_fp = sha12(",".join(union))
    print("   => CAP_FP =", cap_fp)
