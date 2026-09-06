#!/usr/bin/env python3
"""
sweep.py — scan a SET of repos in one go and emit a shareable JSON report
(findings-focused), for walking a POC through the team.

It reuses the engine in scan.py unchanged. Two JSON files, two jobs:
  - certs.json         -> the engine's COMPLETE cache/ledger (every file, for dedup)
  - sweep_report.json  -> the human-facing REPORT (per-repo summary + agentic findings)

Usage:
  python sweep.py owner/repo1 owner/repo2 ...
  python sweep.py --file repos.txt          # one 'owner/name' per line (# = comment)

  # private / GHEC repos, and higher rate limits:
  #   (pwsh) $env:GITHUB_TOKEN = "ghp_xxx"
  python sweep.py your-org/repo-a --host api.SUBDOMAIN.ghe.com
"""
import argparse
import datetime
import json
import os
import sys
import urllib.error

import scan
import signals

# A sweep touches several repos, so raise scan.py's per-run content-fetch budget.
scan.MAX_CONTENT_FETCHES = 60

RANK = {"blocked": 3, "certified-with-warnings": 2, "certified": 1}
REPORT = "sweep_report.json"


def scan_one_repo(gh, store, repo):
    """Scan every file in a repo's default branch, reusing scan.py's triage /
    deep_scan / certify / cache. Returns a per-repo report dict (summary +
    agentic findings only)."""
    ref = gh.get(f"/repos/{repo}")["default_branch"]
    files_scanned = 0
    findings = []          # agentic files only -> the actionable rows
    worst_rank = 0
    worst = "certified"

    for f in gh.full_tree(repo, ref):
        blob, path = f["blob_sha"], f["path"]
        files_scanned += 1

        # same cache rule as scan.py: content AND policy must match to inherit
        if blob in store and store[blob].get("policy_version") == signals.POLICY_VERSION:
            c = store[blob]
            cls, verdict, caps = c["classification"], c["verdict"], c.get("capabilities", [])
        else:
            agentic, _ = scan.triage(path, gh, repo, ref)          # Stage A
            if not agentic:
                cls, verdict, caps = "non-agentic", "certified", []
                scan.certify(store, blob, path, cls, verdict, "no agentic signals")
            else:
                text = gh.text(repo, path, ref)                    # Stage B
                caps = sorted(scan.deep_scan(text or "", path))
                verdict, why = signals.verdict_for(set(caps))
                cls = "agentic"
                scan.certify(store, blob, path, cls, verdict, why, set(caps))

        if RANK.get(verdict, 0) > worst_rank:
            worst_rank, worst = RANK.get(verdict, 0), verdict
        if cls == "agentic":
            findings.append({"file": path, "verdict": verdict,
                             "capabilities": caps, "blob_sha": blob})

    return {
        "repo": repo,
        "files_scanned": files_scanned,
        "agentic": len(findings),
        "non_agentic": files_scanned - len(findings),
        "worst_verdict": worst,
        "findings": sorted(findings, key=lambda r: -RANK.get(r["verdict"], 0)),
    }


def main():
    ap = argparse.ArgumentParser(description="Sweep several repos -> a shareable JSON report")
    ap.add_argument("repos", nargs="*", help="owner/name repos to scan")
    ap.add_argument("--file", help="text file with one owner/name per line")
    ap.add_argument("--host", default="api.github.com")
    args = ap.parse_args()

    repos = list(args.repos)
    if args.file:
        with open(args.file) as fh:
            repos += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not repos:
        sys.exit("give at least one owner/repo (or --file repos.txt)")

    gh = scan.GitHub(args.host, os.environ.get("GITHUB_TOKEN"))
    store = scan.load_certs()

    print(f"{'REPO':42}{'FILES':>6}{'AGENTIC':>9}   WORST VERDICT")
    print("-" * 78)
    repo_reports = []
    for repo in repos:
        try:
            r = scan_one_repo(gh, store, repo)
        except urllib.error.HTTPError as e:
            print(f"{repo:42}{'ERR':>6}   HTTP {e.code}")
            repo_reports.append({"repo": repo, "files_scanned": 0, "agentic": 0,
                                 "non_agentic": 0, "worst_verdict": f"ERROR {e.code}",
                                 "findings": []})
            continue
        repo_reports.append(r)
        print(f"{repo:42}{r['files_scanned']:>6}{r['agentic']:>9}   {r['worst_verdict']}")
    print("-" * 78)

    scan.save_certs(store)   # keep the complete cache/ledger

    report = {
        "policy_version": signals.POLICY_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "repos_scanned": len(repo_reports),
        "total_agentic": sum(r["agentic"] for r in repo_reports),
        "repos": repo_reports,
    }
    with open(REPORT, "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\nsaved report -> {REPORT}  ({report['total_agentic']} agentic findings across "
          f"{report['repos_scanned']} repos)")
    print(f"cache -> certs.json | policy {signals.POLICY_VERSION} | content fetches this run: {gh.fetches}")


if __name__ == "__main__":
    main()
