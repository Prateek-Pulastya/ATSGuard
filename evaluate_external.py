#!/usr/bin/env python3
"""
Score ATSGuard against an EXTERNAL malicious-resume corpus - one not authored
by whoever wrote the detection patterns in atsguard.py.

Unlike evaluate_recall.py (which grades against the built-in attack_corpus.py,
written by the same person who wrote the regexes), this script takes a corpus
from anywhere: a different person, a different LLM with no visibility into
atsguard.py's source, a red-team exercise, real intercepted attempts, etc.
Every case in the file is assumed malicious; ALLOW is a miss.

Input format: a JSON file, a list of objects:
  [{"id": "case-1", "text": "...", "source": "optional note", "notes": "optional"}, ...]

Usage:
    python evaluate_external.py blind_corpus.json
    python evaluate_external.py blind_corpus.json --out blind_report.md
"""
from __future__ import annotations

import argparse
import json
import sys

import atsguard


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score ATSGuard against an external corpus")
    ap.add_argument("corpus", help="JSON file: list of {id, text} objects, all malicious")
    ap.add_argument("--out", default="blind_recall_report.md", help="report output path")
    args = ap.parse_args(argv)

    with open(args.corpus, "r", encoding="utf-8") as fh:
        cases = json.load(fh)

    total = len(cases)
    caught = 0
    blocked = 0
    misses: list[dict] = []
    rows: list[str] = []

    for c in cases:
        rep = atsguard.analyze_text(c["text"])
        hit = rep.verdict in ("FLAG", "BLOCK")
        if hit:
            caught += 1
            if rep.verdict == "BLOCK":
                blocked += 1
        else:
            misses.append(c)
        rows.append(
            f"- [{'CAUGHT' if hit else 'MISSED'}] `{c.get('id','?')}` -> {rep.verdict} "
            f"(score {rep.risk_score}, {len(rep.findings)} findings)"
        )

    recall = 100.0 * caught / total if total else 0.0
    out = [
        "# ATSGuard external (held-out) recall report",
        "",
        f"corpus: {total} externally-authored malicious cases (`{args.corpus}`)",
        "",
        f"- caught (FLAG or BLOCK): {caught}/{total}  -> **recall {recall:.1f}%**",
        f"- blocked (BLOCK): {blocked}/{total}",
        f"- MISSED (ALLOW = false negative): {len(misses)}/{total}",
        "",
        "## per-case",
        *rows,
        "",
        "## missed cases (full text - read these, they're the actual finding)",
    ]
    if misses:
        for m in misses:
            out.append(f"\n### {m.get('id','?')}")
            if m.get("source"):
                out.append(f"*source: {m['source']}*")
            out.append(f"```\n{m['text']}\n```")
    else:
        out.append("- (none)")

    report = "\n".join(out)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    print(report)
    print(f"\n(wrote {args.out})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
