#!/usr/bin/env python3
"""
Measure ATSGuard detection recall / false-negative rate on the attack corpus.

Every case is malicious. A verdict of ALLOW = a MISS (false negative).
  - caught  = verdict in {FLAG, BLOCK}   (recall)
  - blocked = verdict == BLOCK           (hard stop)
Reports overall recall, recall by evasion technique and by payload family, and
lists every MISS. Writes recall_report.md.

    python evaluate_recall.py
"""
from __future__ import annotations

import collections

import atsguard
from attack_corpus import attack_cases


def _verdict(case) -> str:
    if case["mode"] == "text":
        return atsguard.analyze_text(case["text"]).verdict
    return atsguard.analyze_spans(case["spans"]).verdict


def main() -> int:
    cases = attack_cases()
    n = len(cases)
    caught = blocked = 0
    by_tech = collections.defaultdict(lambda: [0, 0])   # tech -> [caught, total]
    by_fam = collections.defaultdict(lambda: [0, 0])
    misses: list[str] = []

    for c in cases:
        v = _verdict(c)
        tech = c["tech"].split(":")[0]
        by_tech[tech][1] += 1
        by_fam[c["family"]][1] += 1
        if v != "ALLOW":
            caught += 1
            by_tech[tech][0] += 1
            by_fam[c["family"]][0] += 1
        if v == "BLOCK":
            blocked += 1
        if v == "ALLOW":
            misses.append(c["id"])

    out = ["# ATSGuard recall / false-negative report", "",
           f"attack corpus: {n} malicious cases", "",
           f"- caught (FLAG or BLOCK): {caught}/{n}  -> **recall {100*caught/n:.1f}%**",
           f"- blocked (BLOCK):        {blocked}/{n}  ({100*blocked/n:.1f}%)",
           f"- MISSED (ALLOW = false negative): {n-caught}/{n}  "
           f"(**FN rate {100*(n-caught)/n:.1f}%**)", "",
           "## recall by evasion technique"]
    for tech in sorted(by_tech, key=lambda t: by_tech[t][0] / by_tech[t][1]):
        cg, tot = by_tech[tech]
        out.append(f"- {tech:14s}: {cg}/{tot} caught ({100*cg/tot:.0f}%)")
    out.append("")
    out.append("## recall by payload family")
    for fam in sorted(by_fam, key=lambda f: by_fam[f][0] / by_fam[f][1]):
        cg, tot = by_fam[fam]
        out.append(f"- {fam:12s}: {cg}/{tot} caught ({100*cg/tot:.0f}%)")
    out.append("")
    out.append("## misses (false negatives)")
    out += [f"- {m}" for m in misses] or ["- (none)"]
    report = "\n".join(out)

    with open("recall_report.md", "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    print(report)
    print("\n(wrote recall_report.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
