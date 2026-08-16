#!/usr/bin/env python3
"""
Measure ATSGuard's false-positive rate on the synthetic clean corpus.

Every resume from corpus.clean_resumes() is benign, so ANY verdict other than
ALLOW is a false positive. Reports overall FP rate, a split by resume type
(general vs trap), the pattern that caused each FP, and sample offenders.
Writes fp_report.md.

    python evaluate_fp.py            # 600 resumes, seed 7
    python evaluate_fp.py 2000 42    # n=2000, seed=42
"""
from __future__ import annotations

import collections
import sys

import atsguard
from corpus import clean_resumes


def main(argv: list[str]) -> int:
    n = int(argv[0]) if len(argv) > 0 else 600
    seed = int(argv[1]) if len(argv) > 1 else 7
    rows = clean_resumes(n=n, seed=seed)

    verdicts = collections.Counter()
    by_label = collections.defaultdict(collections.Counter)  # label -> verdict counts
    fp_pattern = collections.Counter()
    fp_examples: list[tuple[str, str, list[str]]] = []

    for label, text in rows:
        rep = atsguard.analyze_text(text)
        verdicts[rep.verdict] += 1
        by_label[label][rep.verdict] += 1
        if rep.verdict != "ALLOW":  # corpus is 100% clean -> this is a false positive
            ids = sorted({f"{f.layer}/{f.id}" for f in rep.findings})
            for i in ids:
                fp_pattern[i] += 1
            if len(fp_examples) < 12:
                snippets = [f.snippet for f in rep.findings if f.snippet][:2]
                fp_examples.append((label, rep.verdict, snippets))

    total = len(rows)
    fp = verdicts["FLAG"] + verdicts["BLOCK"]
    rate = 100.0 * fp / total

    out: list[str] = []
    out.append("# ATSGuard false-positive report")
    out.append(f"\ncorpus: {total} synthetic CLEAN resumes (seed={seed})\n")
    out.append(f"- ALLOW (correct): {verdicts['ALLOW']}")
    out.append(f"- FLAG  (false positive): {verdicts['FLAG']}")
    out.append(f"- BLOCK (false positive): {verdicts['BLOCK']}")
    out.append(f"- **false-positive rate: {rate:.2f}%**  ({fp}/{total})")
    out.append("")
    out.append("## by resume type")
    for label in ("general", "trap"):
        c = by_label[label]
        tot = sum(c.values())
        fpl = c["FLAG"] + c["BLOCK"]
        rl = 100.0 * fpl / tot if tot else 0.0
        out.append(f"- {label:8s}: {fpl}/{tot} FP ({rl:.2f}%)  "
                   f"[ALLOW {c['ALLOW']}, FLAG {c['FLAG']}, BLOCK {c['BLOCK']}]")
    out.append("")
    out.append("## which pattern fired on clean resumes")
    if fp_pattern:
        for pat, cnt in fp_pattern.most_common():
            out.append(f"- {pat}: {cnt}")
    else:
        out.append("- (none)")
    out.append("")
    out.append("## sample false positives")
    if fp_examples:
        for label, verdict, snips in fp_examples:
            out.append(f"- [{label}] {verdict}: " + " | ".join(repr(s) for s in snips))
    else:
        out.append("- (none)")
    report = "\n".join(out)

    with open("fp_report.md", "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    print(report)
    print(f"\n(wrote fp_report.md)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
