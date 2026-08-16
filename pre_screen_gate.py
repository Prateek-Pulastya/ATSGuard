#!/usr/bin/env python3
"""
ATSGuard pre-screen gate - a mock ATS ingestion pipeline.

This is the ENFORCEMENT POINT. Every incoming resume passes through the gate
BEFORE any LLM screening, and is routed by verdict:

    ALLOW  -> sanitized text + safe prompt written to outbox/  (forward to model)
    FLAG   -> routed to review_queue/  (human looks first; model does NOT auto-run)
    BLOCK  -> quarantined; hidden/injected text stripped and recorded; NEVER sent

Guarantees enforced here:
  1. The model only ever receives the SANITIZED text (visible-only, unicode-
     scrubbed), wrapped as delimited untrusted data by build_safe_prompt().
  2. BLOCK content never reaches the model.
  3. Every decision is written to an append-only audit.jsonl - the trail an
     NYC Local Law 144 bias audit or EU AI Act oversight review needs.

Usage:
    python pre_screen_gate.py --demo                 # build demo intake + run
    python pre_screen_gate.py path/to/intake_dir     # run on your own files
    python pre_screen_gate.py intake --out gate_out  # choose output root
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

import atsguard

VALID_EXT = (".pdf", ".docx", ".txt")
ACTION = {"ALLOW": "forward_to_model", "FLAG": "human_review", "BLOCK": "quarantine"}
SUBDIR = {"ALLOW": "outbox", "FLAG": "review_queue", "BLOCK": "quarantine"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def process_intake(intake_dir: str, out_root: str = "gate_out") -> dict:
    for name in SUBDIR.values():
        os.makedirs(os.path.join(out_root, name), exist_ok=True)
    audit_path = os.path.join(out_root, "audit.jsonl")

    files = sorted(
        os.path.join(intake_dir, f) for f in os.listdir(intake_dir)
        if f.lower().endswith(VALID_EXT)
    )
    summary = {"ALLOW": 0, "FLAG": 0, "BLOCK": 0, "ERROR": 0}
    rows: list[dict] = []

    with open(audit_path, "w", encoding="utf-8") as audit:
        for path in files:
            base = os.path.basename(path)
            try:
                spans = atsguard.extract_any(path)
                report = atsguard.analyze_spans(spans)
            except Exception as e:  # extraction failure = fail closed to review
                rec = {"ts": _now(), "file": base, "verdict": "FLAG",
                       "action": "human_review", "error": f"{type(e).__name__}: {e}"}
                audit.write(json.dumps(rec) + "\n")
                summary["ERROR"] += 1
                rows.append({"file": base, "verdict": "ERROR", "risk": "-",
                             "action": "human_review (extract failed)"})
                continue

            verdict = report.verdict
            action = ACTION[verdict]
            families = sorted({f"{f.layer}/{f.id}" for f in report.findings})

            dest_dir = os.path.join(out_root, SUBDIR[verdict])
            # keep the full filename (incl. extension) so x.pdf and x.docx do
            # not collide on the same artifact name
            stem = base

            if verdict == "ALLOW":
                # only the sanitized text goes forward, wrapped as untrusted data
                messages = atsguard.build_safe_prompt(report.sanitized_text)
                with open(os.path.join(dest_dir, stem + ".prompt.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump({"model_ready": True, "messages": messages}, fh, indent=2)
            elif verdict == "FLAG":
                with open(os.path.join(dest_dir, stem + ".review.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump({"reason": families,
                               "sanitized_text": report.sanitized_text,
                               "findings": [f.__dict__ for f in report.findings]},
                              fh, indent=2)
            else:  # BLOCK - quarantine, never forwarded
                with open(os.path.join(dest_dir, stem + ".quarantine.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump({"blocked": True,
                               "risk_score": report.risk_score,
                               "findings": [f.__dict__ for f in report.findings],
                               "hidden_text_removed": report.hidden_text_removed},
                              fh, indent=2)

            rec = {"ts": _now(), "file": base, "sha256": _sha(path),
                   "verdict": verdict, "risk_score": report.risk_score,
                   "n_findings": len(report.findings), "families": families,
                   "action": action}
            audit.write(json.dumps(rec) + "\n")
            summary[verdict] += 1
            rows.append({"file": base, "verdict": verdict,
                         "risk": report.risk_score, "action": action})

    return {"summary": summary, "rows": rows, "audit": audit_path,
            "out_root": out_root, "n": len(files)}


def build_demo_intake(intake_dir: str = "intake") -> str:
    """Populate an intake dir: the malicious+clean sample files, plus a handful
    of clean corpus resumes written as .txt."""
    os.makedirs(intake_dir, exist_ok=True)
    here = os.path.dirname(os.path.abspath(__file__))
    samples = os.path.join(here, "samples")
    if os.path.isdir(samples):
        for f in os.listdir(samples):
            if f.lower().endswith(VALID_EXT):
                shutil.copy(os.path.join(samples, f), os.path.join(intake_dir, f))
    try:
        from corpus import clean_resumes
        for i, (label, text) in enumerate(clean_resumes(8, seed=5)):
            with open(os.path.join(intake_dir, f"clean_{label}_{i:02d}.txt"), "w",
                      encoding="utf-8") as fh:
                fh.write(text)
    except Exception:
        pass
    return intake_dir


def _print(result: dict) -> None:
    s = result["summary"]
    print(f"Processed {result['n']} file(s) from intake\n" + "-" * 62)
    print(f"{'FILE':32s} {'VERDICT':8s} {'RISK':>4s}  ACTION")
    for r in result["rows"]:
        print(f"{r['file'][:32]:32s} {r['verdict']:8s} {str(r['risk']):>4s}  {r['action']}")
    print("-" * 62)
    print(f"ALLOW forward_to_model : {s['ALLOW']}")
    print(f"FLAG  human_review     : {s['FLAG']}")
    print(f"BLOCK quarantine       : {s['BLOCK']}")
    if s["ERROR"]:
        print(f"ERROR human_review     : {s['ERROR']}")
    print(f"\naudit log : {result['audit']}")
    print(f"outputs   : {result['out_root']}/(outbox|review_queue|quarantine)")
    print("guarantee : only ALLOW files produced a model prompt; "
          "BLOCK files were quarantined, never forwarded.")


def main() -> int:
    ap = argparse.ArgumentParser(description="ATSGuard pre-screen gate")
    ap.add_argument("intake", nargs="?", help="directory of resume files")
    ap.add_argument("--out", default="gate_out", help="output root (default gate_out)")
    ap.add_argument("--demo", action="store_true", help="build demo intake and run")
    args = ap.parse_args()

    if args.demo:
        intake = build_demo_intake()
    elif args.intake:
        intake = args.intake
    else:
        ap.print_help()
        return 2

    result = process_intake(intake, args.out)
    _print(result)
    # non-zero exit if anything was blocked (useful for CI / alerting)
    return 3 if result["summary"]["BLOCK"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
