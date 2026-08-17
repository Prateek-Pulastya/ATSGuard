# Changelog

## 0.2.0 — held-out evaluation and broader coverage

The 98.8% recall was in-sample: `attack_corpus.py` disguises 8 command-style
sentences 8 ways, so it tests normalisation, not whether the patterns cover the
space of ways someone could phrase a manipulation. A held-out set written in
different shapes caught that blind spot.

- **Added** `evaluate_external.py` — scores the detector against any outside
  attack corpus (a JSON list of `{id, text}`), so recall can be measured on
  attacks the author never wrote.
- **Added** two held-out corpora: `quick_check_not_blind.json` (10 cases,
  authored by a different reviewer) and `held_out_corpus.json` (28 cases, fresh
  wordings and novel framings).
- **Added** pattern families for non-imperative injection: text addressed to the
  AI, fake decision-metadata (`auto_advance: true`), third-person
  pre-clearance, authority attribution, no-further-review arguments, favorable-
  scoring and reward framing, suppress-re-evaluation, rhetorical questions, and a
  basic non-English directive. Held-out recall on the 28-case set rose from
  10.7% to 42.9%; false positives stayed at 0.00% across six seeds; in-sample
  recall held at 98.8%.
- **Added** an optional `judge` argument to `analyze_text()` / `analyze_spans()`
  — a semantic second pass (plug in an LLM) for the argument-style attacks regex
  can't reach. Off by default.
- **Changed** the README to report two numbers (in-sample and held-out) with the
  gap explained, plus the disclosures for the partial confusables table, the
  plain-text layer-1 scope, and the non-Latin-script bias tension.

## 0.1.0 — initial release

- Four-layer detector: ingest-with-style, sanitise, detect, harden handoff.
- Pre-screen gate with allow/flag/block routing and an audit log.
- Synthetic clean corpus (0% false positives) and disguised-attack corpus.
- Sample malicious file generators, media, and a graphify knowledge graph.
