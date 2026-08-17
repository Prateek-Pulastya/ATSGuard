# Graph Report - ATSGuard  (2026-08-17)

## Corpus Check
- Corpus is ~15,320 words - fits in a single context window. You may not need a graph.

## Summary
- 128 nodes · 207 edges · 15 communities (11 shown, 4 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 19 edges (avg confidence: 0.64)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Held-out Attacks & Semantic Judge
- Pipeline, Gate & Compliance
- FP Corpus & Gate Runtime
- Attack Corpus & Recall Eval
- Core Scanners & Findings
- Media Rendering
- Analysis Orchestrator
- File Extraction (L1)
- De-obfuscation Normalization
- Flowchart Rendering
- Malicious File Generator
- Self-Test Helpers
- External Held-out Harness
- False-Positive Metric
- Recall Metric

## God Nodes (most connected - your core abstractions)
1. `analyze_spans()` - 15 edges
2. `Non-imperative injection classes` - 13 edges
3. `Span` - 11 edges
4. `analyze_text()` - 10 edges
5. `process_intake()` - 7 edges
6. `L3 Detect` - 7 edges
7. `extract_any()` - 6 edges
8. `clean_resumes()` - 6 edges
9. `pre_screen_gate.py (enforcement point)` - 6 edges
10. `normalize_evasion()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `attack_corpus.py (in-sample attack corpus)` --semantically_similar_to--> `held_out_corpus.json (28-case corpus)`  [INFERRED] [semantically similar]
  docs/TECHNICAL.md → CHANGELOG.md
- `attack_cases()` --uses--> `Span`  [INFERRED]
  attack_corpus.py → atsguard.py
- `main()` --calls--> `analyze_text()`  [EXTRACTED]
  evaluate_external.py → atsguard.py
- `L3 Detect` --references--> `Non-imperative injection classes`  [INFERRED]
  docs/TECHNICAL.md → CHANGELOG.md
- `False positives 0.00%` --conceptually_related_to--> `L3 Detect`  [INFERRED]
  README.md → docs/TECHNICAL.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Four-layer defense-in-depth pipeline (L1-L4)** — docs_technical_l1_ingestion, docs_technical_l2_sanitize, docs_technical_l3_detect, docs_technical_l4_llm_harden [EXTRACTED 1.00]
- **Pre-screen gate routing (ALLOW/FLAG/BLOCK)** — docs_technical_outbox, docs_technical_review_queue, docs_technical_quarantine [EXTRACTED 1.00]
- **In-sample vs held-out recall gap** — readme_in_sample_recall, readme_held_out_recall, readme_in_sample_held_out_gap [EXTRACTED 1.00]

## Communities (15 total, 4 thin omitted)

### Community 0 - "Held-out Attacks & Semantic Judge"
Cohesion: 0.11
Nodes (22): Authority attribution, evaluate_external.py (external held-out harness), Fake decision-metadata (auto_advance: true), Favorable-scoring appeal, held_out_corpus.json (28-case corpus), No-further-review arguments, Non-English directive, Non-imperative injection classes (+14 more)

### Community 1 - "Pipeline, Gate & Compliance"
Cohesion: 0.13
Nodes (20): audit.jsonl (audit log), Four-layer defense-in-depth pipeline, L1 Ingestion (extract text with style), L2 Sanitize, L3 Detect, L4 LLM Harden (build_safe_prompt), outbox/ (ALLOW route), pre_screen_gate.py (enforcement point) (+12 more)

### Community 2 - "FP Corpus & Gate Runtime"
Cohesion: 0.21
Nodes (13): build_safe_prompt(), Return chat messages that pass the resume as delimited untrusted data. Use the…, clean_resumes(), _resume(), main(), build_demo_intake(), main(), _now() (+5 more)

### Community 3 - "Attack Corpus & Recall Eval"
Cohesion: 0.21
Nodes (4): attack_cases(), t_leet(), main(), _verdict()

### Community 4 - "Core Scanners & Findings"
Cohesion: 0.33
Nodes (8): count_obfuscation(), Finding, _is_obfuscation_char(), _is_tag_char(), True for a cross-script homoglyph or a compatibility char that folds to a plain…, Find and strip smuggling/reordering unicode. Returns (findings, clean)., scan_injection(), scan_unicode()

### Community 5 - "Media Rendering"
Cohesion: 0.42
Nodes (8): Image, body_from_output(), color_for(), cover(), main(), render(), run(), wrap()

### Community 6 - "Analysis Orchestrator"
Cohesion: 0.39
Nodes (7): analyze_spans(), analyze_text(), main(), Plain-text entry point (no style info: L1 hidden-render checks skipped)., Report, _selftest(), SemanticJudge

### Community 7 - "File Extraction (L1)"
Cohesion: 0.38
Nodes (6): extract_any(), extract_docx(), extract_pdf(), _luminance_distance_from_white(), A run of text with its rendered style, from L1 extraction., Span

### Community 8 - "De-obfuscation Normalization"
Cohesion: 0.33
Nodes (6): collapse_spaced(), normalize_evasion(), Undo character-spacing evasion: 'i g n o r e a l l' -> 'ignore all'. Works per…, Detection skeleton that also undoes char-spacing and leetspeak, on top of NFKC…, De-obfuscate to an ASCII skeleton used ONLY for detection matching. NFKC (folds…, skeletonize()

### Community 9 - "Flowchart Rendering"
Cohesion: 0.80
Nodes (5): arrow(), box(), F(), main(), pill()

### Community 10 - "Malicious File Generator"
Cohesion: 0.67
Nodes (5): _fullwidth(), main(), make_docx(), make_pdf(), make_txt()

## Knowledge Gaps
- **19 isolated node(s):** `False-Positive Rate (0%)`, `Detection Recall (98.8%)`, `Indirect Prompt Injection (OWASP LLM01)`, `Quick-check recall 100% (10-case)`, `Reader-addressed text (aimed at the AI)` (+14 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Non-imperative injection classes` connect `Held-out Attacks & Semantic Judge` to `Pipeline, Gate & Compliance`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Why does `L3 Detect` connect `Pipeline, Gate & Compliance` to `Held-out Attacks & Semantic Judge`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `Non-imperative injection classes` (e.g. with `L3.5 Semantic Judge (optional judge argument)` and `L3 Detect`) actually correct?**
  _`Non-imperative injection classes` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `False-Positive Rate (0%)`, `Detection Recall (98.8%)`, `Indirect Prompt Injection (OWASP LLM01)` to the rest of the system?**
  _19 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Held-out Attacks & Semantic Judge` be split into smaller, more focused modules?**
  _Cohesion score 0.10822510822510822 - nodes in this community are weakly interconnected._
- **Should `Pipeline, Gate & Compliance` be split into smaller, more focused modules?**
  _Cohesion score 0.13157894736842105 - nodes in this community are weakly interconnected._