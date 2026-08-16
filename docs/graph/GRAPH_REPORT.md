# Graph Report - ATSGuard  (2026-08-16)

## Corpus Check
- Corpus is ~10,667 words - fits in a single context window. You may not need a graph.

## Summary
- 119 nodes · 196 edges · 14 communities
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 15 edges (avg confidence: 0.6)
- Token cost: 100,288 input · 0 output

## Community Hubs (Navigation)
- Gate, Verdicts & Compliance
- FP Corpus & Gate Runtime
- Sanitize/Detect Concepts & Metrics
- Attack Corpus & Recall Eval
- Media Rendering
- File Extraction (L1)
- Hidden-Text Attack Vectors
- Core Scanners & Findings
- Analysis Orchestrator
- De-obfuscation Normalization
- Flowchart Rendering
- Malicious File Generator
- Obfuscation Detection Helpers
- Self-Test Helpers

## God Nodes (most connected - your core abstractions)
1. `analyze_spans()` - 14 edges
2. `Span` - 11 edges
3. `analyze_text()` - 8 edges
4. `process_intake()` - 7 edges
5. `extract_any()` - 6 edges
6. `clean_resumes()` - 6 edges
7. `L1 Ingestion` - 6 edges
8. `L2 Sanitize` - 6 edges
9. `normalize_evasion()` - 5 edges
10. `scan_unicode()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `attack_cases()` --uses--> `Span`  [INFERRED]
  attack_corpus.py → atsguard.py
- `_verdict()` --calls--> `analyze_spans()`  [EXTRACTED]
  evaluate_recall.py → atsguard.py
- `process_intake()` --calls--> `analyze_spans()`  [EXTRACTED]
  pre_screen_gate.py → atsguard.py
- `main()` --calls--> `analyze_text()`  [EXTRACTED]
  evaluate_fp.py → atsguard.py
- `_verdict()` --calls--> `analyze_text()`  [EXTRACTED]
  evaluate_recall.py → atsguard.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **4-Layer Defense-in-Depth Pipeline** — readme_l1_ingestion, readme_l2_sanitize, readme_l3_detect, readme_l4_llm_harden [EXTRACTED 1.00]
- **Pre-Screen Gate Verdict Routing** — readme_pre_screen_gate, readme_outbox, readme_review_queue, readme_quarantine, readme_audit_jsonl [EXTRACTED 1.00]

## Communities (14 total, 0 thin omitted)

### Community 0 - "Gate, Verdicts & Compliance"
Cohesion: 0.14
Nodes (17): ALLOW Verdict, ATSGuard, audit.jsonl Audit Trail, BLOCK Verdict, build_safe_prompt(), Defense in Depth (4 Layers), EU AI Act, FLAG Verdict (+9 more)

### Community 1 - "FP Corpus & Gate Runtime"
Cohesion: 0.21
Nodes (13): build_safe_prompt(), Return chat messages that pass the resume as delimited untrusted data. Use the…, clean_resumes(), _resume(), main(), build_demo_intake(), main(), _now() (+5 more)

### Community 2 - "Sanitize/Detect Concepts & Metrics"
Cohesion: 0.18
Nodes (14): False-Positive Rate (0%), Attack Corpus, Bidi Control Smuggling, Char-Spacing Evasion, Clean Corpus, Deictic-Object Anchoring, Homoglyph / Confusables (incl. Fullwidth), L2 Sanitize (+6 more)

### Community 3 - "Attack Corpus & Recall Eval"
Cohesion: 0.21
Nodes (4): attack_cases(), t_leet(), main(), _verdict()

### Community 4 - "Media Rendering"
Cohesion: 0.42
Nodes (8): Image, body_from_output(), color_for(), cover(), main(), render(), run(), wrap()

### Community 5 - "File Extraction (L1)"
Cohesion: 0.38
Nodes (6): extract_any(), extract_docx(), extract_pdf(), _luminance_distance_from_white(), A run of text with its rendered style, from L1 extraction., Span

### Community 6 - "Hidden-Text Attack Vectors"
Cohesion: 0.33
Nodes (7): DOCX w:vanish Hidden Run, Hidden White Text, L1 Ingestion, Metadata Payloads, Off-Page Text, Tiny-Font Text, Zero-Width Smuggling

### Community 7 - "Core Scanners & Findings"
Cohesion: 0.53
Nodes (5): Finding, _is_tag_char(), Find and strip smuggling/reordering unicode. Returns (findings, clean)., scan_injection(), scan_unicode()

### Community 8 - "Analysis Orchestrator"
Cohesion: 0.47
Nodes (5): analyze_spans(), analyze_text(), main(), Plain-text entry point (no style info: L1 hidden-render checks skipped)., Report

### Community 9 - "De-obfuscation Normalization"
Cohesion: 0.33
Nodes (6): collapse_spaced(), normalize_evasion(), Undo character-spacing evasion: 'i g n o r e a l l' -> 'ignore all'. Works per…, Detection skeleton that also undoes char-spacing and leetspeak, on top of NFKC…, De-obfuscate to an ASCII skeleton used ONLY for detection matching. NFKC (folds…, skeletonize()

### Community 10 - "Flowchart Rendering"
Cohesion: 0.80
Nodes (5): arrow(), box(), F(), main(), pill()

### Community 11 - "Malicious File Generator"
Cohesion: 0.67
Nodes (5): _fullwidth(), main(), make_docx(), make_pdf(), make_txt()

### Community 12 - "Obfuscation Detection Helpers"
Cohesion: 0.67
Nodes (3): count_obfuscation(), _is_obfuscation_char(), True for a cross-script homoglyph or a compatibility char that folds to a plain…

### Community 13 - "Self-Test Helpers"
Cohesion: 0.67
Nodes (3): _fw(), Encode ASCII printable as fullwidth (U+FF01..FF5E) to simulate a compatibility-…, _selftest()

## Knowledge Gaps
- **5 isolated node(s):** `Indirect Prompt Injection (OWASP LLM01)`, `Review Queue Route`, `Quarantine Route`, `Clean Corpus`, `Attack Corpus`
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Defense in Depth (4 Layers)` connect `Gate, Verdicts & Compliance` to `Sanitize/Detect Concepts & Metrics`, `Hidden-Text Attack Vectors`?**
  _High betweenness centrality (0.065) - this node is a cross-community bridge._
- **Why does `L3 Detect` connect `Sanitize/Detect Concepts & Metrics` to `Gate, Verdicts & Compliance`?**
  _High betweenness centrality (0.027) - this node is a cross-community bridge._
- **What connects `Indirect Prompt Injection (OWASP LLM01)`, `Review Queue Route`, `Quarantine Route` to the rest of the system?**
  _5 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Gate, Verdicts & Compliance` be split into smaller, more focused modules?**
  _Cohesion score 0.13970588235294118 - nodes in this community are weakly interconnected._