# Reading Notes 1 — npm Malicious-Package Detection Benchmark (2026)

**Source:** `Project References/arXiv 2026 - npm malicious-package detection benchmark.pdf` · arXiv:2603.27549
**Citation (IEEE draft):** [1] W. Guo, Z. Chen, Z. Xu, C. Liu, and M. Kang, "How effective are NPM malicious package detectors? A large-scale empirical study," in Proc. ASE, 2026. arXiv:2603.27549.

## One-line summary
First large-scale empirical benchmark of NPM malicious-package detectors — 11 tools, 16 variants, unified corpus — that explains WHY tools fail, not just how often.

## Main Findings
- Four detector paradigms compared: Static-based, Dynamic-based, ML-based, LLM-based. IntelGuard (LLM-based, retrieval-grounded) achieved the best F1 overall at 95.98%; GuardDog (static, Semgrep rules) was best among conventional tools at 93.32%.
- Throughput matters in practice: GuardDog processes 1,412 packages/hour while SocketAI (LLM) processes only 24 due to multiple LLM queries per package.
- SocketAI runs the SAME model as IntelGuard but trails it by ~49 recall points — because IntelGuard first retrieves known malware for comparison. Evidence grounding, not raw model power, drives accuracy.
- Dynamic code execution, web injection, and credential theft showed the widest cross-tool variation and lowest mean detection. Reason: these behaviors do not form behavioral chains, so no coupling effect amplifies them. Web injection (browser-side DOM) mismatches all tools that analyze server-side Node.js — IntelGuard drops 98.5% → 62.5% there.
- Credential theft is structurally invisible to feature-based tools: the APIs involved are identical to those used by legitimate authentication libraries, producing no discriminative signal.
- Evasion: 80.3% of the 6,420 malicious packages employ NO evasion at all (ecosystem lacks mandatory pre-publication scanning). Among the 19.7% that do, string and encoding obfuscation dominate — they defeat feature-level tools by altering the surface form features are computed from. Anti-analysis techniques are hardest to detect (mean 52.7%).
- Every tool must resolve the capability-intent ambiguity: malicious and benign packages invoke the SAME OS APIs (https.request, child_process.exec) — capability is what an API makes possible, intent is the purpose served.
- Behavioral coupling amplifies detection: SAP_DT rose 3.2% → 79.3% on the collect-and-exfiltrate chain when behaviors co-occur. Chains are the strongest signal.
- ML tools degrade over time: SAP_DT fell 87.15% → 39.49% (2021→2023), traced to concept CONVERGENCE (malware became minimal-footprint, statistically indistinguishable from benign), not concept drift.
- ML precision-recall tradeoffs: SAP_DT/SAP_RF = near-perfect precision but miss ~1/3 of malicious; SAP_XGB/MalPacDetector/ProfMal more balanced (F1 83.32–88.66%).

## Methodology
- Corpus: 6,420 malicious (from 11 academic datasets — including BKC/Backstabber's Knife Collection, DONAPI, DataDog, MalOSS, Maltracker — plus OSV/Snyk security advisories, spanning 2020–2024) + 7,288 benign.
- Benign selection: official npm registry, ranked by monthly download count, latest version each. Three stated reasons: popular packages give a CONSERVATIVE false-positive estimate, are least likely to carry undiscovered malware, and reflect what developers actually deploy. All 7,288 verified clean against OSV and Snyk.
- Annotation: every package labeled with 1 of 11 behavior categories and 8 evasion techniques.
- Evaluation: unified benchmark, same corpus/settings for all 11 tools and 16 variants; metrics include precision, recall, F1.
- Distinctive move: authors inspected each tool's SOURCE CODE to explain structural failure mechanisms, not just report scores.
- Four RQs: RQ1 detection effectiveness, RQ2 fine-grained behavioral analysis, RQ3 temporal evolution, RQ4 tool complementarity.

## Relevance to My Replication
<!-- NOTE-TO-SELF: these bullets become HW2 prose — REWRITE IN MY OWN WORDS at drafting time. The analysis direction is agreed; the sentences must be mine. -->

- Testable claim I'm reproducing: install-time behavioral detection of behavior CHAINS (collect → exfiltrate) in a sandbox catches credential-theft-class malicious packages that static/feature tools structurally miss — the paper's coupling finding (3.2% → 79.3%) plus its capability-intent analysis of credential theft.
- The paper's own findings justify CatchGate's design: credential theft = no discriminative features (APIs identical to legit auth libs) → static can't see it; chains amplify signals → my rules must detect ORDERED behavior pairs, not single events.
- Sample: draw ~150 malicious from their released benchmark (stratified across the 11 behavior categories, weighted toward exfiltration/credential-theft classes) + ~300 benign selected by their popularity logic (conservative FP test, matches deployment reality).
- Baseline: GuardDog — best conventional tool (93.32% F1), open source, runnable locally as my static baseline on the same sample. Direct comparison to paper's own numbers.
- FP control story: the one dynamic/trace tool they evaluated (Packj_trace) produced 4,656 false positives — my deterministic chain rules are the proposed fix (precision through requiring ordered co-occurrence, not single suspicious events).

## Limitations / Openings (→ my extension)
- They EVALUATE 11 detectors; they build none. No evaluated tool is a free, self-hosted, install-time behavioral gate deployable in CI.
- The dynamic tool that was evaluated (Packj_trace) drowns in false positives — no one demonstrates a usable dynamic detector at practical FP rates.
- LLM-based winners (IntelGuard) need retrieval infrastructure + model queries at 24 pkgs/hr — unusable for a student team's CI gate.
- → CatchGate: deterministic, chain-based, containerized, free, runs in CI. The gap their benchmark quantifies but doesn't fill.

## Key numbers to steal (for HW2 + presentation)
- 11 tools / 16 variants / 6,420 malicious + 7,288 benign / 11 behavior categories / 8 evasion techniques
- IntelGuard F1 95.98% · GuardDog 93.32% (best conventional)
- GuardDog 1,412 pkgs/hr vs SocketAI 24 pkgs/hr
- Coupling: SAP_DT 3.2% → 79.3% (collect-and-exfiltrate chain)
- 80.3% of malware uses no evasion; anti-analysis hardest (mean 52.7%)
- IntelGuard web-injection drop: 98.5% → 62.5%
- SAP_DT temporal decay: 87.15% → 39.49% (2021–2023)
- Packj_trace FP count: 4,656
