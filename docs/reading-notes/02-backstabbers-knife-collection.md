# Reading Notes 2 — Backstabber's Knife Collection (Ohm et al., 2020)

**Source:** `Project References/Ohm et al 2020 - Backstabber's Knife Collection.pdf` · arXiv:2005.09535
**Citation (IEEE draft):** [2] M. Ohm, H. Plate, S. A. Mehmood, A. Decan, E. Liu, and F. Massacci, "Backstabber's knife collection: A review of open source software supply chain attacks," in Proc. DIMVA, 2020.

## One-line summary
The first manually curated dataset of real-world malicious packages (npm/PyPI/RubyGems, 2015–2019) plus two attack trees abstracting how supply-chain attacks inject and trigger malicious code.

## Main Findings
- Dataset: 174 malicious packages used in real-world attacks — 62.6% npm, 16.1% PyPI, 21.3% RubyGems — spanning Nov 2015 to Nov 2019. First manually curated collection of its kind.
- **56% of packages trigger their malicious behavior ON INSTALLATION** — direct validation of install-time as a detection window.
- **41% use further conditions** to decide whether to run (e.g., checking for Jenkins environment variables = only fires on build servers; checking system state).
- **61% leveraged typosquatting** to get injected into the ecosystem; other vectors include dependency/account hijacking (compromised maintainer credentials, social engineering into maintainer roles).
- Primary objectives: **data exfiltration is the most common goal**; other categories include backdoors, combined exfiltration+backdoor, and denial of service.
- Exfiltration targets are a consistent short list: `/etc/passwd`, `~/.ssh/*`, `~/.npmrc`, `~/.bash_history`, environment variables (access tokens), general system info. Discord webhook tokens are a popular channel (7 reported cases, 3 in dataset; Discord accounts can link to payment info).
- Famous real case cited: npm `flatmap-stream` (crypto wallet balance targeting).
- Two attack trees: (1) injection — how malicious code enters the dependency tree; (2) execution — when/under what conditions it runs.

## Methodology
- Packages manually collected from deprecated mirrors, internet archives, and public research repositories — because registries DELETE malicious packages on discovery, so the normal registry can't serve them.
- Manual code analysis of every package to confirm maliciousness and map behaviors to attack-tree nodes.
- Attack trees built from BOTH the dataset and systematic review of potential ecosystem weaknesses — dataset grounds them, review generalizes them.

## Relevance to My Replication
<!-- NOTE-TO-SELF: these bullets become HW2 prose — REWRITE IN MY OWN WORDS at drafting time. -->

- The 56% install-trigger stat is CatchGate's founding justification: a majority of historical attacks execute in exactly the window my sandbox monitors.
- The exfiltration-target list IS my canary design: plant fake `/etc/passwd`, `~/.ssh/*`, `~/.npmrc`, `~/.bash_history`, and token-bearing env vars; flag Discord/webhook endpoints in network rules.
- The 41% conditional-execution finding drives sandbox REALISM: malware that checks its environment won't fire in an empty container. My sandbox must look like a real dev machine (populated env vars, canary files present) or the behavior I'm hunting never triggers.
- Injection vs. execution trees: CatchGate defends the execution side (install-time behavior) regardless of injection vector — typosquatting and hijacking both land in `npm install`.
- Lineage: this dataset (BKC) is one of the eleven academic sources consolidated into the 2026 benchmark's 6,420-package corpus — my replication sample descends from this collection.
- Sampling: `data/packages.json` in the cloned repo is the package index — filter to npm entries, cross-reference against the benchmark's labels, stratify by objective (exfiltration-weighted).

## Limitations / Openings
- Dataset ends Nov 2019 and is small (174) — stale and sparse on its own; compensate by drawing the modern sample from the 2026 benchmark (which adds 2020–2024 advisory data) rather than from BKC alone.
- Cross-ecosystem (PyPI/RubyGems) packages irrelevant to my npm-only scope — filter them.
- Manual analysis is thorough but unscalable — which is the gap automated behavioral detectors (like CatchGate) exist to fill.

## Key numbers to steal
- 174 packages · 62.6% npm / 16.1% PyPI / 21.3% RubyGems · Nov 2015–Nov 2019
- 56% trigger on installation · 41% conditional execution · 61% typosquatting
- Data exfiltration = most common objective; Discord tokens: 7 reported / 3 in dataset
