# Reading Notes 4 — SafeDep Case Study: Dynamic Analysis vs. an npm Attack

**Source:** `Project References/SafeDep - Case Study Dynamic Analysis npm Attack.html` · safedep.io/blog
**Citation (IEEE draft):** [4] K. Singh, "Catching the silent threat: How dynamic analysis revealed a complex npm attack chain," SafeDep Blog, May 2025. [Online]. Available: https://safedep.io/digging-into-dynamic-malware-analysis-signals

## One-line summary
How SafeDep's dynamic system caught a multi-stage remote-code-execution attack (eslint-config-airbnb-compat) that its own static analysis was blind to — starting from a single rare IP address in install-time network logs.

## Main Findings
- Scale of the analysis: ~28 million events from 380,000+ packages. Two heuristic families over the event stream: (1) **network-connection outliers** — rare IPs in the connection distribution, reverse-DNS + VirusTotal lookups; OAST domains (oast.online/.site/.live) are known-exfil infrastructure; (2) **abnormal binary execution** — frequency distribution of binaries run at install (esbuild/workerd/rustc/cmake = normal; one-offs like bsc.exe, test_program = suspicious).
- The attack: `eslint-config-airbnb-compat` impersonates legit eslint-config-airbnb (starjacking). Its postinstall `setup.js` looks BENIGN — copies `.env.example` to `.env` (containing `APP_PROXY=https://proxy.eslint-proxy.site`) and runs `npm install` if node_modules missing.
- The payload hides in a TRANSITIVE dependency, `ts-runtime-compat-check`, whose postinstall fetches `${proxy}/api/v1/hb89/data` — the response's "error" field carries a base64-encoded JS payload that gets decoded and executed via `new Function.constructor('require', code)`. Server-controlled remote code execution, stage-2 hidden one hop deep.
- Detection chain: rare IP 45.11.59.250 → rDNS → mail.sms-system-alert.com → VirusTotal malicious → backtrack to package → dependency-graph analysis → manual confirmation. Static analysis never flagged it; the initial signal was purely behavioral/network.

## Methodology
- Statistical outlier detection over aggregated dynamic events (no signatures): distributions of IPs and executed binaries, then human triage of the tails.
- Correlation workflow: event → package → dependency graph → manual code confirmation.

## Relevance to My Replication
<!-- NOTE-TO-SELF: these bullets become HW2 prose — REWRITE IN MY OWN WORDS at drafting time. -->

- The single concrete "dynamic caught what static missed" instance my hypothesis needs — with a named package, a full attack chain, and a documented detection path. Center this story in HW2's literature review and in the presentation.
- Which of my rules catch it: (a) network rule fires on egress to non-registry host (proxy.eslint-proxy.site); (b) the `.env.example` → `.env` copy extends my canary set — plant a canary `.env` too; (c) `new Function`/eval of decoded remote content is code-execution-from-network — a chain rule candidate (network fetch → dynamic eval).
- It validates the sandbox-realism point from BKC notes: the benign-looking stage-1 only sets up environment; the payload fires deeper. A detector must observe the WHOLE install including transitive dependencies' postinstalls — my sandbox runs full `npm install` of the package with its dependency tree, which covers this.
- Candidate sample: this package/pair belongs in my 150-malicious evaluation set.
- Their outlier method (rare-IP distributions) needs fleet-scale data; my deterministic rules are the single-user equivalent — same signal class, threshold-free design.

## Limitations / Openings
- One case study, found with human-in-the-loop triage — not an automated verdict. My contribution: turn this class of signal into deterministic chain rules with measured detection/FP rates on a labeled corpus.
- OAST/rDNS/VirusTotal enrichment needs external services; my deny-and-log design flags the ATTEMPT without needing reputation feeds.

## Key numbers to steal
- ~28M events · 380,000+ packages analyzed
- Attack chain: eslint-config-airbnb-compat → ts-runtime-compat-check → proxy.eslint-proxy.site (45.11.59.250 / mail.sms-system-alert.com)
- Payload mechanism: base64 error field → `new Function.constructor('require', code)` → RCE
