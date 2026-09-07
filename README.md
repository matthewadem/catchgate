# CatchGate

**An open, self-hosted, install-time behavioral gate for detecting malicious npm dependencies in CI/CD pipelines.**

CatchGate runs each dependency installation inside an instrumented sandbox, observes what the package actually *does* — filesystem changes, network connections, process activity — and blocks packages whose behavior violates policy rules. Instead of judging what a package looks like, it judges what it does.

## Why

Open-source supply chain attacks are accelerating: malware in npm packages more than doubled in 2025, and worms like Shai-Hulud spread by hiding credential-stealing code inside package install scripts, which run automatically on install. Existing behavioral defenses (Socket, Phylum, SafeDep) are commercial and enterprise-priced; free alternatives are pattern-based and miss behavioral attacks. CatchGate aims to be the free, self-hosted option.

## How it works

```
npm install <pkg> ──▶  sandboxed container (strace-level file/net/process logging)
                                │
                                ▼
                       behavior event log ──▶ deterministic policy rules
                                │                       (credential exfiltration,
                                ▼                        out-of-scope writes, ...)
                       ALLOW / BLOCK / ASK verdict
```

## Status

Research in progress — a replication-with-extension capstone (CYBR 498, University of Arizona), reproducing the dynamic behavioral detection approach of the [2026 npm malicious-package benchmark](https://arxiv.org/abs/2603.27549) and SafeDep's published dynamic-analysis methodology, evaluated on labeled corpora (Backstabber's Knife Collection and others).

### Roadmap

- [ ] Stage 1 — run `npm install` inside a container
- [ ] Stage 2 — capture file/network/process behavior (strace)
- [ ] Stage 3 — plant canary credentials in the sandbox image
- [ ] Stage 4 — parse traces into structured behavior events
- [ ] Stage 5 — deterministic rule engine (5–10 rules)
- [ ] Stage 6 — run the labeled sample (~150 malicious / ~300 benign)
- [ ] Stage 7 — detection & false-positive rates vs. static baseline
- [ ] Stage 8 — baseline comparison tooling
- [ ] Stage 9 — GitHub Action demo (CI-gate form factor)

## Evaluation

Stratified sample of the benchmark corpora: ~150 malicious + ~300 benign npm packages. Reported metrics: detection rate and false-positive rate against a static, metadata-only baseline on the same sample.

## Safety

All malicious samples are detonated only in isolated local sandboxes with the network blocked and logged. No live attacker infrastructure is contacted. Canary credentials are always fake.

## License

[MIT](LICENSE)
