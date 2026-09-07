# Lab Notebook — CatchGate

One entry per experiment session. This log is the reproducibility record for the project (and 30% of the capstone rubric). Format per entry:

```
## YYYY-MM-DD — <short title>
- Goal: what this session tried to establish
- Environment: host, VM/container image, tool versions
- What I ran: commands (exact)
- What happened: observed output / surprises
- Conclusion: what this means / next step
```

---

## 2026-09-06 — Project established

- **Goal:** define topic, scope, and evaluation plan; assemble research corpus.
- **Environment:** n/a (planning session)
- **What happened:** topic approved by course instructor (Option 2, replication + extension). Scope narrowed to npm-only, ~150 malicious + ~300 benign stratified sample, container sandbox with strace-level logging, fixed 5–10 deterministic rules, minimal GitHub Actions demo. Concept paper (HW1) submitted.
- **Corpus:** 2026 arXiv npm malicious-package benchmark (arXiv:2603.27549); Ohm et al. 2020, Backstabber's Knife Collection (+ dataset repo); SafeDep dynamic-analysis methodology and case study; Socket 2025 mid-year threat report; Shai-Hulud worm analyses. Local copies in `Project References/`.
- **Next:** deep-read the benchmark paper (tables, dataset provenance, dynamic setup, limitations); set up Zotero; first container run.
