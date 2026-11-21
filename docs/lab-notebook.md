# Lab Notebook — CatchGate

One entry per experiment session, appended in chronological order. Entry dates must match the git commits they belong to. Format per entry:

    ## YYYY-MM-DD — short title
    - Goal / Environment / What I ran / What happened / Conclusion / Next

---

## 2026-09-06 — Project established

- **Goal:** define topic, scope, and evaluation plan; assemble research corpus.
- **Environment:** n/a (planning session)
- **What happened:** topic approved by course instructor (Option 2, replication + extension). Scope narrowed to npm-only, ~150 malicious + ~300 benign stratified sample, container sandbox with strace-level logging, fixed 5–10 deterministic rules, minimal GitHub Actions demo. Concept paper (HW1) submitted.
- **Corpus:** 2026 arXiv npm malicious-package benchmark (arXiv:2603.27549); Ohm et al. 2020, Backstabber's Knife Collection (+ dataset repo); SafeDep dynamic-analysis methodology and case study; Socket 2025 mid-year threat report; Shai-Hulud worm analyses. Local copies in `Project References/`.
- **Next:** deep-read the benchmark paper; first container run.

## 2026-11-16 — Sandbox install test, and a misdiagnosis worth recording

- **Goal:** install a package inside the sandbox container with the network off.
- **Environment:** Docker Desktop on macOS; `catchgate-sandbox` image (node:20-slim, strace installed, non-root devuser).
- **What I ran:** `./scripts/run_install.sh left-pad` (wraps `docker run --rm --network none catchgate-sandbox npm install left-pad`).
- **What happened:** the install failed, and my first conclusion was wrong: I read the failure as proof the sandbox was cut off from the network. The actual error was `ENOENT: no package.json` — npm 10 refuses to install a named package into a directory without one. Fix: added `RUN npm init -y` to the Dockerfile. On the re-run the failure changed to `EAI_AGAIN` on `getaddrinfo registry.npmjs.org` — DNS failing because the container has no network. That second error is the genuine isolation proof.
- **Conclusion:** sandbox network isolation confirmed (on the second attempt). Lesson recorded: verify the failure *mode*, not just the fact of failure — two very different causes produced "a failed install." Also noted: with `--network none`, registry installs can never succeed by design, so installs must come from local tarballs (see next entry).
- **Commit:** `9692e0f` (Stage 1: containerized sandbox, install runner)

## 2026-11-16 — Canary planting, strace capture, and the finding of the week

- **Goal:** capture a full syscall trace of a real install with canary credentials planted first, and read the trace by hand.
- **Environment:** same image; `plant_canaries.sh` mounted into the container (fake `.npmrc`, `.ssh`, `.aws`, `.env`); tarball fetched host-side via `docker run node:20-slim npm pack left-pad --pack-destination /corpus/benign`, then installed offline from `/corpus/benign/left-pad-1.3.0.tgz` under `strace -f -o /traces/left-pad.trace`. Session ran the evening of Nov 16 local (host is UTC-8; container/npm log timestamps print UTC, so the ~05:00 UTC log lines below are ~9-10 PM on the 16th local).
- **What I ran:** offline tarball install under strace (canaries planted before npm starts), then hand-greps on the trace.
- **What happened:**
  - The tarball install **completed** with the network off — the host-fetch / sandbox-install split works.
  - **The finding:** `grep '.npmrc'` on a *benign* trace is **not** empty. npm itself opens `~/.npmrc` (plus `project/.npmrc`, the builtin npmrc, and `/usr/local/etc/npmrc` — its config search order) on every install. My canary `.npmrc` was opened by npm itself (fd 18), not by the package. This contradicted my own expectation of an empty grep — the read was NOT from anything malicious.
  - Benign offline baseline for this run: **3 `execve`** (npm → PATH probe miss on `/usr/local/sbin/node` → `/usr/local/bin/node`), **0 `connect(` calls**.
- **Conclusion:** a single-event rule ("any canary read") would false-positive on essentially 100% of installs, because npm reads the canary itself. This is the capability-vs-intent ambiguity from the benchmark paper, observed in my own sandbox. It confirms the ordered-chain design: the discriminator is a canary read **followed by** a connection attempt — and because the pipeline is offline, benign installs should essentially never `connect()` at all, while exfiltration attempts remain visible as failed `connect()` calls.
- **Next (Session 03):** the parser must emit file-opens with paths plus connect attempts with targets, preserving order; the rule engine consumes the ordered event stream. Also: fold the host-fetch + strace + tarball flow into `run_install.sh` itself so one command does the whole pipeline.

## 2026-11-17 — Event parser: strace → JSONL, plus the one-command runner

- **Goal:** turn a raw strace trace into an ordered JSON event stream the rule engine can read, and make the whole pipeline (canaries → trace → offline install) a single command.
- **Environment:** same sandbox image; runner now `scripts/run_install.sh <tarball>` (derives the trace name from the tarball, mounts traces + tarball + canary script, one container run); parser at `src/parse_trace.py` (Python 3, stdlib only).
- **What I ran:** acceptance tests against my hand-grep baseline from 11-16. Parser output on `traces/left-pad-1.3.0.trace`: **3 exec events** (npm, one PATH-probe miss, node), **4 opens of npmrc paths** (seq 119–122, reproducing npm's config search order exactly as I grepped it by hand), **0 connect events** — all three numbers match the manual baseline. Also a synthetic test: a crafted 3-line trace containing the spec's example `connect` line, because the benign trace has zero connects and a broken connect parser would also print zero. The synthetic run produced the correct event (`192.0.2.1:443`, `ENETUNREACH`).
- **Result:** 1.7 MB of raw trace reduces to **888 ordered events**. That reduction is the parser's whole job.
- **Implementation note:** parser written with AI assistance after my solo attempt stalled. I designed the acceptance baseline (the hand-greps came first, before any code) and verified every number against it manually.
- **Lesson #2 in "verify what the check checks":** my 11-16 oracle used `grep '.npmrc'`, where the dot is a regex *wildcard* — it matched `npm/npmrc` and `etc/npmrc` too. Re-running the same count with an escaped dot (`\.npmrc`) undercounted 4 → 2 and briefly looked like a parser bug. The parser was correct; the test had changed meaning between runs. When your test is itself a regex, escaping changes what you're testing.
- **Next (Session 04):** rule engine — the ordered chain rule (canary read → connect attempt) over this event stream, verdict JSON per package.

## 2026-11-19 — Rule engine, first verdicts, and the pipeline gate

- **Goal:** deterministic rules over the event stream; batch-scan benign packages; reach the working end-to-end pipeline (the Nov 19 gate from the compressed plan).
- **What was built:** `src/rules.py` — R1 ordered chain (successful canary read followed by an internet connect attempt), R2 any internet connect attempt in the offline sandbox (failed connects are the signal), R3 unknown-binary execution vs a build-tool allowlist. Verdicts aggregate duplicate firings (one rule with a count, not N entries). `scripts/scan_benign.sh` runs fetch → sandbox install → verdict per package. A 90-second per-package timeout was added to `run_install.sh` after a hang (below).
- **Runs:** six benign packages end-to-end. First pass: four ALLOW, then `is-even` hung the batch for ~10 minutes and returned BLOCK with 13 repeated R1+R2 pairs. Diagnosis from the trace: **all** its internet connects were DNS machinery — 12× connect to `192.168.65.7:53` (Docker Desktop's internal resolver) as glibc/npm retried fetching the package's dependency (`is-odd`) — plus 2 probes of the local nscd socket. No exfiltration-shaped behavior anywhere. `esbuild` (93 DNS attempts) told the same story.
- **Three fixes, each with a rationale:** (1) per-package 90s timeout — npm's DNS-retry backoff can run ~10 minutes, fatal for a 300-package November run; (2) exempt port-53 connects to private resolver addresses — sound *because* the sandbox is offline: nothing can leave the machine, so DNS-tunnel exfiltration is physically impossible, while exfil-shaped connects to external addresses still fire; (3) skip `unix:` targets entirely — AF_UNIX is local IPC and cannot leave the machine; they were firing R2 only because the target format `unix:/path` happens to contain a colon.
- **Final state:** all six benign packages ALLOW (including the dependency-carrying is-even and the 93-attempt esbuild); the simulated attack trace still BLOCKs with R1 evidence citing both events. **Pipeline gate passed on schedule.**
- **Findings for HW4:** (a) dependency resolution is the dominant offline false-positive class, and its signature is a burst of resolver connects — the design answers are pre-staging dependencies host-side or the resolver exemption (both documented); (b) verdict aggregation is necessary for readable reports; (c) implicit format assumptions in rules (": in target means internet") are bugs waiting to happen — event formats need explicit address families. Implementation work on the parser, rules, and scripts was AI-assisted; the acceptance baselines, diagnoses, and fix rationales came from reading my own traces.
- **Next:** sample acquisition from the DataDog malicious-packages dataset + the GuardDog baseline harness.

> Reproducibility note: raw traces live in `traces/` (gitignored by design — they're data, not source). The commands above regenerate them exactly.
