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

> Reproducibility note: raw traces live in `traces/` (gitignored by design — they're data, not source). The commands above regenerate them exactly.
