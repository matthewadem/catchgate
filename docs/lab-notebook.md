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

## 2026-11-20 — Sample acquisition and first real detections

- **Goal:** acquire ~100 malicious npm samples from the DataDog malicious-software-packages-dataset (Apache-2.0) and run the first real batch.
- **Acquisition:** seeded random sample (seed 20261120) of 100 packages from `samples/npm/malicious_intent/` via the GitHub tree API (frame: 10,098 packages visible; listing truncates — documented). Layout discovery: archives contain *unpacked* package directories, not tarballs — first extraction pass found .tgz in only 1/100. Fix: extract each `package/` dir host-side and re-pack with `npm pack` (offline, executes nothing). Result: **99/100 tarballs staged** (1 pack failure, recorded), metadata in `corpus/meta/`. All samples gitignored; extraction and packing only — nothing executed outside the sandbox at any point.
- **Harness:** `scripts/run_batch.sh` + `src/scan_one.py` (full pipeline over a corpus dir → verdict CSV). Two path-handling bugs fixed after first runs (repo-root prefixing broke absolute paths).
- **First 10 malicious packages: 2 BLOCK / 10**, both verified true positives:
  - `auth0-mcp-server`: two connect attempts to `54.173.15.59:8080` (raw IP, ENETUNREACH) after canary read → R1 chain + R2. Textbook exfil catch.
  - `azure-postgresql-auth`: executed `/usr/bin/whoami` and `/usr/bin/hostname` → R3. Environment recon — exactly the behavior class BKC documented.
- **Miss taxonomy (diagnosed from traces):** (1) *hostname exfiltration is invisible offline* — a payload reaching a webhook by hostname dies at DNS, which we exempted to kill the dependency-fetch FP class (`apple-internal-security-library-v99`: 7 DNS connects, nothing else visible); (2) *payload attempted but sandbox env incomplete* (`beanstalk-api`: postinstall ran, tried `.bin/sh` paths that don't exist, never progressed); (3) *no install-time trigger at all* — payload lives at require-time, outside our declared scope.
- **Honest denominator:** 67 of the 100 sampled packages have install hooks. Detection rates should be reported against the install-triggering subset (mirrors BKC's 56%-trigger-at-install finding), not all packages.
- **Design response (for the full run):** pre-stage dependencies host-side with `npm install --ignore-scripts` (downloads only, executes nothing), so the offline install needs zero DNS — after which *any* DNS attempt in the sandbox is signal again and the hostname-exfil class becomes detectable. This kills the is-even FP class and revives the signal with one change. Deferred to the runner upgrade; tonight's full run uses current rules.
- Implementation AI-assisted; sample selection is seeded and reproducible, and every diagnosis above came from reading the traces.

> Reproducibility note: raw traces live in `traces/` (gitignored by design — they're data, not source). The commands above regenerate them exactly.

### Overnight results (full run, same day)

- **99/99 scanned, zero harness errors.** Verdicts: **19 BLOCK / 80 ALLOW** — 19.2% raw, **28.4% against the 67 packages that have install hooks** (the honest denominator).
- **Catch composition, all verified from traces:**
  - *3 network catches (R1+R2):* `auth0-mcp-server` (raw IP :8080), `ecto-engine` (**23 connect attempts** — a determined exfiltrator; the star case study), `oxrvlllcaj`.
  - *16 recon catches (R3):* every one executed `whoami`/`hostname` (two also `date`, one `cat`) — environment fingerprinting, the exact class BKC documented in 41% of attacks. Recon is the dominant observable behavior in this sample.
- **Allowlist held perfectly:** zero build-tool false positives across 99 malicious + 6 benign runs. Every BLOCK cites verified behavior.
- Known misses remain the three diagnosed classes (hostname-exfil offline-invisible, sandbox-incomplete payloads, require-time payloads). Next: GuardDog paired baseline on the same 99, then dependency pre-staging upgrade and re-run to measure the delta.

### Paired comparison vs GuardDog (Session 07, 2026-11-21)

- **Method:** GuardDog (default rules) over the same 99 staging dirs; paired join by package.json-derived names (npm pack mangles scoped names — `@scope/pkg` → `scope-pkg` — so tarball-prefix joins silently mis-match; two preliminary joins disagreed (13 vs 16 exclusive catches) and were discarded. The authoritative join derives each tarball name from its own package.json `name`+`version`: 99/99 resolved).
- **Final numbers (n=99):** CatchGate **19 (19.2%)** · GuardDog **40 (40.4%)** · **both 3** · **CatchGate-only 16** · GuardDog-only 37 · **union 56 (56.6%)**.
- **The finding: extreme complementarity.** Only 3 of CatchGate's 19 catches overlap with GuardDog — 84% of behavioral catches were invisible to static rules. Combined coverage is ~3x CatchGate alone. This replicates, in our own data, the benchmark's "combination effectiveness equals complementarity" conclusion.
- **Vignette 1 (same attacker, two lenses):** `auth0-mcp-server` — GuardDog statically flagged the `http://54.173.15.59:8080` dependency URL in package.json; CatchGate independently saw live connection attempts to that same IP at install.
- **Vignette 2 (same behavior class, disjoint catches):** GuardDog's top rule was `threat.runtime.system.info` (17 hits, static whoami/hostname patterns), yet 16 packages *executed* recon at install without static signatures — CatchGate caught them in the act.
- **Honest caveats for the paper:** (1) GuardDog ran on local directories without registry metadata, so its rules that rely on registry context were handicapped — its real-world rate is higher; (2) most samples were originally found *by* GuardDog, so the dataset favors its signatures; (3) CatchGate's 19 includes only install-window behavior by design. The claim is not "behavioral beats static" — it is "the two lenses are near-orthogonal, and a free gate can have the behavioral one."

### Benign false-positive test, Config A (2026-11-21)

- 41 popular npm packages (fixed top-downloaded list incl. webpack, typescript, eslint, vite, express) through the full pipeline.
- **41/41 ALLOW — 0 false positives (FP rate 0.0%).** The build-tool allowlist and DNS exemption held at scale, including dependency-heavy packages.
- Config-B (pre-staged + strict-DNS) benign re-run pending; that cell completes the 2x2 matrix.

### S08 result: the ablation (Config B, 2026-11-21)

- **Pre-staging + strict DNS nearly doubled detection: 19/99 (19.2%) -> 37/99 (37.4%).**
- All 19 new catches fire the R1 chain (canary read -> DNS-resolution attempt): the hostname-exfiltration class, invisible in Config A, recovered by design. Six also fired R3.
- **One Config-A catch lost:** `auth0-mcp-server` — its exfil channel IS a dependency URL (`http://54.173.15.59:8080/...` in package.json); in Config B the offline install aborts on that non-cacheable http dependency before its payload runs, so no behavior occurs. The gate doesn't flag it, but it also refuses the channel — a trade to document, not hide.
- **Config B vs GuardDog: 37 vs 40, overlap only 18.** CatchGate-B catches 19 packages the static scanner misses; union 59/99 (59.6%). Near-orthogonality holds at higher coverage.
- Unit verification of the mechanism: `is-even` (dependencies) installs completely offline in Config B — 885 file ops, zero connects, strict ALLOW. The DNS signal is now unambiguous.
- Benign Config-B re-run queued; completes the 2x2 matrix.

### The 2x2 matrix is complete (2026-11-21, final experimental result)

| | Malicious (n=99) | Benign (n=41) |
|---|---|---|
| Config A (offline, DNS exempt) | 19/99 = 19.2% | 0 FP (41/41 ALLOW) |
| **Config B (prestaged, strict DNS)** | **37/99 = 37.4%** | **0 FP (41/41 ALLOW)** |
| GuardDog (static baseline) | 40/99 = 40.4%* | - |

*handicapped: local-dir scan without registry metadata, on a dataset largely discovered by GuardDog itself.

- **Headline: 37.4% detection with zero observed false positives** — the strict configuration that recovered the hostname-exfiltration class introduced no FPs, including on dependency-heavy build tooling (webpack, typescript, vite, eslint) prestaged and installed fully offline.
- **Against the honest denominator** (67 of 99 samples have install hooks): Config B detects 37/67 = **55.2% of install-triggering malicious packages**.
- Precision on this sample: 37/(37+0) = 100% observed (small benign n — stated as "no observed false positives," not a bounded rate).
- Experimental phase complete. Remaining: HW4 write-up (results above), Pres 4, final paper, release.

### Benign scale-up to 359 + FP tuning arc (2026-11-21, evening)

- Benign corpus scaled 41 -> **359 packages** (npm registry search API, popularity-weighted, unscoped; documented query set; 2 fetch failures recorded).
- **First run at scale: 2 false positives (0.56%)** — `node-liblzma`, `ssh2-sftp-client`, both R3. Diagnosis from traces: zero unknown binaries *successfully executed*; the firings were **ENOENT path-probes of `python`/`python3`/`cc`** — node-gyp's standard toolchain discovery, attempting tools absent from the sandbox image. The exact FP class SafeDep documents from production [4].
- Fix (per [4]): allowlist expanded with the standard native-module toolchain (python, python3, cc, gcc, c++, g++, make, node-gyp, cmake, ninja). Verdicts regenerated from stored traces — no re-detonation needed; rules are pure functions of the event stream.
- **Result: 359/359 ALLOW — 0.00% FP at scale** — with every malicious catch preserved (recon catches still BLOCK: whoami/hostname are not build tools).
- This is the FP-tuning result for HW4: found at scale -> diagnosed from traces -> documented fix -> 0.00%, catches intact. Benign FP claim now bounded below ~0.9% (rule of three at n=359)... n=359 with 0 events bounds the rate below 3/359 = 0.84%.
- Malicious 150-scale run (fresh seed 20261121) still in progress; its verdicts will be regenerated with the expanded allowlist for consistency.
