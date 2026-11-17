# Reading Notes 3 — SafeDep: Dynamic Malware Analysis of OSS Packages at Scale

**Source:** `Project References/SafeDep - Dynamic Malware Analysis of OSS Packages at Scale.html` · safedep.io/blog
**Citation (IEEE draft):** [3] SafeDep Team, "Dynamic malware analysis of open source packages at scale," SafeDep Blog, May 2025. [Online]. Available: https://safedep.io/dynamic-analysis-oss-package-at-scale

## One-line summary
Engineering writeup of SafeDep's production system that runs every published open-source package's installation inside a sandboxed, eBPF-monitored environment to capture runtime behavior and correlate it with static-analysis verdicts.

## Main Findings
- Their motivation mirrors our anchor paper: static analysis is bounded by the Halting Problem / Rice's Theorem — false positives AND negatives are inherent, no matter how good the rules. Dynamic analysis verifies and correlates static findings.
- Architecture: executor consumes package-analysis messages (NATS) → creates Docker-in-Docker (DIND) sandbox → runs `npm install` / `pip install` → eBPF-based syscall monitoring via Falco (CNCF graduated) → event handler (gRPC client) filters events → persisted to events DB with a correlation ID for correlation with static results.
- Scale in production: **100k+ events/hour; 12,491,123 events in under 2 weeks**; nodes are 4-CPU/16GB; Falco pods show CPU spikes and a memory leak.
- Explicit threat model for detonating live malware: reverse shells (deliberately unmitigated — ephemeral containers, they WANT to observe them), container escape (DIND = two escapes needed; gVisor planned), kernel exploits (dedicated tainted node pool, no mounted secrets), network attacks (K8s NetworkPolicy; egress only to API server + registry), VMM escape (accepted residual risk).
- Open challenges they name: **baselining install behavior is hard** (package-manager initializer footprints vary by version); command execution is NORMAL at install time (esbuild, node-gyp, make — legitimate build tools); **build telemetry is indistinguishable from C2 without deep packet inspection**; sophisticated payloads detect container environments (they plan syscall emulation — fake sleep/rdtsc).
- They deliberately avoided strace for kernel-level eBPF hooks (stealth + footprint), and took inspiration from Google/OpenSSF's Package Analysis project.

## Methodology
- Trigger: plain `npm install <pkg>` in the sandbox (loading exported functions is future work — some malware only fires on import, e.g. their express-cookie-parser example).
- Observation: syscall-level events via Falco with custom rules matching syscall parameters; standard event schema; correlation IDs tie behavior to packages.
- Verdicting: statistical outlier analysis over aggregated events (see notes 4), correlated with static verdicts; human review for confirmation.

## Relevance to My Replication
<!-- NOTE-TO-SELF: these bullets become HW2 prose — REWRITE IN MY OWN WORDS at drafting time. -->

- This IS the methodology CatchGate reproduces, at a scale I can run: their executor+sandbox+syscall-events+rules pipeline maps 1:1 onto my container + strace + event log + 5–10 rules. Mine is the same idea with strace instead of Falco/eBPF — the scope trade-off Xu approved (deterministic, strace-level, 450 packages vs. their fleet).
- Their stated open problems are my design constraints: build-tool executions (esbuild/node-gyp) are the #1 false-positive source → my rules need a build-tool allowlist; "build telemetry vs. C2" indistinguishability → my network deny-and-log design sidesteps DPI by flagging ANY non-registry egress attempt.
- Their baselining difficulty justifies my chain-rules approach: I don't need a behavioral baseline — ordered collect→exfiltrate pairs are discriminative on their own (anchor paper's coupling finding).
- Their threat model is a ready-made safety checklist for my sandbox: ephemeral containers, no secrets mounted, egress denied by default, dedicated isolated VM. Cite it as the safety model CatchGate follows.
- Honest limitation to state in HW2: SafeDep moved beyond strace for stealth (malware can detect strace) — mine accepts that risk at sample scale; note as future work (eBPF).

## Limitations / Openings
- Commercial platform — the pipeline description is published but the system isn't runnable by a student or small team. (Their OSS tool `vet` covers scanning/guardrails, not self-hosted detonation.)
- Install-time only: packages whose payload fires on import/use escape (they name this as future work — a known coverage gap).
- No published detection/FP rates on labeled corpora — engineering blog, not an evaluation. That measured evaluation is exactly what my replication adds.

## Key numbers to steal
- 100k+ events/hour · 12,491,123 events in <2 weeks · 4-CPU/16GB nodes
- Detection stack: Falco (eBPF) + DIND sandbox + NATS + gRPC event handler
- Falco footprint: 100m CPU / 256MB per pod; DIND 500m CPU / 512MB
