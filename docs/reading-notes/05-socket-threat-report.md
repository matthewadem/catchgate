# Reading Notes 5 — Socket 2025 Mid-Year Threat Report

**Source:** `Project References/Socket - 2025 Mid-Year Threat Report.md` (pre-extracted) · socket.dev/blog
**Citation (IEEE draft):** [5] K. Boychenko and P. Burckhardt, "The landscape of malicious open source packages: 2025 mid-year threat report," Socket Blog, May 2025. [Online]. Available: https://socket.dev/blog/malicious-open-source-packages-2025-mid-year-threat-report

## One-line summary
Threat-landscape survey of supply-chain attacks across npm/PyPI/Go/Maven/RubyGems in H1 2025: six recurring adversarial techniques, real campaigns, and defense recommendations that read like a behavioral-detection design doc.

## Main Findings
- Scale framing: **70–90% of a typical codebase is third-party packages** (Linux Foundation/Census II); npm and PyPI each serve billions of downloads weekly.
- Six recurring techniques:
  1. **Typosquatting** — metamask/"metamaks", browser-cookie3/"browser-cookies3"; Chrome-credential harvesting via Discord webhook exfiltration.
  2. **Repository & caching abuse** — backdoored `boltdb/bolt` clone served by the Go Module Mirror for THREE YEARS; C2 at 49.12.198[.]231:20022.
  3. **Obfuscation** — base64/hex, junk ops, eval(); leftovers (long encoded strings) remain detectable statically.
  4. **Multi-stage malware** — NK-linked npm campaign: "BeaverTail" loader steals browser data + Solana wallets, then fetches "InvisibleFerret" backdoor (C2 172.86.84[.]38:1224).
  5. **Automation & AI** — one actor published **280 malicious npm packages in a single weekend**; "slopsquatting" = registering hallucinated package names LLMs recommend; Google AI Overview endorsed a malicious package (@async-mutex/mutex).
  6. **Weaponizing legitimate services** — exfil via nodemailer/Gmail (Solana keys), fake Sentry error reports (chalk-lookalike sending env vars), OAST infrastructure, Discord webhooks.
- Their recommended defenses are behavioral: monitor install-time network activity, block unexpected outbound connections, sandbox post-install execution, inspect outbound connections during install scripts, avoid blanket domain allowlisting.

## Methodology
- Vendor threat-research survey: campaign tracking across registries, technique categorization with real examples. Not a labeled-corpus evaluation — context, not measurement.

## Relevance to My Replication
<!-- NOTE-TO-SELF: these bullets become HW2 prose — REWRITE IN MY OWN WORDS at drafting time. -->

- Which techniques are INSTALL-TIME behavioral (my detection window): webhook/OAST/Gmail exfil at install (1, 6), multi-stage 2nd-fetch (4), abnormal outbound during postinstall (6). Out of scope: pure registry-side abuse (2's mirror poisoning), AI-slopsquatting (5) — say so honestly in HW2's scope discussion.
- Their defense recommendations independently describe CatchGate's design (sandboxed install, deny-and-log egress, postinstall scrutiny) — three of the six techniques land directly in my rules.
- Discord-webhook exfil appears in BKC (2020) AND here (2025) — five years of consistency = webhook endpoints deserve their own network rule.
- Motivation numbers for the Introduction: 70–90% dependency share, 280 packages/weekend automation, three-year Go mirror poisoning.

## Limitations / Openings
- Vendor report from a detection vendor — naturally argues for behavioral detection (Socket's product). Cite as threat context, not neutral evidence; pair with the academic benchmark for measurement.
- No detection rates/FP data — again, that's what my replication contributes.

## Key numbers to steal
- 70–90% of codebase = third-party · billions of weekly downloads
- 280 malicious packages in one weekend · boltdb/bolt poisoned mirror: 3 years
- BeaverTail → InvisibleFerret (NK-linked) · C2s: 49.12.198[.]231:20022, 172.86.84[.]38:1224
