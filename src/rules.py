#!/usr/bin/env python3
"""CatchGate rule engine: event stream -> verdict.

Evaluates the ordered JSONL event stream produced by parse_trace against a
small set of deterministic rules. Every verdict lists the exact events that
fired it -- nothing is a black box.

Rules:
  R1 chain (primary): a successful read of a canary path FOLLOWED BY an
     internet connect attempt, in that order. This is the benchmark's
     behavioral-coupling finding turned into code: a canary read alone is
     ambiguous (npm reads ~/.npmrc itself on every install), a connect alone
     in an offline sandbox is already damning, the ordered pair is the attack.
  R2 network attempt: ANY internet connect attempt, including failed ones.
     The sandbox has no network by design, so a benign install has no reason
     to reach out; exfiltration shows up as a failed connect (ENETUNREACH
     etc.) and that failure IS the signal (SafeDep's offline detonation
     design).
  R3 unknown binary: exec of a program outside the build-tool allowlist
     (from SafeDep's production findings: legit build tools run binaries, so
     known ones are allowed, unknown ones are not).

Known false-positive class (found 2026-11-19, is-even): packages WITH
dependencies make npm resolve them from the registry, which offline means a
burst of connect attempts to the sandbox's DNS resolver. Those are fetch
machinery, not exfiltration, so connect attempts to port 53 on private
resolver addresses are exempt. This is sound offline: with --network none
nothing can leave the machine, so DNS-tunnel exfiltration is physically
impossible; exfil connects target external addresses, which still fire.

Usage: python3 rules.py <tracefile>
Output: one verdict JSON object (rules aggregated: unique rules, count, and
the first evidence pair for each -- one burst of retries reads as one rule
with count 13, not 13 entries).
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from parse_trace import events  # the parser is a library now

# canary paths planted by scripts/plant_canaries.sh
CANARY_MARKERS = ("/.npmrc", "/.ssh/", "/.aws/", "/.env")
# binaries a normal npm install may execute (build-tool allowlist, from [4])
EXEC_ALLOWLIST = {"node", "npm", "sh", "bash", "dash", "env"}
# private resolver addresses whose port-53 probes are dependency-fetch machinery
DNS_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.")


def is_dns_machinery(target):
    # CATCHGATE_STRICT_DNS=1 disables the exemption: with dependency
    # pre-staging in place, the offline install needs no DNS at all, so any
    # resolver attempt is signal (hostname-based exfiltration becomes visible).
    if os.environ.get("CATCHGATE_STRICT_DNS"):
        return False
    addr, _, port = target.rpartition(":")
    return port == "53" and addr.startswith(DNS_PRIVATE_PREFIXES)


def evaluate(evs):
    order = []      # rule keys in first-fired order
    fired = {}      # key -> {"count": n, "evidence": [first events]}
    canary_read = None  # first successful canary read, as an event dict

    def fire(key, evidence):
        if key not in fired:
            fired[key] = {"count": 0, "evidence": evidence}
            order.append(key)
        fired[key]["count"] += 1

    for ev in evs:
        if ev["type"] == "open" and ev["result"] == "ok":
            if any(marker in ev["target"] for marker in CANARY_MARKERS):
                if canary_read is None:
                    canary_read = ev

        elif ev["type"] == "connect" and ":" in ev["target"] \
                and not ev["target"].startswith("unix:"):
            # AF_UNIX targets ("unix:...") are local IPC (e.g. glibc probing
            # the nscd socket during name resolution) -- cannot leave the
            # machine, so they are not network events.
            if is_dns_machinery(ev["target"]):
                continue  # dependency-fetch machinery, see module docstring
            if canary_read is not None and canary_read["seq"] < ev["seq"]:
                fire("R1:chain canary-read->connect", [canary_read, ev])
            fire("R2:network-attempt (offline sandbox)", [ev])

        elif ev["type"] == "exec":
            binary = ev["target"].rsplit("/", 1)[-1]
            if binary not in EXEC_ALLOWLIST:
                fire(f"R3:unknown binary '{binary}'", [ev])

    return [{"rule": k, "count": fired[k]["count"],
             "evidence": fired[k]["evidence"]} for k in order]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: rules.py <tracefile>")
    fired = evaluate(events(sys.argv[1]))
    verdict = {
        "trace": sys.argv[1],
        "verdict": "BLOCK" if fired else "ALLOW",
        "rules_fired": fired,
    }
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
