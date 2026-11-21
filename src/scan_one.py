#!/usr/bin/env python3
"""Append one package's verdict to the results CSV. Usage:
   scan_one.py <name> <tracefile> <out-csv>"""
import json, subprocess, sys

name, trace, out = sys.argv[1], sys.argv[2], sys.argv[3]
r = subprocess.run(["python3", "src/rules.py", trace], capture_output=True, text=True)
try:
    v = json.loads(r.stdout)
    verdict = v["verdict"]
    rules = "|".join(x["rule"].split(" ")[0] + f"x{x['count']}" for x in v["rules_fired"])
except Exception:
    verdict, rules = "ERROR", r.stderr.strip()[:80].replace(",", ";")
with open(out, "a") as f:
    f.write(f"{name},{verdict},{rules}\n")
print(f"  {name}: {verdict} {rules}")
