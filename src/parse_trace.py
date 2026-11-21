#!/usr/bin/env python3
"""CatchGate trace parser: strace output -> JSONL event stream.

Reads a strace -f trace, keeps three syscall families, and yields one dict
per event in file order (order matters: the chain rule consumes it).

    {"seq": 1, "pid": 12, "type": "exec",    "target": "/usr/local/bin/npm",   "result": "ok"}
    {"seq": 2, "pid": 22, "type": "open",    "target": "/home/devuser/.npmrc", "result": "ok"}
    {"seq": 3, "pid": 20, "type": "connect", "target": "192.0.2.1:443",        "result": "ENETUNREACH"}

Usage: python3 parse_trace.py <tracefile>   (prints JSONL to stdout)
The rules engine imports events() directly as a library.
"""
import json
import re
import sys

# --- line matchers ------------------------------------------------------------
# strace -f prefixes every line with the pid that made the call.
# exec:  12    execve("/usr/local/bin/npm", ["npm", ...], 0x...) = 0
EXEC_RE = re.compile(r'^\s*(\d+)\s+execve\("([^"]+)"')
# open:  22    openat(AT_FDCWD, "/home/devuser/.npmrc", O_RDONLY) = 18
# (older tooling prints `open(` without the AT_FDCWD first arg)
OPEN_RE = re.compile(r'^\s*(\d+)\s+open(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)"')
# connect: 20    connect(3, {sa_family=AF_INET, sin_port=htons(443),
#                           sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH
CONNECT_RE = re.compile(r'^\s*(\d+)\s+connect\(')
INET_RE = re.compile(r'sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)')
UNIX_RE = re.compile(r'sun_path="([^"]+)"')
# the return value sits after the closing paren of the arguments:
#   `) = 18`  -> ok      `) = -1 ENOENT (No such file or directory)` -> ENOENT
RESULT_RE = re.compile(r'\)\s*=\s*(-?\d+)(?:\s+([A-Z0-9_]+))?')


def result_of(line):
    """Translate a syscall's return text into 'ok' or the errno name."""
    m = RESULT_RE.search(line)
    if not m:
        return "unknown"
    value, errno = m.groups()
    if value.startswith("-"):
        return errno or value
    return "ok"


def events(path):
    """Yield one event dict per matched syscall, in file order."""
    seq, skipped = 0, 0
    with open(path) as fh:
        for line in fh:
            # strace -f interleaves threads: some calls get split across
            # "<unfinished ...>" and "... resumed>" lines. Skip them (counted).
            if "unfinished" in line or "resumed" in line:
                skipped += 1
                continue

            m = EXEC_RE.match(line)
            if m:
                seq += 1
                yield {"seq": seq, "pid": int(m.group(1)), "type": "exec",
                       "target": m.group(2), "result": result_of(line)}
                continue

            m = OPEN_RE.match(line)
            if m:
                seq += 1
                yield {"seq": seq, "pid": int(m.group(1)), "type": "open",
                       "target": m.group(2), "result": result_of(line)}
                continue

            m = CONNECT_RE.match(line)
            if m:
                inet = INET_RE.search(line)
                if inet:
                    target = f"{inet.group(2)}:{inet.group(1)}"  # addr:port
                else:
                    unix = UNIX_RE.search(line)
                    target = f"unix:{unix.group(1)}" if unix else "unknown"
                seq += 1
                yield {"seq": seq, "pid": int(m.group(1)), "type": "connect",
                       "target": target, "result": result_of(line)}
                continue
    print(f"skipped {skipped} unfinished/resumed lines", file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: parse_trace.py <tracefile>")
    for ev in events(sys.argv[1]):
        print(json.dumps(ev))


if __name__ == "__main__":
    main()
