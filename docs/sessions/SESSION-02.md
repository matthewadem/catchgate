# Session 02 — Stages 2+3: syscall capture + canaries (90 min)

Goal: capture a full strace of an install, and plant fake canaries first.

1. Trace wrap: change your docker run line so the install runs under strace:
   docker run --rm --network none -v "$PWD/traces:/traces" catchgate-sandbox \
     strace -f -o /traces/<pkg>.trace npm install <pkg>
   (-f follows child processes; traces/ is gitignored on purpose)
2. Run it on left-pad. Open traces/left-pad.trace and FIND these by hand:
   a connect( attempt (it will fail — network is off: that is the signal)
   every execve (what binaries ran?)
3. Canaries: scripts/plant_canaries.sh is written. Wire it in so canaries
   exist in the container home BEFORE npm install runs (hint: RUN it in the
   Dockerfile, or call it in the docker run before strace).
4. Re-run left-pad, grep the trace for ".npmrc" — nothing should read it
   (left-pad is benign). That absence is exactly what a benign trace looks like.
5. Notebook entry. Commit:
   git add scripts/ traces/../ 2>/dev/null; git add -A scripts docs docker
   git commit -m "Stage 2-3: strace capture and canary planting"

You now have the hard middle of the system. Everything after this is Python.
