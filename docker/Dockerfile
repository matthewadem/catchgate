# CatchGate Stage 1 — sandboxed npm install
# Base image pinned for reproducibility
FROM node:20-slim

# strace is the observation layer: every syscall the install makes
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*

# Non-root user = the "plausible development machine" the papers say
# conditional payloads check for (41% of them look before acting)
RUN useradd -m -s /bin/bash devuser
USER devuser
WORKDIR /home/devuser/project
RUN npm init -y
