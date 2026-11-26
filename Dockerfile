# Dockerfile matching the Track 4 judging environment
# Linux container with Node.js 24.11.1, Python 3.12, and pqcrypto
FROM python:3.12-slim-bookworm

# Install required system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy Node.js 24.11.1 binary and npm runtime from official Node image
COPY --from=node:24.11.1-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:24.11.1-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Install pqcrypto for interop verification
RUN pip install --no-cache-dir --break-system-packages "pqcrypto>=0.4.0"

WORKDIR /workspace

# Copy submission
COPY . /workspace/

ENV TRACK4_STATE_DIR=/tmp/track4-state

CMD ["node", "track4_service.cjs"]
