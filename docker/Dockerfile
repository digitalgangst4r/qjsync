# syntax=docker/dockerfile:1
#
# qjsync — Qualys VMDR → Jira Cloud connector.
#
# Single-stage image on python:3.12-slim. We install the project itself (not just
# its deps) so the `qjsync` console entry point is on PATH, then drop to a
# non-root user for runtime.
FROM python:3.12-slim AS runtime

# - Don't write .pyc files, don't buffer stdout/stderr (so logs stream in
#   `docker logs`), and don't let pip cache bloat the layer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build context is the repo root (see docker-compose.yml: build context "../").
# Copy only what the wheel build needs so unrelated changes don't bust the cache.
COPY pyproject.toml README.md ./
COPY src ./src

# Install the project. psycopg[binary] ships its own libpq, so no apt packages
# are required at build or run time.
RUN pip install .

# Run as an unprivileged user. Create it after install so /app is owned by root
# (read-only to the app) while the process itself has no write needs.
RUN useradd --create-home --uid 10001 qjsync
USER qjsync

# `docker run <image> sync --mode incremental -c /app/rules.yml` etc.
ENTRYPOINT ["qjsync"]
CMD ["--help"]
