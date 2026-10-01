# Offline command authorization snapshot reviewer.
# Pure Python standard library: no third-party runtime dependencies.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

COPY app/ ./app/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY webstatic/ ./webstatic/

# Build the deterministic snapshot once so both web and verify services
# share the same committed root/fixtures without needing a writable volume.
RUN mkdir -p data && python scripts/build_snapshot.py

EXPOSE 8080

# Static entry point started by Compose.
CMD ["python", "-m", "app.server"]
