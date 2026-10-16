# syntax=docker/dockerfile:1
# Minimal Python non-root image for the demo agent (Step 1, P1-12.1).
# Hardened, read-only root filesystem compatible, no added capabilities.

FROM python:3.12-alpine

LABEL org.opencontainers.image.title="White Tower Demo Agent" \
      org.opencontainers.image.description="Sample AI agent governed by White Tower runtime control" \
      org.opencontainers.image.url="https://github.com/J466Y/WhiteTower" \
      org.opencontainers.image.source="https://github.com/J466Y/WhiteTower" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="White Tower"

# Run as non-root user (uid 10001)
RUN addgroup -g 10001 -S app && adduser -u 10001 -S app -G app

WORKDIR /app
USER app:app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "-c", "import time; print('White Tower Demo Agent initialized'); time.sleep(0.1)"]
