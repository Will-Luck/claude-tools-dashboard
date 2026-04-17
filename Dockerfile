FROM python:3.12-slim

ARG VERSION=dev
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.source="https://github.com/Will-Luck/claude-tools-dashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="claude-tools-dashboard" \
      org.opencontainers.image.description="Live token-savings wallboard for Claude Code tools (RTK, Headroom, jCodeMunch, jDocMunch)"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV APP_VERSION=${VERSION} \
    APP_BUILD_DATE=${BUILD_DATE}

EXPOSE 8095
CMD ["python", "app.py"]
