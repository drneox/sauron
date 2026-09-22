# Argus ASM — backend (FastAPI + Tortoise + nuclei)
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for cryptography/reportlab builds + nuclei download
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nuclei (ProjectDiscovery) — arch-aware binary from GitHub releases
ARG NUCLEI_VERSION=3.7.1
ARG TARGETARCH
RUN set -e; \
    case "$TARGETARCH" in \
      arm64) ARCH=arm64 ;; \
      *) ARCH=amd64 ;; \
    esac; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && rm /tmp/nuclei.zip && nuclei -version

# ProjectDiscovery toolkit + trufflehog — same arch-aware pattern as nuclei.
# Each tool installs independently: a failed release logs a WARNING instead of
# breaking the build (the backend degrades to "skipped" for missing tools).
ARG SUBFINDER_VERSION=2.16.0
ARG HTTPX_VERSION=1.12.0
ARG KATANA_VERSION=1.7.0
ARG NAABU_VERSION=2.6.1
ARG TRUFFLEHOG_VERSION=3.97.5
RUN set -e; \
    case "$TARGETARCH" in \
      arm64) ARCH=arm64 ;; \
      *) ARCH=amd64 ;; \
    esac; \
    for spec in "subfinder:${SUBFINDER_VERSION}" "httpx:${HTTPX_VERSION}" \
                "katana:${KATANA_VERSION}" "naabu:${NAABU_VERSION}"; do \
      tool="${spec%%:*}"; ver="${spec##*:}"; \
      url="https://github.com/projectdiscovery/${tool}/releases/download/v${ver}/${tool}_${ver}_linux_${ARCH}.zip"; \
      if curl -fsSL -o "/tmp/${tool}.zip" "$url" \
         && unzip -q -o "/tmp/${tool}.zip" -d /usr/local/bin "$tool"; then \
        echo "installed ${tool} ${ver} (${ARCH})"; \
      else \
        echo "WARNING: failed to install ${tool} ${ver} from $url"; \
      fi; \
      rm -f "/tmp/${tool}.zip"; \
    done; \
    th_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz"; \
    if curl -fsSL -o /tmp/trufflehog.tar.gz "$th_url" \
       && tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog; then \
      echo "installed trufflehog ${TRUFFLEHOG_VERSION} (${ARCH})"; \
    else \
      echo "WARNING: failed to install trufflehog ${TRUFFLEHOG_VERSION} from $th_url"; \
    fi; \
    rm -f /tmp/trufflehog.tar.gz; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/katana \
             /usr/local/bin/naabu /usr/local/bin/trufflehog 2>/dev/null || true; \
    for tool in subfinder httpx katana naabu trufflehog; do \
      if which "$tool" >/dev/null 2>&1; then \
        echo "OK: $tool -> $(which "$tool")"; \
      else \
        echo "WARNING: $tool not on PATH after install"; \
      fi; \
    done; \
    subfinder -version 2>&1 | head -1 || true; \
    httpx -version 2>&1 | head -1 || true; \
    katana -version 2>&1 | head -1 || true; \
    naabu -version 2>&1 | head -1 || true; \
    trufflehog --version 2>&1 | head -1 || true

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
# Migraciones (aerich) antes de levantar la API
CMD ["sh", "-c", "aerich upgrade && uvicorn main:app --host 0.0.0.0 --port 8000"]
