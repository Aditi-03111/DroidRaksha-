# ── Stage 1: grab Docker CLI binary (avoids apt repo setup entirely) ──────────
FROM docker:27-cli AS docker-cli

# ── Stage 2: main application image ──────────────────────────────────────────
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── JADX env vars ─────────────────────────────────────────────────────────────
ENV JADX_BIN=/opt/jadx/bin/jadx
ENV JADX_CACHE_DIR=/tmp/jadx_cache
ENV JADX_VERSION=1.5.0

# ── Copy Docker CLI binary from Stage 1 ──────────────────────────────────────
# This lets the backend issue `docker run` commands via the mounted docker.sock
# without needing to install the full Docker apt repo inside the container.
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    libglib2.0-0 \
    libmagic1 \
    default-jre-headless \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Set work directory ────────────────────────────────────────────────────────
WORKDIR /app

# BuildKit cache mount is deliberately removed to prevent the host's Docker.raw
# virtual disk from permanently ballooning by 10+ GB from ML dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── JADX CLI (full distribution incl. lib/*.jar) ─────────────────────────────
# Placed AFTER pip install so changing JADX does NOT bust the pip cache layer.
RUN curl -fsSL \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm -f /tmp/jadx.zip

# ── Copy project source ───────────────────────────────────────────────────────
COPY . .

# Ensure runtime directories exist
RUN mkdir -p uploads ${JADX_CACHE_DIR}

# Expose the port the app runs on
EXPOSE 8000

# Run the backend
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
