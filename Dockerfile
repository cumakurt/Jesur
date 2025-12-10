# JESUR - Enhanced SMB Share Scanner Docker Image
# Optimized multi-stage build for fast builds and small image size

# ============================================================================
# Stage 1: Builder - Compile Python packages
# ============================================================================
FROM python:3.12-slim AS builder

LABEL maintainer="cumakurt"
LABEL description="Professional Penetration Testing Tool for SMB Share Discovery and Analysis"
LABEL version="2.0.0"

# Install build dependencies in single layer
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip (single command for better caching)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies system-wide (cache this layer)
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.12-slim AS runtime

# Install runtime dependencies only
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    libmagic1 \
    file \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy entire Python environment from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin

# Set working directory
WORKDIR /app

# Copy application code (this layer changes most often, so it's last)
COPY . .

# Create output directories
RUN mkdir -p /app/out_download /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Create non-root user (optional - comment out USER line to run as root for debugging)
RUN useradd -m -u 1000 jesur && \
    chown -R jesur:jesur /app

# Run as root for volume mount compatibility (change to USER jesur for production)
# USER jesur

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Entrypoint
ENTRYPOINT ["python3", "Jesur.py"]
CMD ["--help"]
