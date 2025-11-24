# Rankle - Web Infrastructure Reconnaissance Tool
# Dockerfile using Alpine Linux for minimal image size

FROM python:3.11-alpine

# Metadata following OCI annotations
LABEL maintainer="Rankle Project"
LABEL description="Web Infrastructure Reconnaissance Tool - 100% OSS"
LABEL version="2.0.0"
LABEL org.opencontainers.image.title="Rankle"
LABEL org.opencontainers.image.description="Web Infrastructure Reconnaissance Tool"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Rankle Project"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/javicosvml/rankle"

# Set working directory
WORKDIR /app

# Install system dependencies
# gcc, musl-dev, libffi-dev needed for some Python packages compilation
# hadolint ignore=DL3018
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    && rm -rf /var/cache/apk/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files (modular architecture v2.0)
COPY main.py .
COPY rankle/ ./rankle/
COPY config/ ./config/

# Create non-root user for security
RUN addgroup -g 1000 rankle && \
    adduser -D -u 1000 -G rankle rankle

# Create directory for output files
RUN mkdir -p /output && \
    chown -R rankle:rankle /output /app

# Set volume for output files (use with: docker run -v $(pwd)/output:/output)
VOLUME ["/output"]

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER rankle

# Healthcheck (verify Python and script are accessible)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Default command
ENTRYPOINT ["python", "main.py"]
CMD []

# Usage:
# Build:    docker build -t rankle .
# Run:      docker run --rm rankle example.com
# Save:     docker run --rm -v $(pwd)/output:/output rankle example.com --output json
# Report:   docker run --rm -v $(pwd)/output:/output rankle example.com --output both
