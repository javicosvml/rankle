# Rankle - Web Infrastructure Reconnaissance Tool
# Dockerfile using Alpine Linux for minimal image size

FROM python:3.11-alpine

# Metadata
LABEL maintainer="Rankle Project"
LABEL description="Web Infrastructure Reconnaissance Tool - 100% OSS"
LABEL version="1.0"

# Set working directory
WORKDIR /app

# Install system dependencies
# gcc, musl-dev, libffi-dev needed for some Python packages compilation
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

# Copy application files
COPY rankle.py .
COPY README.md .

# Make script executable
RUN chmod +x rankle.py

# Create directory for output files
RUN mkdir -p /output

# Set volume for output files
VOLUME ["/output"]

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command shows help
ENTRYPOINT ["python", "rankle.py"]
CMD []

# Usage:
# Build:    docker build -t rankle .
# Run:      docker run --rm rankle example.com
# Save:     docker run --rm -v $(pwd):/output rankle example.com
