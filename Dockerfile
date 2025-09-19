# Multi-stage build for production
FROM python:3.11-dev as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy syft from builder
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft

# Create non-root user
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/scanner/.local

# Copy application code
COPY eolscan/ ./eolscan/
COPY README.md .
COPY docs/ ./docs/

# Set environment variables
ENV PATH="/home/scanner/.local/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Create necessary directories
RUN mkdir -p /app/logs /app/models && \
    chown -R scanner:scanner /app

# Switch to non-root user
USER scanner

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python", "-m", "eolscan.api"]
