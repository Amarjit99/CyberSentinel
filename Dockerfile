FROM python:3.11-slim-bookworm

# Set working directory and environment variables
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Create non-root system user
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Install curl/utilities for healthchecks and apply latest distribution security patches
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies configuration
COPY pyproject.toml README.md ./

# Install project dependencies
RUN pip install --upgrade pip && \
    pip install .

# Copy application source code
COPY schemas/ ./schemas/
COPY packages/ ./packages/
COPY services/ ./services/
COPY apps/ ./apps/
COPY rules/ ./rules/
COPY attack/ ./attack/
COPY playbooks/ ./playbooks/
COPY infrastructure/ ./infrastructure/

# Change ownership to non-privileged user
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
