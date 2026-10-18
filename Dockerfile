FROM python:3.11-slim-bookworm

# Set working directory and environment variables
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    VIRTUAL_ENV="/app/.venv"

# Create non-root system user
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Install curl for healthchecks and apply latest distribution security patches
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv from official binary image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy dependency configuration and locked dependencies
COPY pyproject.toml uv.lock README.md ./

# Install locked production dependencies (no dev extras)
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source code (excluding frontend web node_modules)
COPY schemas/ ./schemas/
COPY packages/ ./packages/
COPY services/ ./services/
COPY apps/__init__.py ./apps/__init__.py
COPY apps/api/ ./apps/api/
COPY rules/ ./rules/
COPY attack/ ./attack/
COPY playbooks/ ./playbooks/
COPY infrastructure/ ./infrastructure/
COPY .trivyignore ./

# Install project itself into the venv without copying dev/frontend bloat
RUN uv pip install --no-deps -e .

# Clean up uv binary to reduce attack surface and container size
RUN rm -f /bin/uv

# Change ownership to non-privileged user
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
