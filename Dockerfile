# Multi-stage Docker build for Aegis Shield
FROM python:3.10-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
# Create dummy files for package setup
RUN mkdir -p aegis_shield && touch aegis_shield/__init__.py

RUN pip install --no-cache-dir --user .[dashboard]

# Final runner stage
FROM python:3.10-slim AS runner

WORKDIR /app

COPY --from=builder /root/.local /root/.local
COPY aegis_shield/ aegis_shield/

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

EXPOSE 8000
EXPOSE 8501

CMD ["python", "-m", "uvicorn", "aegis_shield.app:app", "--host", "0.0.0.0", "--port", "8000"]
