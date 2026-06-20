ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Kairon symbol egress gateway" \
      org.opencontainers.image.description="Isolated outbound HTTPS gateway for managed Windows symbol acquisition" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.licenses="Kairon project license"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAIRON_COMMIT="${KAIRON_COMMIT}" \
    KAIRON_WORKER_ID="symbol-egress-gateway"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system --gid 10001 kairon \
    && adduser --system --uid 10001 --ingroup kairon --home /home/kairon kairon \
    && mkdir -p /home/kairon \
    && chown -R kairon:kairon /app /home/kairon

COPY backend/app /app/app
COPY backend/pyproject.toml /app/pyproject.toml

RUN python -m pip install --no-cache-dir "fastapi>=0.115.0" "uvicorn[standard]>=0.30.0"

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8443/internal/healthz', timeout=3).status == 200 else 1)"

CMD ["python", "-m", "app.services.memory.symbol_egress_gateway"]
