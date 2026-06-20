ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Kairon optional Windows symbol fetcher" \
      org.opencontainers.image.description="Isolated, operator-built fetcher for exact official Windows debugging symbols" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.licenses="Kairon project license and Volatility Software License 1.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAIRON_COMMIT="${KAIRON_COMMIT}" \
    KAIRON_WORKER_ID="symbol-fetcher" \
    XDG_CACHE_HOME=/volatility-cache \
    HOME=/volatility-cache

WORKDIR /app

RUN addgroup --system --gid 10001 kairon \
    && adduser --system --uid 10001 --ingroup kairon --home /home/kairon kairon \
    && mkdir -p /app/data /app/data/tmp /volatility-cache /licenses/volatility3 /licenses/kairon \
    && chown -R kairon:kairon /app /home/kairon /volatility-cache

COPY backend/app /app/app
COPY backend/pyproject.toml /app/pyproject.toml
COPY docker/memory-worker/requirements.lock /build/requirements.lock
COPY docker/memory-worker/copy_volatility_notice.py /build/copy_volatility_notice.py
COPY docker/symbol-fetcher/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
COPY LICENSE /licenses/kairon/LICENSE

RUN python -m pip install --no-cache-dir ".[dev]" \
    && python -m pip install --require-hashes --no-deps --no-cache-dir -r /build/requirements.lock \
    && python /build/copy_volatility_notice.py \
    && rm -rf /root/.cache /build

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python -c 'from app.core.config import get_settings; import os, sys; p=get_settings().memory_symbol_cache_path; sys.exit(0 if p.is_dir() and os.access(p, os.W_OK | os.X_OK) else 1)'

CMD ["python", "-m", "app.workers.symbol_fetcher"]
