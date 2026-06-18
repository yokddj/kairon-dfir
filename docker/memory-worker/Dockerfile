ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG VOLATILITY3_VERSION=2.28.0
ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Kairon optional Volatility memory worker" \
      org.opencontainers.image.description="Operator-built isolated worker for authorized Kairon memory analysis using Volatility 3 from PyPI" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.licenses="Kairon project license: see repository LICENSE; bundled-at-build dependency: Volatility 3, Volatility Software License 1.0" \
      org.opencontainers.image.version="${BUILD_DATE}" \
      org.kairon.volatility3.version="${VOLATILITY3_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAIRON_COMMIT="${KAIRON_COMMIT}" \
    KAIRON_WORKER_ID="memory-worker"

WORKDIR /app

RUN addgroup --system --gid 10001 kairon \
    && adduser --system --uid 10001 --ingroup kairon --home /home/kairon kairon \
    && mkdir -p /app/data /app/data/tmp /licenses/volatility3 /licenses/kairon /volatility-cache \
    && chown -R kairon:kairon /app /home/kairon /volatility-cache

COPY backend/app /app/app
COPY backend/pyproject.toml /app/pyproject.toml
COPY docker/memory-worker/requirements.lock /build/requirements.lock
COPY docker/memory-worker/copy_volatility_notice.py /build/copy_volatility_notice.py
COPY docker/memory-worker/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
COPY LICENSE /licenses/kairon/LICENSE

RUN python -m pip install --no-cache-dir ".[dev]" \
    && python -m pip install --require-hashes --no-deps --no-cache-dir -r /build/requirements.lock \
    && python /build/copy_volatility_notice.py \
    && vol --help >/tmp/vol-help.txt \
    && grep -i "volatility" /tmp/vol-help.txt >/dev/null \
    && rm -rf /root/.cache /tmp/vol-help.txt /build

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python -c 'import shutil, subprocess, sys; sys.exit(1) if not shutil.which("vol") else None; result = subprocess.run(["vol", "--help"], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10); sys.exit(0 if result.returncode == 0 else 1)'

CMD ["python", "-m", "app.workers.memory_worker"]
