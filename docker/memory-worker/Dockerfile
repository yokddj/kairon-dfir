ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG VOLATILITY3_VERSION=2.28.0
# MemProcFS (FindEvil). Release binaries, pinned by version and SHA-256 per architecture.
ARG MEMPROCFS_VERSION=5.19.0
ARG MEMPROCFS_TAG=v5.19
ARG MEMPROCFS_BUILD=20261005
ARG MEMPROCFS_SHA256_AMD64=2ec75bba2a243525a16be22d1ea6863c9fcd4de694c07e4896d4029017c43ea5
ARG MEMPROCFS_SHA256_ARM64=03554471c1702d73f2b83c22e2483b0e110b04399fc399c07fc4f7a47827c3a5
ARG TARGETARCH
ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="Kairon optional Volatility memory worker" \
      org.opencontainers.image.description="Operator-built isolated worker for authorized Kairon memory analysis using Volatility 3 from PyPI" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.licenses="Kairon project license: see repository LICENSE; bundled-at-build dependency: Volatility 3, Volatility Software License 1.0" \
      org.opencontainers.image.version="${BUILD_DATE}" \
      org.kairon.volatility3.version="${VOLATILITY3_VERSION}" \
      org.kairon.memprocfs.version="${MEMPROCFS_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAIRON_COMMIT="${KAIRON_COMMIT}" \
    KAIRON_WORKER_ID="memory-worker"

WORKDIR /app

# build-essential is required to build libewf-python (a main backend
# dependency with no prebuilt wheel) from source -- this image installs
# the same backend package ("pip install .[dev]") as backend/Dockerfile,
# which already carries this toolchain; memory-worker never needed it
# until libewf-python was added as a dependency for disk-image EWF
# streaming, unrelated to memory analysis itself.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# MemProcFS's library (vmm.so) is loaded by app/services/memory/memprocfs_findevil.py in a child
# process. The download is checked against the pinned SHA-256 before it is unpacked; any other
# architecture fails the build instead of shipping without it silently.
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) asset=linux_x64; sha="${MEMPROCFS_SHA256_AMD64}" ;; \
      arm64) asset=linux_aarch64; sha="${MEMPROCFS_SHA256_ARM64}" ;; \
      *) echo "MemProcFS: unsupported architecture ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/ufrisk/MemProcFS/releases/download/${MEMPROCFS_TAG}/MemProcFS_files_and_binaries_v${MEMPROCFS_VERSION}-${asset}-${MEMPROCFS_BUILD}.tar.gz"; \
    python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/memprocfs.tgz')" "$url"; \
    echo "${sha}  /tmp/memprocfs.tgz" | sha256sum -c -; \
    mkdir -p /opt/memprocfs /licenses/memprocfs; \
    tar -xzf /tmp/memprocfs.tgz -C /opt/memprocfs; \
    rm /tmp/memprocfs.tgz; \
    cp /opt/memprocfs/LICENSE.txt /opt/memprocfs/license_*.txt /licenses/memprocfs/; \
    chmod -R a+rX /opt/memprocfs; \
    test -f /opt/memprocfs/vmm.so

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
