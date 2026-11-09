ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG VOLATILITY3_VERSION=2.28.0
# MemProcFS (FindEvil). The release *tag* (MEMPROCFS_TAG) is the pin an
# operator controls; the exact build within that tag is resolved at build
# time from the GitHub Releases API (see fetch_memprocfs.py), because
# upstream reuses the same tag across builds and deletes previous build
# assets, which repeatedly broke a hardcoded build date + SHA-256 (see
# PROJECT_CONTEXT.md). MEMPROCFS_VERSION/BUILD/SHA256_* below are only a
# fallback used if the API is unreachable at build time (e.g. offline
# build); keep them reasonably current but they are not required to be.
ARG MEMPROCFS_TAG=v5.19
ARG MEMPROCFS_VERSION=9.9.9
ARG MEMPROCFS_BUILD=99999999
ARG MEMPROCFS_SHA256_AMD64=aaaa
ARG MEMPROCFS_SHA256_ARM64=bbbb
# Set to "1" to skip the GitHub API lookup and use the fallback pin directly
# (genuinely offline/air-gapped builds; also used by CI to verify the
# fallback pin on its own).
ARG MEMPROCFS_FORCE_FALLBACK=0
ARG TARGETARCH

LABEL org.opencontainers.image.title="Kairon optional Volatility memory worker" \
      org.opencontainers.image.description="Operator-built isolated worker for authorized Kairon memory analysis using Volatility 3 from PyPI" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir" \
      org.opencontainers.image.licenses="Kairon project license: see repository LICENSE; bundled-at-build dependency: Volatility 3, Volatility Software License 1.0" \
      org.kairon.volatility3.version="${VOLATILITY3_VERSION}" \
      org.kairon.memprocfs.tag="${MEMPROCFS_TAG}"
      # Note: the exact MemProcFS build/version is resolved at build time (see
      # fetch_memprocfs.py below) and recorded in
      # /opt/memprocfs/KAIRON_RESOLVED_VERSION.txt inside the image, not in a
      # label, since it is not known until that RUN step executes.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KAIRON_WORKER_ID="memory-worker"

WORKDIR /app

# build-essential is required to build libewf-python (a main backend
# dependency with no prebuilt wheel) from source -- this image installs
# the same backend package ("pip install .[dev]") as backend/Dockerfile,
# which already carries this toolchain; memory-worker never needed it
# until libewf-python was added as a dependency for disk-image EWF
# streaming, unrelated to memory analysis itself.
#
# gdb: optional, best-effort diagnostic for memprocfs.findevil (see
# app/services/memory/memprocfs_runner.py). MemProcFS's own vmm.so has an
# intermittent native crash (SIGSEGV inside VMMDLL_Initialize's forensic
# mode) on some amd64 hosts; attaching gdb to a retried run both sometimes
# avoids the same timing-sensitive race and, if it crashes again, captures
# a real backtrace instead of an empty stderr. ptrace-attaching to one's
# own child process (same UID, direct parent) does not need CAP_SYS_PTRACE
# and works fine under this container's cap_drop: ALL + no-new-privileges
# (verified manually); its absence (e.g. a minimal custom image) only
# disables the retry/backtrace, never a normal run.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libusb-1.0-0 gdb \
    && rm -rf /var/lib/apt/lists/*

# MemProcFS's library (vmm.so) is loaded by app/services/memory/memprocfs_findevil.py in a child
# process. fetch_memprocfs.py resolves the current build for MEMPROCFS_TAG against the GitHub
# Releases API (falling back to the pinned MEMPROCFS_VERSION/BUILD/SHA256_* above if the API is
# unreachable), downloads it, and verifies it against the SHA-256 GitHub itself reports for that
# asset before it is unpacked; any other architecture, or any hash mismatch, fails the build
# instead of shipping without it or with a corrupted copy silently.
COPY docker/memory-worker/fetch_memprocfs.py /tmp/fetch_memprocfs.py
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) sha="${MEMPROCFS_SHA256_AMD64}" ;; \
      arm64) sha="${MEMPROCFS_SHA256_ARM64}" ;; \
      *) echo "MemProcFS: unsupported architecture ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/memprocfs /licenses/memprocfs; \
    force_flag=""; \
    if [ "${MEMPROCFS_FORCE_FALLBACK}" = "1" ]; then force_flag="--force-fallback"; fi; \
    python /tmp/fetch_memprocfs.py \
      --tag "${MEMPROCFS_TAG}" \
      --target-arch "${TARGETARCH:-$(dpkg --print-architecture)}" \
      --dest-dir /opt/memprocfs \
      --fallback-version "${MEMPROCFS_VERSION}" \
      --fallback-build "${MEMPROCFS_BUILD}" \
      --fallback-sha256 "${sha}" \
      ${force_flag}; \
    rm /tmp/fetch_memprocfs.py; \
    cp /opt/memprocfs/LICENSE.txt /opt/memprocfs/license_*.txt /licenses/memprocfs/; \
    cp /opt/memprocfs/KAIRON_RESOLVED_VERSION.txt /licenses/memprocfs/; \
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

# Per-commit metadata last: declared earlier, it changes every build and invalidates every layer
# below it, rebuilding MemProcFS and reinstalling Volatility on each deploy.
ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV KAIRON_COMMIT="${KAIRON_COMMIT}"
LABEL org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.version="${BUILD_DATE}"

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python -c 'import shutil, subprocess, sys; sys.exit(1) if not shutil.which("vol") else None; result = subprocess.run(["vol", "--help"], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10); sys.exit(0 if result.returncode == 0 else 1)'

CMD ["python", "-m", "app.workers.memory_worker"]
