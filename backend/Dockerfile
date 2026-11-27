FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ARG KAIRON_VERSION=1.2.0
ARG DOTNET_VERSION=10.0

ENV APP_VERSION=${KAIRON_VERSION}
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="/opt/dotnet:${PATH}"
ENV EVTXECMD_DOTNET_DLL=/opt/evtxecmd/EvtxECmd.dll
ENV EZTOOLS_ROOT=/opt/eztools

WORKDIR /app

LABEL org.opencontainers.image.title="Kairon DFIR backend" \
      org.opencontainers.image.version="${KAIRON_VERSION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev libyara-dev pkg-config p7zip-full unar curl ca-certificates libicu-dev ewf-tools sleuthkit dosfstools mtools gdisk parted qemu-utils \
    && rm -rf /var/lib/apt/lists/*

# Known limitation: dotnet-install.sh checksum is not verified (script changes per-channel)
# Mitigation: pinned channel (DOTNET_VERSION), retry on failure, connection via HTTPS
RUN curl -fsSL --retry 3 --retry-delay 5 https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel ${DOTNET_VERSION} --runtime dotnet --install-dir /opt/dotnet \
    && mkdir -p /opt/evtxecmd \
    && curl -fsSL --retry 3 --retry-delay 5 https://download.ericzimmermanstools.com/net/EvtxECmd.zip -o /tmp/EvtxECmd.zip \
    && python -m zipfile -e /tmp/EvtxECmd.zip /opt/evtxecmd \
    && ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet \
    && ln -sf "$(find /opt/evtxecmd -iname EvtxECmd.dll -print -quit)" /opt/evtxecmd/EvtxECmd.dll \
    && rm -f /tmp/dotnet-install.sh /tmp/EvtxECmd.zip

RUN set -eux; \
    mkdir -p /opt/eztools; \
    for tool in LECmd JLECmd PECmd AmcacheParser AppCompatCacheParser RECmd MFTECmd SrumECmd SBECmd; do \
        mkdir -p "/opt/eztools/${tool}"; \
        curl -fsSL --retry 3 --retry-delay 5 "https://download.ericzimmermanstools.com/net/${tool}.zip" -o "/tmp/${tool}.zip"; \
        python -m zipfile -e "/tmp/${tool}.zip" "/opt/eztools/${tool}"; \
        dll="$(find "/opt/eztools/${tool}" -iname "${tool}.dll" -print -quit)"; \
        test -n "$dll"; \
        if [ "$dll" != "/opt/eztools/${tool}/${tool}.dll" ]; then ln -sf "$dll" "/opt/eztools/${tool}/${tool}.dll"; fi; \
        rm -f "/tmp/${tool}.zip"; \
    done

# macOS Unified Logs: Mandiant's unifiedlog_iterator (Apache-2.0), a prebuilt release binary per
# architecture, pinned by version and SHA-256 (tooling/tooling.lock.yaml).
ARG UNIFIEDLOG_VERSION=0.7.0
ARG UNIFIEDLOG_SHA256_AMD64=7192a187f93c6fb8eafdad9885522e73dc2ae7a9a5000f5957edd4fcd0ca1c82
ARG UNIFIEDLOG_SHA256_ARM64=ab40daf464376a2e52c4b51fd82b003b7f360a4e2726501ba853889fa3a959f4
ENV UNIFIEDLOG_ITERATOR=/opt/unifiedlog/unifiedlog_iterator
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) target=x86_64-unknown-linux-gnu; sha="${UNIFIEDLOG_SHA256_AMD64}" ;; \
        arm64) target=aarch64-unknown-linux-gnu; sha="${UNIFIEDLOG_SHA256_ARM64}" ;; \
        *) echo "unifiedlog_iterator: no release binary for $arch"; exit 1 ;; \
    esac; \
    name="unifiedlog_iterator-v${UNIFIEDLOG_VERSION}-${target}"; \
    curl -fsSL --retry 3 --retry-delay 5 "https://github.com/mandiant/macos-UnifiedLogs/releases/download/v${UNIFIEDLOG_VERSION}/${name}.tar.gz" -o /tmp/unifiedlog.tar.gz; \
    echo "${sha}  /tmp/unifiedlog.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/unifiedlog; \
    tar -xzf /tmp/unifiedlog.tar.gz -C /opt/unifiedlog --strip-components=1; \
    test -x /opt/unifiedlog/unifiedlog_iterator; \
    rm -f /tmp/unifiedlog.tar.gz

# The pinned dependency set first, so a code change does not reinstall every package.
COPY backend/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock

COPY backend/app /app/app
COPY backend/tests /app/tests
COPY backend/pyproject.toml /app/pyproject.toml
COPY docs /app/docs
COPY tools/demo /app/tools/demo
# pyproject.toml's dependency bounds are loose (e.g. "fastapi>=0.115.0"), so
# a plain install floats to whatever is newest on PyPI on build day -- not
# reproducible, and a real regression (some routes registered via
# app.include_router() silently failing to dispatch) was hit in the wild
# with fastapi 0.141.1/starlette 1.5.0. requirements.lock pins the exact,
# known-good version set; installing it second overrides anything the
# first pass resolved differently.
RUN pip install --no-cache-dir ".[dev]" \
    && pip install --no-cache-dir -r requirements.lock

# Per-commit metadata last: declared earlier, it changes every build and invalidates every layer
# below it, re-downloading .NET and the Eric Zimmerman tools on each deploy.
ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV KAIRON_COMMIT=${KAIRON_COMMIT} \
    BUILD_DATE=${BUILD_DATE}
LABEL org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"
# The update check reads the commit from here: docker compose sets KAIRON_COMMIT=unknown in the
# environment when it is started without the variable exported.
RUN printf '%s\n' "${KAIRON_COMMIT}" > /app/.kairon-commit

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
