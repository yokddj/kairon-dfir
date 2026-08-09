FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG KAIRON_VERSION=0.9.0-beta
ARG DOTNET_VERSION=9.0

ENV KAIRON_COMMIT=${KAIRON_COMMIT}
ENV BUILD_DATE=${BUILD_DATE}
ENV APP_VERSION=${KAIRON_VERSION}
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="/opt/dotnet:${PATH}"
ENV EVTXECMD_DOTNET_DLL=/opt/evtxecmd/EvtxECmd.dll
ENV EZTOOLS_ROOT=/opt/eztools

WORKDIR /app

LABEL org.opencontainers.image.title="Kairon DFIR backend" \
      org.opencontainers.image.version="${KAIRON_VERSION}" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev libyara-dev pkg-config p7zip-full curl ca-certificates libicu-dev ewf-tools sleuthkit dosfstools mtools gdisk parted qemu-utils \
    && rm -rf /var/lib/apt/lists/*

# Known limitation: dotnet-install.sh checksum is not verified (script changes per-channel)
# Mitigation: pinned channel (DOTNET_VERSION), retry on failure, connection via HTTPS
RUN curl -fsSL --retry 3 --retry-delay 5 https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel ${DOTNET_VERSION} --runtime dotnet --install-dir /opt/dotnet \
    && mkdir -p /opt/evtxecmd \
    && curl -fsSL --retry 3 --retry-delay 5 https://download.ericzimmermanstools.com/net9/EvtxECmd.zip -o /tmp/EvtxECmd.zip \
    && python -m zipfile -e /tmp/EvtxECmd.zip /opt/evtxecmd \
    && ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet \
    && ln -sf "$(find /opt/evtxecmd -iname EvtxECmd.dll -print -quit)" /opt/evtxecmd/EvtxECmd.dll \
    && rm -f /tmp/dotnet-install.sh /tmp/EvtxECmd.zip

RUN set -eux; \
    mkdir -p /opt/eztools; \
    for tool in LECmd JLECmd PECmd AmcacheParser AppCompatCacheParser RECmd MFTECmd SrumECmd; do \
        mkdir -p "/opt/eztools/${tool}"; \
        curl -fsSL --retry 3 --retry-delay 5 "https://download.ericzimmermanstools.com/net9/${tool}.zip" -o "/tmp/${tool}.zip"; \
        python -m zipfile -e "/tmp/${tool}.zip" "/opt/eztools/${tool}"; \
        dll="$(find "/opt/eztools/${tool}" -iname "${tool}.dll" -print -quit)"; \
        test -n "$dll"; \
        if [ "$dll" != "/opt/eztools/${tool}/${tool}.dll" ]; then ln -sf "$dll" "/opt/eztools/${tool}/${tool}.dll"; fi; \
        rm -f "/tmp/${tool}.zip"; \
    done

COPY backend/app /app/app
COPY backend/tests /app/tests
COPY backend/pyproject.toml /app/pyproject.toml
COPY backend/requirements.lock /app/requirements.lock
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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
