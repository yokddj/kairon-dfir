FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DOTNET_ROOT=/opt/dotnet
ENV PATH="/opt/dotnet:${PATH}"
ENV EVTXECMD_DOTNET_DLL=/opt/evtxecmd/EvtxECmd.dll
ENV EZTOOLS_ROOT=/opt/eztools

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev libyara-dev pkg-config p7zip-full curl ca-certificates libicu76 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /opt/dotnet \
    && mkdir -p /opt/evtxecmd \
    && curl -fsSL https://download.ericzimmermanstools.com/net9/EvtxECmd.zip -o /tmp/EvtxECmd.zip \
    && python -m zipfile -e /tmp/EvtxECmd.zip /opt/evtxecmd \
    && ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet \
    && ln -sf "$(find /opt/evtxecmd -iname EvtxECmd.dll -print -quit)" /opt/evtxecmd/EvtxECmd.dll \
    && rm -f /tmp/dotnet-install.sh /tmp/EvtxECmd.zip

RUN set -eux; \
    mkdir -p /opt/eztools; \
    for tool in LECmd JLECmd PECmd AmcacheParser AppCompatCacheParser RECmd MFTECmd SrumECmd; do \
        mkdir -p "/opt/eztools/${tool}"; \
        curl -fsSL "https://download.ericzimmermanstools.com/net9/${tool}.zip" -o "/tmp/${tool}.zip"; \
        python -m zipfile -e "/tmp/${tool}.zip" "/opt/eztools/${tool}"; \
        dll="$(find "/opt/eztools/${tool}" -iname "${tool}.dll" -print -quit)"; \
        test -n "$dll"; \
        if [ "$dll" != "/opt/eztools/${tool}/${tool}.dll" ]; then ln -sf "$dll" "/opt/eztools/${tool}/${tool}.dll"; fi; \
        rm -f "/tmp/${tool}.zip"; \
    done

COPY backend/app /app/app
COPY backend/tests /app/tests
COPY backend/pyproject.toml /app/pyproject.toml
COPY docs /app/docs
COPY tools/demo /app/tools/demo
RUN pip install --no-cache-dir ".[dev]"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
