ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="Kairon MCP server" \
      org.opencontainers.image.description="A generic MCP server over Kairon DFIR's read-only case tools" \
      org.opencontainers.image.source="https://github.com/yokddj/kairon-dfir"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system --gid 10001 kairon \
    && adduser --system --uid 10001 --ingroup kairon --home /home/kairon kairon

# This image is a standalone client of Kairon's API: it never imports
# app.*, so only this directory is needed, not the rest of backend/.
COPY backend/mcp_server /app/mcp_server

RUN pip install --no-cache-dir /app/mcp_server

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ENV KAIRON_COMMIT="${KAIRON_COMMIT}"
LABEL org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

USER 10001:10001

ENTRYPOINT ["kairon-mcp-server"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8800"]
