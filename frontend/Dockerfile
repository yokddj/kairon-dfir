FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG KAIRON_VERSION=1.1.0

WORKDIR /workspace/frontend

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

COPY frontend/ ./
COPY docs ../docs
RUN npm run build

FROM nginx:stable-alpine@sha256:0d3b80406a13a767339fbe2f41406d6c7da727ab89cf8fae399e81f780f814d1

ARG KAIRON_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG KAIRON_VERSION=1.1.0

LABEL org.opencontainers.image.title="Kairon DFIR frontend" \
      org.opencontainers.image.version="${KAIRON_VERSION}" \
      org.opencontainers.image.revision="${KAIRON_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/frontend/dist /usr/share/nginx/html

EXPOSE 80
