#!/usr/bin/env sh
set -eu

IMAGE="${1:-dfir_app-frontend}"
NETWORK="kairon-frontend-nginx-test-$$"
BACKEND="kairon-backend-stub-$$"
FRONTEND="kairon-frontend-nginx-test-$$"
BACKEND_LOG="/tmp/kairon-backend-stub-$$.log"
PORT="${KAIRON_FRONTEND_TEST_PORT:-5173}"

cleanup() {
  docker rm -f "$FRONTEND" "$BACKEND" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -f "$BACKEND_LOG" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$NETWORK" >/dev/null

docker run -d --name "$BACKEND" --network "$NETWORK" --network-alias backend python:3.12-alpine \
  sh -lc 'python -u - <<"PY"
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.path, flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"path": self.path}).encode())

    def do_PUT(self):
        print(self.path, flush=True)
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
PY' >/dev/null

docker run -d --name "$FRONTEND" --network "$NETWORK" -p "${PORT}:80" "$IMAGE" >/dev/null

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:${PORT}/" >/tmp/kairon-index-check.html; then
    break
  fi
  sleep 1
done

docker exec "$FRONTEND" nginx -t >/dev/null
docker exec "$FRONTEND" sh -lc 'test -f /usr/share/nginx/html/index.html'
docker exec "$FRONTEND" sh -lc '! ps aux | grep -E "[v]ite|[n]ode.*5173"'
docker exec "$FRONTEND" sh -lc 'grep -q "proxy_request_buffering off" /etc/nginx/conf.d/default.conf'
docker exec "$FRONTEND" sh -lc 'grep -q "proxy_pass http://backend:8000" /etc/nginx/conf.d/default.conf'

grep -qi '<html' /tmp/kairon-index-check.html
curl -fsS "http://127.0.0.1:${PORT}/cases/deep/link" >/tmp/kairon-spa-check.html
grep -qi '<html' /tmp/kairon-spa-check.html

ASSET_PATH="$(docker exec "$FRONTEND" sh -lc 'find /usr/share/nginx/html/assets -type f | head -n 1 | sed "s#^/usr/share/nginx/html##"')"
test -n "$ASSET_PATH"
curl -fsS "http://127.0.0.1:${PORT}${ASSET_PATH}" >/dev/null

curl -fsS "http://127.0.0.1:${PORT}/api/proxy-preserve?x=1" >/tmp/kairon-api-check.json
grep -q '"path": "/api/proxy-preserve?x=1"' /tmp/kairon-api-check.json

STATUS_AND_SIZE="$(curl -sS -o /tmp/kairon-204-check.body -w '%{http_code} %{size_download}' -X PUT --data-binary 'abc' "http://127.0.0.1:${PORT}/api/cases/case-id/memory/uploads/upload-id/chunks/0")"
test "$STATUS_AND_SIZE" = "204 0"

docker logs "$BACKEND" > "$BACKEND_LOG"
grep -q '/api/proxy-preserve?x=1' "$BACKEND_LOG"
grep -q '/api/cases/case-id/memory/uploads/upload-id/chunks/0' "$BACKEND_LOG"
docker port "$FRONTEND" | grep -Eq '80/tcp -> .*:5173'

echo "FRONTEND_NGINX_VALIDATION_OK"
