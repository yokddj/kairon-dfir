#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DFIR_BASE_URL:-http://127.0.0.1:8000}"
CASE_ID="${DFIR_DEMO_CASE_ID:-}"
PACKAGE_PATH="${1:-}"

if [[ -z "${CASE_ID}" || -z "${PACKAGE_PATH}" ]]; then
  echo "Usage: DFIR_DEMO_CASE_ID=<case-id> $0 <validation-metadata.json>"
  echo "This helper is a placeholder for deployment-specific demo metadata import."
  exit 2
fi

echo "Demo metadata import is deployment-specific."
echo "Backend: ${BASE_URL}"
echo "Case: ${CASE_ID}"
echo "Package: ${PACKAGE_PATH}"
echo "No evidence is uploaded by this script."
