#!/usr/bin/env bash
# Authenticated ZAP API scan of a LOCAL DocVault instance (never point this at a system you do not own).
# Usage: TOKEN=<access token> dast/run-zap.sh
set -euo pipefail
: "${TOKEN:?export TOKEN with a valid access token first}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
OUT=docs/evidence/zap
mkdir -p "$OUT" && chmod 777 "$OUT"        # the ZAP container writes as its own user
cp dast/openapi.yaml "$OUT/openapi.yaml"
# --network host: the container reaches the app at localhost:5000 (Linux).
# ZAP_AUTH_HEADER*: ZAP adds "Authorization: Bearer <token>" to every request it sends.
docker run --rm --network host \
  -e ZAP_AUTH_HEADER=Authorization \
  -e ZAP_AUTH_HEADER_VALUE="Bearer ${TOKEN}" \
  -v "$(pwd)/$OUT:/zap/wrk:rw" \
  "$ZAP_IMAGE" zap-api-scan.py \
    -t /zap/wrk/openapi.yaml -f openapi \
    -r zap-report.html -J zap-report.json -w zap-report.md \
    -I || true                               # -I: do not fail on warnings; we read the report
rm -f "$OUT/openapi.yaml"
echo "Report: $OUT/zap-report.html"
