#!/usr/bin/env bash
# A02: ZAP baseline (passive) scans of the vulnerable and the fixed app.
# Both listen on 127.0.0.1 only, inside this CI runner.
set -uo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/lib.sh

DEMO_PASSWORD="$(openssl rand -hex 16)"
export DEMO_PASSWORD
nohup node vulnerable/server.js > vulnerable.log 2>&1 &
nohup node src/server.js > app.log 2>&1 &
must "timeout 30 bash -c 'until curl -sf http://127.0.0.1:3000/ > /dev/null && curl -sf http://127.0.0.1:3001/ > /dev/null; do sleep 1; done'"
must 'docker pull -q ghcr.io/zaproxy/zaproxy:2.17.0'

capture zap-vulnerable 0 <<'CMD'
docker run --rm --network host ghcr.io/zaproxy/zaproxy:2.17.0 zap-baseline.py -t http://127.0.0.1:3001/ -I | grep -v '^PASS'
CMD
capture zap-fixed 0 <<'CMD'
docker run --rm --network host ghcr.io/zaproxy/zaproxy:2.17.0 zap-baseline.py -t http://127.0.0.1:3000/ -I | grep -v '^PASS'
CMD
must 'mkdir -p zap && cp zap-rules.conf zap/rules.conf && chmod -R a+rwX zap'
capture zap-fixed-gated 0 <<'CMD'
docker run --rm --network host -v "$PWD/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:2.17.0 zap-baseline.py -t http://127.0.0.1:3000/ -c rules.conf | grep -v '^PASS'
CMD

finish
