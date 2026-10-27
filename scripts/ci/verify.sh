#!/usr/bin/env bash
# A08: verify the build provenance attestation of the package tarball.
set -uo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/lib.sh

capture attestation-verify 0 <<'CMD'
gh attestation verify owasp-top-10-demo-1.0.0.tgz --repo The-DevOps-Daily/guide-owasp-top-10-demo-2026-10-27
CMD

finish
