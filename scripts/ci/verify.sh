#!/usr/bin/env bash
# A08: verify the build provenance attestation of the package tarball.
set -uo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/lib.sh

capture release-download 0 <<'CMD'
gh release download v1 --repo The-DevOps-Daily/guide-owasp-top-10-demo-2026-10-27 --pattern 'owasp-top-10-demo-1.0.0.tgz' --dir release --clobber
CMD
capture attestation-verify 0 <<'CMD'
gh attestation verify release/owasp-top-10-demo-1.0.0.tgz --repo The-DevOps-Daily/guide-owasp-top-10-demo-2026-10-27 --signer-workflow The-DevOps-Daily/guide-owasp-top-10-demo-2026-10-27/.github/workflows/guide.yml --source-ref refs/heads/main
CMD

finish
