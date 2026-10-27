#!/usr/bin/env bash
# Static checks whose output the guide shows: Semgrep, Trivy and zizmor, plus
# validation of every example file (not shown, but the job fails if one breaks).
set -uo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/lib.sh

# Validation only
must 'cd examples/terraform && terraform init -backend=false -input=false -no-color > /dev/null && terraform validate -no-color && cd - > /dev/null'
must 'kubeconform -strict -summary examples/deploy/deployment.yaml examples/insecure/deployment.yaml'
must 'mkdir -p examples/deploy/secrets && echo example > examples/deploy/secrets/db_password.txt'
must 'docker compose -f examples/deploy/compose.yaml config -q && docker compose -f examples/insecure/compose.yaml config -q'
must 'rm -rf examples/deploy/secrets'
must 'docker build -q -f examples/deploy/Dockerfile -t invoices-demo:ci .'
must 'actionlint examples/workflows/security.yml .github/workflows/guide.yml'

# A05: static analysis of the vulnerable and the fixed code
capture semgrep-vulnerable 0 <<'CMD'
semgrep scan --config p/javascript --config p/owasp-top-ten --metrics off vulnerable/
CMD
capture semgrep-src 0 <<'CMD'
semgrep scan --config p/javascript --config p/owasp-top-ten --metrics off src/
CMD

# A03: known vulnerabilities in a lockfile
capture trivy-outdated 0 <<'CMD'
trivy fs --scanners vuln examples/outdated
CMD

# A02: misconfiguration in Kubernetes, Dockerfile and Terraform files
capture trivy-config-insecure 0 <<'CMD'
trivy config examples/insecure
CMD
capture trivy-config-deploy 0 <<'CMD'
trivy config examples/deploy
CMD
capture trivy-config-terraform 0 <<'CMD'
trivy config examples/terraform
CMD
capture trivy-image 0 <<'CMD'
trivy image --scanners vuln --severity HIGH,CRITICAL invoices-demo:ci
CMD

# A03 and A08: the workflow itself is part of the supply chain
capture zizmor-example 0 <<'CMD'
zizmor examples/workflows/security.yml
CMD

finish
