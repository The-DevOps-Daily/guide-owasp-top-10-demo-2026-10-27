#!/usr/bin/env bash
# Static checks whose output the guide shows: Semgrep, Trivy and zizmor, plus
# validation of every example file (not shown, but the job fails if one breaks).
set -uo pipefail
cd "$(dirname "$0")/../.."
source scripts/ci/lib.sh

# Validation only
must 'cd examples/terraform && terraform init -backend=false -input=false -no-color > /dev/null && terraform validate -no-color && cd - > /dev/null'
must 'kubeconform -strict -summary examples/deploy/deployment.yaml examples/deploy/networkpolicy.yaml examples/insecure/deployment.yaml'
must 'mkdir -p examples/deploy/secrets && echo example > examples/deploy/secrets/db_password.txt'
must 'docker compose -f examples/deploy/compose.yaml config -q && docker compose -f examples/insecure/compose.yaml config -q'
must 'rm -rf examples/deploy/secrets'
must 'docker build -q -f examples/deploy/Dockerfile -t invoices-demo:ci .'
must 'docker build -q -f examples/insecure/Dockerfile -t invoices-demo:insecure .'
must 'actionlint examples/workflows/security.yml .github/workflows/guide.yml'
must 'lokitool rules lint --dry-run examples/alerts/loki-rules.yaml && lokitool rules check examples/alerts/loki-rules.yaml'

export NO_COLOR=1

# A05: static analysis of the vulnerable and the fixed code
capture semgrep-vulnerable 0 <<'CMD'
semgrep scan --config p/javascript --config p/owasp-top-ten --metrics off vulnerable/
CMD
capture semgrep-rules 0 <<'CMD'
semgrep scan --config semgrep.yml --metrics off vulnerable/ src/
CMD
capture semgrep-src 0 <<'CMD'
semgrep scan --config p/javascript --config p/owasp-top-ten --config semgrep.yml --metrics off --error src/
CMD

# A03: known vulnerabilities in a lockfile and in the container image
capture trivy-outdated 0 <<'CMD'
trivy fs --quiet --scanners vuln --format json examples/outdated | jq -r '.Results[].Vulnerabilities[] | [.Severity, .PkgName, .InstalledVersion, .VulnerabilityID, .FixedVersion] | @tsv' | column -t -s $'\t'
CMD
for tag in insecure ci; do
  capture "trivy-image-$tag" 0 <<CMD
trivy image --quiet --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --format json invoices-demo:$tag | jq -r '[.Results[] | {type: .Type, n: (.Vulnerabilities // [] | length)}] | group_by(.type)[] | "\(.[0].type): \(map(.n) | add)"'
CMD
done

# A02: misconfiguration in Kubernetes, Dockerfile and Terraform files
for dir in insecure deploy terraform; do
  capture "trivy-config-$dir" 0 <<CMD
trivy config --quiet --format json examples/$dir | jq -r '.Results[] | .Target as \$file | .Misconfigurations[]? | [\$file, .Severity, .ID, .Message] | @tsv'
CMD
done
# The same scans with the reviewed, expiring exceptions; any other finding fails
for dir in deploy terraform; do
  capture "trivy-accepted-$dir" 0 <<CMD
trivy config --quiet --ignorefile .trivyignore.yaml --exit-code 1 examples/$dir
CMD
done

# A03 and A08: the workflow itself is part of the supply chain
capture zizmor-insecure 14 <<'CMD'
zizmor -q examples/insecure/workflow.yml
CMD
capture zizmor-example 0 <<'CMD'
zizmor -q examples/workflows/security.yml
CMD

finish
