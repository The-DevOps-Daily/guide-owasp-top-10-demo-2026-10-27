#!/usr/bin/env bash
# Installs the pinned scanners for the guide runs into ~/.local/bin, checking
# every download against a SHA-256 written here (not one fetched next to it).
set -euo pipefail
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
  curl -fsSL --retry 3 -o "$work/$3" "$1"
  echo "$2  $work/$3" | sha256sum -c --quiet -
}

fetch https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz \
  c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 trivy.tgz
tar -xzf "$work/trivy.tgz" -C "$BIN" trivy

fetch https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
  8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 actionlint.tgz
tar -xzf "$work/actionlint.tgz" -C "$BIN" actionlint

fetch https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz \
  9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 kubeconform.tgz
tar -xzf "$work/kubeconform.tgz" -C "$BIN" kubeconform

fetch https://releases.hashicorp.com/terraform/1.17.0/terraform_1.17.0_linux_amd64.zip \
  c168cab7c637a8769fdb90089ddd19de701bc6ff8aca64dc2e2185fe46f59f67 terraform.zip
unzip -q -o "$work/terraform.zip" terraform -d "$BIN"

fetch https://github.com/grafana/loki/releases/download/v3.7.9/lokitool-linux-amd64.zip \
  eba96fc190bb3c4c14ae96c69212bd9aacd92644e7fa2565e12b46a5031d10d9 lokitool.zip
unzip -q -o -j "$work/lokitool.zip" -d "$work/lokitool"
install -m 0755 "$work/lokitool/lokitool-linux-amd64" "$BIN/lokitool"

pipx install --quiet semgrep==1.182.1
pipx install --quiet zizmor==1.31.1

trivy --version | head -1
semgrep --version
zizmor --version
