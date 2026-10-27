# OWASP Top 10:2025: companion repository

A small invoices API (Express 5 on Node.js 24 LTS) for the DevOps Daily guide
[OWASP Top 10](https://devops-daily.com/guides/owasp-top-10).

> [!WARNING]
> This is a teaching app. `vulnerable/` contains deliberate security flaws, one or more
> for each OWASP Top 10:2025 category. Never deploy it or expose it to a network. Both
> servers listen on `127.0.0.1` only.

- `src/` is the fixed app: access checks in the queries, parameterized SQL, an SSRF-safe
  fetch, Argon2id password hashes, sessions that expire and end on logout, security headers,
  request limits, a central error handler, transactions that roll back, and JSON logs.
- `vulnerable/` is the "before" version of the same routes, used to show what tests and
  scanners catch.
- `tests/` holds one test file per category. `APP=vulnerable` runs a test file against the
  vulnerable version.
- `examples/` holds the configuration files from the guide: a hardened Dockerfile, Kubernetes
  and Compose files (with insecure versions in `examples/insecure/`), Terraform, an old Express
  lockfile for the dependency audit, and an example security workflow. The workflow is under
  `examples/workflows/` on purpose, so it never runs in this repository.
- `.github/workflows/guide.yml` runs Semgrep, Trivy, zizmor and ZAP baseline scans and an
  artifact attestation when started by hand. The scanner output in the guide comes from these runs.

## Run it

You need Node.js 24.7 or later (for the built-in `crypto.argon2`).

```bash
git clone https://github.com/The-DevOps-Daily/guide-owasp-top-10-demo-2026-10-27.git
cd guide-owasp-top-10-demo-2026-10-27
npm ci
npm test
DEMO_PASSWORD='correct horse battery staple' npm start
```

The server refuses to start without `DEMO_PASSWORD` (15 characters or more): every demo user
gets that password. There are no default credentials.
