# Monitoring stack — Prometheus + Blackbox Exporter + Grafana + Alertmanager ✅

This directory contains a minimal, self-hosted monitoring stack scaffold to monitor a target host (default: `192.168.18.1`).

Contents:
- `docker-compose.yml` — runs Prometheus, Blackbox Exporter, Grafana, and Alertmanager
- `prometheus/` — `prometheus.yml` and alerting rules
- `blackbox/` — `blackbox` config (icmp/tcp/http modules)
- `grafana/` — provisioning for datasources and a basic dashboard
- `alertmanager/` — Alertmanager config (edit to add receivers)
- `scripts/` — `ping_monitor.sh` (bash) and `tcp_probe.py` (python) for local checks
- `systemd/` — example unit files for the scripts
- `start.sh` — helper to bring up the stack

Quick start (docker-compose):
1. From this directory: `./start.sh`
2. Open Grafana at `http://localhost:3000` (user: `admin`, password: `admin`).
3. Prometheus UI: `http://localhost:9090`.
4. Alertmanager UI: `http://localhost:9093`.

Customize:
- Edit `prometheus/prometheus.yml` to change targets or modules.
- Configure Alertmanager receivers securely (Slack/email/webhook) using Docker secrets. See `monitoring/alertmanager/secrets/README.md` for details.
- The repo includes a local test webhook (port 5000) and templates under `alertmanager/templates/` for formatting.
- To test the webhook receiver: `docker compose -f docker-compose.yml up -d --build test-receiver` then `curl http://localhost:5000/` (returns "Test receiver OK"). Received webhook payloads are appended to `/var/log/alertmanager_webhook.log` inside the `test-receiver` container.
- Make `scripts/*.sh` executable and copy `systemd/*.service` to `/etc/systemd/system/` then `systemctl daemon-reload && systemctl enable --now ping-monitor.service`. ▼

Secret management (local & production)
- For local testing you can place secret files in `monitoring/alertmanager/secrets/` (this folder contains placeholder files and is ignored by Git).
- The Alertmanager service has been updated to build a custom image that reads secrets from `/run/secrets/` and replaces placeholders in `alertmanager/alertmanager.yml.tmpl` at startup.
- For production, use your secret manager (e.g., Docker Secrets, HashiCorp Vault, cloud provider secrets) and avoid committing credentials to the repo.

Reloading Alertmanager config
- After editing `alertmanager/alertmanager.yml.tmpl` or changing secrets, reload with:
  `curl -X POST http://localhost:9093/-/reload`
- To update secrets, replace the contents of the files in `monitoring/alertmanager/secrets/` (or update your secret manager) and then reload Alertmanager.

Security & compliance ⚠️
- Only monitor hosts you own or have explicit permission to monitor.
- Review and secure Grafana credentials before exposing to the internet.

Examples and small steps are intentionally minimal — tell me whether you prefer:
1) Extend probe list and add a `targets.yml` that Prometheus reads dynamically
2) Add a Grafana dashboard JSON with more panels (ICMP latency percentiles, alert list)
3) Add CI checks for Prometheus config validation

Security: Prevent committing secrets ✅
- Pre-commit: install pre-commit, then `pre-commit install` to enable the `detect-secrets` hook. A template baseline is provided as `.secrets.baseline.template`. Generate your actual baseline locally with:

  pip install detect-secrets
  detect-secrets scan > .secrets.baseline

- CI: a GitHub Action (`.github/workflows/secret-scan.yml`) runs `gitleaks` and `detect-secrets` on pushes and PRs to block commits that include secrets.

Local scan helper:
- `monitoring/scripts/run_gitleaks.sh` — runs gitleaks in a container against the repo.

Notes:
- Update the `.secrets.baseline` locally to accept intentional secrets (API tokens in local dev config, etc.).
- This setup is a guard but not a replacement for a secret manager. For production, use external secret stores and policies.

