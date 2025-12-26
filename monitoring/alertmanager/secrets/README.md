This directory is for *local secret placeholders* used by the Alertmanager Docker Compose setup.

IMPORTANT: Do NOT commit real secrets. Replace the placeholders with your real secrets on your local machine or use Docker secret management.

Example secret files (place in this folder or create them elsewhere and point docker-compose secrets to them):
- `smtp_smarthost` — e.g. "smtp.example.com:587"
- `smtp_from` — e.g. "alertmanager@example.com"
- `smtp_auth_username` — SMTP username (if needed)
- `smtp_auth_password` — SMTP password (if needed)
- `slack_webhook_critical` — Slack incoming webhook URL for critical alerts
- `slack_webhook_warning` — Slack incoming webhook URL for warnings

For local testing you can populate these with dummy values, e.g.: 

  echo "smtp.example.com:587" > smtp_smarthost

Add this folder to `.gitignore` or only store placeholders here; never commit real credentials.
