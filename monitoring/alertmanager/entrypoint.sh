#!/bin/sh
set -eu

# Helper to read a docker secret file into env var if present
read_secret_to_env() {
  secret_name="$1"
  env_name="$2"
  if [ -f "/run/secrets/${secret_name}" ]; then
    # shellcheck disable=SC2086
    export "${env_name}"=$(cat "/run/secrets/${secret_name}")
  fi
}

# Read known secrets into environment variables
read_secret_to_env smtp_smarthost SMTP_SMARTHOST
read_secret_to_env smtp_from SMTP_FROM
read_secret_to_env smtp_auth_username SMTP_AUTH_USERNAME
read_secret_to_env smtp_auth_password SMTP_AUTH_PASSWORD
read_secret_to_env slack_webhook_critical SLACK_WEBHOOK_CRITICAL
read_secret_to_env slack_webhook_warning SLACK_WEBHOOK_WARNING

# Fallback defaults if not set (do NOT use in production)
: "${SMTP_SMARTHOST:=smtp.example.com:587}"
: "${SMTP_FROM:=alertmanager@example.com}"
: "${SLACK_WEBHOOK_CRITICAL:=https://hooks.slack.com/services/T000/B000/XXX}"
: "${SLACK_WEBHOOK_WARNING:=https://hooks.slack.com/services/T000/B000/YYY}"

# Generate config from template using sed replacements (avoid requiring envsubst)
cp /etc/alertmanager/alertmanager.yml.tmpl /tmp/alertmanager.yml

replace_var() {
  name="$1"
  eval "val=\"\${${name}:-}\""
  # escape sed special chars
  val_escaped=$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')
  sed -i "s|\${${name}}|${val_escaped}|g" /tmp/alertmanager.yml
}

replace_var SMTP_SMARTHOST
replace_var SMTP_FROM
replace_var SMTP_AUTH_USERNAME
replace_var SMTP_AUTH_PASSWORD
replace_var SLACK_WEBHOOK_CRITICAL
replace_var SLACK_WEBHOOK_WARNING

mv /tmp/alertmanager.yml /etc/alertmanager/alertmanager.yml

# Exec Alertmanager directly as PID 1
exec /bin/alertmanager --config.file=/etc/alertmanager/alertmanager.yml
