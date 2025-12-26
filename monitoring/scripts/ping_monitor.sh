#!/usr/bin/env bash
# Simple ping monitor for 192.168.18.1
IP=${IP:-192.168.18.1}
LOG=${LOG:-/var/log/monitor_${IP}.log}
INTERVAL=${INTERVAL:-60}

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

while true; do
  ts=$(date -Iseconds)
  if ping -c 1 -W 2 "$IP" >/dev/null 2>&1; then
    echo "$ts UP" >> "$LOG"
  else
    echo "$ts DOWN" >> "$LOG"
    # Place hooks here (curl webhook, systemctl restart, etc.)
  fi
  sleep "$INTERVAL"
done
