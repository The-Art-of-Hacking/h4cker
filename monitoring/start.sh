#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Starting monitoring stack (docker compose)..."
# Use docker compose, ensure Docker is installed and user has permission
docker compose up -d

echo "Stack started. Prometheus: http://localhost:9090, Grafana: http://localhost:3000 (admin/admin), Alertmanager: http://localhost:9093"
