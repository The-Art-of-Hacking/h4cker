#!/usr/bin/env bash
# Local helper to run gitleaks container for quick scans
set -euo pipefail

docker run --rm -v "$PWD":/src -w /src zricethezav/gitleaks:latest detect --source=.
