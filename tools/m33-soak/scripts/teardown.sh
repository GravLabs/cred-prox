#!/usr/bin/env bash
# Remove EVERYTHING this run owns - containers, network, volumes. Runs on every exit path
# of run-soak.sh (trap) and is safe to run twice. Leaves the run dir (evidence) alone.
set -u
cd "$(dirname "$0")/../compose" || exit 2
# compose file interpolation needs SOAK_RUN_DIR even for `down`; without it compose fails
# at config validation, and a swallowed error + unconditional marker printed a false
# TEARDOWN-DONE over live containers (B3 probe, 2026-11-09). Value is irrelevant here -
# `down` does not mount anything.
export SOAK_RUN_DIR="${SOAK_RUN_DIR:-/tmp/m33-teardown}"
docker compose down -v --remove-orphans >/dev/null 2>&1 \
  || { echo "TEARDOWN-FAIL: docker compose down errored"; exit 1; }
echo "TEARDOWN-DONE"
