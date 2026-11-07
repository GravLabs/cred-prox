#!/usr/bin/env bash
# E8 smoke in stub mode (plan §6: "stub mode in CI"): generated RSA App key and both
# GitHub endpoints in-process — no Docker and no GitHub account needed.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --smoke
