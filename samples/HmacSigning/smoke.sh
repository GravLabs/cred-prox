#!/usr/bin/env bash
# E9 smoke (plan §6: "CI yes"): the signature-verifying vendor stub lives in-process,
# so no Docker and no vendor account are needed.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --smoke
