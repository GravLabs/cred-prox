#!/usr/bin/env bash
# E13 smoke (in-process, no Docker): the provider is stubbed in the same host so the SSE
# timing assertion is deterministic — the stub flushes a first event, waits 400 ms, then
# writes the second; the smoke fails if CredProx delivered them buffered together.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --smoke
