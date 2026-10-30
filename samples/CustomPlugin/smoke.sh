#!/usr/bin/env bash
# E10 in stub mode (plan §6): the conformance suite the plugin ships, then the full
# proxy path against in-process vendor stubs — no Docker, no vendor account.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --selftest
dotnet run -- --smoke
