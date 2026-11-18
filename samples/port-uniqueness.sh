#!/usr/bin/env bash
# Offline check: the cross-sample host-port uniqueness guard plus the loaded-library
# stamp gate (tests/CredProx.SampleSmokes, Traits Sample=PortUniqueness and
# Sample=Stamp) — they read the sample configs and fixtures, so no sample process and
# no compose stack are involved. The detailed console logger makes the stamp cell's
# CREDPROX_STAMP lines (which library bytes each test host loaded) visible in the run
# output.
set -euo pipefail
cd "$(dirname "$0")/.."
dotnet test tests/CredProx.SampleSmokes --filter "Sample=PortUniqueness|Sample=Stamp" --logger "console;verbosity=detailed"
