#!/usr/bin/env bash
# Offline check: the sample's smoke cells live in the shared test project
# (tests/CredProx.SampleSmokes, Trait Sample=FoundryLocalGateway) — this script is the
# per-sample entry point CI keeps calling.
set -euo pipefail
cd "$(dirname "$0")/../.."
dotnet test tests/CredProx.SampleSmokes --filter "Sample=FoundryLocalGateway|Sample=Stamp"
