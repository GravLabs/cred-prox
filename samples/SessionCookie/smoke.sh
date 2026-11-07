#!/usr/bin/env bash
# E16 smoke (in-process, no Docker): the session-cookie vendor — form login issuing
# Set-Cookie and a cookie-guarded API — is stubbed in the same host. The stubs make the
# checks the real vendor makes (form credentials on the login, the live session cookie on
# the API), so 200s prove the egress path; the session value, the login passwords and the
# caller's own cookies must appear nowhere the caller or the logs can see them.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --smoke
