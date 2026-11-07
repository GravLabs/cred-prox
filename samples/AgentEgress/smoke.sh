#!/usr/bin/env bash
# E15 smoke (in-process, no Docker): the Salesforce token endpoint and data API are
# stubbed in the same host. The stubs make the checks the real vendor makes (client
# credentials on the token call, session bearer on the API), so 200s prove the egress
# path; the session token must appear nowhere in what the agents receive or the logs.
set -euo pipefail
cd "$(dirname "$0")"

dotnet run -- --smoke
