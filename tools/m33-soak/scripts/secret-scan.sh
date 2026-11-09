#!/usr/bin/env bash
# §5.5 secret hygiene, product-side scope: every injected sentinel must appear ZERO times
# in everything CREDPROX produced - host logs, k6 caller-side outputs, stats CSV, per-fault
# log slices. The WireMock journal is deliberately NOT in the blanket scan: it is the
# vendor-side wire witness and legitimately carries raw stub secrets on the wire (M20
# scrubbed-echo doctrine: raw expected vendor-side, redacted caller-side - the caller-side
# witness is soak.js noSentinelInBody plus this scan of the product's own outputs).
# Hits land OUTSIDE the scanned paths. Exit 0 = clean, 1 = hit, 2 = scan incomplete.
set -u
RUN="${1:?usage: secret-scan.sh <run-dir>}"
[ -f "$RUN/sentinels.txt" ] || { echo "no sentinels.txt in $RUN"; exit 2; }
PATHS=("$RUN/logs" "$RUN/k6-line.csv" "$RUN/stats.csv")
[ -d "$RUN/faults" ] && PATHS+=("$RUN/faults")
grep -rF -f "$RUN/sentinels.txt" "${PATHS[@]}" \
  > "$RUN/secret-scan-hits.txt" 2> "$RUN/secret-scan-stderr.txt"
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "SECRET-SCAN FAILED - hits:"; head -5 "$RUN/secret-scan-hits.txt" | cut -c1-200; exit 1
elif [ "$rc" -eq 1 ]; then
  echo "SECRET-SCAN-OK (zero hits)"
  [ -s "$RUN/secret-scan-stderr.txt" ] && { echo "SCAN-WARN stderr non-empty:"; head -3 "$RUN/secret-scan-stderr.txt"; exit 2; }
  exit 0
else
  echo "SECRET-SCAN ERROR (grep rc=$rc - scan incomplete):"; head -3 "$RUN/secret-scan-stderr.txt"; exit 2
fi
