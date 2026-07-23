#!/usr/bin/env sh
# Fail if total statement coverage falls below the threshold.
#
# Lives in one place so CI, the release workflow, and `make coverage-check` all
# enforce the same number — a threshold that differs between local and CI is
# worse than none, because it trains people to ignore it.
#
# Usage: scripts/coverage-check.sh [profile] [minimum]
set -eu

profile="${1:-coverage.out}"
minimum="${2:-${COVERAGE_MIN:-80}}"

if [ ! -f "$profile" ]; then
    echo "coverage-check: no profile at $profile — run go test -coverprofile first" >&2
    exit 1
fi

total=$(go tool cover -func="$profile" | awk '/^total:/ { gsub(/%/, "", $3); print $3 }')

if [ -z "$total" ]; then
    echo "coverage-check: could not read a total from $profile" >&2
    exit 1
fi

awk -v have="$total" -v want="$minimum" 'BEGIN {
    if (have + 0 < want + 0) {
        printf "FAIL: coverage %.1f%% is below the %.1f%% threshold\n", have, want
        exit 1
    }
    printf "ok: coverage %.1f%% meets the %.1f%% threshold\n", have, want
}'
