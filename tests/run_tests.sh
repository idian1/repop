#!/usr/bin/env bash
#
# beavertrap test harness.
#
# Fixtures are inert. Never replace them with real malware samples.
#
# The fixtures under tests/fixtures/ contain suspicious-LOOKING strings (known
# IOCs stored as \xNN hex escapes, a postinstall hook, a folderOpen VS Code
# task, recruiter-scam pretext text) but NO working payload. The referenced
# "payload" only does console.log. Do not add real malware here for "realism".
#
# What this asserts:
#   * tests/fixtures/malicious/ -> beavertrap prints CRITICAL and exits 2
#   * tests/fixtures/clean/     -> beavertrap prints LOW      and exits 0
#
# Both fixtures are committed to the repo, so this script only runs the scanner
# against them. It never mutates them.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SCANNER="$ROOT/beavertrap.py"
FIXTURES="$HERE/fixtures"

PASS=0
FAIL=0

# run_case <fixture-dir> <expected-verdict> <expected-exit-code>
run_case() {
  local dir="$1" want_verdict="$2" want_exit="$3"
  local out rc

  out="$(python3 "$SCANNER" "$dir" --no-color 2>&1)"
  rc=$?

  local got_verdict
  got_verdict="$(printf '%s\n' "$out" | grep -Eo 'VERDICT: [A-Z]+' | head -n1 | awk '{print $2}')"

  if [ "$got_verdict" = "$want_verdict" ] && [ "$rc" = "$want_exit" ]; then
    echo "PASS  $(basename "$dir"): verdict=$got_verdict exit=$rc"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $(basename "$dir"): expected verdict=$want_verdict exit=$want_exit, got verdict=${got_verdict:-<none>} exit=$rc"
    echo "----- scanner output -----"
    printf '%s\n' "$out"
    echo "--------------------------"
    FAIL=$((FAIL + 1))
  fi
}

if [ ! -f "$SCANNER" ]; then
  echo "FAIL  scanner not found at $SCANNER"
  exit 1
fi

echo "Running beavertrap against test fixtures..."
echo
run_case "$FIXTURES/malicious" "CRITICAL" 2
run_case "$FIXTURES/clean"     "LOW"      0
echo
echo "Results: $PASS passed, $FAIL failed."

[ "$FAIL" -eq 0 ] || exit 1
