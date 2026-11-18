#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Runs mayhem/build/oracle_probe (built by build.sh with normal flags, dynamically linked against the
# real usr/ initiator code). It asserts known-answer values: an idbm record file parsed and printed
# back, an iSCSI login exchange against canned target PDUs (status, negotiated MaxRecvDataSegmentLength,
# the request text the initiator sent), the CHAP MD5 response for a known id/challenge/secret, and a
# SendTargets discovery against canned Text Response PDUs (the node records, portals and tags it builds).
probe="$SRC/mayhem/build/oracle_probe"
if [ ! -x "$probe" ]; then
  echo "missing $probe: mayhem/build.sh must build it" >&2
  emit_ctrf "open-iscsi-kat" 0 1 0
  exit 1
fi

out=$("$probe" 2>&1); rc=$?
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | grep -c '^ok ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL ')
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ "$passed" -lt 30 ]; then failed=$(( failed + 1 )); fi

# Upstream's own libopeniscsiusr suite (libopeniscsiusr/tests, `TESTS` in libopeniscsiusr/Makefile and
# meson.build): each binary assert()s its results and exits non-zero on a failure. build.sh compiled them
# against a copy of the library whose idbm root and lock dir are mayhem/build/utest-db, recreated here so
# every run starts from an empty node/iface database. With no live sessions, test_session and test_node check
# little; the known-answer probe above stays the behavioral oracle.
db="$SRC/mayhem/build/utest-db"
rm -rf "$db" && mkdir -p "$db"
for t in context iface node session; do
  bin="$SRC/mayhem/build/test_$t"
  if [ ! -x "$bin" ]; then
    echo "FAIL test_$t: missing $bin (mayhem/build.sh must build it)"
    failed=$(( failed + 1 )); continue
  fi
  if "$bin" > "$SRC/mayhem/build/test_$t.log" 2>&1; then
    echo "ok test_$t"; passed=$(( passed + 1 ))
  else
    echo "FAIL test_$t (exit $?)"; tail -n 20 "$SRC/mayhem/build/test_$t.log"
    failed=$(( failed + 1 ))
  fi
done

emit_ctrf "open-iscsi-kat" "$passed" "$failed" 0
