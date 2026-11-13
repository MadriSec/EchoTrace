#!/usr/bin/env bash
#############################################################################
# workload_validation.sh - compare SysJava seccomp policies against the
# syscalls containers actually make under a real workload (the
# docker-library/official-images smoke tests).
#
# For every subject in subjects.conf, sequentially, and every test:
#   workload  run the test under an allow-all seccomp filter while bpftrace counts
#             every syscall made by the container under test, then diff:
#               missing = observed - policy   (needed, not found by SysJava)
#               used    = observed & policy
#               unused  = policy - observed   (allowed, not exercised)
#             with each policy syscall attributed to its SysJava source.
#             In the same run a second bpftrace records the binaries executed and the
#             native libraries (and jars) opened by the container under test,
#             and these are diffed against SysJava's startup discovery:
#               new = seen under the workload, not at startup
#   enforce   run the same test under the SysJava policy: does it still pass?
#
# Run as root (bpftrace needs it), keeping your PATH for jq/python3:
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh            # all
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation.sh cassandra  # some
#
# Environment:
#   PHASES=workload,enforce   phases to run
#   TEST_TIMEOUT=1200         per-test timeout (s)
#   ARTIFACTS=1               0 = do not record the binaries/libraries of the workload
#   OI_REF=<commit>           pin docker-library/official-images (recorded in meta.txt)
#   CONF=<file>               subjects file (default: subjects.conf next to this script)
#   SYSJAVA_ROOT=<dir>        SysJava artifact (default: ../SysJava, next to Prototype)
#   SYSJAVA_RESULTS=<dir>     SysJava policies (default: $SYSJAVA_ROOT/2_swat4j_vs_sysjava/sysjava_results)
#   OUT=<dir>                 output dir (default: workload_validation_runs/results)
#
# Output: one folder per subject under $OUT. Re-running a subject replaces only
# that subject's results (and only for the phases that ran). At the end,
# report.py prints the per-subject diff and writes $OUT/report.csv.
#
# Requires: x86_64 Linux, root, docker, bpftrace, jq, git, python3, timeout.
# The binaries/libraries diff needs a kernel with BTF and fentry (bpftrace >= 0.20).
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${CONF:-$HERE/subjects.conf}"
WV_EXTRA_TOOLS="git"
source "$HERE/wv_lib.sh"   # configuration, preflight, tracing, prepare_subject, postprocess

OI_DIR="${OI_DIR:-$ROOT/.cache/official-images}"
OI_REF="${OI_REF:-}"
mkdir -p "$OUT/bin"

GIT=(git -c safe.directory='*')
if [[ ! -d "$OI_DIR/.git" ]]; then
  log "cloning docker-library/official-images into $OI_DIR"
  "${GIT[@]}" clone -q https://github.com/docker-library/official-images.git "$OI_DIR" || die "clone failed"
fi
if [[ -n $OI_REF ]]; then
  "${GIT[@]}" -C "$OI_DIR" fetch -q origin && "${GIT[@]}" -C "$OI_DIR" checkout -q "$OI_REF" \
    || die "cannot check out $OI_REF"
fi
OI_COMMIT="$("${GIT[@]}" -C "$OI_DIR" rev-parse HEAD)"

# Docker shim, first on PATH for the test scripts: adds the cgroup parent (and,
# in the enforce phase, the seccomp policy) to the `docker run` that starts the
# container under test. Every other docker call passes through unchanged.
cat > "$OUT/bin/docker" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == run && -n "${WV_MODE:-}" ]]; then
  detached=0
  for a in "${@:2}"; do [[ "$a" == -d || "$a" == --detach ]] && detached=1; done
  if [[ "$WV_MODE" == all || $detached == 1 ]]; then
    shift
    extra=(--cgroup-parent "$WV_CGROUP_PARENT")
    [[ -n "${WV_PROFILE:-}" ]] && extra+=(--security-opt "seccomp=$WV_PROFILE")
    echo "$(date +%s) docker run ${extra[*]} $*" >> "$WV_INJECT_LOG"
    if (( detached )); then
      cid="$("$WV_REAL_DOCKER" run "${extra[@]}" "$@")"; rc=$?
      [[ -n "$cid" ]] && { echo "cid $cid" >> "$WV_INJECT_LOG"; echo "$cid"; }
      exit $rc
    fi
    exec "$WV_REAL_DOCKER" run "${extra[@]}" "$@"
  fi
fi
exec "$WV_REAL_DOCKER" "$@"
EOF
chmod +x "$OUT/bin/docker"

RUN_META+="
official-images: $OI_COMMIT"
log "output: $OUT"

run_test() {  # image test inject_mode profile('' = none) out_prefix -> prints status
  local image=$1 t=$2 mode=$3 profile=$4 pre=$5 tdir="$OI_DIR/test/tests/$2" rc status
  [[ -x "$tdir/run.sh" ]] || { echo missing-test; return; }
  : > "$pre.injected"
  WV_MODE="$mode" WV_PROFILE="$profile" WV_CGROUP_PARENT="$CG_PARENT" WV_INJECT_LOG="$pre.injected" \
    WV_REAL_DOCKER="$REAL_DOCKER" PATH="$OUT/bin:$PATH" \
    timeout "$TEST_TIMEOUT" "$tdir/run.sh" "$image" < /dev/null > "$pre.stdout" 2> "$pre.stderr"
  rc=$?
  # remove containers left behind (e.g. after a timeout)
  awk '$1 == "cid" { print $2 }' "$pre.injected" | xargs -r "$REAL_DOCKER" rm -f >/dev/null 2>&1
  if (( rc == 124 )); then status=timeout
  elif (( rc != 0 )); then status=fail
  elif [[ -f "$tdir/expected-std-out.txt" ]] && ! diff -q "$tdir/expected-std-out.txt" "$pre.stdout" >/dev/null; then
    status=fail-output
  else status=pass; fi
  grep -q 'docker run' "$pre.injected" || status="$status(container-not-found!)"
  echo "$status"
}

# ------------------------------------------------------------------ main loop
while read -r -u 3 subject image policy_rel mode tests _; do
  [[ -z "${subject:-}" || "$subject" == \#* ]] && continue
  if (( $# )) && [[ " $* " != *" $subject "* ]]; then continue; fi
  log "==================== $subject ($image)"
  prepare_subject "$subject" "$image" "$policy_rel" "inject: $mode  tests: $tests" || continue

  IFS=',' read -ra test_list <<< "$tests"
  for t in "${test_list[@]}"; do
    if has_phase workload; then
      rm -f "$sd/$t.workload."*
      log "[$subject] $t: workload run (allow-all filter, tracing)"
      trace_start "$sd/$t.workload"
      wl="$(run_test "$image" "$t" "$mode" "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
      trace_stop
      echo "$wl" > "$sd/$t.workload.status"
      log "[$subject] $t: workload run -> $wl"
      postprocess "$sd/$t.workload"
    fi

    if has_phase enforce; then
      rm -f "$sd/$t.enforce."*
      log "[$subject] $t: enforce run (SysJava policy)"
      en="$(run_test "$image" "$t" "$mode" "$sd/policy.json" "$sd/$t.enforce")"
      echo "$en" > "$sd/$t.enforce.status"
      log "[$subject] $t: enforce run -> $en"
    fi
  done
done 3< "$CONF"

echo
"$PY" "$HERE/report.py" "$OUT"
