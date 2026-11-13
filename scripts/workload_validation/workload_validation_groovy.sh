#!/usr/bin/env bash
#############################################################################
# workload_validation_groovy.sh - the workload validation of
# workload_validation.sh for Groovy, with the benchmark scripts of Apache
# Groovy's own repository (benchmark/bench/*.groovy) as the workload.
#
# The Groovy container is itself the workload: every benchmark run is one
# container of the analyzed image, started with the image's `groovy` command
# (groovy_subject.conf lists the scripts and their inputs). All runs of a
# phase are traced together and reported as one test, groovy-bench.
#
#   workload  the runs under an allow-all seccomp filter while bpftrace records
#             their syscalls, binaries and libraries; then the diffs against
#             the SysJava policy and against SysJava's startup discovery.
#   enforce   the same runs under the SysJava policy: do they still pass?
#
# Results go to the same folder and in the same layout as
# workload_validation.sh (subject: groovy, test: groovy-bench), so report.py
# and table.py cover it.
#
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation_groovy.sh
#
# Environment (plus those of workload_validation.sh: PHASES, ARTIFACTS, OUT, ...):
#   GROOVY_BENCH_DIR=<dir>    folder with the .groovy scripts (default: downloaded
#                             once from GitHub at BENCH_TAG to .cache/groovy-bench/)
#   RUN_TIMEOUT=600           seconds allowed for one benchmark run
#
# Requires: as workload_validation.sh, plus network access for the first run
# (the benchmark scripts).
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${CONF:-$HERE/groovy_subject.conf}"
source "$HERE/wv_lib.sh"   # configuration, preflight, tracing, prepare_subject, postprocess
BENCHMARKS=(); RUN_ARGS=()
source "$CONF"             # SUBJECT, IMAGE, POLICY, BENCH_TAG, BENCHMARKS

RUN_TIMEOUT="${RUN_TIMEOUT:-600}"
TEST=groovy-bench
BENCH_URL="https://raw.githubusercontent.com/apache/groovy/$BENCH_TAG/benchmark/bench"
DOWNLOAD=0
if [[ -z "${GROOVY_BENCH_DIR:-}" ]]; then
  GROOVY_BENCH_DIR="$ROOT/.cache/groovy-bench/$BENCH_TAG"; DOWNLOAD=1
fi

# ------------------------------------------------------------------ benchmark scripts
mkdir -p "$GROOVY_BENCH_DIR"
BENCH_META=""
for b in "${BENCHMARKS[@]}"; do
  f="${b%%:*}.groovy"
  if [[ ! -s "$GROOVY_BENCH_DIR/$f" ]]; then
    (( DOWNLOAD )) || die "benchmark script not found: $GROOVY_BENCH_DIR/$f"
    log "downloading $BENCH_URL/$f"
    "$PY" -c 'import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
      "$BENCH_URL/$f" "$GROOVY_BENCH_DIR/$f.part" && mv "$GROOVY_BENCH_DIR/$f.part" "$GROOVY_BENCH_DIR/$f" \
      || die "cannot download $f (set GROOVY_BENCH_DIR to a folder with the scripts)"
  fi
  BENCH_META+="
  $f sha256 $(sha256sum "$GROOVY_BENCH_DIR/$f" | cut -c1-16) inputs: ${b#*:}"
done
chmod -R a+rX "$GROOVY_BENCH_DIR"   # the container runs as the unprivileged user groovy

RUN_META+="
groovy benchmark scripts: apache/groovy $BENCH_TAG benchmark/bench ($GROOVY_BENCH_DIR)$BENCH_META"
log "output: $OUT"

# ------------------------------------------------------------------ runs
# run_bench profile out_prefix -> prints the status
# Runs every (script, input) of BENCHMARKS in its own container under the profile.
run_bench() {
  local profile=$1 pre=$2 status=pass b script input rc out
  : > "$pre.stdout"; : > "$pre.stderr"; : > "$pre.injected"
  for b in "${BENCHMARKS[@]}"; do
    script="${b%%:*}"
    for input in ${b#*:}; do
      echo "### groovy /bench/$script.groovy $input" | tee -a "$pre.stdout" >> "$pre.stderr"
      echo "docker run --cgroup-parent $CG_PARENT --security-opt seccomp=$profile ${RUN_ARGS[*]} $IMAGE groovy /bench/$script.groovy $input" >> "$pre.injected"
      out="$(timeout "$RUN_TIMEOUT" "$REAL_DOCKER" run --rm --cgroup-parent "$CG_PARENT" \
               --security-opt "seccomp=$profile" -v "$GROOVY_BENCH_DIR:/bench:ro" "${RUN_ARGS[@]}" \
               "$IMAGE" groovy "/bench/$script.groovy" "$input" < /dev/null 2>> "$pre.stderr")"
      rc=$?
      printf '%s\n' "$out" >> "$pre.stdout"
      echo "### exit code: $rc" >> "$pre.stdout"
      [[ $status == pass ]] || continue   # keep running the rest, report the first failure
      if (( rc == 124 )); then status="timeout($script $input)"
      elif (( rc != 0 )); then status="fail($script $input)"
      elif [[ -z "${out//[[:space:]]/}" ]]; then status="fail-output($script $input)"
      fi
    done
  done
  echo "$status"
}

# ------------------------------------------------------------------ main
log "==================== $SUBJECT ($IMAGE)"
if prepare_subject "$SUBJECT" "$IMAGE" "$POLICY" \
     "benchmark: apache/groovy $BENCH_TAG benchmark/bench: ${BENCHMARKS[*]}; run args: ${RUN_ARGS[*]}"; then
  t=$TEST
  if has_phase workload; then
    rm -f "$sd/$t.workload."*
    log "[$SUBJECT] $t: workload run (allow-all filter, tracing)"
    trace_start "$sd/$t.workload"
    wl="$(run_bench "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
    trace_stop
    echo "$wl" > "$sd/$t.workload.status"
    log "[$SUBJECT] $t: workload run -> $wl"
    postprocess "$sd/$t.workload"
  fi

  if has_phase enforce; then
    rm -f "$sd/$t.enforce."*
    log "[$SUBJECT] $t: enforce run (SysJava policy)"
    en="$(run_bench "$sd/policy.json" "$sd/$t.enforce")"
    echo "$en" > "$sd/$t.enforce.status"
    log "[$SUBJECT] $t: enforce run -> $en"
  fi
fi

echo
"$PY" "$HERE/report.py" "$OUT"
