#!/usr/bin/env bash
#############################################################################
# workload_validation_ycsb.sh - the workload validation of
# workload_validation.sh, with YCSB as the workload, for the subjects that
# have no docker-library official test (ycsb_subjects.conf).
#
# For every subject, sequentially:
#   workload  start the server under an allow-all seccomp filter, wait until it
#             is ready, run YCSB against it (load, then the core workloads)
#             while bpftrace records the server's syscalls, binaries and
#             libraries; then diff against the SysJava policy and against
#             SysJava's startup discovery (see workload_validation.sh).
#   enforce   the same under the SysJava policy: does the benchmark still pass?
#
# The YCSB client runs in its own container, outside the traced cgroup and
# without the policy: only the server is the container under test.
#
# Results go to the same folder and in the same layout as
# workload_validation.sh (test name: ycsb-<workloads>), so report.py and
# table.py cover both.
#
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation_ycsb.sh         # all
#   sudo env "PATH=$PATH" scripts/workload_validation/workload_validation_ycsb.sh solr    # some
#
# Environment (plus those of workload_validation.sh: PHASES, TEST_TIMEOUT, ARTIFACTS, OUT, ...):
#   YCSB_DIR=<dir>            YCSB checkout (default: ../YCSB, next to Prototype)
#   YCSB_IMAGE=<image>        image that builds and runs YCSB (default: maven:3-eclipse-temurin-8)
#   RECORDCOUNT=10000         records loaded
#   OPERATIONCOUNT=10000      operations per workload
#   THREADS=1                 YCSB client threads
#   READY_TIMEOUT=300         seconds to wait for the server to start
#   KEEP_FAILED=1             keep the server container of a failed run (for debugging)
#
# Requires: as workload_validation.sh, plus network access for the first YCSB
# build (Maven Central) and the YCSB_IMAGE pull.
#############################################################################
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${CONF:-$HERE/ycsb_subjects.conf}"
source "$HERE/wv_lib.sh"   # configuration, preflight, tracing, prepare_subject, postprocess

YCSB_DIR="${YCSB_DIR:-$(cd "$ROOT/.." && pwd)/YCSB}"
YCSB_IMAGE="${YCSB_IMAGE:-maven:3-eclipse-temurin-8}"
RECORDCOUNT="${RECORDCOUNT:-10000}"
OPERATIONCOUNT="${OPERATIONCOUNT:-10000}"
THREADS="${THREADS:-1}"
READY_TIMEOUT="${READY_TIMEOUT:-300}"
M2_CACHE="$ROOT/.cache/ycsb-m2"

[[ -f "$YCSB_DIR/bin/bindings.properties" ]] || die "YCSB checkout not found: $YCSB_DIR (set YCSB_DIR)"
declare -A IMAGE POLICY RUN_ARGS READY_LOG READY_PORT SETUP_URLS BINDING MODULE PROPS WORKLOADS
SUBJECTS=()
source "$CONF"

CID=""
ycsb_cleanup() {
  [[ -n $CID ]] && "$REAL_DOCKER" rm -vf "$CID" >/dev/null 2>&1
  # the build writes target/ folders into the YCSB checkout as root
  [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$YCSB_DIR" 2>/dev/null
  wv_cleanup
}
trap ycsb_cleanup EXIT

YCSB_GIT=(git -c safe.directory='*' -C "$YCSB_DIR")
YCSB_REV="$("${YCSB_GIT[@]}" rev-parse HEAD 2>/dev/null || echo unknown)"
[[ -n "$("${YCSB_GIT[@]}" status --porcelain --untracked-files=no 2>/dev/null)" ]] && YCSB_REV+=" (modified)"
RUN_META+="
ycsb: $YCSB_REV
ycsb_image: $YCSB_IMAGE  recordcount: $RECORDCOUNT  operationcount: $OPERATIONCOUNT  threads: $THREADS"
log "output: $OUT"

# ------------------------------------------------------------------ YCSB
# The YCSB containers use the host's network: they reach the server by its
# container address and need no DNS inside the container.

ycsb_build() {  # module -> 0 if the binding is built
  local module=$1
  [[ -d "$YCSB_DIR/$module/target/dependency" && -d "$YCSB_DIR/core/target/dependency" ]] && return 0
  log "building YCSB $module (log: $OUT/ycsb-build-$module.log)"
  mkdir -p "$M2_CACHE"
  "$REAL_DOCKER" run --rm --network=host -v "$YCSB_DIR:/ycsb" -v "$M2_CACHE:/root/.m2" -w /ycsb "$YCSB_IMAGE" \
    mvn -B -pl "$module" -am package dependency:copy-dependencies -DincludeScope=runtime \
        -DskipTests -Dcheckstyle.skip=true > "$OUT/ycsb-build-$module.log" 2>&1
}

ycsb_class() {  # binding -> its client class
  sed -n "s/^$1:[[:space:]]*//p" "$YCSB_DIR/bin/bindings.properties" | head -1
}

# ycsb_step load|run module class workload props... ; YCSB's output on stdout/stderr
ycsb_step() {
  local mode=$1 module=$2 class=$3 workload=$4 flag p; shift 4
  [[ $mode == load ]] && flag=-load || flag=-t
  local args=(-db "$class" "$flag" -s -threads "$THREADS" -P "workloads/workload$workload"
              -p "recordcount=$RECORDCOUNT" -p "operationcount=$OPERATIONCOUNT")
  for p in "$@"; do args+=(-p "$p"); done
  echo "### ycsb $mode workload$workload: site.ycsb.Client ${args[*]}"
  timeout "$TEST_TIMEOUT" "$REAL_DOCKER" run --rm --network=host -v "$YCSB_DIR:/ycsb:ro" -w /ycsb "$YCSB_IMAGE" \
    java -cp "$module/conf:$module/target/*:$module/target/dependency/*:core/target/*:core/target/dependency/*" \
    site.ycsb.Client "${args[@]}"
}

# ------------------------------------------------------------------ server
wait_ready() {  # cid ip marker port -> 0 when the marker is logged and the port accepts connections
  local cid=$1 ip=$2 marker=$3 port=$4 deadline=$(( SECONDS + READY_TIMEOUT ))
  while (( SECONDS < deadline )); do
    [[ "$("$REAL_DOCKER" inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" == true ]] || return 1
    if "$REAL_DOCKER" logs "$cid" 2>&1 | grep -q -F -- "$marker" \
       && "$PY" -c 'import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()' \
            "$ip" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

http_get() {  # url ; prints the response, fails on an HTTP error
  "$PY" -c 'import sys,urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=120).read().decode(errors="replace"))' "$1"
}

# run_ycsb subject profile out_prefix -> prints the status
# Starts the server under the profile, runs the benchmark, removes the server.
run_ycsb() {
  local s=$1 profile=$2 pre=$3 class ip status=pass rc w url p first args=() props=()
  class="$(ycsb_class "${BINDING[$s]}")"
  eval "args=(${RUN_ARGS[$s]})"
  : > "$pre.stdout"; : > "$pre.stderr"

  CID="$("$REAL_DOCKER" run -d --cgroup-parent "$CG_PARENT" --security-opt "seccomp=$profile" \
          "${args[@]}" "${IMAGE[$s]}" 2>> "$pre.stderr")"
  if [[ -z $CID ]]; then echo "fail(start)"; return; fi
  echo "cid $CID" > "$pre.injected"
  ip="$("$REAL_DOCKER" inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CID")"

  if ! wait_ready "$CID" "$ip" "${READY_LOG[$s]}" "${READY_PORT[$s]}"; then
    status="fail(not-ready)"
  else
    for url in ${SETUP_URLS[$s]}; do
      echo "### setup: GET ${url//@IP@/$ip}" >> "$pre.stdout"
      http_get "${url//@IP@/$ip}" >> "$pre.stdout" 2>> "$pre.stderr" || status="fail(setup)"
    done
    for p in ${PROPS[$s]}; do props+=("${p//@IP@/$ip}"); done
    if [[ $status == pass ]]; then
      first="${WORKLOADS[$s]%% *}"
      ycsb_step load "${MODULE[$s]}" "$class" "$first" "${props[@]}" >> "$pre.stdout" 2>> "$pre.stderr"; rc=$?
      if (( rc == 124 )); then status=timeout; elif (( rc != 0 )); then status="fail(load)"; fi
      for w in ${WORKLOADS[$s]}; do
        [[ $status == pass ]] || break
        ycsb_step run "${MODULE[$s]}" "$class" "$w" "${props[@]}" >> "$pre.stdout" 2>> "$pre.stderr"; rc=$?
        if (( rc == 124 )); then status=timeout; elif (( rc != 0 )); then status="fail(run-$w)"; fi
      done
    fi
    # YCSB exits 0 even when operations fail: check its summary
    if [[ $status == pass ]]; then
      if grep -q -E '^\[[A-Z-]+-FAILED\]|Return=(ERROR|NOT_FOUND|UNEXPECTED_STATE|BAD_REQUEST|FORBIDDEN|SERVICE_UNAVAILABLE)' "$pre.stdout"; then
        status="fail(operations)"
      elif ! grep -q 'Return=OK' "$pre.stdout"; then
        status="fail(no-operations)"
      fi
    fi
  fi

  "$REAL_DOCKER" logs "$CID" > "$pre.server.log" 2>&1
  if [[ $status != pass && -n "${KEEP_FAILED:-}" ]]; then
    log "keeping the server container of the failed run: $CID"
  else
    # removed without a graceful stop, as the official tests do (docker rm -f)
    "$REAL_DOCKER" rm -vf "$CID" >/dev/null 2>&1
  fi
  CID=""
  echo "$status"
}

# ------------------------------------------------------------------ main loop
for subject in "${SUBJECTS[@]}"; do
  if (( $# )) && [[ " $* " != *" $subject "* ]]; then continue; fi
  image="${IMAGE[$subject]}"
  log "==================== $subject ($image)"
  t="ycsb-${WORKLOADS[$subject]// /}"
  prepare_subject "$subject" "$image" "${POLICY[$subject]}" \
    "ycsb binding: ${BINDING[$subject]}  workloads: ${WORKLOADS[$subject]}  run args: ${RUN_ARGS[$subject]}" || continue
  if [[ -z "$(ycsb_class "${BINDING[$subject]}")" ]]; then
    log "SKIP $subject: unknown YCSB binding ${BINDING[$subject]}"
    skip "$subject" "SKIPPED (unknown YCSB binding ${BINDING[$subject]})"; continue
  fi
  if ! ycsb_build "${MODULE[$subject]}"; then
    log "SKIP $subject: YCSB build failed"
    skip "$subject" "SKIPPED (YCSB build failed, see ycsb-build-${MODULE[$subject]}.log)"; continue
  fi

  if has_phase workload; then
    rm -f "$sd/$t.workload."*
    log "[$subject] $t: workload run (allow-all filter, tracing)"
    trace_start "$sd/$t.workload"
    wl="$(run_ycsb "$subject" "$ALLOW_ALL_PROFILE" "$sd/$t.workload")"
    trace_stop
    echo "$wl" > "$sd/$t.workload.status"
    log "[$subject] $t: workload run -> $wl"
    postprocess "$sd/$t.workload"
  fi

  if has_phase enforce; then
    rm -f "$sd/$t.enforce."*
    log "[$subject] $t: enforce run (SysJava policy)"
    en="$(run_ycsb "$subject" "$sd/policy.json" "$sd/$t.enforce")"
    echo "$en" > "$sd/$t.enforce.status"
    log "[$subject] $t: enforce run -> $en"
  fi
done

echo
"$PY" "$HERE/report.py" "$OUT"
